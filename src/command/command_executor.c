#include "edr/command_executor.h"

#include "edr/command.h"
#include "edr/command_state.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#else
#include <pthread.h>
#include <time.h>
#endif

enum { EDR_COMMAND_EXECUTOR_MAX_WORKERS = 8 };

typedef struct EdrCommandWorker {
  EdrCommandExecutionLane lane;
#ifdef _WIN32
  HANDLE thread;
#else
  pthread_t thread;
#endif
} EdrCommandWorker;

typedef struct EdrCommandExecutor {
  int started;
  int accepting;
  uint32_t active_workers;
  uint32_t worker_count;
  uint32_t queue_capacity;
  uint32_t queue_critical_reserve;
  uint32_t admission_reservations;
  uint64_t wake_count;
  uint64_t executed_count;
  uint64_t replay_error_count;
  uint64_t queue_rejected_count;
  uint64_t lane_executed[EDR_COMMAND_LANE_COUNT];
  EdrCommandWorker workers[EDR_COMMAND_EXECUTOR_MAX_WORKERS];
#ifdef _WIN32
  CRITICAL_SECTION lock;
  CONDITION_VARIABLE wake;
#else
  pthread_mutex_t lock;
  pthread_cond_t wake;
#endif
} EdrCommandExecutor;

static EdrCommandExecutor s_executor;

static uint32_t executor_env_u32(const char *name, uint32_t fallback,
                                 uint32_t min_value, uint32_t max_value) {
  const char *raw = getenv(name);
  unsigned long value = fallback;
  if (raw && raw[0]) {
    char *end = NULL;
    unsigned long parsed = strtoul(raw, &end, 10);
    if (end != raw && *end == '\0') {
      value = parsed;
    }
  }
  if (value < min_value) value = min_value;
  if (value > max_value) value = max_value;
  return (uint32_t)value;
}

#ifdef _WIN32
static void executor_lock(void) { EnterCriticalSection(&s_executor.lock); }
static void executor_unlock(void) { LeaveCriticalSection(&s_executor.lock); }
static void executor_wait(void) {
  (void)SleepConditionVariableCS(&s_executor.wake, &s_executor.lock, 1000u);
}
static void executor_signal_all(void) { WakeAllConditionVariable(&s_executor.wake); }
#else
static void executor_lock(void) { pthread_mutex_lock(&s_executor.lock); }
static void executor_unlock(void) { pthread_mutex_unlock(&s_executor.lock); }
static void executor_wait(void) {
  struct timespec deadline;
  if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
    pthread_cond_wait(&s_executor.wake, &s_executor.lock);
    return;
  }
  deadline.tv_sec += 1;
  (void)pthread_cond_timedwait(&s_executor.wake, &s_executor.lock, &deadline);
}
static void executor_signal_all(void) { pthread_cond_broadcast(&s_executor.wake); }
#endif

#ifdef _WIN32
static unsigned __stdcall executor_main(void *arg)
#else
static void *executor_main(void *arg)
#endif
{
  EdrCommandWorker *worker = (EdrCommandWorker *)arg;
  for (;;) {
    executor_lock();
    if (!s_executor.accepting) {
      executor_unlock();
      break;
    }
    s_executor.active_workers++;
    executor_unlock();

    int rc = edr_command_replay_persisted_inbox_once_for_lane((int)worker->lane);

    executor_lock();
    if (s_executor.active_workers > 0u) {
      s_executor.active_workers--;
    }
    if (rc > 0) {
      s_executor.executed_count++;
      s_executor.lane_executed[worker->lane]++;
    } else if (rc < 0) {
      s_executor.replay_error_count++;
    }
    if (rc <= 0 && s_executor.accepting) {
      executor_wait();
    }
    executor_unlock();
  }
#ifdef _WIN32
  return 0u;
#else
  return NULL;
#endif
}

static int executor_add_worker(EdrCommandExecutionLane lane) {
  if (s_executor.worker_count >= EDR_COMMAND_EXECUTOR_MAX_WORKERS) {
    return -1;
  }
  EdrCommandWorker *worker = &s_executor.workers[s_executor.worker_count];
  memset(worker, 0, sizeof(*worker));
  worker->lane = lane;
#ifdef _WIN32
  worker->thread = (HANDLE)_beginthreadex(NULL, 0, executor_main, worker, 0, NULL);
  if (!worker->thread) {
    return -1;
  }
#else
  if (pthread_create(&worker->thread, NULL, executor_main, worker) != 0) {
    return -1;
  }
#endif
  s_executor.worker_count++;
  return 0;
}

int edr_command_executor_start(void) {
  if (s_executor.started) {
    return 0;
  }
  memset(&s_executor, 0, sizeof(s_executor));
#ifdef _WIN32
  InitializeCriticalSection(&s_executor.lock);
  InitializeConditionVariable(&s_executor.wake);
#else
  if (pthread_mutex_init(&s_executor.lock, NULL) != 0) {
    return -1;
  }
  if (pthread_cond_init(&s_executor.wake, NULL) != 0) {
    pthread_mutex_destroy(&s_executor.lock);
    return -1;
  }
#endif
  s_executor.queue_capacity = executor_env_u32("EDR_COMMAND_QUEUE_CAPACITY", 128u, 8u, 1024u);
  s_executor.queue_critical_reserve =
      executor_env_u32("EDR_COMMAND_QUEUE_CRITICAL_RESERVE", 16u, 1u, 128u);
  s_executor.accepting = 1;

  uint32_t critical_workers = executor_env_u32("EDR_COMMAND_CRITICAL_WORKERS", 1u, 1u, 2u);
  uint32_t interactive_workers = executor_env_u32("EDR_COMMAND_INTERACTIVE_WORKERS", 2u, 1u, 4u);
  uint32_t bulk_workers = executor_env_u32("EDR_COMMAND_BULK_WORKERS", 1u, 1u, 2u);
  for (uint32_t i = 0; i < critical_workers; i++) {
    if (executor_add_worker(EDR_COMMAND_LANE_CRITICAL) != 0) goto fail;
  }
  for (uint32_t i = 0; i < interactive_workers; i++) {
    if (executor_add_worker(EDR_COMMAND_LANE_INTERACTIVE) != 0) goto fail;
  }
  for (uint32_t i = 0; i < bulk_workers; i++) {
    if (executor_add_worker(EDR_COMMAND_LANE_BULK) != 0) goto fail;
  }
  s_executor.started = 1;
  return 0;

fail:
  executor_lock();
  s_executor.accepting = 0;
  executor_signal_all();
  executor_unlock();
  for (uint32_t i = 0; i < s_executor.worker_count; i++) {
#ifdef _WIN32
    (void)WaitForSingleObject(s_executor.workers[i].thread, INFINITE);
    CloseHandle(s_executor.workers[i].thread);
#else
    pthread_join(s_executor.workers[i].thread, NULL);
#endif
  }
#ifdef _WIN32
  DeleteCriticalSection(&s_executor.lock);
#else
  pthread_cond_destroy(&s_executor.wake);
  pthread_mutex_destroy(&s_executor.lock);
#endif
  memset(&s_executor, 0, sizeof(s_executor));
  return -1;
}

void edr_command_executor_wake(void) {
  if (!s_executor.started && edr_command_executor_start() != 0) {
    return;
  }
  executor_lock();
  if (s_executor.accepting) {
    s_executor.wake_count++;
    executor_signal_all();
  }
  executor_unlock();
}

int edr_command_executor_admit(const char *command_type) {
  if (!s_executor.started && edr_command_executor_start() != 0) {
    return 0;
  }
  int critical = edr_command_registry_execution_lane(command_type) == EDR_COMMAND_LANE_CRITICAL;
  executor_lock();
  size_t pending = edr_command_state_count_inbox();
  size_t effective_pending = pending + (size_t)s_executor.admission_reservations;
  int admitted = s_executor.accepting &&
                 (effective_pending < (size_t)s_executor.queue_capacity ||
                  (critical && effective_pending < (size_t)s_executor.queue_capacity +
                                                     (size_t)s_executor.queue_critical_reserve));
  if (admitted) {
    s_executor.admission_reservations++;
  } else {
    s_executor.queue_rejected_count++;
  }
  executor_unlock();
  return admitted;
}

void edr_command_executor_release_admission(void) {
  if (!s_executor.started) {
    return;
  }
  executor_lock();
  if (s_executor.admission_reservations > 0u) {
    s_executor.admission_reservations--;
  }
  executor_unlock();
}

void edr_command_executor_shutdown(void) {
  if (!s_executor.started) {
    return;
  }
  executor_lock();
  s_executor.accepting = 0;
  executor_signal_all();
  executor_unlock();
  for (uint32_t i = 0; i < s_executor.worker_count; i++) {
#ifdef _WIN32
    (void)WaitForSingleObject(s_executor.workers[i].thread, INFINITE);
    CloseHandle(s_executor.workers[i].thread);
#else
    pthread_join(s_executor.workers[i].thread, NULL);
#endif
  }
#ifdef _WIN32
  DeleteCriticalSection(&s_executor.lock);
#else
  pthread_cond_destroy(&s_executor.wake);
  pthread_mutex_destroy(&s_executor.lock);
#endif
  memset(&s_executor, 0, sizeof(s_executor));
}

void edr_command_executor_get_health(EdrCommandExecutorHealth *out_health) {
  if (!out_health) {
    return;
  }
  memset(out_health, 0, sizeof(*out_health));
  if (!s_executor.started) {
    return;
  }
  executor_lock();
  out_health->started = s_executor.started;
  out_health->accepting = s_executor.accepting;
  out_health->active = s_executor.active_workers > 0u;
  out_health->worker_count = s_executor.worker_count;
  out_health->queue_capacity = s_executor.queue_capacity;
  out_health->queue_critical_reserve = s_executor.queue_critical_reserve;
  out_health->admission_reservations = s_executor.admission_reservations;
  out_health->wake_count = s_executor.wake_count;
  out_health->executed_count = s_executor.executed_count;
  out_health->replay_error_count = s_executor.replay_error_count;
  out_health->queue_rejected_count = s_executor.queue_rejected_count;
  for (int lane = 0; lane < EDR_COMMAND_LANE_COUNT; lane++) {
    out_health->lane_executed[lane] = s_executor.lane_executed[lane];
  }
  executor_unlock();
  out_health->pending_count = (uint32_t)edr_command_state_count_inbox();
}
