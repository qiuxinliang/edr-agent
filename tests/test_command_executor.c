#include "edr/command_executor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep_ms(unsigned ms) { Sleep(ms); }
static void test_setenv(const char *name, const char *value) { _putenv_s(name, value); }
#else
#include <time.h>
static void sleep_ms(unsigned ms) {
  struct timespec ts;
  ts.tv_sec = (time_t)(ms / 1000u);
  ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
  nanosleep(&ts, NULL);
}
static void test_setenv(const char *name, const char *value) { setenv(name, value, 1); }
#endif

static volatile int s_bulk_work;
static volatile int s_bulk_started;
static volatile int s_bulk_release;
static volatile int s_bulk_done;
static volatile int s_critical_work;
static volatile int s_critical_done;
static volatile size_t s_pending_count;

int edr_command_replay_persisted_inbox_once_for_lane(int lane) {
  if (lane == EDR_COMMAND_LANE_BULK && s_bulk_work && !s_bulk_started) {
    s_bulk_started = 1;
    while (!s_bulk_release) {
      sleep_ms(5u);
    }
    s_bulk_done = 1;
    return 1;
  }
  if (lane == EDR_COMMAND_LANE_CRITICAL && s_critical_work && !s_critical_done) {
    s_critical_done = 1;
    return 1;
  }
  return 0;
}

size_t edr_command_state_count_inbox(void) { return s_pending_count; }

EdrCommandExecutionLane edr_command_registry_execution_lane(const char *command_type) {
  if (command_type && strcmp(command_type, "isolate_host") == 0) {
    return EDR_COMMAND_LANE_CRITICAL;
  }
  if (command_type && strcmp(command_type, "deep_forensic") == 0) {
    return EDR_COMMAND_LANE_BULK;
  }
  return EDR_COMMAND_LANE_INTERACTIVE;
}

static void require_true(int ok, const char *message) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
  }
}

static void wait_until(volatile int *value, const char *message) {
  for (int i = 0; i < 200 && !*value; i++) {
    sleep_ms(5u);
  }
  require_true(*value, message);
}

int main(void) {
  test_setenv("EDR_COMMAND_CRITICAL_WORKERS", "1");
  test_setenv("EDR_COMMAND_INTERACTIVE_WORKERS", "1");
  test_setenv("EDR_COMMAND_BULK_WORKERS", "1");
  test_setenv("EDR_COMMAND_QUEUE_CAPACITY", "8");
  test_setenv("EDR_COMMAND_QUEUE_CRITICAL_RESERVE", "2");
  require_true(edr_command_executor_start() == 0, "start command executor");

  s_bulk_work = 1;
  edr_command_executor_wake();
  wait_until(&s_bulk_started, "bulk worker starts long task");

  s_critical_work = 1;
  edr_command_executor_wake();
  wait_until(&s_critical_done, "critical command bypasses blocked bulk worker");
  require_true(!s_bulk_done, "critical command finishes while bulk task remains blocked");

  s_pending_count = 7u;
  require_true(edr_command_executor_admit("deep_forensic"),
               "normal lane reserves the final durable queue slot");
  require_true(!edr_command_executor_admit("deep_forensic"),
               "concurrent admission reservation prevents capacity oversubscription");
  edr_command_executor_release_admission();

  s_pending_count = 8u;
  require_true(!edr_command_executor_admit("deep_forensic"),
               "normal lane is rejected at durable queue capacity");
  require_true(edr_command_executor_admit("isolate_host"),
               "critical reserve admits isolation at normal capacity");
  edr_command_executor_release_admission();
  s_pending_count = 10u;
  require_true(!edr_command_executor_admit("isolate_host"),
               "critical lane is bounded after reserve is consumed");

  s_bulk_release = 1;
  wait_until(&s_bulk_done, "bulk task completes after release");
  EdrCommandExecutorHealth health;
  edr_command_executor_get_health(&health);
  require_true(health.started && health.worker_count == 3u,
               "executor exposes bounded worker count");
  require_true(health.admission_reservations == 0u,
               "admission reservations are released after persistence window");
  require_true(health.lane_executed[EDR_COMMAND_LANE_CRITICAL] > 0u &&
                   health.lane_executed[EDR_COMMAND_LANE_BULK] > 0u,
               "executor reports per-lane completion counters");
  require_true(health.queue_rejected_count >= 2u,
               "executor reports durable queue rejections");

  edr_command_executor_shutdown();
  printf("ok\n");
  return 0;
}
