/**
 * A4.1：事件总线 MPMC 无锁环表压测 + 单线程对拍小测。
 * 主线程 = 唯—消费者（与预处理线程模型一致），多线 = 生产者；满则 backpressure(dropped) 为预期之一。
 * 用法： test_event_bus_mpmc_stress [duration_ms=300] [producers=4] [cap=128]
 */

#include "edr/event_bus.h"
#include "edr/types.h"

#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <errno.h>
#include <process.h>
#include <windows.h>
static uint64_t edr_stress_ms_now(void) { return (uint64_t)GetTickCount64(); }
static void edr_stress_thread_yield(void) { SwitchToThread(); }
#else
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
static uint64_t edr_stress_ms_now(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000L);
}
static void edr_stress_thread_yield(void) { sched_yield(); }
#endif

typedef struct {
  EdrEventBus *bus;
  _Atomic int go;
} TArg;

static int test_seq(void) {
  EdrEventBus *b = edr_event_bus_create(16u);
  if (!b) {
    fprintf(stderr, "seq: create failed\n");
    return 1;
  }
  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.type = EDR_EVENT_PROCESS_CREATE;
  for (int i = 0; i < 10; i++) {
    if (!edr_event_bus_try_push(b, &slot)) {
      fprintf(stderr, "seq: push %d failed\n", i);
      edr_event_bus_destroy(b);
      return 1;
    }
  }
  if (edr_event_bus_pushed_total(b) != 10u) {
    fprintf(stderr, "seq: bad pushed_total\n");
    edr_event_bus_destroy(b);
    return 1;
  }
  if (!edr_event_bus_wait(b, 1u)) {
    fprintf(stderr, "seq: wait did not observe queued data\n");
    edr_event_bus_destroy(b);
    return 1;
  }
  for (int j = 0; j < 10; j++) {
    if (!edr_event_bus_try_pop(b, &slot)) {
      fprintf(stderr, "seq: pop %d failed\n", j);
      edr_event_bus_destroy(b);
      return 1;
    }
  }
  if (edr_event_bus_used_approx(b) != 0u) {
    fprintf(stderr, "seq: not empty (used=%u)\n", edr_event_bus_used_approx(b));
    edr_event_bus_destroy(b);
    return 1;
  }
  if (edr_event_bus_wait(b, 1u)) {
    fprintf(stderr, "seq: empty wait reported data\n");
    edr_event_bus_destroy(b);
    return 1;
  }
  edr_event_bus_destroy(b);
  return 0;
}

static void make_dummy_slot(EdrEventSlot *o) {
  memset(o, 0, sizeof(*o));
  o->type = EDR_EVENT_FILE_WRITE;
  o->size = 4;
  memcpy(o->data, "ABCD", 4u);
}

#if defined(_WIN32) && defined(EDR_EVENT_BUS_TESTING)
/* Test-only owner hooks; no production header or runtime API exposes them. */
void edr_event_bus_test_lock(EdrEventBus *bus);
void edr_event_bus_test_unlock(EdrEventBus *bus);
typedef struct { EdrEventBus *bus; HANDLE locked, release; DWORD held_wait; } SnapshotBusy;
static DWORD WINAPI snapshot_hold_lock(void *value) {
  SnapshotBusy *a = (SnapshotBusy *)value;
  edr_event_bus_test_lock(a->bus);
  SetEvent(a->locked);
  a->held_wait = WaitForMultipleObjects(1u, &a->release, TRUE, 1000u);
  edr_event_bus_test_unlock(a->bus);
  return 0;
}
static int test_snapshot_busy(EdrEventBus *bus) {
  SnapshotBusy *a = (SnapshotBusy *)calloc(1, sizeof(*a));
  HANDLE thread = NULL;
  int failed = 1;
  if (!a) return 1;
  a->bus = bus; a->held_wait = WAIT_FAILED;
  a->locked = CreateEventW(NULL, TRUE, FALSE, NULL);
  a->release = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!a->locked || !a->release) goto done;
  thread = CreateThread(NULL, 0, snapshot_hold_lock, a, 0, NULL);
  if (!thread) goto done;
  if (WaitForMultipleObjects(1u, &a->locked, TRUE, 2000u) == WAIT_OBJECT_0) {
    EdrEventBusSnapshot value = {7u, 999u, 888u};
    int known = edr_event_bus_try_snapshot(bus, &value);
    failed = known || value.used != 7u ||
             value.pushed != 999u || value.dropped != 888u;
  }
  SetEvent(a->release);
  /* Finite holder timeout also makes an accidentally waiting snapshot fail. */
  if (WaitForMultipleObjects(1u, &thread, TRUE, 2000u) != WAIT_OBJECT_0) {
    /* Fail the test process retaining these thread-owned dependencies. */
    fprintf(stderr, "snapshot holder join unknown\n");
    return 2;
  }
  if (a->held_wait != WAIT_OBJECT_0) failed = 1;
done:
  if (thread) CloseHandle(thread);
  if (a->release) CloseHandle(a->release);
  if (a->locked) CloseHandle(a->locked);
  free(a);
  return failed;
}
#endif

static int test_stop_snapshot(void) {
  EdrEventBusSnapshot value = {7u, 999u, 888u};
  EdrEventBus *bus = edr_event_bus_create(8u);
  EdrEventSlot slot, out;
  int failed = 1;
  if (!bus) return 1;
  make_dummy_slot(&slot); slot.p0_critical = 1u;
  if (edr_event_bus_try_snapshot(NULL, &value) || value.used != 7u ||
      value.pushed != 999u || value.dropped != 888u ||
      edr_event_bus_try_snapshot(bus, NULL)) goto done;
  if (!edr_event_bus_try_snapshot(bus, &value) || value.used ||
      value.pushed || value.dropped) goto done;
  for (unsigned i = 0; i < 8u; ++i) {
    slot.timestamp_ns = i + 1u;
    if (!edr_event_bus_try_push(bus, &slot)) goto done;
    if (i == 3u && (!edr_event_bus_try_snapshot(bus, &value) ||
        value.used != 4u || value.pushed != 4u || value.dropped)) goto done;
  }
  if (edr_event_bus_try_push(bus, &slot) ||
      !edr_event_bus_try_snapshot(bus, &value) || value.used != 8u ||
      value.pushed != 8u || value.dropped != 1u) goto done;
#if defined(_WIN32) && defined(EDR_EVENT_BUS_TESTING)
  int busy_result = test_snapshot_busy(bus);
  if (busy_result == 2) return 1; /* retain bus until test-process exit */
  if (busy_result) goto done;
  if (!edr_event_bus_try_snapshot(bus, &value) || value.used != 8u ||
      value.pushed != 8u || value.dropped != 1u) goto done;
#endif
  for (unsigned i = 0; i < 8u; ++i)
    if (!edr_event_bus_try_pop(bus, &out) || out.timestamp_ns != i + 1u) goto done;
  if (!edr_event_bus_try_snapshot(bus, &value) || value.used ||
      value.pushed != 8u || value.dropped != 1u) goto done;
  failed = 0;
done:
  edr_event_bus_destroy(bus);
  if (failed) fprintf(stderr, "stop snapshot contract failed\n");
  return failed;
}

static int test_rejected_types(void) {
  EdrEventBus *bus = edr_event_bus_create(4u);
  EdrEventSlot s;
  EdrEventBusRejections snapshot;
  if (!bus) return 1;
  make_dummy_slot(&s);
  /* Physical full while ordinary admission is still below its own limit. */
  s.p0_critical = 1u;
  for (int i = 0; i < 3; ++i) if (!edr_event_bus_try_push(bus, &s)) return 1;
  s.p0_critical = 0u;
  if (!edr_event_bus_try_push(bus, &s)) return 1;
  edr_event_bus_rejection_snapshot(bus, &snapshot);
  for (uint32_t i = 0; i < EDR_EVENT_BUS_REJECTION_TYPES; ++i) {
    if (snapshot.ordinary[i] || snapshot.p0[i]) return 1;
    s.type = (EdrEventType)i;
    s.p0_critical = 0u;
    if (edr_event_bus_try_push(bus, &s)) return 1;
    s.p0_critical = 1u;
    if (edr_event_bus_try_push(bus, &s)) return 1;
  }
  s.type = (EdrEventType)-1;
  if (edr_event_bus_try_push(bus, &s)) return 1;
  s.type = (EdrEventType)9999;
  s.p0_critical = 0u;
  if (edr_event_bus_try_push(bus, &s)) return 1;
  edr_event_bus_rejection_snapshot(bus, &snapshot);
  uint64_t total = 0u;
  for (uint32_t i = 0; i < EDR_EVENT_BUS_REJECTION_TYPES; ++i) {
    if (snapshot.ordinary[i] != (i ? 1u : 2u) ||
        snapshot.p0[i] != (i ? 1u : 2u)) return 1;
    total += snapshot.ordinary[i] + snapshot.p0[i];
  }
  if (total != edr_event_bus_dropped_total(bus)) return 1;
  edr_event_bus_destroy(bus);
  edr_event_bus_rejection_snapshot(NULL, &snapshot);
  edr_event_bus_rejection_snapshot(NULL, NULL);
  for (uint32_t i = 0; i < EDR_EVENT_BUS_REJECTION_TYPES; ++i)
    if (snapshot.ordinary[i] || snapshot.p0[i]) return 1;
  return 0;
}

/* Ordinary flood must never consume the P0 reservation.  This is deliberately
 * a cap=1 seam: it proves the invariant without relying on queue timing. */
static int test_p0_reserve(void) {
  EdrEventSlot ordinary;
  EdrEventSlot critical;
  EdrEventSlot out;
  EdrEventBus *one = edr_event_bus_create(1u);
  if (!one) {
    fprintf(stderr, "p0 reserve: cap=1 create failed\n");
    return 1;
  }
  make_dummy_slot(&ordinary);
  make_dummy_slot(&critical);
  critical.p0_critical = 1u;
  if (edr_event_bus_p0_reserved_slots(one) != 1u ||
      edr_event_bus_try_push(one, &ordinary) ||
      !edr_event_bus_try_push(one, &critical) ||
      !edr_event_bus_try_pop(one, &out) || !out.p0_critical ||
      edr_event_bus_ordinary_reserve_rejected_total(one) != 1u) {
    fprintf(stderr, "p0 reserve: cap=1 invariant failed\n");
    edr_event_bus_destroy(one);
    return 1;
  }
  edr_event_bus_destroy(one);

  EdrEventBus *bus = edr_event_bus_create(16u);
  if (!bus) {
    fprintf(stderr, "p0 reserve: create failed\n");
    return 1;
  }
  for (uint32_t i = 0u; i < 15u; ++i) {
    if (!edr_event_bus_try_push(bus, &ordinary)) {
      fprintf(stderr, "p0 reserve: ordinary slot %u rejected early\n", i);
      edr_event_bus_destroy(bus);
      return 1;
    }
  }
  if (edr_event_bus_try_push(bus, &ordinary) ||
      !edr_event_bus_try_push(bus, &critical) ||
      edr_event_bus_try_push(bus, &critical) ||
      edr_event_bus_p0_reserve_rejected_total(bus) != 1u) {
    fprintf(stderr, "p0 reserve: logical reservation invariant failed\n");
    edr_event_bus_destroy(bus);
    return 1;
  }
  EdrEventBusRejections rejected;
  edr_event_bus_rejection_snapshot(bus, &rejected);
  if (rejected.ordinary[EDR_EVENT_FILE_WRITE] != 1u ||
      rejected.p0[EDR_EVENT_FILE_WRITE] != 1u) return 1;
  for (uint32_t i = 0u; i < 16u; ++i) {
    if (!edr_event_bus_try_pop(bus, &out)) {
      fprintf(stderr, "p0 reserve: pop %u failed\n", i);
      edr_event_bus_destroy(bus);
      return 1;
    }
  }
  if (edr_event_bus_used_approx(bus) != 0u) {
    fprintf(stderr, "p0 reserve: queue did not drain\n");
    edr_event_bus_destroy(bus);
    return 1;
  }
  edr_event_bus_destroy(bus);
  return 0;
}

#ifdef _WIN32
static unsigned __stdcall edr_stress_producer(void *p) {
  TArg *a = (TArg *)p;
  EdrEventSlot s;
  make_dummy_slot(&s);
  while (atomic_load_explicit(&a->go, memory_order_relaxed)) {
    (void)edr_event_bus_try_push(a->bus, &s);
  }
  return 0;
}

static void edr_stress_wait_all_or_abort(HANDLE *handles, DWORD count,
                                         DWORD timeout_ms, const char *phase) {
  const DWORD wait_result = WaitForMultipleObjects(count, handles, TRUE, timeout_ms);
  if (wait_result != WAIT_OBJECT_0) {
    const DWORD error = GetLastError();
    fprintf(stderr,
            "mpmc: %s wait-all failed result=%lu error=%lu count=%lu timeout_ms=%lu\n",
            phase, (unsigned long)wait_result, (unsigned long)error,
            (unsigned long)count, (unsigned long)timeout_ms);
    abort();
  }
}

static void edr_stress_close_handles_or_abort(HANDLE *handles, DWORD count,
                                              const char *phase) {
  for (DWORD i = 0u; i < count; ++i) {
    if (!CloseHandle(handles[i])) {
      const DWORD error = GetLastError();
      fprintf(stderr, "mpmc: %s CloseHandle failed index=%lu error=%lu\n",
              phase, (unsigned long)i, (unsigned long)error);
      abort();
    }
  }
}
#else
static void *edr_stress_producer(void *p) {
  TArg *a = (TArg *)p;
  EdrEventSlot s;
  make_dummy_slot(&s);
  while (atomic_load_explicit(&a->go, memory_order_relaxed)) {
    (void)edr_event_bus_try_push(a->bus, &s);
  }
  return NULL;
}
#endif

static int run_mpmc(uint32_t duration_ms, int nprod, uint32_t cap) {
#ifdef _WIN32
  if (nprod < 1 || nprod > (int)MAXIMUM_WAIT_OBJECTS) {
    fprintf(stderr, "mpmc: Windows producer count must be in 1..%u (got %d)\n",
            (unsigned)MAXIMUM_WAIT_OBJECTS, nprod);
    return 1;
  }
#endif
  if (cap < 8u) {
    cap = 8u;
  }
  EdrEventBus *bus = edr_event_bus_create(cap);
  if (!bus) {
    return 1;
  }
  TArg arg;
  arg.bus = bus;
  atomic_init(&arg.go, 1);

#ifdef _WIN32
  HANDLE *hp = (HANDLE *)calloc((size_t)nprod, sizeof(HANDLE));
  if (!hp) {
    edr_event_bus_destroy(bus);
    return 1;
  }
  for (int i = 0; i < nprod; i++) {
    errno = 0;
    hp[i] = (HANDLE)_beginthreadex(NULL, 0, edr_stress_producer, &arg, 0, NULL);
    if (!hp[i]) {
      const int create_error = errno;
      atomic_store(&arg.go, 0);
      if (i > 0) {
        edr_stress_wait_all_or_abort(hp, (DWORD)i, 60000u, "producer creation cleanup");
        edr_stress_close_handles_or_abort(hp, (DWORD)i, "producer creation cleanup");
      }
      free(hp);
      edr_event_bus_destroy(bus);
      fprintf(stderr, "mpmc: _beginthreadex failed index=%d errno=%d\n", i, create_error);
      return 1;
    }
  }
#else
  pthread_t *tp = (pthread_t *)calloc((size_t)nprod, sizeof(pthread_t));
  if (!tp) {
    edr_event_bus_destroy(bus);
    return 1;
  }
  for (int i = 0; i < nprod; i++) {
    if (pthread_create(&tp[i], NULL, edr_stress_producer, &arg) != 0) {
      atomic_store(&arg.go, 0);
      for (int j = 0; j < i; j++) {
        (void)pthread_join(tp[j], NULL);
      }
      free(tp);
      edr_event_bus_destroy(bus);
      return 1;
    }
  }
#endif
  EdrEventSlot s;
  uint64_t pops = 0u;
  const uint64_t t0 = edr_stress_ms_now();
  while (edr_stress_ms_now() - t0 < (uint64_t)duration_ms) {
    if (edr_event_bus_try_pop(bus, &s)) {
      pops++;
    } else {
      edr_stress_thread_yield();
    }
  }
  atomic_store(&arg.go, 0);

#ifdef _WIN32
  edr_stress_wait_all_or_abort(hp, (DWORD)nprod, 60000u, "producer join");
  edr_stress_close_handles_or_abort(hp, (DWORD)nprod, "producer join");
  free(hp);
#else
  for (int i = 0; i < nprod; i++) {
    (void)pthread_join(tp[i], NULL);
  }
  free(tp);
#endif
  /* 生产者已停，排空剩余（单消费者不变式：成功入队均可被 pop） */
  while (edr_event_bus_try_pop(bus, &s)) {
    pops++;
  }
  {
    const uint64_t ptot = edr_event_bus_pushed_total(bus);
    const uint64_t dtot = edr_event_bus_dropped_total(bus);
    EdrEventBusRejections rejected;
    edr_event_bus_rejection_snapshot(bus, &rejected);
    if (rejected.ordinary[EDR_EVENT_FILE_WRITE] != dtot ||
        rejected.p0[EDR_EVENT_FILE_WRITE] != 0u) return 1;
    if (pops != ptot) {
      fprintf(
          stderr,
          "mpmc: invariant failed pops=%" PRIu64 " pushed=%" PRIu64 " (dropped=%" PRIu64 " used=%u)\n",
          pops, ptot, dtot, edr_event_bus_used_approx(bus));
      edr_event_bus_destroy(bus);
      return 1;
    }
    if (edr_event_bus_used_approx(bus) != 0u) {
      fprintf(stderr, "mpmc: used not zero: %u\n", edr_event_bus_used_approx(bus));
      edr_event_bus_destroy(bus);
      return 1;
    }
    fprintf(
        stdout,
        "[event_bus] A4.1 mpmc: duration=%ums nprod=%d cap=%u pops=push=%" PRIu64 " dropped=%" PRIu64
        " hwm_hits=%" PRIu64 "\n",
        (unsigned)duration_ms, nprod, edr_event_bus_capacity(bus), ptot, dtot, edr_event_bus_high_water_hits(bus));
  }
  edr_event_bus_destroy(bus);
  return 0;
}

int main(int argc, char **argv) {
  if (test_stop_snapshot() != 0) return 1;
  if (test_rejected_types() != 0) {
    fprintf(stderr, "rejected event type accounting failed\n");
    return 1;
  }
  if (test_seq() != 0) {
    return 1;
  }
  if (test_p0_reserve() != 0) {
    return 1;
  }
  uint32_t dms = 300u;
  int nprod = 4;
  uint32_t cap = 128u;
  if (argc >= 2) {
    dms = (uint32_t)strtoul(argv[1], NULL, 10);
    if (dms < 20u) {
      dms = 20u;
    }
  }
  if (argc >= 3) {
    nprod = (int)strtol(argv[2], NULL, 10);
    if (nprod < 1) {
      nprod = 1;
    }
    if (nprod > 32) {
      nprod = 32;
    }
  }
  if (argc >= 4) {
    cap = (uint32_t)strtoul(argv[3], NULL, 10);
  }
  return run_mpmc(dms, nprod, cap);
}
