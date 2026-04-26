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
  edr_event_bus_destroy(b);
  return 0;
}

static void make_dummy_slot(EdrEventSlot *o) {
  memset(o, 0, sizeof(*o));
  o->type = EDR_EVENT_FILE_WRITE;
  o->size = 4;
  memcpy(o->data, "ABCD", 4u);
}

#ifdef _WIN32
static DWORD WINAPI edr_stress_producer(void *p) {
  TArg *a = (TArg *)p;
  EdrEventSlot s;
  make_dummy_slot(&s);
  while (atomic_load_explicit(&a->go, memory_order_relaxed)) {
    (void)edr_event_bus_try_push(a->bus, &s);
  }
  return 0;
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
    hp[i] = (HANDLE)_beginthreadex(NULL, 0, edr_stress_producer, &arg, 0, NULL);
    if (!hp[i]) {
      atomic_store(&arg.go, 0);
      for (int j = 0; j < i; j++) {
        (void)WaitForSingleObject(hp[j], 20000u);
        CloseHandle(hp[j]);
      }
      free(hp);
      edr_event_bus_destroy(bus);
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
  for (int i = 0; i < nprod; i++) {
    (void)WaitForSingleObject(hp[i], 60000u);
    CloseHandle(hp[i]);
  }
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
  if (test_seq() != 0) {
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
