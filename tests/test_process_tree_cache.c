#include "edr/process_tree_cache.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static uint64_t test_wall_ns(void) {
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  uint64_t ticks = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
  return (ticks - 116444736000000000ULL) * 100ULL;
}
#else
#include <pthread.h>
static uint64_t test_wall_ns(void) {
  struct timespec ts;
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

typedef struct {
  uint32_t base_pid;
} ThreadArgs;

static void *writer_thread(void *raw) {
  const ThreadArgs *args = (const ThreadArgs *)raw;
  for (uint32_t i = 0; i < 2000u; i++) {
    uint32_t pid = args->base_pid + (i % 32u);
    (void)edr_pt_cache_put(pid, 10u, "worker.exe", "worker.exe --scan",
                           "/opt/worker.exe", "parent.exe", i + 1u);
    if ((i % 7u) == 0u) (void)edr_pt_cache_remove(pid);
  }
  return NULL;
}

static void *reader_thread(void *raw) {
  const ThreadArgs *args = (const ThreadArgs *)raw;
  ProcessTreeEntry entry;
  for (uint32_t i = 0; i < 4000u; i++) {
    (void)edr_pt_cache_snapshot(args->base_pid + (i % 32u), &entry);
  }
  return NULL;
}
#endif

static uint64_t test_unix_ns_to_filetime(uint64_t unix_ns) {
  return UINT64_C(116444736000000000) + unix_ns / 100u;
}

static char *make_text(size_t length, char seed) {
  char *value = (char *)malloc(length + 1u);
  assert(value != NULL);
  for (size_t i = 0u; i < length; ++i) {
    value[i] = (char)(seed + (char)(i % 17u));
  }
  value[length] = '\0';
  return value;
}

static void reset_exit_test(void) {
  edr_pt_cache_init();
  edr_pt_cache_test_set_monotonic_ns(UINT64_C(1000000000));
}

static void put_exact(uint32_t pid, uint32_t ppid, uint64_t key, uint64_t birth) {
  assert(edr_pt_cache_put_generation(pid, ppid, "parent.exe", "parent --original",
      "C:/parent.exe", "", birth, key, test_unix_ns_to_filetime(birth)) == 0);
}

static void test_exit_observation_order_and_idempotence(void) {
  const uint64_t birth = UINT64_C(1700000000000000000);
  const uint64_t child = birth + UINT64_C(1000000);
  const uint64_t exit = child + UINT64_C(1000000);
  const uint64_t ft = test_unix_ns_to_filetime(birth);
  ProcessTreeEntry entry;
  EdrProcessTreeCacheMetrics metrics;
  reset_exit_test();
  /* A target PID+CreateTime declaration does not create a process or proof. */
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_PENDING);
  assert(edr_pt_cache_snapshot(9000u, &entry) == -1);
  assert(edr_pt_cache_snapshot_parent_at(9000u, child, &entry) == -1);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_PENDING);
  edr_pt_cache_get_metrics(&metrics);
  assert(metrics.entries == 0u && metrics.pending_exits == 1u);
  assert(metrics.exits_marked == 0u && metrics.pending_exits_stored == 1u);
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_snapshot_parent_at(9000u, child, &entry) == 0);
  assert(entry.process_start_key == 9000u && entry.creation_filetime_100ns == ft);
  assert(entry.exit_time_observed && entry.exit_time_ns == exit);
  assert(!strcmp(entry.cmdline, "parent --original"));
  /* Both strong and existing live-parent callers share the same no-op rule. */
  assert(edr_pt_cache_observe_exit_generation(9000u, 9000u, ft, exit) == EDR_PTC_EXIT_APPLIED);
  assert(edr_pt_cache_mark_exit_generation(9000u, 9000u, exit) == 0);
  put_exact(9000u, 4u, 9000u, birth);
  edr_pt_cache_get_metrics(&metrics);
  assert(metrics.entries == 1u && metrics.pending_exits == 0u);
  assert(metrics.exits_marked == 1u && metrics.pending_exits_applied == 1u);
  assert(metrics.exit_observations_duplicate == 3u);
  assert(edr_pt_cache_snapshot_generation_at(9000u, 9000u, child, &entry) == 0);
  assert(entry.start_time_ns == birth && entry.exit_time_ns == exit);

  /* A different PID reuse cannot consume the older declaration. */
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_PENDING);
  put_exact(9000u, 4u, 9001u, exit + 100u);
  assert(edr_pt_cache_snapshot(9000u, &entry) == 0 && !entry.exit_time_observed);
  edr_pt_cache_get_metrics(&metrics);
  assert(metrics.pending_exits == 1u && metrics.pending_exits_applied == 0u);
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_snapshot_parent_at(9000u, child, &entry) == 0);
  assert(entry.process_start_key == 9000u);
  assert(edr_pt_cache_snapshot_generation_at(9000u, 9001u, exit + 100u, &entry) == 0);
  assert(!entry.exit_time_observed && !entry.generation_conflict);

  /* Legacy key-only calls do not create speculative pending state. */
  reset_exit_test();
  assert(edr_pt_cache_mark_exit_generation(9000u, 9000u, exit) == -1);
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_snapshot_parent_at(9000u, child, &entry) == -2);
}

static void test_exit_observation_conflicts(void) {
  const uint64_t birth = UINT64_C(1700000000000000000);
  const uint64_t child = birth + 1000u, exit = birth + 2000u;
  const uint64_t ft = test_unix_ns_to_filetime(birth);
  ProcessTreeEntry entry;
  EdrProcessTreeCacheMetrics metrics;
  /* Earlier and later conflicting exits must never rewrite the first exit. */
  for (int earlier = 0; earlier < 2; ++earlier) {
    reset_exit_test();
    put_exact(9000u, 4u, 9000u, birth);
    assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_APPLIED);
    assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft,
        earlier ? exit - 100u : exit + 100u) == EDR_PTC_EXIT_CONFLICT);
    assert(edr_pt_cache_snapshot(9000u, &entry) == 0);
    assert(entry.exit_time_ns == exit && entry.generation_conflict);
    assert(edr_pt_cache_snapshot_parent_at(9000u, child, &entry) == -2);
    put_exact(9000u, 4u, 9000u, birth);
    assert(edr_pt_cache_snapshot(9000u, &entry) == 0 && entry.generation_conflict);
    edr_pt_cache_get_metrics(&metrics);
    assert(metrics.exits_marked == 1u);
  }
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_PENDING);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit + 100u) == EDR_PTC_EXIT_CONFLICT);
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_snapshot(9000u, &entry) == 0);
  assert(entry.generation_conflict && !entry.exit_time_observed);
  assert(edr_pt_cache_snapshot_parent_at(9000u, child, &entry) == -2);

  /* A target key constraint may not be replaced by the arriving native key. */
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 9001u, ft, exit) == EDR_PTC_EXIT_PENDING);
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_snapshot(9000u, &entry) == 0);
  assert(entry.generation_conflict && !entry.exit_time_observed);
  reset_exit_test();
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_observe_exit_generation(9000u, 9001u, ft, exit) == EDR_PTC_EXIT_CONFLICT);
  assert(edr_pt_cache_snapshot(9000u, &entry) == 0 && entry.generation_conflict);

  /* Same birth/multiple keys and same key/different births are contradictory. */
  reset_exit_test();
  put_exact(9000u, 4u, 9000u, birth);
  put_exact(9000u, 4u, 9001u, birth);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_CONFLICT);
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 9000u, ft, exit) == EDR_PTC_EXIT_PENDING);
  assert(edr_pt_cache_observe_exit_generation(9000u, 9000u, ft + 1u, exit) == EDR_PTC_EXIT_CONFLICT);
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_snapshot(9000u, &entry) == 0 && entry.generation_conflict);
  reset_exit_test();
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_observe_exit_generation(9000u, 9000u, ft + 1u, exit) == EDR_PTC_EXIT_CONFLICT);

  /* A claimed exit before a same-handle alive witness is not safe closure. */
  reset_exit_test();
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_mark_alive_generation(9000u, 9000u, ft, exit + 100u) == 0);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_CONFLICT);
  assert(edr_pt_cache_snapshot_parent_at(9000u, child, &entry) == -2);

  reset_exit_test();
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_APPLIED);
  assert(edr_pt_cache_mark_alive_generation(9000u, 9000u, ft, exit + 100u) == -2);
  assert(edr_pt_cache_snapshot(9000u, &entry) == 0);
  assert(entry.generation_conflict && entry.exit_time_ns == exit);
  assert(edr_pt_cache_snapshot_parent_at(9000u, child, &entry) == -2);

  /* A Stop crossing a known PID reuse cannot expand the old lifetime. */
  reset_exit_test();
  put_exact(9000u, 4u, 9000u, birth);
  put_exact(9000u, 4u, 9001u, child);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_CONFLICT);
  assert(edr_pt_cache_snapshot_generation_at(9000u, 9000u, birth, &entry) == 0);
  assert(entry.exit_time_ns == child && !entry.exit_time_observed && entry.generation_conflict);
  assert(edr_pt_cache_snapshot_generation_at(9000u, 9001u, child, &entry) == 0 && entry.generation_conflict);
}

static void test_pending_exit_bounds_and_restart(void) {
  const uint64_t birth = UINT64_C(1700000000000000000), exit = birth + 1000u;
  const uint64_t ft = test_unix_ns_to_filetime(birth);
  const uint64_t monotonic_start = UINT64_C(1000000000);
  ProcessTreeEntry entry;
  EdrProcessTreeCacheMetrics metrics;
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(0u, 0u, ft, exit) == EDR_PTC_EXIT_INVALID);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, 0u, exit) == EDR_PTC_EXIT_INVALID);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, UINT64_MAX, exit) == EDR_PTC_EXIT_INVALID);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, 0u) == EDR_PTC_EXIT_INVALID);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, birth - 1u) == EDR_PTC_EXIT_INVALID);
  edr_pt_cache_get_metrics(&metrics);
  assert(metrics.pending_exits == 0u && metrics.exit_observations_invalid == 5u);
  for (uint32_t i = 0u; i < EDR_PTC_PENDING_EXIT_CAPACITY; ++i)
    assert(edr_pt_cache_observe_exit_generation(10000u + i, 0u, ft, exit) == EDR_PTC_EXIT_PENDING);
  assert(edr_pt_cache_observe_exit_generation(20000u, 0u, ft, exit) == EDR_PTC_EXIT_CAPACITY);
  edr_pt_cache_get_metrics(&metrics);
  assert(metrics.entries == 0u && metrics.pending_exits == EDR_PTC_PENDING_EXIT_CAPACITY);
  assert(metrics.pending_exits_capacity_rejected == 1u);
  /* A duplicate at the boundary neither needs space nor renews its deadline. */
  edr_pt_cache_test_set_monotonic_ns(monotonic_start + EDR_PTC_PENDING_EXIT_TTL_NS - 1u);
  assert(edr_pt_cache_observe_exit_generation(10000u, 0u, ft, exit) == EDR_PTC_EXIT_PENDING);
  edr_pt_cache_test_set_monotonic_ns(monotonic_start + EDR_PTC_PENDING_EXIT_TTL_NS);
  edr_pt_cache_get_metrics(&metrics);
  assert(metrics.pending_exits == 0u && metrics.pending_exits_expired == EDR_PTC_PENDING_EXIT_CAPACITY);
  put_exact(10000u, 4u, 10000u, birth);
  assert(edr_pt_cache_snapshot(10000u, &entry) == 0 && !entry.exit_time_observed);
  assert(edr_pt_cache_observe_exit_generation(20000u, 0u, ft, exit) == EDR_PTC_EXIT_PENDING);

  /* Put also expires old declarations even without a metrics/Stop request. */
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_PENDING);
  edr_pt_cache_test_set_monotonic_ns(monotonic_start + EDR_PTC_PENDING_EXIT_TTL_NS);
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_snapshot(9000u, &entry) == 0 && !entry.exit_time_observed);
  edr_pt_cache_get_metrics(&metrics);
  assert(metrics.pending_exits_expired == 1u && metrics.pending_exits_applied == 0u);

  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_PENDING);
  edr_pt_cache_shutdown();
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, exit) == EDR_PTC_EXIT_INVALID);
  edr_pt_cache_get_metrics(&metrics);
  assert(metrics.pending_exits == 0u);
  edr_pt_cache_init();
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_snapshot(9000u, &entry) == 0 && !entry.exit_time_observed);
  edr_pt_cache_get_metrics(&metrics);
  assert(metrics.pending_exits_stored == 0u && metrics.pending_exits_applied == 0u);
}

static void test_known_parent_binding_conflicts(void) {
  const uint64_t birth = UINT64_C(1700000000000000000), child = birth + 1000u;
  const uint64_t ft = test_unix_ns_to_filetime(birth), cft = test_unix_ns_to_filetime(child);
#define BINDING_CONFLICT() edr_pt_cache_parent_binding_conflicts(9001u, 9001u, cft, 9000u, 9000u, ft)
  reset_exit_test();
  assert(!BINDING_CONFLICT()); /* Missing entries do not disprove a saved proof. */
  put_exact(9000u, 4u, 9000u, birth);
  put_exact(9001u, 9000u, 9001u, child);
  assert(!BINDING_CONFLICT());
  put_exact(9000u, 4u, 9100u, child + 1000u);
  assert(!BINDING_CONFLICT()); /* Later reuse is not a conflicting parent. */
  put_exact(9001u, 9999u, 9001u, child);
  assert(BINDING_CONFLICT());
  reset_exit_test();
  assert(edr_pt_cache_put_generation_with_parent_state(9001u, 0u, "child", "", "", "",
      child, 9001u, cft, 0u, EDR_PARENT_PID_EXPLICIT_ZERO) == 0);
  assert(BINDING_CONFLICT());
  reset_exit_test();
  put_exact(9000u, 4u, 9000u, birth);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, child - 100u) == EDR_PTC_EXIT_APPLIED);
  assert(BINDING_CONFLICT());
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft, child - 100u) == EDR_PTC_EXIT_PENDING);
  assert(BINDING_CONFLICT()); /* An exact target exit is also negative evidence. */
  reset_exit_test();
  put_exact(9000u, 4u, 9100u, birth);
  assert(BINDING_CONFLICT());
  reset_exit_test();
  put_exact(9001u, 9000u, 9001u, child + 100u);
  assert(BINDING_CONFLICT());
  reset_exit_test();
  put_exact(9000u, 4u, 9100u, birth + 100u);
  assert(BINDING_CONFLICT()); /* Native reuse before child disproves old proof. */
  assert(edr_pt_cache_mark_alive_generation(9000u, 9100u, ft + 1u, child) == 0);
  assert(BINDING_CONFLICT()); /* Another proved generation covers child birth. */
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft + 1u, child + 100u) == EDR_PTC_EXIT_PENDING);
  assert(BINDING_CONFLICT()); /* Target birth alone disproves the old lifetime. */
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, cft + 1u, child + 200u) == EDR_PTC_EXIT_PENDING);
  assert(!BINDING_CONFLICT()); /* Reuse strictly after the child stays harmless. */
  reset_exit_test();
  put_exact(9000u, 4u, 9100u, birth - 100u);
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft - 1u, birth + 100u) == EDR_PTC_EXIT_APPLIED);
  assert(BINDING_CONFLICT()); /* Older exact exit overlaps the saved birth. */
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft - 1u, birth + 100u) == EDR_PTC_EXIT_PENDING);
  assert(BINDING_CONFLICT()); /* Same negative proof while Start is pending. */
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft - 2u, birth - 100u) == EDR_PTC_EXIT_PENDING);
  assert(!BINDING_CONFLICT()); /* An unrelated older process already exited. */
  reset_exit_test();
  assert(edr_pt_cache_observe_exit_generation(9000u, 0u, ft - 1u, birth) == EDR_PTC_EXIT_PENDING);
  assert(!BINDING_CONFLICT()); /* Adjacent lifetimes are not an overlap. */
  assert(edr_pt_cache_parent_binding_conflicts(0u, 9001u, cft, 9000u, 9000u, ft));
#undef BINDING_CONFLICT
}

#ifndef _WIN32
static void *repeat_lifecycle_start(void *unused) {
  (void)unused;
  for (unsigned i = 0u; i < 200u; ++i)
    put_exact(9000u, 4u, 9000u, UINT64_C(1700000000000000000));
  return NULL;
}
static void *repeat_lifecycle_stop(void *unused) {
  (void)unused;
  const uint64_t birth = UINT64_C(1700000000000000000);
  for (unsigned i = 0u; i < 200u; ++i) {
    EdrProcessExitResult rc = edr_pt_cache_observe_exit_generation(
        9000u, 0u, test_unix_ns_to_filetime(birth), birth + 1000u);
    assert(rc == EDR_PTC_EXIT_APPLIED || rc == EDR_PTC_EXIT_PENDING);
  }
  return NULL;
}
static void test_concurrent_lifecycle_observations(void) {
  pthread_t start, stop;
  EdrProcessTreeCacheMetrics metrics;
  ProcessTreeEntry entry;
  reset_exit_test();
  assert(!pthread_create(&start, NULL, repeat_lifecycle_start, NULL));
  assert(!pthread_create(&stop, NULL, repeat_lifecycle_stop, NULL));
  assert(!pthread_join(start, NULL));
  assert(!pthread_join(stop, NULL));
  edr_pt_cache_get_metrics(&metrics);
  assert(metrics.entries == 1u && metrics.pending_exits == 0u);
  assert(metrics.exits_marked == 1u && metrics.exit_observations_duplicate == 199u);
  assert(metrics.exit_observations_conflict == 0u);
  assert(edr_pt_cache_snapshot(9000u, &entry) == 0);
  assert(entry.exit_time_observed && entry.exit_time_ns == UINT64_C(1700000000000001000));
}
#endif

int main(void) {
  ProcessTreeEntry entry;
  edr_pt_cache_init();
  assert(edr_pt_cache_snapshot(4242u, &entry) == -1);
  assert(edr_pt_cache_put(4242u, 3131u, "powershell.exe", "powershell.exe -NoP",
                          "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                          "cmd.exe", 123u) == 0);
  assert(edr_pt_cache_snapshot(4242u, &entry) == 0);
  assert(entry.pid == 4242u);
  assert(entry.ppid == 3131u);
  assert(strcmp(entry.process_name, "powershell.exe") == 0);
  assert(strcmp(entry.cmdline, "powershell.exe -NoP") == 0);
  assert(edr_pt_cache_put(4243u, 3131u, "cmd.exe", "cmd /c whoami",
                          "C:/Windows/System32/cmd.exe", "explorer.exe", 124u) == 0);
  assert(edr_pt_cache_remove(4242u) == 0);
  assert(edr_pt_cache_snapshot(4243u, &entry) == 0);
  assert(strcmp(entry.process_name, "cmd.exe") == 0);

  {
    /* The 256/512 and 1024 intermediate thresholds are not source limits.
     * A full BehaviorRecord-sized fact survives; only input beyond the public
     * 4096-byte contract is clipped and named. */
    char *cmd_256 = make_text(256u, 'a');
    char *path_1024 = make_text(1024u, 'A');
    char *full_cmd = make_text(EDR_PTC_STR_LONG - 1u, 'b');
    char *full_path = make_text(EDR_PTC_STR_PATH - 1u, 'B');
    char *over_cmd = make_text(EDR_PTC_STR_LONG, 'c');
    char *over_path = make_text(EDR_PTC_STR_PATH, 'C');

    assert(edr_pt_cache_put(8100u, 1u, "boundary.exe", cmd_256,
                            path_1024, "parent.exe", 100u) == 0);
    assert(edr_pt_cache_snapshot(8100u, &entry) == 0);
    assert(strlen(entry.cmdline) == 256u);
    assert(strlen(entry.exe_path) == 1024u);
    assert(entry.source_truncation_mask == 0u);

    assert(edr_pt_cache_put(8101u, 1u, "full.exe", full_cmd,
                            full_path, "parent.exe", 101u) == 0);
    assert(edr_pt_cache_snapshot(8101u, &entry) == 0);
    assert(strlen(entry.cmdline) == EDR_PTC_STR_LONG - 1u);
    assert(strlen(entry.exe_path) == EDR_PTC_STR_PATH - 1u);
    assert(entry.source_truncation_mask == 0u);

    assert(edr_pt_cache_put(8102u, 1u, "over.exe", over_cmd,
                            over_path, "parent.exe", 102u) == 0);
    assert(edr_pt_cache_snapshot(8102u, &entry) == 0);
    assert(strlen(entry.cmdline) == EDR_PTC_STR_LONG - 1u);
    assert(strlen(entry.exe_path) == EDR_PTC_STR_PATH - 1u);
    assert((entry.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_CMDLINE) != 0u);
    assert((entry.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_EXE_PATH) != 0u);

    /* A full-size prefix may already have been clipped by the collector.
     * Provenance, not strlen, must keep that fact non-resolved. */
    assert(edr_pt_cache_put_generation_with_provenance(
               8103u, 1u, "upstream.exe", full_cmd, full_path, "parent.exe",
               103u, UINT64_C(0x8103), test_unix_ns_to_filetime(103u),
               EDR_PTC_SOURCE_TRUNC_CMDLINE | EDR_PTC_SOURCE_TRUNC_EXE_PATH) == 0);
    assert(edr_pt_cache_snapshot(8103u, &entry) == 0);
    assert(strlen(entry.cmdline) == EDR_PTC_STR_LONG - 1u);
    assert(strlen(entry.exe_path) == EDR_PTC_STR_PATH - 1u);
    assert((entry.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_CMDLINE) != 0u);
    assert((entry.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_EXE_PATH) != 0u);

    free(cmd_256);
    free(path_1024);
    free(full_cmd);
    free(full_path);
    free(over_cmd);
    free(over_path);
  }

  {
    char *over_cmd = make_text(EDR_PTC_STR_LONG, 'd');
    char *over_path = make_text(EDR_PTC_STR_PATH, 'D');
    char *parent_cmdline = (char *)calloc(EDR_PTC_STR_LONG, 1u);
    char grandparent_path[512];
    uint8_t projection_truncation = 0u;
    assert(parent_cmdline != NULL);
    assert(edr_pt_cache_put(8200u, 0u, "grandparent.exe", "grandparent",
                            over_path, "", 200u) == 0);
    assert(edr_pt_cache_put(8201u, 8200u, "parent.exe", over_cmd,
                            "C:/parent.exe", "grandparent.exe", 201u) == 0);
    assert(edr_pt_cache_put(8202u, 8201u, "child.exe", "child",
                            "C:/child.exe", "parent.exe", 202u) == 0);
    edr_pt_cache_fill_record_at_with_provenance(
        8202u, 203u, NULL, 0u, grandparent_path,
        sizeof(grandparent_path), NULL, parent_cmdline, EDR_PTC_STR_LONG,
        NULL, &projection_truncation);
    assert(strlen(parent_cmdline) == EDR_PTC_STR_LONG - 1u);
    assert(strlen(grandparent_path) == sizeof(grandparent_path) - 1u);
    assert((projection_truncation & EDR_PTC_RECORD_TRUNC_PARENT_CMDLINE) != 0u);
    assert((projection_truncation & EDR_PTC_RECORD_TRUNC_GRANDPARENT_PATH) != 0u);
    free(parent_cmdline);
    free(over_cmd);
    free(over_path);
  }

  {
    uint64_t now = test_wall_ns();
    assert(edr_pt_cache_put(7000u, 6000u, "old.exe", "old.exe --run",
                            "C:/old.exe", "parent.exe", now - 1000000000ULL) == 0);
    assert(edr_pt_cache_snapshot_at(7000u, now - 500000000ULL, &entry) == 0);
    assert(edr_pt_cache_snapshot_at(7000u, now - 2000000000ULL, &entry) == -2);
    assert(edr_pt_cache_mark_exit(7000u, now) == 0);
    assert(edr_pt_cache_snapshot_at(7000u, now - 100000000ULL, &entry) == 0);
    assert(edr_pt_cache_snapshot_at(7000u, now + 1u, &entry) == -2);
    assert(edr_pt_cache_put(7000u, 6001u, "new.exe", "new.exe --run",
                            "C:/new.exe", "new-parent.exe", now + 1000000000ULL) == 0);
    assert(edr_pt_cache_put(7000u, 6000u, "stale.exe", "stale.exe",
                            "C:/stale.exe", "old-parent.exe", now) == -2);
    assert(edr_pt_cache_snapshot_at(7000u, now + 1000000000ULL, &entry) == 0);
    assert(strcmp(entry.process_name, "new.exe") == 0);
    assert(entry.exit_time_ns == 0u);
  }

  {
    uint64_t now = test_wall_ns();
    uint64_t start = now - EDR_PTC_EXIT_GRACE_NS - 2000000000ULL;
    uint64_t exit = now - EDR_PTC_EXIT_GRACE_NS - 1000000000ULL;
    assert(edr_pt_cache_put(7001u, 6000u, "expired.exe", "expired.exe --run",
                            "C:/expired.exe", "parent.exe", start) == 0);
    assert(edr_pt_cache_mark_exit(7001u, exit) == 0);
    assert(edr_pt_cache_snapshot_at(7001u, exit - 1u, &entry) == -2);
  }

  {
    /* Field shape captured on WIN-FAC3AC1PS5O: an old parent generation was
     * still open, the real generation arrived around the child birth, then a
     * same-generation metadata observation arrived later.  The late put must
     * not move the real birth past the child or clear a known exit. */
    const uint32_t parent_pid = 3404u;
    const uint64_t old_key = UINT64_C(11540474045138450);
    const uint64_t old_creation = UINT64_C(134337831008307727);
    const uint64_t real_key = UINT64_C(11540474045138506);
    const uint64_t real_creation = UINT64_C(134337835417985964);
    const uint64_t child_creation = UINT64_C(134337835418663457);
    const uint64_t epoch = UINT64_C(116444736000000000);
    const uint64_t old_birth = (old_creation - epoch) * 100u;
    const uint64_t real_birth = (real_creation - epoch) * 100u;
    const uint64_t child_birth = (child_creation - epoch) * 100u;
    assert(edr_pt_cache_put_generation(parent_pid, 3228u,
                                       "gspawn-win64-helper.exe", "old-parent",
                                       "C:/Program Files/Qemu-ga/gspawn-win64-helper.exe",
                                       "qemu-ga.exe", old_birth, old_key,
                                       old_creation) == 0);
    assert(edr_pt_cache_put_generation(parent_pid, 3228u,
                                       "gspawn-win64-helper.exe", "real-parent",
                                       "C:/Program Files/Qemu-ga/gspawn-win64-helper.exe",
                                       "qemu-ga.exe", real_birth, real_key,
                                       real_creation) == 0);
    assert(edr_pt_cache_put_generation(parent_pid, 3228u,
                                       "gspawn-win64-helper.exe", "late-metadata",
                                       "C:/Program Files/Qemu-ga/gspawn-win64-helper.exe",
                                       "qemu-ga.exe", child_birth + 2000000000u,
                                       real_key, real_creation) == 0);
    assert(edr_pt_cache_snapshot_at(parent_pid, child_birth, &entry) == 0);
    assert(entry.process_start_key == real_key);
    assert(entry.creation_filetime_100ns == real_creation);
    assert(entry.start_time_ns == real_birth);
    assert(entry.exit_time_ns == 0u);
    assert(strcmp(entry.cmdline, "late-metadata") == 0);
  }

  {
    const uint32_t pid = 3405u;
    const uint64_t now = test_wall_ns();
    const uint64_t birth = (now / 100u) * 100u - 1000000000u;
    const uint64_t exit = now + 100000000u;
    const uint64_t creation = test_unix_ns_to_filetime(birth);
    assert(edr_pt_cache_put_generation(pid, 3228u, "short.exe", "initial",
                                       "C:/short.exe", "parent.exe", birth,
                                       UINT64_C(0x3405), creation) == 0);
    assert(edr_pt_cache_mark_exit_generation(pid, UINT64_C(0x3405), exit) == 0);
    assert(edr_pt_cache_put_generation(pid, 3228u, "short.exe", "late",
                                       "C:/short.exe", "parent.exe",
                                       exit + 100000000u, UINT64_C(0x3405),
                                       creation) == 0);
    assert(edr_pt_cache_snapshot_at(pid, exit - 1u, &entry) == 0);
    assert(entry.start_time_ns == birth && entry.exit_time_ns == exit);
    assert(strcmp(entry.cmdline, "late") == 0);
    assert(edr_pt_cache_snapshot_at(pid, exit + 1u, &entry) == -2);
  }

  {
    /* A delayed child event must continue to select parent generation A after
     * A exits and its PID is reused by B.  The real StartKey/FILETIME pair is
     * stored with each historical entry; event time chooses the only valid
     * parent interval instead of overwriting A with B. */
    const uint32_t parent_pid = 7100u;
    const uint32_t child_pid = 7101u;
    uint64_t now = test_wall_ns();
    uint64_t a_start = (now / 100u) * 100u - 800000000ULL;
    uint64_t child_time = a_start + 100000000ULL;
    uint64_t a_exit = a_start + 200000000ULL;
    uint64_t b_start = a_start + 400000000ULL;
    char parent_cmdline[EDR_PTC_STR_LONG];
    assert(edr_pt_cache_put_generation(parent_pid, 4u, "parent-A.exe", "A --parent",
                                       "C:/A.exe", "System", a_start,
                                       0xa001u, test_unix_ns_to_filetime(a_start)) == 0);
    assert(edr_pt_cache_put_generation(child_pid, parent_pid, "child.exe", "child --late",
                                       "C:/child.exe", "parent-A.exe", child_time,
                                       0xc001u, test_unix_ns_to_filetime(child_time)) == 0);
    assert(edr_pt_cache_mark_exit_generation(parent_pid, 0xa001u, a_exit) == 0);
    assert(edr_pt_cache_put_generation(parent_pid, 4u, "parent-B.exe", "B --parent",
                                       "C:/B.exe", "System", b_start,
                                       0xb001u, test_unix_ns_to_filetime(b_start)) == 0);
    assert(edr_pt_cache_snapshot_at(parent_pid, child_time, &entry) == 0);
    assert(entry.process_start_key == 0xa001u);
    assert(entry.creation_filetime_100ns == test_unix_ns_to_filetime(a_start));
    assert(strcmp(entry.process_name, "parent-A.exe") == 0);
    memset(parent_cmdline, 0, sizeof(parent_cmdline));
    edr_pt_cache_fill_record_at(child_pid, child_time, NULL, 0u, NULL, 0u,
                                NULL, parent_cmdline, sizeof(parent_cmdline), NULL);
    assert(strcmp(parent_cmdline, "A --parent") == 0);
    assert(edr_pt_cache_snapshot_at(parent_pid, b_start + 1000000ULL, &entry) == 0);
    assert(entry.process_start_key == 0xb001u);
    assert(strcmp(entry.process_name, "parent-B.exe") == 0);
  }

  {
    /* A delayed FileRead keeps its exited actor generation, while an event
     * from the reused PID's interval selects only the replacement. */
    const uint32_t actor_pid = 7200u;
    uint64_t now = test_wall_ns();
    uint64_t a_start = (now / 100u) * 100u - 700000000ULL;
    uint64_t read_time = a_start + 100000000ULL;
    uint64_t a_exit = a_start + 200000000ULL;
    uint64_t b_start = a_start + 400000000ULL;
    assert(edr_pt_cache_put_generation(actor_pid, 400u, "reader-A.exe", "A --read",
                                       "C:/reader-A.exe", "parent.exe", a_start,
                                       0xa7200u, test_unix_ns_to_filetime(a_start)) == 0);
    assert(edr_pt_cache_mark_exit_generation(actor_pid, 0xa7200u, a_exit) == 0);
    assert(edr_pt_cache_put_generation(actor_pid, 401u, "reader-B.exe", "B --idle",
                                       "C:/reader-B.exe", "other.exe", b_start,
                                       0xb7200u, test_unix_ns_to_filetime(b_start)) == 0);
    assert(edr_pt_cache_snapshot_at(actor_pid, read_time, &entry) == 0);
    assert(entry.process_start_key == 0xa7200u);
    assert(entry.creation_filetime_100ns == test_unix_ns_to_filetime(a_start));
    assert(strcmp(entry.exe_path, "C:/reader-A.exe") == 0);
    assert(edr_pt_cache_snapshot_at(actor_pid, b_start + 1000000ULL, &entry) == 0);
    assert(entry.process_start_key == 0xb7200u);
    assert(strcmp(entry.exe_path, "C:/reader-B.exe") == 0);
    assert(edr_pt_cache_snapshot_at(actor_pid, a_exit + 1u, &entry) == -2);
  }

  {
    EdrProcessTreeCacheMetrics metrics;
    memset(&metrics, 0, sizeof(metrics));
    edr_pt_cache_get_metrics(&metrics);
    assert(metrics.puts >= 3u);
    assert(metrics.updates >= 1u);
    assert(metrics.put_time_rejects >= 1u);
    assert(metrics.snapshot_hits >= 5u);
    assert(metrics.snapshot_misses >= 1u);
    assert(metrics.snapshot_time_rejects >= 2u);
    assert(metrics.exits_marked >= 1u);
    assert(metrics.entries >= 2u);
  }

#ifndef _WIN32
  ThreadArgs args = {5000u};
  pthread_t writer;
  pthread_t reader;
  assert(pthread_create(&writer, NULL, writer_thread, &args) == 0);
  assert(pthread_create(&reader, NULL, reader_thread, &args) == 0);
  assert(pthread_join(writer, NULL) == 0);
  assert(pthread_join(reader, NULL) == 0);
#endif

  test_exit_observation_order_and_idempotence();
  test_exit_observation_conflicts();
  test_pending_exit_bounds_and_restart();
  test_known_parent_binding_conflicts();
#ifndef _WIN32
  test_concurrent_lifecycle_observations();
#endif
  edr_pt_cache_test_set_monotonic_ns(0u);
  edr_pt_cache_shutdown();
  printf("test_process_tree_cache: ok\n");
  return 0;
}
