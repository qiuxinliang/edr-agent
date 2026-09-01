#include "edr/process_tree_cache.h"

#include <assert.h>
#include <stdio.h>
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
    /* A delayed child event must continue to select parent generation A after
     * A exits and its PID is reused by B.  The real StartKey/FILETIME pair is
     * stored with each historical entry; event time chooses the only valid
     * parent interval instead of overwriting A with B. */
    const uint32_t parent_pid = 7100u;
    const uint32_t child_pid = 7101u;
    uint64_t now = test_wall_ns();
    uint64_t a_start = now - 800000000ULL;
    uint64_t child_time = a_start + 100000000ULL;
    uint64_t a_exit = a_start + 200000000ULL;
    uint64_t b_start = a_start + 400000000ULL;
    char parent_cmdline[EDR_PTC_STR_LONG];
    assert(edr_pt_cache_put_generation(parent_pid, 4u, "parent-A.exe", "A --parent",
                                       "C:/A.exe", "System", a_start,
                                       0xa001u, 133700000000000001ULL) == 0);
    assert(edr_pt_cache_put_generation(child_pid, parent_pid, "child.exe", "child --late",
                                       "C:/child.exe", "parent-A.exe", child_time,
                                       0xc001u, 133700000000000003ULL) == 0);
    assert(edr_pt_cache_mark_exit_generation(parent_pid, 0xa001u, a_exit) == 0);
    assert(edr_pt_cache_put_generation(parent_pid, 4u, "parent-B.exe", "B --parent",
                                       "C:/B.exe", "System", b_start,
                                       0xb001u, 133700000000000002ULL) == 0);
    assert(edr_pt_cache_snapshot_at(parent_pid, child_time, &entry) == 0);
    assert(entry.process_start_key == 0xa001u);
    assert(entry.creation_filetime_100ns == 133700000000000001ULL);
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

  edr_pt_cache_shutdown();
  printf("test_process_tree_cache: ok\n");
  return 0;
}
