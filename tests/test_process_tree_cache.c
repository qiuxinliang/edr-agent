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
