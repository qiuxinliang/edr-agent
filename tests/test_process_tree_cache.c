#include "edr/process_tree_cache.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <pthread.h>

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
