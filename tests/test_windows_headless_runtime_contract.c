#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long size = ftell(f);
  if (size < 0) {
    fclose(f);
    return NULL;
  }
  rewind(f);
  char *data = (char *)calloc((size_t)size + 1u, 1u);
  if (!data) {
    fclose(f);
    return NULL;
  }
  if (fread(data, 1u, (size_t)size, f) != (size_t)size) {
    free(data);
    fclose(f);
    return NULL;
  }
  fclose(f);
  return data;
}

static int require_contains(const char *text, const char *needle, const char *message) {
  if (text && strstr(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (missing %s)\n", message, needle);
  return 0;
}

static int require_absent(const char *text, const char *needle, const char *message) {
  if (!text || !strstr(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (unexpected %s)\n", message, needle);
  return 0;
}

static char *read_source(const char *root, const char *relative) {
  char path[1400];
  snprintf(path, sizeof(path), "%s/%s", root, relative);
  char *data = read_file(path);
  if (!data) fprintf(stderr, "FAIL: cannot read %s\n", path);
  return data;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  if (!root || !root[0]) root = ".";
  int ok = 1;

  char *errors = read_source(root, "include/edr/error.h");
  if (!errors) return 1;
  ok &= require_contains(errors, "EDR_ERR_QUEUE_PERMISSION = 5005",
                         "queue ACL failures must have a distinct error code");
  free(errors);

  char *queue = read_source(root, "src/storage/queue_sqlite.c");
  if (!queue) return 1;
  ok &= require_contains(queue, "return EDR_ERR_QUEUE_PERMISSION;",
                         "queue lock access denial must not be reported as another instance");
  ok &= require_contains(queue, "err != ERROR_SHARING_VIOLATION && err != ERROR_LOCK_VIOLATION",
                         "only Windows lock-contention errors may enter the lock wait path");
  free(queue);

  char *main_source = read_source(root, "src/main.c");
  if (!main_source) return 1;
  ok &= require_contains(main_source, "queue ACL denies the Agent runtime identity",
                         "Agent startup must diagnose queue ACL failures explicitly");
  ok &= require_contains(main_source, "fatal open failure",
                         "Agent startup must fail closed when the durable queue cannot open");
  free(main_source);

  char *worker = read_source(root, "src/installer_worker/installer_worker_win.c");
  if (!worker) return 1;
  ok &= require_contains(worker, "edr_windows_autorun.ps1",
                         "native worker must delegate task registration to the structured PowerShell task installer");
  ok &= require_contains(worker, "stage=start-autorun begin",
                         "native worker must start and verify the scheduled task");
  ok &= require_contains(worker, "scheduled_task_started_without_agent_process",
                         "scheduled-task startup must fail when no Agent process appears");
  ok &= require_contains(worker, "takeown.exe",
                         "ACL repair must recover ownership before applying queue permissions");
  ok &= require_absent(worker, "L\"/Create /F /TN %ls /SC ONSTART",
                       "native worker must not build a nested-quoted schtasks action");
  free(worker);

  char *autorun = read_source(root, "install/windows-inno/edr_windows_autorun.ps1");
  if (!autorun) return 1;
  ok &= require_contains(autorun, "`$p.WaitForExit()",
                         "task launcher must remain alive so Task Scheduler supervises the Agent");
  ok &= require_contains(autorun, "-ExecutionTimeLimit ([TimeSpan]::Zero)",
                         "scheduled Agent must not inherit the 72-hour task limit");
  ok &= require_contains(autorun, "-RestartCount 3",
                         "scheduled Agent must be restarted after abnormal exit");
  ok &= require_contains(autorun, "-WorkingDirectory $instDir",
                         "scheduled task must use the installation directory");
  free(autorun);

  char *inno = read_source(root, "install/windows-inno/EDRAgentSetup.bundled.iss");
  if (!inno) return 1;
  ok &= require_contains(inno, "EdrWorkerStartAutorunParams, True",
                         "headless setup must fail if the scheduled task cannot start the Agent");
  ok &= require_contains(inno, "EdrWorkerBaseParams('start-autorun')",
                         "headless setup must start the registered task instead of a detached process");
  free(inno);

  return ok ? 0 : 1;
}
