#ifdef _WIN32
#include "edr/local_evidence_cache.h"
#include "edr/config.h"
#include "cJSON.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile LONG cancelled;
static BOOL WINAPI migration_control(DWORD signal) {
  if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
    InterlockedExchange(&cancelled, 1); return TRUE;
  }
  return FALSE;
}
static int migration_cancelled(void *unused) {
  (void)unused; return InterlockedCompareExchange(&cancelled, 0, 0) != 0;
}

static int absolute_path(const char *path) {
  return path && ((strlen(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) ||
                  (path[0] == '\\' && path[1] == '\\')) && !strchr(path, '"');
}

static int number_is(const cJSON *root, const char *name, int value) {
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name);
  return cJSON_IsNumber(item) && item->valuedouble == value;
}

/* Probe the actual selected rollback executable. Unknown options, a hung
 * process, oversized output, or a missing runtime dependency fail closed. */
static int compatible_rollback(const char *path) {
  char self[4096], command[8192], output[1024];
  HANDLE read_pipe = NULL, write_pipe = NULL, null_file = INVALID_HANDLE_VALUE;
  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  STARTUPINFOA si; PROCESS_INFORMATION pi;
  int ok = 0;
  DWORD self_len = GetModuleFileNameA(NULL, self, sizeof(self));
  if (!absolute_path(path) || !self_len || self_len >= sizeof(self)) return 0;
  HANDLE rollback_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  HANDLE self_file = CreateFileA(self, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  BY_HANDLE_FILE_INFORMATION rollback_id, self_id;
  int distinct = rollback_file != INVALID_HANDLE_VALUE && self_file != INVALID_HANDLE_VALUE &&
    GetFileInformationByHandle(rollback_file, &rollback_id) && GetFileInformationByHandle(self_file, &self_id) &&
    !(rollback_id.dwVolumeSerialNumber == self_id.dwVolumeSerialNumber &&
      rollback_id.nFileIndexHigh == self_id.nFileIndexHigh && rollback_id.nFileIndexLow == self_id.nFileIndexLow);
  if (self_file != INVALID_HANDLE_VALUE) CloseHandle(self_file);
  if (!distinct) goto done;
  if (snprintf(command, sizeof(command), "\"%s\" --evidence-cache-format-capabilities", path) >= (int)sizeof(command)) goto done;
  if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0) || !SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0)) goto done;
  null_file = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
  if (null_file == INVALID_HANDLE_VALUE) goto done;
  memset(&si, 0, sizeof(si)); memset(&pi, 0, sizeof(pi)); si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = write_pipe; si.hStdError = null_file; si.hStdInput = null_file;
  if (!CreateProcessA(path, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) goto done;
  CloseHandle(write_pipe); write_pipe = NULL;
  DWORD wait = WaitForSingleObject(pi.hProcess, 5000), code = 1, available = 0, received = 0;
  if (wait != WAIT_OBJECT_0) { TerminateProcess(pi.hProcess, 125); WaitForSingleObject(pi.hProcess, 2000); }
  if (wait == WAIT_OBJECT_0 && GetExitCodeProcess(pi.hProcess, &code) && code == 0 &&
      PeekNamedPipe(read_pipe, NULL, 0, NULL, &available, NULL) && available > 0 && available < sizeof(output) &&
      ReadFile(read_pipe, output, available, &received, NULL) && received == available) {
    output[received] = 0;
    const char *end = NULL;
    cJSON *root = cJSON_ParseWithOpts(output, &end, 1);
    ok = number_is(root, "protocol", 1) && number_is(root, "read_min", 0) && number_is(root, "read_max", 2) &&
         number_is(root, "write_min", 0) && number_is(root, "write_max", 2);
    cJSON_Delete(root);
  }
  CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
done:
  if (rollback_file != INVALID_HANDLE_VALUE) CloseHandle(rollback_file);
  if (read_pipe) CloseHandle(read_pipe);
  if (write_pipe) CloseHandle(write_pipe);
  if (null_file != INVALID_HANDLE_VALUE) CloseHandle(null_file);
  return ok;
}

int edr_local_evidence_cache_maintenance_main(int argc, char **argv) {
  const char *config = NULL, *rollback = NULL;
  uint32_t timeout = 600000;
  int timeout_seen = 0;
  for (int i = 2; i < argc; ++i) {
    if (!strcmp(argv[i], "--config") && !config && i + 1 < argc) config = argv[++i];
    else if (!strcmp(argv[i], "--evidence-cache-rollback-exe") && !rollback && i + 1 < argc) rollback = argv[++i];
    else if (!strcmp(argv[i], "--migration-timeout-ms") && !timeout_seen && i + 1 < argc) {
      char *end = NULL; const char *value = argv[++i];
      unsigned long parsed = strtoul(value, &end, 10);
      if (!value[0] || !end || *end || parsed == 0 || parsed > 600000) {
        fprintf(stderr, "migration timeout must be an integer from 1 to 600000 milliseconds\n"); return 2;
      }
      timeout = (uint32_t)parsed; timeout_seen = 1;
    } else {
      fprintf(stderr, "cache maintenance accepts only config, rollback executable and timeout options\n"); return 2;
    }
  }
  if (!absolute_path(config) || !absolute_path(rollback)) {
    fprintf(stderr, "cache maintenance requires absolute --config and --evidence-cache-rollback-exe paths\n"); return 2;
  }
  if (!compatible_rollback(rollback)) {
    fprintf(stderr, "selected rollback executable must be a separate runnable copy supporting cache formats 0..2\n"); return 2;
  }
  EdrConfig cfg; memset(&cfg, 0, sizeof(cfg));
  if (edr_config_load(config, &cfg) != EDR_OK) {
    fprintf(stderr, "cache maintenance could not load the installed config\n"); edr_config_free_heap(&cfg); return 2;
  }
  const char *path = getenv("EDR_EVIDENCE_CACHE_PATH");
  if (!path || !path[0]) path = cfg.offline.evidence_cache_path;
  if (!absolute_path(path) || cfg.offline.evidence_cache_max_size_mb < 4) {
    fprintf(stderr, "cache maintenance requires the configured absolute cache path and size budget\n");
    edr_config_free_heap(&cfg); return 2;
  }
  InterlockedExchange(&cancelled, 0);
  if (!SetConsoleCtrlHandler(migration_control, TRUE)) {
    fprintf(stderr, "cache maintenance cancellation handler failed: %lu\n", (unsigned long)GetLastError());
    edr_config_free_heap(&cfg); return 2;
  }
  EdrEvidenceMigrationResult result;
  int rc = edr_local_evidence_cache_migrate(path, cfg.offline.evidence_cache_max_size_mb, timeout,
                                            migration_cancelled, NULL, &result);
  SetConsoleCtrlHandler(migration_control, FALSE);
  edr_config_free_heap(&cfg);
  cJSON *out = cJSON_CreateObject();
  if (!out) { fprintf(stderr, "cache migration finished with rc=%d but result allocation failed\n", rc); return 1; }
  cJSON_AddNumberToObject(out, "format", result.format);
  cJSON_AddBoolToObject(out, "complete", result.complete != 0);
  cJSON_AddNumberToObject(out, "moved_refs", (double)result.moved_refs);
  cJSON_AddNumberToObject(out, "batches", (double)result.batches);
  cJSON_AddNumberToObject(out, "peak_physical_bytes", (double)result.peak_physical_bytes);
  cJSON_AddNumberToObject(out, "elapsed_ms", (double)result.elapsed_ms);
  cJSON_AddStringToObject(out, "error", result.error);
  char *json = cJSON_PrintUnformatted(out);
  if (json) { puts(json); cJSON_free(json); } else rc = -1;
  cJSON_Delete(out); return rc == 0 ? 0 : 1;
}
#endif
