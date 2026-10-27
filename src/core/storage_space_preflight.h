#ifndef EDR_STORAGE_SPACE_PREFLIGHT_H
#define EDR_STORAGE_SPACE_PREFLIGHT_H

#include "edr/storage_space_policy.h"
#include "edr/local_evidence_cache.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#include <intrin.h>
#else
#include <unistd.h>
#endif

/* Explicit local operation only. No Agent init, store maintenance, migration,
 * enrollment, collection, or network. Existing owner's normal lock protects
 * its read/calibration; the JSONL is never appended or compacted here. */
static int edr_storage_space_preflight_body(int argc, char **argv) {
  const char *config = NULL, *output = NULL;
  int defaults = 0;
  for (int i = 2; i < argc; ++i) {
    if (!strcmp(argv[i], "--config") && i + 1 < argc && !config) config = argv[++i];
    else if (!strcmp(argv[i], "--output") && i + 1 < argc && !output) output = argv[++i];
    else if (!strcmp(argv[i], "--defaults") && !defaults) defaults = 1;
    else { fprintf(stderr, "storage preflight: invalid arguments\n"); return 2; }
  }
  if (!output || !*output || (config && !*config) || (!!config == !!defaults)) {
    fprintf(stderr, "storage preflight: require --output and exactly one of --config or --defaults\n");
    return 2;
  }
  EdrConfig cfg = {0};
  if (edr_config_load(config ? config : "", &cfg) != EDR_OK) {
    edr_config_free_heap(&cfg);
    fprintf(stderr, "storage preflight: local configuration unavailable\n"); return 3;
  }
  int rc = edr_storage_policy_apply(&cfg, defaults ? EDR_STORAGE_POLICY_DEFAULTS : EDR_STORAGE_POLICY_READ_ONLY);
  int evidence_rc=0;
  if (!rc && !defaults) {
    const char *path=getenv("EDR_EVIDENCE_CACHE_PATH");
    if (!path || !path[0]) path=cfg.offline.evidence_cache_path;
    if (!path || !path[0]) path="local_evidence_cache.db";
    evidence_rc=edr_local_evidence_cache_startup_preflight(path,cfg.offline.evidence_cache_max_size_mb);
  }
  edr_config_free_heap(&cfg);
  if (rc == EDR_STORAGE_POLICY_INVENTORY_LOCK_TIMEOUT) {
    fprintf(stderr, "storage preflight: owner_lock_timeout\n"); return 7;
  }
  if (rc == EDR_STORAGE_POLICY_INVENTORY_LOCK_GRANTED_EXPIRED) {
    fprintf(stderr, "storage preflight: owner_lock_granted_expired\n"); return 9;
  }
  if (rc == EDR_STORAGE_POLICY_INVENTORY_DEADLINE_BEFORE_REQUEST) {
    fprintf(stderr, "storage preflight: owner_lock_deadline_before_request\n"); return 10;
  }
  if (evidence_rc) {
    fprintf(stderr,"storage preflight: %s\n",evidence_rc==1
        ? "evidence_schema_no_page_headroom" : "evidence_schema_inspection_unavailable");
    return evidence_rc==1 ? 11 : 12;
  }
  uint64_t floor = 0;
  if (rc || edr_storage_min_free_bytes(&floor) || floor > 9007199254740991ULL) {
    fprintf(stderr, "storage preflight: owner accounting or policy unavailable\n"); return 4;
  }
  floor=edr_storage_add_bytes(floor,edr_storage_artifact_reserved());
  if(floor>9007199254740991ULL) {
    fprintf(stderr,"storage preflight: artifact reservation unavailable\n");return 4;
  }
  char decimal[32];
  int size = snprintf(decimal, sizeof(decimal), "%llu", (unsigned long long)floor);
  if (size <= 0 || (size_t)size >= sizeof(decimal)) return 4;
  /* Never overwrite a caller-selected path, follow a link, or expose config. */
#ifdef _WIN32
  HANDLE file = CreateFileA(output, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (file == INVALID_HANDLE_VALUE) return 5;
  DWORD written = 0;
  int ok = WriteFile(file, decimal, (DWORD)size, &written, NULL) && written == (DWORD)size && FlushFileBuffers(file);
  if (!CloseHandle(file)) ok = 0;
  if (!ok) { DeleteFileA(output); return 5; }
#else
  int fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if (fd < 0) return 5;
  int ok = write(fd, decimal, (size_t)size) == size && fsync(fd) == 0;
  if (close(fd)) ok = 0;
  if (!ok) { unlink(output); return 5; }
#endif
  return 0;
}

#ifdef _WIN32
#define EDR_STORAGE_PREFLIGHT_WATCHDOG_MS 15000u
/* Only this explicit, short-lived CLI starts a thread. The Agent service does
 * not start it. TerminateProcess avoids DLL detach while another thread may
 * be inside an I/O or loader call; kernel completion is not hard real-time. */
typedef struct EdrStoragePreflightDeadline {
  ULONGLONG started;
  HANDLE stop;
  volatile LONG state; /* 0 running, 1 completed, 2 expired */
} EdrStoragePreflightDeadline;

static void edr_storage_preflight_terminate(UINT code) {
  TerminateProcess(GetCurrentProcess(), code);
  /* Only an unrecoverable termination failure reaches this instruction.
   * It does not run CRT/DLL cleanup and its exception status is not 124. */
  __fastfail(FAST_FAIL_FATAL_APP_EXIT);
}

static DWORD WINAPI edr_storage_preflight_watchdog(LPVOID context) {
  EdrStoragePreflightDeadline *deadline = (EdrStoragePreflightDeadline *)context;
  ULONGLONG elapsed = GetTickCount64() - deadline->started;
  DWORD wait = elapsed >= EDR_STORAGE_PREFLIGHT_WATCHDOG_MS ? WAIT_TIMEOUT
      : WaitForSingleObject(deadline->stop,
          (DWORD)(EDR_STORAGE_PREFLIGHT_WATCHDOG_MS - elapsed));
  elapsed = GetTickCount64() - deadline->started;
  if (wait == WAIT_FAILED) edr_storage_preflight_terminate(8u);
  if (elapsed >= EDR_STORAGE_PREFLIGHT_WATCHDOG_MS || wait != WAIT_OBJECT_0) {
    if (InterlockedCompareExchange(&deadline->state, 2, 0) == 0)
      edr_storage_preflight_terminate(124u);
  } else if (InterlockedCompareExchange(&deadline->state, 0, 0) != 1) {
    edr_storage_preflight_terminate(8u);
  }
  return 0;
}

static int edr_storage_space_preflight_main(int argc, char **argv) {
  EdrStoragePreflightDeadline deadline = {0};
  deadline.started = GetTickCount64();
  deadline.stop = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (!deadline.stop) {
    fprintf(stderr, "storage preflight: deadline_unavailable\n"); return 8;
  }
  HANDLE worker = CreateThread(NULL, 0, edr_storage_preflight_watchdog, &deadline, 0, NULL);
  if (!worker) {
    CloseHandle(deadline.stop);
    fprintf(stderr, "storage preflight: deadline_unavailable\n"); return 8;
  }
  int rc = edr_storage_space_preflight_body(argc, argv);
  ULONGLONG elapsed = GetTickCount64() - deadline.started;
  if (elapsed >= EDR_STORAGE_PREFLIGHT_WATCHDOG_MS ||
      InterlockedCompareExchange(&deadline.state, 1, 0) != 0)
    edr_storage_preflight_terminate(124u);
  if (!SetEvent(deadline.stop)) edr_storage_preflight_terminate(124u);
  elapsed = GetTickCount64() - deadline.started;
  if (elapsed >= EDR_STORAGE_PREFLIGHT_WATCHDOG_MS ||
      WaitForSingleObject(worker, (DWORD)(EDR_STORAGE_PREFLIGHT_WATCHDOG_MS - elapsed)) != WAIT_OBJECT_0)
    edr_storage_preflight_terminate(124u);
  if (GetTickCount64() - deadline.started >= EDR_STORAGE_PREFLIGHT_WATCHDOG_MS)
    edr_storage_preflight_terminate(124u);
  int closed_worker = CloseHandle(worker);
  int closed_stop = CloseHandle(deadline.stop);
  if (!closed_worker || !closed_stop) {
    fprintf(stderr, "storage preflight: deadline_unavailable\n"); return 8;
  }
  if (GetTickCount64() - deadline.started >= EDR_STORAGE_PREFLIGHT_WATCHDOG_MS)
    edr_storage_preflight_terminate(124u);
  return rc;
}
#else
static int edr_storage_space_preflight_main(int argc, char **argv) {
  return edr_storage_space_preflight_body(argc, argv);
}
#endif

#endif
