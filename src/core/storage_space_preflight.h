#ifndef EDR_STORAGE_SPACE_PREFLIGHT_H
#define EDR_STORAGE_SPACE_PREFLIGHT_H

#include "edr/storage_space_policy.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

/* Explicit local operation only. No Agent init, store maintenance, migration,
 * enrollment, collection, or network. Existing owner's normal lock protects
 * its read/calibration; the JSONL is never appended or compacted here. */
static int edr_storage_space_preflight_main(int argc, char **argv) {
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
  edr_config_free_heap(&cfg);
  uint64_t floor = 0;
  if (rc || edr_storage_min_free_bytes(&floor) || floor > 9007199254740991ULL) {
    fprintf(stderr, "storage preflight: owner accounting or policy unavailable\n"); return 4;
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

#endif
