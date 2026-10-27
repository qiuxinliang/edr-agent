#ifndef EDR_STORAGE_PHYSICAL_GUARD_H
#define EDR_STORAGE_PHYSICAL_GUARD_H

#include "edr/command_state.h"
#include "edr/storage_reservation.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/statvfs.h>
#endif

/* Volume free-space admission, not a directory quota. Callers supply the peak
 * additional physical bytes (including WAL/checkpoint or temporary-copy work).
 * Only completion of an already durable, reserved owner may consume the floor.
 * No free-space observation can reserve blocks against other processes. */
typedef struct EdrStoragePhysicalSnapshot {
  uint64_t available_bytes, required_bytes, min_free_bytes;
  const char *cause;
} EdrStoragePhysicalSnapshot;

/* UINT64_MAX means unknown, never an empty file. Missing WAL/SHM (ENOENT)
 * is normal; access errors, invalid paths and non-files must fail closed.
 * This measures file length, not allocated blocks or a directory quota. */
static inline uint64_t edr_storage_file_size(const char *path) {
  if (!path || !*path) return UINT64_MAX;
#if defined(_WIN32) && defined(_MSC_VER)
  struct __stat64 st;
  if (_stat64(path, &st) != 0) return errno == ENOENT ? 0u : UINT64_MAX;
  if (!(st.st_mode & _S_IFREG) || st.st_size < 0) return UINT64_MAX;
#else
  struct stat st;
  if (stat(path, &st) != 0) return errno == ENOENT ? 0u : UINT64_MAX;
  if (!S_ISREG(st.st_mode) || st.st_size < 0) return UINT64_MAX;
#endif
  return (uint64_t)st.st_size;
}

static inline uint64_t edr_storage_add_bytes(uint64_t a, uint64_t b) {
  return UINT64_MAX - a < b ? UINT64_MAX : a + b;
}

static inline int edr_storage_parse_u64(const char *s, uint64_t *value) {
  uint64_t n = 0;
  if (!s || !*s || !value) return -1;
  for (; *s; ++s) {
    if (*s < '0' || *s > '9' || n > (UINT64_MAX - (unsigned)(*s - '0')) / 10u) return -1;
    n = n * 10u + (unsigned)(*s - '0');
  }
  *value = n;
  return 0;
}

static inline int edr_storage_min_free_bytes(uint64_t *out) {
  uint64_t owner = EDR_COMMAND_STATE_DEFAULT_OWNER_BUDGET_BYTES, configured = 0, v = 0;
  int owner_unknown = 0;
  const char *s = getenv("EDR_COMMAND_STATE_OWNER_BUDGET_BYTES");
  if (s && *s) {
    if (edr_storage_parse_u64(s, &v) != 0) return -1;
    if (v) owner = v;
  }
  /* Calibrated once before workers start. A lower new configuration cannot
   * donate space already promised to durable owners from an earlier run. */
  s = getenv("EDR_STORAGE_OWNER_PROTECTED_BYTES");
  if (s && *s) {
    if (!strcmp(s, "unavailable")) owner_unknown = 1;
    else {
      if (edr_storage_parse_u64(s, &v) != 0) return -1;
      if (v > owner) owner = v;
    }
  }
  s = getenv("EDR_STORAGE_MIN_FREE_MB");
  if (s && *s) {
    if (edr_storage_parse_u64(s, &v) != 0 || v > UINT64_MAX / (1024u * 1024u)) return -1;
    configured = v * (1024u * 1024u);
  }
  /* JSONL owner + append/atomic-compaction copy, two 4 MiB SQLite
   * checkpoint double-writes, and the existing 4 MiB terminal reserve twice. */
  if (owner > (UINT64_MAX - 24u * 1024u * 1024u) / 3u) return -1;
  v = owner * 3u + 24u * 1024u * 1024u;
  *out = configured > v ? configured : v;
  return owner_unknown ? -2 : 0;
}

static inline int edr_storage_physical_evaluate(uint64_t available, uint64_t growth,
    uint64_t floor, int reserved_write, EdrStoragePhysicalSnapshot *out) {
  EdrStoragePhysicalSnapshot s = {available, growth, floor, "ok"};
  uint64_t keep = reserved_write ? 0 : floor;
  int rc = 0;
  if (growth > UINT64_MAX - keep) { s.cause = "physical_size_overflow"; rc = -2; }
  else {
    s.required_bytes = growth + keep;
    if (available < s.required_bytes) { s.cause = "volume_free_space_exhausted"; rc = -1; }
  }
  if (out) *out = s;
  return rc;
}

/* Query the containing volume, walking missing parent directories only.
 * Access/encoding errors fail closed instead of guessing another volume. */
static inline int edr_storage_volume_available(const char *file, uint64_t *available) {
  char parent[4096];
  size_t len = file ? strlen(file) : 0;
  if (!len || len >= sizeof(parent) || !available) return -1;
  memcpy(parent, file, len + 1);
  for (unsigned depth = 0; depth < 64; ++depth) {
    char *slash = strrchr(parent, '/');
#ifdef _WIN32
    char *back = strrchr(parent, '\\');
    if (back && (!slash || back > slash)) slash = back;
#endif
    if (!slash) strcpy(parent, ".");
    else if (slash == parent) slash[1] = '\0';
#ifdef _WIN32
    else if (slash == parent + 2 && parent[1] == ':') slash[1] = '\0';
#endif
    else *slash = '\0';
#ifdef _WIN32
    wchar_t wide[4096];
    ULARGE_INTEGER free_bytes;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, parent, -1, wide, 4096)) return -1;
    if (GetDiskFreeSpaceExW(wide, &free_bytes, NULL, NULL)) { *available = free_bytes.QuadPart; return 0; }
    DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return -1;
#else
    struct statvfs fs;
    if (statvfs(parent, &fs) == 0) {
      if (fs.f_frsize && (uint64_t)fs.f_bavail > UINT64_MAX / fs.f_frsize) return -1;
      *available = (uint64_t)fs.f_bavail * fs.f_frsize;
      return 0;
    }
    if (errno != ENOENT && errno != ENOTDIR) return -1;
#endif
    if (!strcmp(parent, ".") || !strcmp(parent, "/")) return -1;
  }
  return -1;
}

static inline int edr_storage_physical_admit_owned(const char *file, uint64_t growth_bytes,
    int reserved_write, uint64_t artifact_credit, EdrStoragePhysicalSnapshot *out) {
  uint64_t floor = 0, available = 0;
  EdrStoragePhysicalSnapshot s = {0, growth_bytes, 0, "physical_configuration_invalid"};
  int configured = edr_storage_min_free_bytes(&floor);
  /* An unknown JSONL owner inventory holds ordinary admission, but must not
   * cancel another store's already durable completion reservation. Invalid
   * configuration still fails closed; actual volume growth is always checked. */
  if (configured != 0 && !(configured == -2 && reserved_write)) {
    if (configured == -2) s.cause = "owner_accounting_unavailable";
    if (out) *out = s;
    return -2;
  }
  uint64_t artifact_reserved=edr_storage_artifact_reserved();
  if(artifact_reserved==UINT64_MAX || artifact_credit>artifact_reserved) {
    s.cause="artifact_reservation_unavailable";if(out)*out=s;return -2;
  }
  /* Existing DB/command reserved completion may consume its own old floor,
   * but never another artifact owner's promised growth. A producer receives
   * credit only from its frozen durable staging owner. Across volumes the
   * global balance is conservatively retained on each volume, never borrowed. */
  floor=edr_storage_add_bytes(reserved_write?0u:floor,artifact_reserved-artifact_credit);
  if(floor==UINT64_MAX) {s.cause="physical_size_overflow";if(out)*out=s;return -2;}
  s.min_free_bytes = floor;
  if (edr_storage_volume_available(file, &available) != 0) {
    s.cause = "volume_free_space_unavailable";
    if (out) *out = s;
    return -2;
  }
  return edr_storage_physical_evaluate(available, growth_bytes, floor, 0, out);
}

static inline int edr_storage_physical_admit(const char *file, uint64_t growth_bytes,
    int reserved_write, EdrStoragePhysicalSnapshot *out) {
  return edr_storage_physical_admit_owned(file,growth_bytes,reserved_write,0u,out);
}

#endif
