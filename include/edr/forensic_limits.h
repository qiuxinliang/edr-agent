#ifndef EDR_FORENSIC_LIMITS_H
#define EDR_FORENSIC_LIMITS_H

#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/statvfs.h>
#endif

/* Baseline snapshots only: explicit memory-dump commands keep their own policy. */
#define EDR_FORENSIC_BASELINE_MAX_BYTES (64u * 1024u * 1024u)
#define EDR_FORENSIC_BASELINE_MAX_FILES 64u
#define EDR_FORENSIC_MIN_FREE_BYTES (256ULL * 1024ULL * 1024ULL)

/* Reserve room for input, an incompressible archive, and the Agent queue. */
static inline int edr_forensic_storage_ready(const char *dir) {
#ifdef _WIN32
  ULARGE_INTEGER available;
  if (!GetDiskFreeSpaceExA(dir, &available, NULL, NULL)) return 0;
  return available.QuadPart >= EDR_FORENSIC_MIN_FREE_BYTES;
#else
  struct statvfs st;
  if (statvfs(dir, &st) != 0) return 0;
  return (uint64_t)st.f_bavail * st.f_frsize >= EDR_FORENSIC_MIN_FREE_BYTES;
#endif
}
#endif
