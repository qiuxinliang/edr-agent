/* Test-only measurement boundary shared by the two retention comparisons.
 * VFS counters are SQLite-issued I/O. Windows process counters also include
 * non-SQLite file I/O; neither counter measures physical-device writes. */
#ifndef EDR_RETENTION_BENCHMARK_SUPPORT_H
#define EDR_RETENTION_BENCHMARK_SUPPORT_H
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/resource.h>
#endif

typedef struct {
  double user_seconds, system_seconds, wall_seconds;
  uint64_t process_read_bytes, process_write_bytes;
  int process_io_available;
  unsigned native_machine, process_machine;
} RetentionBenchMetrics;

static RetentionBenchMetrics retention_bench_metrics(void) {
  RetentionBenchMetrics value = {0};
#ifdef _WIN32
  FILETIME created, exited, kernel, user;
  LARGE_INTEGER counter, frequency;
  IO_COUNTERS io;
  USHORT process_machine = 0, native_machine = 0;
  assert(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user));
  assert(QueryPerformanceCounter(&counter) && QueryPerformanceFrequency(&frequency));
  assert(GetProcessIoCounters(GetCurrentProcess(), &io));
  assert(IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine));
  value.user_seconds = ((uint64_t)user.dwHighDateTime << 32 | user.dwLowDateTime) / 1e7;
  value.system_seconds = ((uint64_t)kernel.dwHighDateTime << 32 | kernel.dwLowDateTime) / 1e7;
  value.wall_seconds = (double)counter.QuadPart / (double)frequency.QuadPart;
  value.process_read_bytes = io.ReadTransferCount;
  value.process_write_bytes = io.WriteTransferCount;
  value.process_io_available = 1;
  value.native_machine = native_machine;
  value.process_machine = process_machine;
#else
  struct rusage usage;
  struct timespec stamp;
  assert(getrusage(RUSAGE_SELF, &usage) == 0);
  assert(clock_gettime(CLOCK_MONOTONIC, &stamp) == 0);
  value.user_seconds = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6;
  value.system_seconds = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
  value.wall_seconds = stamp.tv_sec + stamp.tv_nsec / 1e9;
#endif
  return value;
}

/* Real SQLite I/O is forwarded without replacing errors, delays or results. */
typedef struct { sqlite3_file base; sqlite3_file *real; } RetentionBenchFile;
static sqlite3_vfs *retention_bench_vfs_parent;
static uint64_t retention_bench_reads, retention_bench_writes, retention_bench_syncs;
#define BENCH_FILE(f) (((RetentionBenchFile *)(f))->real)
static int bench_close(sqlite3_file *f) { return BENCH_FILE(f)->pMethods->xClose(BENCH_FILE(f)); }
static int bench_read(sqlite3_file *f, void *b, int n, sqlite3_int64 o) { retention_bench_reads+=(unsigned)n; return BENCH_FILE(f)->pMethods->xRead(BENCH_FILE(f),b,n,o); }
static int bench_write(sqlite3_file *f,const void *b,int n,sqlite3_int64 o) { retention_bench_writes+=(unsigned)n; return BENCH_FILE(f)->pMethods->xWrite(BENCH_FILE(f),b,n,o); }
static int bench_truncate(sqlite3_file *f,sqlite3_int64 n) { return BENCH_FILE(f)->pMethods->xTruncate(BENCH_FILE(f),n); }
static int bench_sync(sqlite3_file *f,int flags) { ++retention_bench_syncs; return BENCH_FILE(f)->pMethods->xSync(BENCH_FILE(f),flags); }
static int bench_size(sqlite3_file *f,sqlite3_int64 *n) { return BENCH_FILE(f)->pMethods->xFileSize(BENCH_FILE(f),n); }
static int bench_lock(sqlite3_file *f,int n) { return BENCH_FILE(f)->pMethods->xLock(BENCH_FILE(f),n); }
static int bench_unlock(sqlite3_file *f,int n) { return BENCH_FILE(f)->pMethods->xUnlock(BENCH_FILE(f),n); }
static int bench_reserved(sqlite3_file *f,int *n) { return BENCH_FILE(f)->pMethods->xCheckReservedLock(BENCH_FILE(f),n); }
static int bench_control(sqlite3_file *f,int n,void *p) { return BENCH_FILE(f)->pMethods->xFileControl(BENCH_FILE(f),n,p); }
static int bench_sector(sqlite3_file *f) { return BENCH_FILE(f)->pMethods->xSectorSize(BENCH_FILE(f)); }
static int bench_characteristics(sqlite3_file *f) { return BENCH_FILE(f)->pMethods->xDeviceCharacteristics(BENCH_FILE(f)); }
static int bench_map(sqlite3_file *f,int p,int n,int e,void volatile **o) { return BENCH_FILE(f)->pMethods->xShmMap(BENCH_FILE(f),p,n,e,o); }
static int bench_shm_lock(sqlite3_file *f,int o,int n,int flags) { return BENCH_FILE(f)->pMethods->xShmLock(BENCH_FILE(f),o,n,flags); }
static void bench_barrier(sqlite3_file *f) { BENCH_FILE(f)->pMethods->xShmBarrier(BENCH_FILE(f)); }
static int bench_unmap(sqlite3_file *f,int d) { return BENCH_FILE(f)->pMethods->xShmUnmap(BENCH_FILE(f),d); }
static int bench_fetch(sqlite3_file *f,sqlite3_int64 o,int n,void **p) {
  if (BENCH_FILE(f)->pMethods->iVersion<3 || !BENCH_FILE(f)->pMethods->xFetch) { *p=NULL; return SQLITE_OK; }
  return BENCH_FILE(f)->pMethods->xFetch(BENCH_FILE(f),o,n,p);
}
static int bench_unfetch(sqlite3_file *f,sqlite3_int64 o,void *p) {
  return BENCH_FILE(f)->pMethods->iVersion>=3 && BENCH_FILE(f)->pMethods->xUnfetch ? BENCH_FILE(f)->pMethods->xUnfetch(BENCH_FILE(f),o,p) : SQLITE_OK;
}
static const sqlite3_io_methods retention_bench_methods = {3,bench_close,bench_read,bench_write,bench_truncate,bench_sync,bench_size,
  bench_lock,bench_unlock,bench_reserved,bench_control,bench_sector,bench_characteristics,bench_map,bench_shm_lock,bench_barrier,bench_unmap,bench_fetch,bench_unfetch};
static int retention_bench_open(sqlite3_vfs *v,const char *name,sqlite3_file *file,int flags,int *out) {
  (void)v; RetentionBenchFile *f=(RetentionBenchFile *)file;
  f->real=(sqlite3_file *)(f+1); memset(f->real,0,(size_t)retention_bench_vfs_parent->szOsFile);
  int rc=retention_bench_vfs_parent->xOpen(retention_bench_vfs_parent,name,f->real,flags,out);
  if (f->real->pMethods) f->base.pMethods=&retention_bench_methods;
  return rc;
}
#undef BENCH_FILE
#endif
