#include "edr/edr_log.h"

#include <stdlib.h>
#include <string.h>

static int edr_env_is_off(const char *v) {
  if (!v || !v[0]) {
    return 1;
  }
  if (strcmp(v, "0") == 0 || strcmp(v, "false") == 0 || strcmp(v, "off") == 0 || strcmp(v, "no") == 0 ||
      strcmp(v, "FALSE") == 0 || strcmp(v, "NO") == 0) {
    return 1;
  }
  return 0;
}

int edr_log_verbose(void) {
  static int cached = -1;
  if (cached < 0) {
    const char *e = getenv("EDR_AGENT_VERBOSE");
    cached = (!edr_env_is_off(e) && e && e[0]) ? 1 : 0;
  }
  return cached;
}

int edr_log_want_shutdown_stats(void) {
  if (edr_log_verbose()) {
    return 1;
  }
  const char *e = getenv("EDR_AGENT_SHUTDOWN_LOG");
  if (!e || !e[0]) {
    return 0;
  }
  return !edr_env_is_off(e);
}

int edr_log_shelldcode_windivert_verbose(void) {
  if (edr_log_verbose()) {
    return 1;
  }
  const char *e = getenv("EDR_SHELCODE_LOG");
  if (!e || !e[0]) {
    return 0;
  }
  return !edr_env_is_off(e);
}

#include <errno.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#define EDR_LOG_DUP2 _dup2
#define EDR_LOG_FILENO _fileno
#else
#include <unistd.h>
#define EDR_LOG_DUP2 dup2
#define EDR_LOG_FILENO fileno
#endif

static char s_log_path[1152];
static uint64_t s_log_limit_bytes;
static uint32_t s_log_backups;
static uint64_t s_log_last_check_ns;
static int s_log_rebind_pending;
static int s_log_prune_pending;
static int s_log_config_failed;
static uint64_t s_log_last_error_ns;

static void log_stream_lock(void) {
#ifdef _WIN32
  _lock_file(stdout);
  _lock_file(stderr);
#else
  flockfile(stdout);
  flockfile(stderr);
#endif
}
static void log_stream_unlock(void) {
#ifdef _WIN32
  _unlock_file(stderr);
  _unlock_file(stdout);
#else
  funlockfile(stderr);
  funlockfile(stdout);
#endif
}

static int log_make_directory(const char *path) {
#ifdef _WIN32
  wchar_t wide[1200];
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, 1200)) return -1;
  int rc = _wmkdir(wide);
#else
  int rc = mkdir(path, 0700);
#endif
  return rc == 0 || errno == EEXIST ? 0 : -1;
}

static int log_ensure_directory(const char *directory) {
  char path[1024];
  size_t n = strlen(directory);
  if (!n || n >= sizeof(path)) return -1;
  memcpy(path, directory, n + 1u);
  for (size_t i = 1u; i < n; ++i) {
    if (path[i] != '/' && path[i] != '\\') continue;
    if (path[i - 1u] == ':' || path[i - 1u] == '/' || path[i - 1u] == '\\') continue;
    char separator = path[i];
    path[i] = '\0';
    int rc = log_make_directory(path);
    path[i] = separator;
    if (rc != 0) return -1;
  }
  return log_make_directory(path);
}

#ifdef _WIN32
/* SCM and CREATE_NO_WINDOW children may have CRT streams with fd=-2. Give
 * only those uninitialized streams a real log descriptor before rebinding
 * to the owned delete-share handle. Initialize before _fdopen can reuse a
 * closed standard FILE object. */
static int log_standard_handle_missing(DWORD which) {
  HANDLE handle = GetStdHandle(which);
  if (!handle || handle == INVALID_HANDLE_VALUE) return 1;
  SetLastError(ERROR_SUCCESS);
  return GetFileType(handle) == FILE_TYPE_UNKNOWN && GetLastError() == ERROR_INVALID_HANDLE;
}
static int log_initialize_missing_streams(const char *path) {
  wchar_t wide[1200];
  int missing_error = EDR_LOG_FILENO(stderr) < 0 || log_standard_handle_missing(STD_ERROR_HANDLE);
  int missing_output = EDR_LOG_FILENO(stdout) < 0 || log_standard_handle_missing(STD_OUTPUT_HANDLE);
  if (missing_error || missing_output) {
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, 1200)) return -1;
    if (missing_error && !_wfreopen(wide, L"ab", stderr)) return -1;
    if (missing_output && !_wfreopen(wide, L"ab", stdout)) return -1;
  }
  return 0;
}
#endif

/* Delete sharing is required on Windows: rotate the name while stream locks
 * protect writers, then replace descriptors only after the new file opens.
 * If opening fails, the previous descriptors still retain every diagnostic. */
#ifdef EDR_LOG_TESTING
static unsigned s_log_test_fail_open_count;
static unsigned s_log_test_fail_buffering_count;
#endif
static FILE *log_open_append(const char *path) {
#ifdef _WIN32
  if (log_initialize_missing_streams(path) != 0) return NULL;
#endif
#ifdef EDR_LOG_TESTING
  if (s_log_test_fail_open_count) { --s_log_test_fail_open_count; errno = EACCES; return NULL; }
#endif
#ifdef _WIN32
  wchar_t wide[1200];
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, 1200)) return NULL;
  HANDLE handle = CreateFileW(wide, FILE_APPEND_DATA | SYNCHRONIZE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL, NULL);
  if (handle == INVALID_HANDLE_VALUE) return NULL;
  int fd = _open_osfhandle((intptr_t)handle, _O_WRONLY | _O_APPEND | _O_BINARY);
  if (fd < 0) { CloseHandle(handle); return NULL; }
  FILE *file = _fdopen(fd, "ab");
  if (!file) _close(fd);
  return file;
#else
  return fopen(path, "ab");
#endif
}

static int log_bind_streams(FILE *file, const char *path) {
  (void)path;
  int fd = EDR_LOG_FILENO(file);
  if (EDR_LOG_DUP2(fd, EDR_LOG_FILENO(stderr)) < 0 ||
      EDR_LOG_DUP2(fd, EDR_LOG_FILENO(stdout)) < 0) return -1;
#ifdef _WIN32
  SetStdHandle(STD_ERROR_HANDLE, (HANDLE)_get_osfhandle(EDR_LOG_FILENO(stderr)));
  SetStdHandle(STD_OUTPUT_HANDLE, (HANDLE)_get_osfhandle(EDR_LOG_FILENO(stdout)));
#endif
  return 0;
}

static int log_configure_stream_buffering(void) {
#ifdef EDR_LOG_TESTING
  if (s_log_test_fail_buffering_count) {
    --s_log_test_fail_buffering_count;
    errno = ENOMEM;
    return -1;
  }
#endif
  if (setvbuf(stderr, NULL, _IONBF, 0u) != 0) return -1;
#ifdef _WIN32
  /* UCRT treats _IOLBF as full buffering and rejects a zero buffer size.
   * Keep Windows diagnostics immediately visible, including headless tasks. */
  return setvbuf(stdout, NULL, _IONBF, 0u);
#else
  return setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
#endif
}

static int log_remove(const char *path) {
#ifdef _WIN32
  wchar_t wide[1200];
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, 1200)) return -1;
  return _wremove(wide);
#else
  return remove(path);
#endif
}
static int log_rename(const char *source, const char *destination) {
#ifdef _WIN32
  wchar_t from[1200], to[1200];
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, source, -1, from, 1200) ||
      !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, destination, -1, to, 1200)) return -1;
  return _wrename(from, to);
#else
  return rename(source, destination);
#endif
}
static int log_file_size(const char *path, uint64_t *size) {
#ifdef _WIN32
  wchar_t wide[1200];
  struct _stat64 st;
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, 1200) ||
      _wstat64(wide, &st) != 0) return -1;
#else
  struct stat st;
  if (stat(path, &st) != 0) return -1;
#endif
  *size = (uint64_t)st.st_size;
  return 0;
}

static int log_configure(const EdrConfig *cfg) {
  char path[1152];
  if (!cfg || !cfg->logging.log_dir[0]) return -1;
  uint32_t megabytes = cfg->logging.max_log_size_mb;
  uint32_t files = cfg->logging.max_log_files;
  if (!megabytes) megabytes = 100u;
  if (!files) files = 1u;
  if (files > 100u) files = 100u;
  uint32_t backups = files - 1u;
  if (snprintf(path, sizeof(path), "%s/agent.log", cfg->logging.log_dir) >= (int)sizeof(path)) return -1;
  uint64_t limit = (uint64_t)megabytes * 1024ULL * 1024ULL;
  if (!strcmp(s_log_path, path)) {
    s_log_limit_bytes = limit;
    if (backups < s_log_backups) s_log_prune_pending = 1;
    s_log_backups = backups;
    return 0;
  }
  if (log_ensure_directory(cfg->logging.log_dir) != 0) return -1;
  FILE *file = log_open_append(path);
  if (!file) return -1;
  log_stream_lock();
  fflush(stdout); fflush(stderr);
  /* Configure valid buffering before moving the owned descriptors so a
   * configuration failure preserves the previous diagnostic destination. */
  int rc = log_configure_stream_buffering();
  if (rc == 0) rc = log_bind_streams(file, path);
  fclose(file);
  if (rc == 0) {
    snprintf(s_log_path, sizeof(s_log_path), "%s", path);
    s_log_limit_bytes = limit;
    s_log_backups = backups;
    s_log_last_check_ns = 0u;
    s_log_prune_pending = 1;
    s_log_rebind_pending = 0;
  }
  log_stream_unlock();
  return rc;
}

int edr_log_configure(const EdrConfig *cfg) {
  int rc = log_configure(cfg);
  s_log_config_failed = rc != 0;
  return rc;
}

static void log_report_failure(uint64_t now_ns, const char *cause) {
  if (s_log_last_error_ns && now_ns >= s_log_last_error_ns &&
      now_ns - s_log_last_error_ns < 60000000000ULL) return;
  s_log_last_error_ns = now_ns ? now_ns : 1u;
  fprintf(stderr, "[logging] %s; check configured directory permissions and disk space\n", cause);
}

void edr_log_poll(uint64_t now_ns) {
  uint64_t size = 0u;
  if (s_log_config_failed) log_report_failure(now_ns, "configuration failed; retaining previous diagnostic streams");
  if (!s_log_path[0] || (s_log_last_check_ns &&
      now_ns - s_log_last_check_ns < 1000000000ULL)) return;
  s_log_last_check_ns = now_ns;
  if (s_log_rebind_pending) {
    FILE *replacement = log_open_append(s_log_path);
    if (!replacement) { log_report_failure(now_ns, "rotation recovery failed; retaining previous file handles"); return; }
    log_stream_lock();
    fflush(stdout); fflush(stderr);
    if (log_bind_streams(replacement, s_log_path) == 0) s_log_rebind_pending = 0;
    fclose(replacement);
    log_stream_unlock();
    if (s_log_rebind_pending) return;
  }
  if (s_log_prune_pending) {
    char obsolete[1200];
    int failed = 0;
    log_stream_lock();
    for (uint32_t i = s_log_backups + 1u; i < 100u; ++i) {
      snprintf(obsolete, sizeof(obsolete), "%s.%u", s_log_path, i);
      if (log_remove(obsolete) != 0 && errno != ENOENT) failed = 1;
    }
    log_stream_unlock();
    if (!failed) s_log_prune_pending = 0;
    else log_report_failure(now_ns, "backup retention cleanup failed; retrying");
  }
  if (log_file_size(s_log_path, &size) != 0 || size < s_log_limit_bytes) return;
  log_stream_lock();
  fflush(stdout); fflush(stderr);
  int failed = 0;
  char source[1200], destination[1200];
  if (s_log_backups) {
    snprintf(destination, sizeof(destination), "%s.%u", s_log_path, s_log_backups);
    if (log_remove(destination) != 0 && errno != ENOENT) failed = 1;
    for (uint32_t i = s_log_backups; !failed && i > 1u; --i) {
      snprintf(source, sizeof(source), "%s.%u", s_log_path, i - 1u);
      snprintf(destination, sizeof(destination), "%s.%u", s_log_path, i);
      if (log_rename(source, destination) != 0 && errno != ENOENT) failed = 1;
    }
    snprintf(destination, sizeof(destination), "%s.1", s_log_path);
    if (!failed && log_rename(s_log_path, destination) != 0) failed = 1;
    if (!failed) {
      FILE *file = log_open_append(s_log_path);
      if (!file || log_bind_streams(file, s_log_path) != 0) {
        failed = 1;
        s_log_rebind_pending = 1;
      }
      if (file) fclose(file);
    }
  } else {
    /* Explicit zero backups discards prior content without unlinking the
     * currently owned file, so failure cannot detach diagnostics from disk. */
#ifdef _WIN32
    wchar_t wide[1200];
    HANDLE truncation = INVALID_HANDLE_VALUE;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s_log_path, -1, wide, 1200))
      truncation = CreateFileW(wide, GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
          FILE_ATTRIBUTE_NORMAL, NULL);
    if (truncation == INVALID_HANDLE_VALUE) failed = 1;
    else {
      LARGE_INTEGER zero; zero.QuadPart = 0;
      if (!SetFilePointerEx(truncation, zero, NULL, FILE_BEGIN) || !SetEndOfFile(truncation)) failed = 1;
      CloseHandle(truncation);
    }
#else
    if (ftruncate(EDR_LOG_FILENO(stderr), 0) != 0) failed = 1;
#endif
  }
  log_stream_unlock();
  if (failed) log_report_failure(now_ns, "rotation failed; retaining diagnostic streams and retrying");
}
