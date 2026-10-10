#define EDR_LOG_TESTING 1
#include "../src/core/edr_log.c"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#define dup _dup
#define dup2 _dup2
#define close _close
#define fileno _fileno
#else
#include <unistd.h>
#endif
#ifdef _WIN32
static void headless_trace(const char *directory, const char *phase) {
  char path[1152]; snprintf(path, sizeof(path), "%s/headless.trace", directory);
  HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    DWORD written; WriteFile(h, phase, (DWORD)strlen(phase), &written, NULL); CloseHandle(h);
  }
}
#endif
int main(int argc, char **argv) {
  assert(argc == 3);
  int headless = !strcmp(argv[2], "rotate-headless");
  int saved_err = -1, saved_out = -1;
  if (headless) {
#ifdef _WIN32
    headless_trace(argv[1], "before-standard-handles-check\n");
    /* The Windows runtime may populate std handles despite the process
     * startup flags. Close only this isolated child's streams to exercise the
     * same missing-CRT-stream boundary deterministically. */
    fclose(stderr); fclose(stdout);
    SetStdHandle(STD_ERROR_HANDLE, NULL); SetStdHandle(STD_OUTPUT_HANDLE, NULL);
    assert(fileno(stderr) < 0 && fileno(stdout) < 0);
    /* MSVC uses fd=-2; MinGW may retain stream indices with no OS handles.
     * Do not call _get_osfhandle on an unallocated CRT descriptor. */
#else
    return 2;
#endif
  } else {
    saved_err = dup(fileno(stderr)); saved_out = dup(fileno(stdout));
    assert(saved_err >= 0 && saved_out >= 0);
  }
  EdrConfig *cfg = calloc(1u, sizeof(*cfg));
  assert(cfg);
  snprintf(cfg->logging.log_dir, sizeof(cfg->logging.log_dir), "%s", argv[1]);
  cfg->logging.max_log_size_mb = 1u;
  cfg->logging.max_log_files = 3u; /* current + 2 retained backups */
#ifdef _WIN32
  if (headless) headless_trace(argv[1], "before-configure\n");
#endif
  int ok = edr_log_configure(cfg) == 0;
#ifdef _WIN32
  if (headless) headless_trace(argv[1], ok ? "configured\n" : "configure-failed\n");
#endif
  if (!strcmp(argv[2], "rotate") || headless) {
    char bytes[4096]; memset(bytes, 'x', sizeof(bytes));
    for (unsigned cycle=0; cycle<3u && ok; ++cycle) {
      fprintf(stderr, "cycle-%u\n", cycle);
      for (unsigned i=0; i<257u; ++i) ok &= fwrite(bytes, 1u, sizeof(bytes), stderr) == sizeof(bytes);
      edr_log_poll((uint64_t)(cycle + 1u) * 1000000000ULL);
#ifdef _WIN32
      if (headless) headless_trace(argv[1], "rotated\n");
#endif
    }
    fprintf(stderr, "after-rotation\n");
    if (headless) fprintf(stdout, "stdout-headless\n");
  } else if (!strcmp(argv[2], "restart")) {
    fprintf(stderr, "after-restart\n");
    snprintf(cfg->logging.log_dir, sizeof(cfg->logging.log_dir), "%s/agent.log/invalid", argv[1]);
    ok &= edr_log_configure(cfg) != 0;
    fprintf(stderr, "after-failed-config\n");
  } else if (!strcmp(argv[2], "replacement-failure-retention")) {
    char bytes[4096]; memset(bytes, 'r', sizeof(bytes));
    for (unsigned i=0; i<257u; ++i) ok &= fwrite(bytes, 1u, sizeof(bytes), stderr) == sizeof(bytes);
    s_log_test_fail_open_count = 2u;
    edr_log_poll(1000000000ULL);
    ok &= s_log_rebind_pending != 0;
    cfg->logging.max_log_files = 1u;
    ok &= edr_log_configure(cfg) == 0;
    edr_log_poll(2000000000ULL);
    ok &= s_log_rebind_pending != 0;
    fprintf(stderr, "after-pending-retention-failure\n");
  } else if (!strcmp(argv[2], "zero-backups")) {
    cfg->logging.max_log_files = 1u;
    ok &= edr_log_configure(cfg) == 0;
    char bytes[4096]; memset(bytes, 'z', sizeof(bytes));
    for (unsigned i=0; i<257u; ++i) ok &= fwrite(bytes, 1u, sizeof(bytes), stderr) == sizeof(bytes);
    edr_log_poll(1000000000ULL);
    fprintf(stderr, "after-truncation\n");
  } else if (!strcmp(argv[2], "reduce-retention")) {
    cfg->logging.max_log_files = 2u;
    ok &= edr_log_configure(cfg) == 0;
    edr_log_poll(1000000000ULL);
    fprintf(stderr, "after-retention-change\n");
  } else if (!strcmp(argv[2], "rename-failure")) {
    char bytes[4096]; memset(bytes, 'y', sizeof(bytes));
    for (unsigned i=0; i<257u; ++i) ok &= fwrite(bytes, 1u, sizeof(bytes), stderr) == sizeof(bytes);
    edr_log_poll(1000000000ULL);
    fprintf(stderr, "after-failed-rotation\n");
  }
  fflush(stderr); fflush(stdout);
  if (!headless) {
    dup2(saved_err, fileno(stderr)); dup2(saved_out, fileno(stdout));
    close(saved_err); close(saved_out);
  }
  free(cfg);
  assert(ok);
  return 0;
}
