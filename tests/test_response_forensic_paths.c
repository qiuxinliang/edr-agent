#include "edr/response.h"
#include "edr/response_utils.h"
#include "edr/forensic_limits.h"
#ifdef EDR_RESPONSE_COPY_TESTING
void response_copy_test_set_chunk(void (*callback)(const char *, const char *));
#endif
#ifdef _WIN32
#include "edr/windows_file_identity.h"
#endif
#ifdef _WIN32
#include <direct.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require_true(int ok, const char *message) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
  }
}

static void test_baseline_copy_budget(void) {
  char dir[512];
#ifdef _WIN32
  char tmp[400];
  require_true(GetTempPathA(sizeof(tmp), tmp) > 0, "get temporary directory");
  snprintf(dir, sizeof(dir), "%sforensic copy %lu", tmp, (unsigned long)GetCurrentProcessId());
  require_true(_mkdir(dir) == 0, "create copy workspace");
  _putenv_s("EDR_FORENSIC_COPY_PATHS", "1");
#else
  snprintf(dir, sizeof(dir), "/tmp/forensic copy %lu", (unsigned long)getpid());
  require_true(mkdir(dir, 0700) == 0, "create copy workspace");
  setenv("EDR_FORENSIC_COPY_PATHS", "1", 1);
#endif
  char src[600], first[600], second[600], payload[1250];
  snprintf(src, sizeof(src), "%s/source", dir);
  snprintf(first, sizeof(first), "%s/copied_00", dir);
  snprintf(second, sizeof(second), "%s/copied_01", dir);
  FILE *f = fopen(src, "wb"); require_true(f != NULL, "create synthetic evidence");
  require_true(fseek(f, 33L * 1024L * 1024L - 1L, SEEK_SET) == 0, "size synthetic evidence");
  fputc(0, f); fclose(f);
  snprintf(payload, sizeof(payload), "%s\n%s", src, src);
  require_true(response_forensic_copy_lines(dir, (const uint8_t *)payload, strlen(payload)) == EDR_RESPONSE_BYTE_BUDGET_EXCEEDED,
               "fallback enforces aggregate budget");
  f = fopen(second, "rb"); require_true(f != NULL, "fallback retains incomplete oversized copy");
  require_true(fseek(f, 0, SEEK_END) == 0, "measure partial copy");
  long partial = ftell(f); fclose(f);
  require_true(partial > 0 && partial <= (long)EDR_FORENSIC_BASELINE_MAX_BYTES - 4096L - 33L * 1024L * 1024L,
               "retained partial and first copy remain within aggregate budget");
  f = fopen(src, "rb"); require_true(f != NULL, "original source remains present");
  require_true(fseek(f, 0, SEEK_END) == 0 && ftell(f) == 33L * 1024L * 1024L,
               "overbudget failure preserves original source length"); fclose(f);
  remove(first); remove(second);
  f = fopen(src, "wb"); require_true(f != NULL, "replace synthetic evidence");
  fputs("synthetic", f); fclose(f);
  require_true(response_forensic_copy_lines(dir, (const uint8_t *)src, strlen(src)) == 0,
               "fallback accepts bounded evidence");
  remove(first); remove(src);
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_COPY_PATHS", ""); _rmdir(dir);
#else
  unsetenv("EDR_FORENSIC_COPY_PATHS"); rmdir(dir);
#endif
}

static void copy_test_write(const char *path, size_t bytes, int value) {
  FILE *f = fopen(path, "wb"); require_true(f != NULL, "create synthetic boundary source");
  for (size_t i = 0; i < bytes; ++i) require_true(fputc(value, f) != EOF, "write synthetic source");
  require_true(fclose(f) == 0, "close synthetic source");
}
static long copy_test_size(const char *path) {
  FILE *f = fopen(path, "rb"); if (!f) return -1;
  require_true(fseek(f, 0, SEEK_END) == 0, "measure synthetic file");
  long n = ftell(f); require_true(fclose(f) == 0, "close measured file"); return n;
}
#ifdef EDR_RESPONSE_COPY_TESTING
static int copy_test_change, copy_test_attempted, copy_test_blocked;
static char copy_test_renamed[700];
static void copy_test_change_chunk(const char *src, const char *dst) {
  (void)dst;
  if (copy_test_attempted++) return;
  if (copy_test_change == 1) {
#ifdef _WIN32
    HANDLE writer = CreateFileA(src, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    copy_test_blocked = writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION;
    if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
#else
    FILE *writer = fopen(src, "ab"); require_true(writer != NULL, "open synthetic concurrent writer");
    require_true(fputc('x', writer) != EOF && fclose(writer) == 0, "append during copy");
#endif
  } else {
#ifdef _WIN32
    copy_test_blocked = !MoveFileA(src, copy_test_renamed) && GetLastError() == ERROR_SHARING_VIOLATION;
#else
    require_true(rename(src, copy_test_renamed) == 0, "replace pathname while original handle is held");
    copy_test_write(src, 17, 'r');
#endif
  }
}
#endif
static void test_baseline_copy_identity(const char *only) {
  char root[512], src[600], dst[600], special[600];
#ifdef _WIN32
  char tmp[400]; require_true(GetTempPathA(sizeof(tmp), tmp) > 0, "get boundary temporary directory");
  snprintf(root, sizeof(root), "%scopy identity %lu", tmp, (unsigned long)GetCurrentProcessId());
  require_true(_mkdir(root) == 0, "create boundary workspace");
  _putenv_s("EDR_FORENSIC_COPY_PATHS", "1");
#else
  snprintf(root, sizeof(root), "/tmp/copy identity %lu", (unsigned long)getpid());
  require_true(mkdir(root, 0700) == 0, "create boundary workspace");
  setenv("EDR_FORENSIC_COPY_PATHS", "1", 1);
#endif
  snprintf(src, sizeof(src), "%s/source", root); snprintf(dst, sizeof(dst), "%s/copied_00", root);
  snprintf(special, sizeof(special), "%s/special", root);
  copy_test_write(src, 131072, 's');
#define RUN_COPY_CASE(name) (!only || !strcmp(only, name))
  if (RUN_COPY_CASE("existing")) {
    copy_test_write(dst, 19, 'p');
    require_true(response_forensic_copy_lines(root, (const uint8_t *)src, strlen(src)) == EDR_RESPONSE_COPY_DESTINATION_FAILED, "existing destination refused");
    require_true(copy_test_size(dst) == 19, "existing evidence not overwritten");
    FILE *f = fopen(dst, "rb"); require_true(f && fgetc(f) == 'p', "existing evidence content preserved"); fclose(f);
    require_true(remove(dst) == 0, "remove synthetic destination fixture");
  }
  if (RUN_COPY_CASE("reparse")) {
#ifdef _WIN32
    edr_windows_file_identity_test_force_reparse_denied(1);
    require_true(response_forensic_copy_lines(root, (const uint8_t *)src, strlen(src)) == EDR_RESPONSE_COPY_SOURCE_UNAVAILABLE, "same native reparse denial branch refuses source");
    edr_windows_file_identity_test_force_reparse_denied(0);
#else
    require_true(symlink(src, special) == 0, "create synthetic symlink");
    require_true(response_forensic_copy_lines(root, (const uint8_t *)special, strlen(special)) == EDR_RESPONSE_COPY_SOURCE_UNAVAILABLE, "symlink source refused");
    require_true(remove(special) == 0, "remove synthetic symlink");
#endif
    require_true(copy_test_size(dst) == -1, "reparse denial creates no destination");
  }
  if (RUN_COPY_CASE("nonregular")) {
#ifdef _WIN32
    const char *nonregular = "NUL";
#else
    require_true(mkfifo(special, 0600) == 0, "create synthetic FIFO");
    const char *nonregular = special;
#endif
    require_true(response_forensic_copy_lines(root, (const uint8_t *)nonregular, strlen(nonregular)) == EDR_RESPONSE_COPY_SOURCE_UNAVAILABLE, "nonregular source refused without blocking");
    require_true(copy_test_size(dst) == -1, "nonregular denial creates no destination");
#ifndef _WIN32
    require_true(remove(special) == 0, "remove synthetic FIFO");
#endif
  }
#ifdef EDR_RESPONSE_COPY_TESTING
  const char *changes[] = {"append", "replace"};
  for (int i = 0; i < 2; ++i) if (RUN_COPY_CASE(changes[i])) {
    copy_test_change = i + 1; copy_test_attempted = 0; copy_test_blocked = 0;
    snprintf(copy_test_renamed, sizeof(copy_test_renamed), "%s/original", root);
    response_copy_test_set_chunk(copy_test_change_chunk);
    int result = response_forensic_copy_lines(root, (const uint8_t *)src, strlen(src));
    response_copy_test_set_chunk(NULL);
    require_true(copy_test_attempted > 0, "concurrent change attempted after first copied chunk");
#ifdef _WIN32
    require_true(copy_test_blocked && result == 0, "held source denies concurrent write or delete and copies unchanged bytes");
    require_true(copy_test_size(src) == 131072 && copy_test_size(dst) == 131072, "Windows source and copy remain complete and unchanged");
#else
    require_true(result == EDR_RESPONSE_COPY_IDENTITY_CHANGED, "concurrent identity or content change fails independently of byte budget");
    require_true(copy_test_size(dst) >= 65536, "changed source partial evidence retained");
    if (i == 0) {
      require_true(copy_test_size(src) == 131073, "concurrent source append preserved");
      require_true(remove(src) == 0, "remove synthetic modified source"); copy_test_write(src, 131072, 's');
    } else {
      require_true(copy_test_size(src) == 17 && copy_test_size(copy_test_renamed) == 131072, "both replaced source objects preserved");
      require_true(remove(src) == 0 && rename(copy_test_renamed, src) == 0, "restore synthetic source fixture");
    }
#endif
    require_true(remove(dst) == 0, "remove synthetic retained partial");
  }
#endif
  require_true(copy_test_size(src) == 131072, "all refusals preserve original evidence");
  require_true(remove(src) == 0, "remove synthetic source fixture");
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_COPY_PATHS", ""); require_true(_rmdir(root) == 0, "remove synthetic boundary workspace");
#else
  unsetenv("EDR_FORENSIC_COPY_PATHS"); require_true(rmdir(root) == 0, "remove synthetic boundary workspace");
#endif
  printf("PASS: baseline copy identity, exclusive destination and retained partial (%s)\n", only ? only : "all");
#undef RUN_COPY_CASE
}

int main(int argc, char **argv) {
  if (argc == 3 && !strcmp(argv[1], "--copy-boundary")) {test_baseline_copy_identity(argv[2]); return 0;}
  require_true(argc == 1, "known test arguments");
  test_baseline_copy_identity(NULL);

  test_baseline_copy_budget();
  const char *normal_observation = "{\"schema\":\"edr.isolation.observation.v2\",\"state\":\"normal\",\"restoration_verified\":false,\"reason\":\"recovery_baseline_missing\"}";
  const char *unknown_observation = "{\"schema\":\"edr.isolation.observation.v2\",\"state\":\"unknown\",\"restoration_verified\":false,\"reason\":\"os_state_unverified\"}";
  require_true(response_isolation_observation_valid(normal_observation), "normal observation does not require historical restoration");
  require_true(response_isolation_observation_valid(unknown_observation), "unknown is a valid observation, not verified enforcement");
  require_true(response_isolation_observation_valid("{\"schema\":\"edr.isolation.observation.v2\",\"state\":\"isolated\",\"restoration_verified\":false,\"reason\":\"\"}"), "accept isolated observation");
  require_true(response_isolation_observation_valid("{\"schema\":\"edr.isolation.observation.v2\",\"state\":\"normal\",\"restoration_verified\":true,\"reason\":\"\"}"), "accept restored observation");
  require_true(!response_isolation_status_verified(normal_observation, 0), "normal observation must never satisfy a restore completion check");
  const char *bad_observations[] = {
    "{\"schema\":\"edr.isolation.observation.v2\",\"state\":\"isolated\",\"restoration_verified\":true,\"reason\":\"\"}",
    "{\"schema\":\"edr.isolation.observation.v2\",\"state\":\"unknown\",\"restoration_verified\":true,\"reason\":\"\"}",
    "{\"schema\":\"edr.isolation.observation.v2\",\"state\":\"normal\",\"state\":\"normal\",\"restoration_verified\":false,\"reason\":\"\"}",
    "{\"schema\":\"edr.isolation.observation.v2\",\"state\":\"normal\",\"restoration_verified\":\"false\",\"reason\":\"\"}",
    "{\"schema\":\"edr.isolation.observation.v2\",\"state\":\"normal\",\"restoration_verified\":false,\"reason\":null}",
    "{\"schema\":\"edr.isolation.observation.v2\",\"state\":\"normal\",\"restoration_verified\":false,\"reason\":\"\",\"extra\":1}",
    "{\"schema\":\"edr.isolation.observation.v2\",\"state\":\"normal\",\"restoration_verified\":false,\"reason\":\"\"} noise"
  };
  for (size_t i = 0; i < sizeof(bad_observations)/sizeof(bad_observations[0]); ++i)
    require_true(!response_isolation_observation_valid(bad_observations[i]), "reject inconsistent or malformed observations");
  const char *active = "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":false,\"enforcement_verified\":true}";
  const char *restored = "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":false,\"restored\":true,\"enforcement_verified\":true}";
  const char *active_with_management = "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":false,\"enforcement_verified\":true,\"management_reachable\":true}";
  const char *restored_with_management = "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":false,\"restored\":true,\"enforcement_verified\":true,\"management_reachable\":false}";
  const char *restored_with_unknown_management = "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":false,\"restored\":true,\"enforcement_verified\":true,\"management_reachable\":null}";
  require_true(response_isolation_status_verified(active, 1), "accept verified active receipt");
  require_true(response_isolation_status_verified(restored, 0), "accept verified restored receipt");
  require_true(response_isolation_status_verified(active_with_management, 1),
               "accept active receipt with management reachability");
  require_true(response_isolation_status_verified(restored_with_management, 0),
               "accept restored receipt with management reachability");
  require_true(response_isolation_status_verified(restored_with_unknown_management, 0),
               "accept restored receipt with unknown management reachability");
  require_true(!response_isolation_status_verified(active, 0), "active is not restored");
  const char *bad_receipts[] = {
    "State file: state.json", "{}", "{\"isolated\":true}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":true,\"enforcement_verified\":true}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":false,\"enforcement_verified\":false}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":\"true\",\"restored\":false,\"enforcement_verified\":true}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"isolated\":false,\"restored\":false,\"enforcement_verified\":true}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":false,\"enforcement_verified\":true,\"unexpected\":true}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":false,\"enforcement_verified\":true,\"management_reachable\":\"true\"}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":false,\"enforcement_verified\":true,\"management_reachable\":true,\"management_reachable\":false}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":false,\"enforcement_verified\":true} garbage"
  };
  for (size_t i = 0; i < sizeof(bad_receipts)/sizeof(bad_receipts[0]); ++i)
    require_true(!response_isolation_status_verified(bad_receipts[i], 1), "reject unverified or malformed receipt");
  char reqpath[900];
  char artifact[900];
  char extra[2048];
  require_true(response_forensic_build_collector_paths(
                   "/tmp/edr_forensic", '/', "memory_dump", "cmd-42", 1710000000LL,
                   "dmp", reqpath, sizeof(reqpath), artifact, sizeof(artifact),
                   extra, sizeof(extra)) == 0,
               "normal collector paths build");
  require_true(strcmp(reqpath, "/tmp/edr_forensic/memory_dump_cmd-42_1710000000.req") == 0,
               "request path is exact");
  require_true(strcmp(artifact, "/tmp/edr_forensic/memory_dump_cmd-42_1710000000.dmp") == 0,
               "artifact path is exact");
  require_true(strcmp(extra,
                       "--request=/tmp/edr_forensic/memory_dump_cmd-42_1710000000.req "
                       "--out-file=/tmp/edr_forensic/memory_dump_cmd-42_1710000000.dmp") == 0,
               "collector arguments are exact");

  require_true(response_forensic_build_collector_paths(
                   "C:\\Program Files\\FDSecurity\\forensic", '\\', "collect_forensic",
                   "cmd-43", 1710000001LL, "tar.gz", reqpath, sizeof(reqpath), artifact,
                   sizeof(artifact), extra, sizeof(extra)) == 0,
               "Windows collector paths with spaces build");
  require_true(strcmp(reqpath,
                      "C:\\Program Files\\FDSecurity\\forensic\\collect_forensic_cmd-43_1710000001.req") == 0,
               "Windows request path is exact");
  require_true(strcmp(extra,
                      "--request=\"C:\\Program Files\\FDSecurity\\forensic\\collect_forensic_cmd-43_1710000001.req\" "
                      "--out-file=\"C:\\Program Files\\FDSecurity\\forensic\\collect_forensic_cmd-43_1710000001.tar.gz\"") == 0,
               "Windows collector path arguments preserve spaces");

  char overlong_dir[900];
  memset(overlong_dir, 'x', sizeof(overlong_dir) - 1u);
  overlong_dir[sizeof(overlong_dir) - 1u] = '\0';
  memset(reqpath, 'r', sizeof(reqpath));
  memset(artifact, 'a', sizeof(artifact));
  memset(extra, 'e', sizeof(extra));
  require_true(response_forensic_build_collector_paths(
                   overlong_dir, '/', "memory_dump", "cmd-42", 1710000000LL,
                   "dmp", reqpath, sizeof(reqpath), artifact, sizeof(artifact),
                   extra, sizeof(extra)) != 0,
               "overlong collector path is rejected");
  require_true(reqpath[0] == '\0' && artifact[0] == '\0' && extra[0] == '\0',
               "rejected collector path leaves no partial action arguments");

  char short_req[32];
  char short_artifact[32];
  char short_extra[64];
  require_true(response_forensic_build_collector_paths(
                   "/tmp/edr_forensic", '/', "memory_dump", "cmd-42", 1710000000LL,
                   "dmp", short_req, sizeof(short_req), short_artifact, sizeof(short_artifact),
                   short_extra, sizeof(short_extra)) != 0,
               "undersized collector argument buffers are rejected");
  require_true(short_req[0] == '\0' && short_artifact[0] == '\0' && short_extra[0] == '\0',
               "undersized buffers do not retain a truncated action");
  require_true(response_forensic_external_failure_must_not_fallback(
                   EDR_FORENSIC_EXTERNAL_ERR_BOUNDS),
               "bounds failure cannot fall back to another forensic action");
  require_true(!response_forensic_external_failure_must_not_fallback(-100),
               "ordinary collector preparation failure retains existing fallback behavior");
  return 0;
}
