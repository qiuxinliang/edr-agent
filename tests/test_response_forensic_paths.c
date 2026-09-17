#include "edr/response.h"
#include "edr/response_utils.h"
#include "edr/forensic_limits.h"
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
  require_true(response_forensic_copy_lines(dir, (const uint8_t *)payload, strlen(payload)) != 0,
               "fallback enforces aggregate budget");
  f = fopen(second, "rb"); require_true(f == NULL, "fallback removes incomplete oversized copy");
  remove(first);
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

int main(void) {
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
