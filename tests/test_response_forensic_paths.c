#include "edr/response.h"
#include "edr/response_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require_true(int ok, const char *message) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
  }
}

int main(void) {
  const char *active = "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":false,\"enforcement_verified\":true}";
  const char *restored = "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":false,\"restored\":true,\"enforcement_verified\":true}";
  require_true(response_isolation_status_verified(active, 1), "accept verified active receipt");
  require_true(response_isolation_status_verified(restored, 0), "accept verified restored receipt");
  require_true(!response_isolation_status_verified(active, 0), "active is not restored");
  const char *bad_receipts[] = {
    "State file: state.json", "{}", "{\"isolated\":true}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":true,\"enforcement_verified\":true}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":false,\"enforcement_verified\":false}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":\"true\",\"restored\":false,\"enforcement_verified\":true}",
    "{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"isolated\":false,\"restored\":false,\"enforcement_verified\":true}",
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
