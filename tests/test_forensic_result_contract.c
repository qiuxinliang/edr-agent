#include "edr/forensic_result_contract.h"

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
  char out[8192];
  const char *result = edr_command_normalize_forensic_result(
      "pmfe_scan", EdrCmdExecOk, 0, "pmfe completed pid=42", out, sizeof(out));
  require_true(strstr(result, "\"schema\":\"edr.forensic.result.v1\"") != NULL,
               "forensic success uses unified schema");
  require_true(strstr(result, "\"status\":\"success\"") != NULL,
               "forensic success has success status");
  require_true(strstr(result, "\"raw_detail\":\"pmfe completed pid=42\"") != NULL,
               "legacy detail is retained");

  result = edr_command_normalize_forensic_result(
      "yara_scan", EdrCmdExecFailed, 130, "cancelled\nby operator", out, sizeof(out));
  require_true(strstr(result, "\"status\":\"cancelled\"") != NULL,
               "cancel exit code maps to cancelled status");
  require_true(strstr(result, "cancelled\\nby operator") != NULL,
               "detail is JSON escaped");

  {
    char long_detail[7000];
    memset(long_detail, 'x', sizeof(long_detail) - 1u);
    long_detail[sizeof(long_detail) - 1u] = '\0';
    result = edr_command_normalize_forensic_result(
        "deep_forensic", EdrCmdExecFailed, 9, long_detail, out, sizeof(out));
    require_true(result[0] == '{' && result[strlen(result) - 1u] == '}',
                 "long forensic detail remains valid bounded JSON");
    require_true(strlen(result) < sizeof(out), "long forensic detail fits output buffer");
  }

  const char *existing =
      "{\"schema\":\"edr.forensic.result.v1\",\"status\":\"partial_success\"}";
  result = edr_command_normalize_forensic_result(
      "yara_scan", EdrCmdExecOk, 0, existing, out, sizeof(out));
  require_true(result == existing, "existing unified result is not double wrapped");

  const char *yara_v1 =
      "{\"schema\":\"edr.yara_scan.result.v1\",\"status\":\"success\",\"matched\":false}";
  result = edr_command_normalize_forensic_result(
      "yara_scan", EdrCmdExecOk, 0, yara_v1, out, sizeof(out));
  require_true(result == yara_v1, "dedicated YARA result is not double wrapped");

  const char *pmfe_v1 =
      "{\"schema\":\"pmfe_result_v1\",\"status\":\"completed_clean\"}";
  result = edr_command_normalize_forensic_result(
      "pmfe_scan", EdrCmdExecOk, 0, pmfe_v1, out, sizeof(out));
  require_true(result == pmfe_v1, "structured PMFE result is not double wrapped");

  const char *plain = "pong";
  result = edr_command_normalize_forensic_result(
      "noop", EdrCmdExecOk, 0, plain, out, sizeof(out));
  require_true(result == plain, "non-forensic results are unchanged");
  return 0;
}
