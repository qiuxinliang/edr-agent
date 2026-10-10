#include "edr/forensic_result_contract.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require_true(int ok, const char *message) {
  if (!ok) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}
static const char *text(const cJSON *object, const char *key) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
  require_true(cJSON_IsString(value), key);
  return value->valuestring;
}
static const char *receipt =
    "{\"manifest_path\":\"C:/Synthetic/manifest.json\",\"bundle_path\":\"C:/Synthetic/bundle.tgz\","
    "\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
    "\"upload_status\":\"ok\",\"minio_key\":\"tenant/endpoint/task/bundle\",\"outbox\":\"none\"}";

int main(void) {
  char out[8192];
  const char *result = edr_command_normalize_forensic_result(
      "forensic", EdrCmdExecOk, 0, receipt, out, sizeof(out));
  cJSON *decoded = cJSON_ParseWithOpts(result, NULL, 1);
  require_true(decoded != NULL && result == out, "actual legacy producer receipt is normalized");
  require_true(!strcmp(text(decoded, "schema"), "edr.forensic.result.v1"), "receipt schema");
  require_true(!strcmp(text(decoded, "status"), "success"), "success status preserved");
  require_true(!strcmp(text(decoded, "sha256"), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), "hash preserved");
  require_true(!strcmp(text(decoded, "object_key"), "tenant/endpoint/task/bundle"), "object key preserved");
  require_true(!strcmp(text(decoded, "upload_status"), "ok"), "actual upload status preserved");
  require_true(!strcmp(text(decoded, "raw_detail"), receipt), "complete original preserved locally");
  require_true(!cJSON_HasObjectItem(decoded, "truncated"), "uncalculated truncation not fabricated");
  cJSON_Delete(decoded);
  require_true(edr_command_normalize_forensic_result("forensic", EdrCmdExecOk, 0, result, out, sizeof(out)) == result,
               "normalization is idempotent");

  const char *failed = "{\"manifest_path\":\"m\",\"bundle_path\":\"b\",\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"upload_status\":\"failed\",\"minio_key\":\"\",\"outbox\":\"queued\"}";
  result = edr_command_normalize_forensic_result("collect_forensic", EdrCmdExecFailed, 4, failed, out, sizeof(out));
  decoded = cJSON_ParseWithOpts(result, NULL, 1);
  require_true(decoded && !strcmp(text(decoded, "upload_status"), "failed") && !strcmp(text(decoded, "object_key"), ""), "failed upload is not changed into not_requested");
  require_true(!strcmp(text(decoded, "raw_detail"), failed), "pending outbox original retained");
  cJSON_Delete(decoded);

  const char *plain = "cancelled\nby operator SYNTHETIC";
  const char *failure_types[] = {"pmfe_scan", "yara_scan"};
  for (size_t i = 0; i < 2; i++) {
    result = edr_command_normalize_forensic_result(failure_types[i], EdrCmdExecFailed, 130, plain, out, sizeof(out));
    decoded = cJSON_ParseWithOpts(result, NULL, 1);
    require_true(decoded && !strcmp(text(decoded, "schema"), "edr.command.status.v1"), "pre-execution failure is finite status");
    require_true(!strcmp(text(decoded, "diagnostic"), "command_failed"), "finite failure cause");
    require_true(!strcmp(text(decoded, "raw_detail"), plain), "failure original remains local");
    require_true(cJSON_GetObjectItemCaseSensitive(decoded, "exit_code")->valueint == 130, "cancel code preserved");
    cJSON_Delete(decoded);
  }
  const char *unknown[] = {
      "pmfe completed pid=42", "mentions edr.forensic.result.v1 only",
      "{\"rows\":[{\"unrelated\":\"synthetic\"}]}",
      "{\"sha256\":\"x\",\"minio_key\":\"k\",\"upload_status\":\"ok\"}",
      "{\"schema\":\"unknown\",\"message\":\"edr.forensic.result.v1\"}",
      "{\"manifest_path\":\"m\",\"bundle_path\":\"b\",\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"upload_status\":\"ok\",\"minio_key\":\"\",\"outbox\":\"none\"}",
      "{\"manifest_path\":\"m\",\"manifest_path\":\"duplicate\",\"bundle_path\":\"b\",\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"upload_status\":\"failed\",\"minio_key\":\"\",\"outbox\":\"queued\"}",
  };
  for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); i++)
    require_true(edr_command_normalize_forensic_result("forensic", EdrCmdExecOk, 0, unknown[i], out, sizeof(out)) == unknown[i], "unknown success stays original for policy holding");

  /* Mutate the real producer fixture, not a separate surrogate parser. */
  char malformed[2048];
  const char *upload = strstr(receipt, "\"upload_status\":\"ok\"");
  require_true(upload != NULL, "real receipt upload field");
  snprintf(malformed, sizeof(malformed), "%.*s\"upload_status\":\"ok\\u0000extra\"%s",
           (int)(upload - receipt), receipt, upload + strlen("\"upload_status\":\"ok\""));
  require_true(edr_command_normalize_forensic_result("forensic", EdrCmdExecOk, 0, malformed, out, sizeof(out)) == malformed,
               "decoded NUL cannot launder an upload status into ok");
  snprintf(malformed, sizeof(malformed), "%s {\"unexpected\":true}", receipt);
  require_true(edr_command_normalize_forensic_result("forensic", EdrCmdExecOk, 0, malformed, out, sizeof(out)) == malformed,
               "trailing object is not normalized");
  snprintf(malformed, sizeof(malformed), "%.*s,\"context\":{\"key\":1,\"key\":2}}",
           (int)strlen(receipt)-1, receipt);
  require_true(edr_command_normalize_forensic_result("forensic", EdrCmdExecOk, 0, malformed, out, sizeof(out)) == malformed,
               "nested duplicate keys remain original for holding");
  require_true(edr_command_normalize_forensic_result("pmfe_scan", EdrCmdExecOk, 0, receipt, out, sizeof(out)) == receipt, "receipt does not authorize PMFE semantics");
  require_true(edr_command_normalize_forensic_result("yara_scan", EdrCmdExecFailed, 9, unknown[2], out, sizeof(out)) == unknown[2], "unknown structured failure remains original");

  const char *schemas[] = {
      "{\"schema\":\"edr.forensic.result.v1\",\"status\":\"partial_success\"}",
      "{\"schema\":\"edr.yara_scan.result.v1\",\"status\":\"success\",\"matched\":false}",
      "{\"schema\":\"pmfe_result_v1\",\"status\":\"completed_clean\"}",
  };
  for (size_t i = 0; i < 3; i++)
    require_true(edr_command_normalize_forensic_result("yara_scan", EdrCmdExecOk, 0, schemas[i], out, sizeof(out)) == schemas[i], "structured schema is not double wrapped");
  char small[64];
  require_true(edr_command_normalize_forensic_result("forensic", EdrCmdExecOk, 0, receipt, small, sizeof(small)) == receipt, "small buffer never emits truncated receipt");
  char long_detail[9000];memset(long_detail, 'x', sizeof(long_detail)-1);long_detail[sizeof(long_detail)-1] = 0;
  require_true(edr_command_normalize_forensic_result("deep_forensic", EdrCmdExecFailed, 9, long_detail, out, sizeof(out)) == long_detail, "over-budget original is not truncated");
  require_true(edr_command_normalize_forensic_result("noop", EdrCmdExecOk, 0, plain, out, sizeof(out)) == plain, "other command results unchanged");
  puts("PASS: real legacy receipts preserve hash/key/upload state; unknown data held unchanged; finite failures retain local evidence; no truncation");
  return 0;
}
