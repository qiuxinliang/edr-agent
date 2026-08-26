#include "edr/agent_update_command.h"
#include "edr/command_contract.h"
#include "edr/command_registry.h"
#include "edr/ingest_http.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

int edr_ingest_http_post_json_suffix(const char *suffix, const char *body_json,
                                     char *resp_body, size_t resp_body_cap) {
  (void)suffix; (void)body_json; (void)resp_body; (void)resp_body_cap;
  return -1;
}

/* The contract test links the production executor to exercise the parser and
 * Windows staging helpers, but it never starts an update.  Keep its two live
 * execution dependencies explicit so Windows linkers do not pull in the
 * complete command-cancellation registry or HTTP transport stack. */
int edr_command_cancel_requested(const char *command_id) {
  (void)command_id;
  return 0;
}

int edr_ingest_http_get_url_to_file(const char *url, const char *file_path,
                                    size_t max_bytes) {
  (void)url;
  (void)file_path;
  (void)max_bytes;
  return -1;
}

void edr_ingest_http_get_runtime(EdrIngestHttpRuntime *out) {
  if (!out) return;
  memset(out, 0, sizeof(*out));
  snprintf(out->last_error, sizeof(out->last_error), "%s",
           "http get status: HTTP/1.1 500 Internal Server Error");
}

int edr_transport_v2_upload_file_for_command(
    const char *command_id, const char *upload_id, const char *file_path,
    const char *sha256_hex, char *out_minio_key,
    size_t out_minio_key_cap) {
  (void)command_id;
  (void)upload_id;
  (void)file_path;
  (void)sha256_hex;
  if (out_minio_key && out_minio_key_cap) out_minio_key[0] = '\0';
  return -1;
}

static void require_true(int value, const char *message) {
  if (!value) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}

typedef struct RecoveryFinalizeProbe {
  int upload_calls;
  int flush_calls;
  int upload_rc;
  int flush_rc;
  uint64_t acked_seq;
  char command_id[129];
  char upload_id[160];
  char sha256[65];
} RecoveryFinalizeProbe;

static int recovery_upload_probe(
    const char *command_id, const char *upload_id, const char *file_path,
    const char *sha256_hex, char *out_storage_key,
    size_t out_storage_key_cap, void *user) {
  RecoveryFinalizeProbe *probe = (RecoveryFinalizeProbe *)user;
  probe->upload_calls++;
  snprintf(probe->command_id, sizeof(probe->command_id), "%s", command_id);
  snprintf(probe->upload_id, sizeof(probe->upload_id), "%s", upload_id);
  snprintf(probe->sha256, sizeof(probe->sha256), "%s", sha256_hex);
  require_true(file_path && strcmp(file_path, "C:\\ProgramData\\FDSecurity\\logs\\installer.redacted") == 0,
               "recovery uploads the validated controlled snapshot path");
  if (probe->upload_rc == 0)
    snprintf(out_storage_key, out_storage_key_cap,
             "tenant/endpoint/%s.redacted", upload_id);
  return probe->upload_rc;
}

static int recovery_flush_probe(const char *outbox_dir,
                                uint64_t *last_acked_seq, void *user) {
  RecoveryFinalizeProbe *probe = (RecoveryFinalizeProbe *)user;
  probe->flush_calls++;
  require_true(outbox_dir && strcmp(outbox_dir, "event-outbox/cmd-1") == 0,
               "recovery flushes the bound event outbox");
  *last_acked_seq = probe->acked_seq;
  return probe->flush_rc;
}

int main(void) {
  const char *valid =
      "{\"schema\":\"edr.agent_update.v1\",\"task_id\":\"task-1\","
      "\"campaign_id\":\"campaign-1\",\"operation\":\"upgrade\","
      "\"initiated_by\":\"operator\",\"artifact_id\":\"artifact-1\","
      "\"artifact_url\":\"https://updates.example/agent/FDSensor.exe\","
      "\"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
      "\"version\":\"2.1.0\",\"arch\":\"x64\","
      "\"internal_name\":\"FDSensor\",\"publisher_thumbprint\":\"AABB\","
      "\"publisher_subject\":\"CN=FDSecurity\",\"deployment_mode\":\"auto\","
      "\"upgrade_class\":\"binary_hot\","
      "\"min_current_version\":\"2.0.0\",\"max_current_version\":\"2.0.99\","
      "\"issued_at_unix_ms\":1720000000000,\"deadline_unix_ms\":1720003600000,"
      "\"health_observe_ms\":300000}";
  char reason[256];
  EdrAgentUpdateRequest request;
  const EdrCommandDescriptor *descriptor = edr_command_registry_lookup("agent_update");
  require_true(descriptor && descriptor->kind == EDR_COMMAND_KIND_AGENT_UPDATE,
               "agent_update is registered with a dedicated kind");
  require_true((descriptor->flags & (EDR_COMMAND_FLAG_DANGEROUS | EDR_COMMAND_FLAG_OPERATOR_ONLY)) ==
                   (EDR_COMMAND_FLAG_DANGEROUS | EDR_COMMAND_FLAG_OPERATOR_ONLY),
               "agent_update is dangerous and operator-only");
  require_true(descriptor->payload_schema == EDR_COMMAND_PAYLOAD_AGENT_UPDATE,
               "agent_update has a strict payload schema");
  require_true(edr_command_registry_execution_lane("agent_update") == EDR_COMMAND_LANE_CRITICAL,
               "agent_update uses the critical lane");
  require_true(edr_command_registry_replay_policy("agent_update") == EDR_COMMAND_REPLAY_FINAL_ONLY,
               "agent_update cannot replay interrupted replacement");
  require_true(edr_command_registry_default_timeout_s("agent_update") == 1800u,
               "agent_update has a bounded production timeout");
  require_true(edr_command_contract_validate("agent_update", (const uint8_t *)valid,
                                              strlen(valid), reason, sizeof(reason)),
               "strict command contract accepts valid update");
  require_true(edr_agent_update_parse_request((const uint8_t *)valid, strlen(valid),
                                               &request, reason, sizeof(reason)),
               "executor parser accepts valid update");
  require_true(strcmp(request.target_version, "2.1.0") == 0 &&
                   strcmp(request.task_id, "task-1") == 0 &&
                   strcmp(request.operation, "upgrade") == 0 &&
                   strcmp(request.artifact_id, "artifact-1") == 0 &&
                   request.deadline_unix_ms == 1720003600000ULL,
               "strict update identity and timestamps parsed");
  require_true(strcmp(request.deployment_mode, "auto") == 0 &&
                   strcmp(request.upgrade_class, "binary_hot") == 0 &&
                   strcmp(request.scheduled_task_name, "FDSecurityAgent") == 0 &&
                   strcmp(request.scheduled_task_path, "\\") == 0 &&
                   strcmp(request.service_name, "FDSecurityAgent") == 0,
               "missing runtime identifiers receive safe Windows defaults");
  char invalid[4096];
  snprintf(invalid, sizeof(invalid), "%s", valid);
  char *url = strstr(invalid, "https://");
  require_true(url != NULL, "valid fixture has https URL");
  memmove(url + 4, url + 5, strlen(url + 5) + 1u);
  require_true(!edr_command_contract_validate("agent_update", (const uint8_t *)invalid,
                                               strlen(invalid), reason, sizeof(reason)),
               "plain HTTP update artifact rejected");
  const char *legacy =
      "{\"artifact_url\":\"https://updates.example/FDSensor.exe\","
      "\"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
      "\"version\":\"2.1.0\",\"arch\":\"x64\","
      "\"internal_name\":\"FDSensor\",\"publisher_thumbprint\":\"AA\","
      "\"publisher_subject\":\"CN=FDSecurity\"}";
  require_true(!edr_agent_update_parse_request((const uint8_t *)legacy, strlen(legacy),
                                                &request, reason, sizeof(reason)),
               "legacy update payload without task identity rejected");
  snprintf(invalid, sizeof(invalid), "%.*s,\"manual\":true}",
           (int)strlen(valid) - 1, valid);
  require_true(!edr_command_contract_validate("agent_update", (const uint8_t *)invalid,
                                               strlen(invalid), reason, sizeof(reason)),
               "strict update contract rejects common manual escape field");
  int comparison = 0;
  require_true(edr_agent_update_semver_compare("2.1.0", "2.0.99", &comparison) && comparison > 0,
               "semantic version ordering supports anti-downgrade");
  require_true(!edr_agent_update_semver_compare("02.1.0", "2.1.0", &comparison),
               "invalid semantic version rejected");
  require_true(edr_agent_update_journal_blocks_replacement("replacement_committed"),
               "recovery journal blocks duplicate replacement after commit");
  require_true(edr_agent_update_journal_is_terminal("failed_rolled_back"),
               "rollback result is terminal");
  EdrAgentUpdateRecovery recovery;
  const char *running_journal =
      "{\"schema_version\":2,\"task_id\":\"task-1\",\"command_id\":\"cmd-1\","
      "\"operation\":\"upgrade\",\"artifact_id\":\"artifact-1\","
      "\"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
      "\"version\":\"2.1.0\",\"status\":\"running\",\"stage\":\"replacement_committed\","
      "\"last_event_seq\":3,\"events\":[{\"event_seq\":3,\"status\":\"verified\",\"progress\":35,\"detail\":{}}]}";
  require_true(edr_agent_update_parse_journal(running_journal, &recovery) == 1 &&
                   recovery.last_event_seq == 3 && strcmp(recovery.task_id, "task-1") == 0,
               "v2 nonterminal journal retains bound identity and sequence");
  const char *success_journal =
      "{\"schema_version\":2,\"task_id\":\"task-1\",\"command_id\":\"cmd-1\","
      "\"operation\":\"upgrade\",\"artifact_id\":\"artifact-1\","
      "\"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
      "\"version\":\"2.1.0\",\"status\":\"succeeded\",\"stage\":\"completed\","
      "\"installer_log_file\":\"agent-update-task-1-cmd-1-installer.log\","
      "\"installer_log_sha256\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\","
      "\"installer_log_size\":1234,\"installer_log_evidence_id\":\"ev_installer_1\","
      "\"installer_log_storage_key\":\"evidence/ev_installer_1/sha.log\","
      "\"installer_evidence_status\":\"pending_upload\","
      "\"last_event_seq\":7,\"events\":[{\"event_seq\":7,\"status\":\"health_check\",\"progress\":100,\"detail\":{}}]}";
  require_true(edr_agent_update_parse_journal(success_journal, &recovery) == 2 &&
                   recovery.succeeded && recovery.exit_code == 0 &&
                   strcmp(recovery.installer_log_file, "agent-update-task-1-cmd-1-installer.log") == 0 &&
                   recovery.installer_log_size == 1234 &&
                   strcmp(recovery.installer_evidence_status, "pending_upload") == 0,
               "v2 succeeded journal maps terminal OK and preserves installer evidence descriptor");
  const char *runtime_bundle_success_journal =
      "{\"schema_version\":2,\"task_id\":\"task-1\",\"command_id\":\"cmd-1\","
      "\"operation\":\"upgrade\",\"artifact_id\":\"artifact-1\","
      "\"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
      "\"version\":\"2.1.0\",\"status\":\"succeeded\",\"stage\":\"completed\","
      "\"installer_log_file\":null,\"installer_log_sha256\":null,"
      "\"installer_log_evidence_id\":null,\"installer_log_storage_key\":null,"
      "\"installer_evidence_status\":null,\"last_event_seq\":7,"
      "\"events\":[{\"event_seq\":7,\"status\":\"health_check\",\"progress\":100,\"detail\":{}}]}";
  EdrAgentUpdateRecovery runtime_bundle_recovery;
  require_true(edr_agent_update_parse_journal(runtime_bundle_success_journal,
                                               &runtime_bundle_recovery) == 2 &&
                   runtime_bundle_recovery.succeeded &&
                   runtime_bundle_recovery.installer_log_file[0] == '\0' &&
                   runtime_bundle_recovery.installer_log_sha256[0] == '\0',
               "v2 runtime-bundle journal accepts JSON null for absent optional installer evidence");

  RecoveryFinalizeProbe finalize_probe;
  memset(&finalize_probe, 0, sizeof(finalize_probe));
  finalize_probe.upload_rc = -1;
  EdrAgentUpdateRecovery finalize_recovery = recovery;
  require_true(edr_agent_update_finalize_recovery(
                   &finalize_recovery,
                   "C:\\ProgramData\\FDSecurity\\logs\\installer.redacted",
                   "event-outbox/cmd-1", recovery_upload_probe,
                   recovery_flush_probe, &finalize_probe) < 0 &&
                   finalize_probe.upload_calls == 1 && finalize_probe.flush_calls == 0,
               "terminal events are not flushed when installer evidence upload fails");

  finalize_probe.upload_rc = 0;
  finalize_probe.flush_rc = -1;
  finalize_recovery = recovery;
  require_true(edr_agent_update_finalize_recovery(
                   &finalize_recovery,
                   "C:\\ProgramData\\FDSecurity\\logs\\installer.redacted",
                   "event-outbox/cmd-1", recovery_upload_probe,
                   recovery_flush_probe, &finalize_probe) < 0 &&
                   finalize_probe.upload_calls == 2 && finalize_probe.flush_calls == 1,
               "lost terminal acknowledgement retains recovery for retry after upload");

  finalize_probe.flush_rc = 0;
  finalize_probe.acked_seq = recovery.last_event_seq;
  finalize_recovery = recovery;
  require_true(edr_agent_update_finalize_recovery(
                   &finalize_recovery,
                   "C:\\ProgramData\\FDSecurity\\logs\\installer.redacted",
                   "event-outbox/cmd-1", recovery_upload_probe,
                   recovery_flush_probe, &finalize_probe) == 2 &&
                   finalize_probe.upload_calls == 3 && finalize_probe.flush_calls == 2 &&
                   finalize_recovery.terminal_event_acked &&
                   strcmp(finalize_probe.command_id, "cmd-1") == 0 &&
                   strcmp(finalize_probe.upload_id, "ev_installer_1") == 0 &&
                   strcmp(finalize_probe.sha256,
                          "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789") == 0,
               "reboot retry reuses evidence identity and flushes only after durable upload");
  cJSON *artifact_array = cJSON_Parse(finalize_recovery.installer_artifact_json);
  cJSON *artifact = cJSON_IsArray(artifact_array)
                        ? cJSON_GetArrayItem(artifact_array, 0)
                        : NULL;
  cJSON *artifact_id = cJSON_GetObjectItemCaseSensitive(artifact, "artifact_id");
  cJSON *artifact_kind = cJSON_GetObjectItemCaseSensitive(artifact, "kind");
  cJSON *artifact_key = cJSON_GetObjectItemCaseSensitive(artifact, "storage_key");
  cJSON *artifact_sha = cJSON_GetObjectItemCaseSensitive(artifact, "sha256");
  cJSON *artifact_size = cJSON_GetObjectItemCaseSensitive(artifact, "size");
  cJSON *artifact_status = cJSON_GetObjectItemCaseSensitive(artifact, "status");
  require_true(cJSON_IsObject(artifact) && cJSON_IsString(artifact_id) &&
                   cJSON_IsString(artifact_kind) && cJSON_IsString(artifact_key) &&
                   cJSON_IsString(artifact_sha) && cJSON_IsNumber(artifact_size) &&
                   cJSON_IsString(artifact_status) &&
                   strcmp(artifact_id->valuestring, "ev_installer_1") == 0 &&
                   strcmp(artifact_kind->valuestring,
                          "agent_upgrade_installer_log") == 0 &&
                   cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(
                       artifact, "agent_redacted")) &&
                   strcmp(artifact_key->valuestring,
                          "tenant/endpoint/ev_installer_1.redacted") == 0 &&
                   strcmp(artifact_sha->valuestring,
                          "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789") == 0 &&
                   artifact_size->valuedouble == 1234.0 &&
                   strcmp(artifact_status->valuestring, "uploaded") == 0,
               "terminal result carries the exact durable redacted artifact reference");
  cJSON_Delete(artifact_array);

  const char *failure_journal =
      "{\"schema_version\":2,\"task_id\":\"task-1\",\"command_id\":\"cmd-1\","
      "\"operation\":\"upgrade\",\"artifact_id\":\"artifact-1\","
      "\"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
      "\"version\":\"2.1.0\",\"status\":\"failed_rolled_back\",\"stage\":\"rollback_completed\","
      "\"last_event_seq\":8,\"events\":[{\"event_seq\":8,\"status\":\"failed\",\"progress\":100,\"detail\":{}}],"
      "\"error\":\"startup failed\"}";
  require_true(edr_agent_update_parse_journal(failure_journal, &recovery) == 2 &&
                   !recovery.succeeded && recovery.exit_code != 0 && strstr(recovery.detail, "startup failed"),
               "v2 rollback journal maps to terminal failure");
  memset(&finalize_probe, 0, sizeof(finalize_probe));
  finalize_probe.acked_seq = recovery.last_event_seq;
  require_true(edr_agent_update_finalize_recovery(
                   &recovery, NULL, "event-outbox/cmd-1",
                   recovery_upload_probe, recovery_flush_probe,
                   &finalize_probe) == 2 &&
                   finalize_probe.upload_calls == 0 && finalize_probe.flush_calls == 1,
               "pre-installer terminal failure can flush without fabricated installer evidence");
  require_true(edr_agent_update_parse_journal(
                   "{\"schema_version\":1,\"status\":\"succeeded\"}", &recovery) < 0,
               "legacy journal without bound identity rejected");
#ifdef _WIN32
  char temp[MAX_PATH], nested[MAX_PATH];
  DWORD temp_len = GetTempPathA(sizeof(temp), temp);
  require_true(temp_len > 0u && temp_len < sizeof(temp), "Windows temp directory is available");
  snprintf(nested, sizeof(nested), "%sFDSecurity-update-dir-test-%lu\\parent\\child",
           temp, (unsigned long)GetCurrentProcessId());
  require_true(edr_agent_update_create_directories(nested),
               "first upgrade recursively creates staging parents");
  DWORD attrs = GetFileAttributesA(nested);
  require_true(attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0u,
               "recursive staging directory exists");
  require_true(edr_agent_update_create_directories(nested),
               "existing staging directory is idempotent");
  const char *baseline_files[] = {
      "FDSensor.exe", "agent.toml", "unins000.exe", "unins000.dat"};
  for (size_t i = 0; i < sizeof(baseline_files) / sizeof(baseline_files[0]); ++i) {
    char candidate[MAX_PATH];
    snprintf(candidate, sizeof(candidate), "%s\\%s", nested, baseline_files[i]);
    FILE *created = fopen(candidate, "wb");
    require_true(created != NULL && fputs("test-only", created) >= 0 &&
                     fclose(created) == 0,
                 "Windows readiness negative fixture is created");
  }
  char readiness_reason[160] = {0};
  require_true(!edr_agent_update_probe_full_installer_baseline(
                   nested, readiness_reason, sizeof(readiness_reason)) &&
                   strcmp(readiness_reason,
                          "uninstaller_provenance_missing_or_mismatch") == 0,
               "production registry adapter rejects a filename-only fake baseline");

  /* A Windows installer acceptance job sets this to the directory installed by
   * the real Service or Scheduled Task package.  That job then executes the
   * same production adapters used by the manifest producer, rather than the
   * dependency-fake decision test. */
  const char *installed_baseline = getenv("EDR_FULL_INSTALLER_ACCEPTANCE_DIR");
  if (installed_baseline && installed_baseline[0]) {
    memset(readiness_reason, 0, sizeof(readiness_reason));
    require_true(edr_agent_update_probe_full_installer_baseline(
                     installed_baseline, readiness_reason,
                     sizeof(readiness_reason)) &&
                     strcmp(readiness_reason, "ready") == 0,
                 "real installed Windows baseline is accepted by production adapters");
  }
  for (size_t i = 0; i < sizeof(baseline_files) / sizeof(baseline_files[0]); ++i) {
    char candidate[MAX_PATH];
    snprintf(candidate, sizeof(candidate), "%s\\%s", nested, baseline_files[i]);
    DeleteFileA(candidate);
  }
  RemoveDirectoryA(nested);
  char *leaf = strrchr(nested, '\\');
  if (leaf) {
    *leaf = '\0'; RemoveDirectoryA(nested);
    leaf = strrchr(nested, '\\');
    if (leaf) { *leaf = '\0'; RemoveDirectoryA(nested); }
  }
#endif
#ifndef _WIN32
  char detail[128];
  char readiness_reason[64] = {0};
  require_true(!edr_agent_update_probe_full_installer_baseline(
                   "/tmp/not-a-windows-install", readiness_reason,
                   sizeof(readiness_reason)) &&
                   strcmp(readiness_reason, "platform_unsupported") == 0,
               "non-Windows production baseline probe fails closed");
  require_true(edr_agent_update_execute("cmd-1", (const uint8_t *)valid, strlen(valid),
                                        detail, sizeof(detail)) == EDR_AGENT_UPDATE_EXIT_UNSUPPORTED,
               "non-Windows execution returns stable unsupported");
  require_true(strstr(detail, "unsupported on non-Windows") != NULL,
               "non-Windows result has stable unsupported detail");
#endif
  puts("ok");
  return 0;
}
