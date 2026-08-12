#include "edr/agent_update_command.h"
#include "edr/command_contract.h"
#include "edr/command_registry.h"

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

static void require_true(int value, const char *message) {
  if (!value) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
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
      "\"last_event_seq\":7,\"events\":[{\"event_seq\":7,\"status\":\"health_check\",\"progress\":100,\"detail\":{}}]}";
  require_true(edr_agent_update_parse_journal(success_journal, &recovery) == 2 &&
                   recovery.succeeded && recovery.exit_code == 0,
               "v2 succeeded journal maps to terminal OK");
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
  require_true(edr_agent_update_execute("cmd-1", (const uint8_t *)valid, strlen(valid),
                                        detail, sizeof(detail)) == EDR_AGENT_UPDATE_EXIT_UNSUPPORTED,
               "non-Windows execution returns stable unsupported");
  require_true(strstr(detail, "unsupported on non-Windows") != NULL,
               "non-Windows result has stable unsupported detail");
#endif
  puts("ok");
  return 0;
}
