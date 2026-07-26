#include "edr/agent_update_command.h"
#include "edr/command_contract.h"
#include "edr/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require_true(int value, const char *message) {
  if (!value) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}

int main(void) {
  const char *valid =
      "{\"artifact_url\":\"https://updates.example/agent/FDSensor.exe\","
      "\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
      "\"target_version\":\"2.1.0\",\"architecture\":\"x64\","
      "\"internal_name\":\"FDSensor\",\"publisher_thumbprint\":\"AABB\","
      "\"publisher_subject\":\"CN=FDSecurity\",\"deployment_mode\":\"auto\","
      "\"min_current_version\":\"2.0.0\",\"max_current_version\":\"2.0.99\"}";
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
  require_true(strcmp(request.target_version, "2.1.0") == 0, "target version parsed");
  const char *http =
      "{\"artifact_url\":\"http://updates.example/FDSensor.exe\","
      "\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
      "\"target_version\":\"2.1.0\",\"architecture\":\"x64\","
      "\"internal_name\":\"FDSensor\",\"publisher_thumbprint\":\"AA\","
      "\"publisher_subject\":\"CN=FDSecurity\"}";
  require_true(!edr_command_contract_validate("agent_update", (const uint8_t *)http,
                                               strlen(http), reason, sizeof(reason)),
               "plain HTTP update artifact rejected");
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
  require_true(edr_agent_update_parse_journal(
                   "{\"status\":\"running\",\"stage\":\"replacement_committed\"}", &recovery) == 1,
               "nonterminal replacement journal retains inbox");
  require_true(edr_agent_update_parse_journal(
                   "{\"status\":\"succeeded\",\"stage\":\"completed\"}", &recovery) == 2 &&
                   recovery.succeeded && recovery.exit_code == 0,
               "restart recovery maps succeeded journal to terminal OK");
  require_true(edr_agent_update_parse_journal(
                   "{\"status\":\"failed_rolled_back\",\"stage\":\"rollback_completed\",\"error\":\"startup failed\"}", &recovery) == 2 &&
                   !recovery.succeeded && recovery.exit_code != 0 && strstr(recovery.detail, "startup failed"),
               "restart recovery maps rollback journal to terminal failure");
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
