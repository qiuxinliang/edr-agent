#include "edr/command_contract.h"
#include "edr/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
static void test_setenv(const char *name, const char *value) { _putenv_s(name, value); }
#else
static void test_setenv(const char *name, const char *value) { setenv(name, value, 1); }
#endif

static void require_true(int ok, const char *message) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
  }
}

static int validate(const char *type, const char *payload, char *reason, size_t reason_cap) {
  return edr_command_contract_validate(type, (const uint8_t *)payload,
                                       payload ? strlen(payload) : 0u,
                                       reason, reason_cap);
}

int main(void) {
  char reason[256];
  const EdrCommandDescriptor *descriptor = edr_command_registry_lookup("RTR_GET_FILE");
  require_true(descriptor != NULL, "registered alias lookup");
  require_true(strcmp(descriptor->canonical_type, "rtr_get_file") == 0,
               "alias canonicalization");
  require_true((descriptor->flags & EDR_COMMAND_FLAG_DANGEROUS) != 0u,
               "dangerous flag is registry-owned");
  require_true(edr_command_registry_lookup("rtr_get") != NULL,
               "backend file-get command is registered");
  require_true(edr_command_registry_lookup("rtr_put") != NULL,
               "backend file-put command is registered");
  require_true(edr_command_registry_lookup("rtr_rm") != NULL,
               "backend file-remove command is registered");
  require_true(edr_command_registry_lookup("forensic_deep") != NULL,
               "backend deep-forensic command is registered");
  require_true(edr_command_registry_lookup("file_get") != NULL,
               "task-chain file-get command is registered");
  require_true(edr_command_registry_is_shell("remote_shell"), "shell alias flag");
  require_true(edr_command_registry_execution_lane("isolate_host") == EDR_COMMAND_LANE_CRITICAL,
               "isolation is routed to critical execution lane");
  require_true(edr_command_registry_execution_lane("deep_forensic") == EDR_COMMAND_LANE_BULK,
               "deep forensic is routed to bulk execution lane");
  require_true(edr_command_registry_execution_lane("yara_scan") == EDR_COMMAND_LANE_SCAN,
               "YARA is isolated from long-running bulk collectors");
  require_true(edr_command_registry_execution_lane("pmfe_scan") == EDR_COMMAND_LANE_SCAN,
               "PMFE scanning shares the bounded scan lane");
  require_true(edr_command_registry_cancel_mode("rtr_shell") == EDR_COMMAND_CANCEL_HARD,
               "RTR shell declares hard cancellation");
  require_true(edr_command_registry_cancel_mode("rtq_execute") == EDR_COMMAND_CANCEL_COOPERATIVE,
               "RTQ declares implemented cooperative cancellation");
  require_true(edr_command_registry_cancel_mode("yara_scan") == EDR_COMMAND_CANCEL_COOPERATIVE,
               "YARA declares implemented cooperative cancellation");
  require_true(edr_command_registry_cancel_mode("process_snapshot") == EDR_COMMAND_CANCEL_COOPERATIVE,
               "snapshot declares implemented cooperative cancellation");
  require_true(edr_command_registry_cancel_mode("list_modules") == EDR_COMMAND_CANCEL_COOPERATIVE,
               "module listing declares implemented cooperative cancellation");
  require_true(edr_command_registry_cancel_mode("list_autoruns") == EDR_COMMAND_CANCEL_COOPERATIVE,
               "autoruns declares implemented cooperative cancellation");
  require_true(edr_command_registry_execution_lane("eventlog_view") == EDR_COMMAND_LANE_BULK,
               "event log collection is routed to bulk execution lane");
  require_true(edr_command_registry_cancel_mode("eventlog_view") == EDR_COMMAND_CANCEL_COOPERATIVE,
               "event log collection declares implemented cooperative cancellation");
  require_true(edr_command_registry_cancel_mode("agent_update") == EDR_COMMAND_CANCEL_COOPERATIVE,
               "Agent update supports cancellation before replacement starts");
  require_true(edr_command_registry_execution_lane("agent_restart_service") == EDR_COMMAND_LANE_CRITICAL,
               "Agent restart is routed to the critical execution lane");
  require_true(edr_command_registry_replay_policy("agent_restart_service") == EDR_COMMAND_REPLAY_FINAL_ONLY,
               "Agent restart cannot be launched twice after a process restart");
  require_true(edr_command_registry_default_timeout_s("agent_restart_service") == 1800u,
               "Agent restart has a bounded recovery timeout");
  test_setenv("EDR_COMMAND_REQUIRE_SIGNATURE", "0");
  test_setenv("EDR_COMMAND_ALLOW_UNSIGNED", "0");

  const char *lifecycle =
      "{\"schema\":\"edr.endpoint.lifecycle.v1\",\"task_id\":\"task-1\","
      "\"action\":\"restart\",\"tenant_id\":\"tenant-1\",\"endpoint_id\":\"ep-1\","
      "\"reason\":\"policy activation\",\"requested_by\":\"operator-1\","
      "\"initiated_by\":\"operator\",\"keep_data\":true}";
  require_true(validate("agent_restart_service", lifecycle, reason, sizeof(reason)),
               "valid endpoint lifecycle restart contract");
  require_true(!validate("agent_uninstall", lifecycle, reason, sizeof(reason)),
               "lifecycle action must match its command type");
  const char *uninstall =
      "{\"schema\":\"edr.endpoint.lifecycle.v1\",\"task_id\":\"task-2\","
      "\"action\":\"uninstall\",\"tenant_id\":\"tenant-1\",\"endpoint_id\":\"ep-1\","
      "\"reason\":\"retire endpoint\",\"requested_by\":\"operator-1\","
      "\"initiated_by\":\"operator\",\"keep_data\":false,"
      "\"attestation_url\":\"https://edr.example/api/v1/agent/lifecycle/uninstall-attest\","
      "\"attestation_token\":\"signed-token_123\","
      "\"attestation_expires_unix_ms\":1786500000000}";
  require_true(validate("agent_uninstall", uninstall, reason, sizeof(reason)),
               "uninstall accepts the platform attestation payload");
  require_true(!validate("agent_uninstall",
                         "{\"schema\":\"edr.endpoint.lifecycle.v1\",\"task_id\":\"task-2\","
                         "\"action\":\"uninstall\",\"tenant_id\":\"tenant-1\",\"endpoint_id\":\"ep-1\","
                         "\"reason\":\"retire endpoint\",\"requested_by\":\"operator-1\","
                         "\"initiated_by\":\"operator\",\"keep_data\":false}",
                         reason, sizeof(reason)),
               "uninstall rejects a payload without attestation");
  require_true(!validate("agent_uninstall",
                         "{\"schema\":\"edr.endpoint.lifecycle.v1\",\"task_id\":\"task-2\","
                         "\"action\":\"uninstall\",\"tenant_id\":\"tenant-1\",\"endpoint_id\":\"ep-1\","
                         "\"reason\":\"retire endpoint\",\"requested_by\":\"operator-1\","
                         "\"initiated_by\":\"operator\",\"keep_data\":false,"
                         "\"attestation_url\":\"http://edr.example/attest\","
                         "\"attestation_token\":\"signed-token_123\","
                         "\"attestation_expires_unix_ms\":1786500000000}",
                         reason, sizeof(reason)),
               "uninstall requires an HTTPS attestation endpoint");
  require_true(!validate("agent_restart_service",
                         "{\"schema\":\"edr.endpoint.lifecycle.v1\",\"task_id\":\"task-1\","
                         "\"action\":\"restart\",\"tenant_id\":\"tenant-1\","
                         "\"endpoint_id\":\"ep-1\",\"reason\":\"x\","
                         "\"requested_by\":\"operator-1\",\"initiated_by\":\"automation\","
                         "\"keep_data\":true}", reason, sizeof(reason)),
               "lifecycle commands require explicit operator initiation");
  test_setenv("EDR_COMMAND_ALLOW_UNSIGNED_DANGEROUS", "0");
  require_true(edr_command_contract_signature_required("cmd-1", "ping"),
               "external read-only command requires signature by default");
  require_true(edr_command_contract_signature_required("auto-local-1", "pmfe_scan"),
               "transport cannot bypass signature by spoofing auto command id");
  test_setenv("EDR_COMMAND_ALLOW_UNSIGNED", "1");
  require_true(!edr_command_contract_signature_required("cmd-2", "ping"),
               "explicit legacy escape allows unsigned read-only command");
  require_true(edr_command_contract_signature_required("cmd-3", "kill_process"),
               "dangerous command remains signed under read-only escape");
  require_true(edr_command_contract_signature_required("cmd-4", "rtr_shell"),
               "shell command can never be unsigned");
  test_setenv("EDR_COMMAND_ALLOW_UNSIGNED", "0");

  require_true(validate("kill_process", "{\"pid\":42}", reason, sizeof(reason)),
               "valid pid contract");
  require_true(!validate("kill_process", "{\"pid\":0}", reason, sizeof(reason)),
               "reject non-positive pid");
  require_true(!validate("kill_process", "{\"pid\":\"42\"}", reason, sizeof(reason)),
               "reject string pid");
  require_true(!validate("kill_process", "{\"pid\":42.5}", reason, sizeof(reason)),
               "reject fractional pid");
  require_true(validate("pmfe_scan", "{\"pid\":42,\"region_base\":\"0x7ff60000\",\"region_size\":65536,\"extract_region\":true,\"run_yara\":true}", reason, sizeof(reason)),
               "accept targeted PMFE region extraction contract");
  require_true(!validate("pmfe_scan", "{\"pid\":42,\"region_size\":2097152}", reason, sizeof(reason)),
               "reject oversized PMFE region sample");
  require_true(validate("file_stat", "{\"path\":\"/tmp/a\"}", reason, sizeof(reason)),
               "valid path contract");
  require_true(!validate("file_stat", "{\"path\":\"/tmp/a\",\"typo\":1}", reason, sizeof(reason)),
               "reject unknown command-specific field");
  require_true(!validate("file_stat", "{}", reason, sizeof(reason)),
               "reject missing path");
  require_true(validate("reg_query", "{\"key\":\"HKLM\\\\Software\"}", reason, sizeof(reason)),
               "registry key contract");
  require_true(validate("shell_input", "{\"session_id\":\"s1\",\"input\":\"whoami\"}",
                        reason, sizeof(reason)),
               "valid shell input contract");
  require_true(!validate("shell_input", "{\"session_id\":\"s1\"}", reason, sizeof(reason)),
               "reject incomplete shell input");
  require_true(!validate("kill_process", "{\"pid\":42,\"pid\":43}", reason, sizeof(reason)),
               "reject duplicate JSON fields");
  require_true(validate("rtq_execute", "{\"process_name\":\"powershell.exe\"}", reason, sizeof(reason)),
               "valid strict RTQ contract");
  char rtq_max_path[520];
  memset(rtq_max_path, 'a', sizeof(rtq_max_path) - 1u);
  rtq_max_path[sizeof(rtq_max_path) - 1u] = '\0';
  char rtq_path_payload[600];
  snprintf(rtq_path_payload, sizeof(rtq_path_payload),
           "{\"file_path\":\"%s\"}", rtq_max_path);
  require_true(validate("rtq_execute", rtq_path_payload, reason, sizeof(reason)),
               "accept RTQ file path at Agent buffer contract");
  char rtq_overlong_path[521];
  memset(rtq_overlong_path, 'b', sizeof(rtq_overlong_path) - 1u);
  rtq_overlong_path[sizeof(rtq_overlong_path) - 1u] = '\0';
  snprintf(rtq_path_payload, sizeof(rtq_path_payload),
           "{\"file_path\":\"%s\"}", rtq_overlong_path);
  require_true(!validate("rtq_execute", rtq_path_payload, reason, sizeof(reason)),
               "reject RTQ file path beyond Agent buffer contract");
  require_true(!validate("rtq_execute", "{\"network_remote_port\":70000}", reason, sizeof(reason)),
               "reject out-of-range RTQ port");
  require_true(validate("rtq_execute",
                        "{\"registry_path\":\"HKLM\\\\Software\",\"registry_mode\":\"subtree\"}",
                        reason, sizeof(reason)),
               "accept bounded registry subtree mode");
  require_true(!validate("rtq_execute", "{\"registry_mode\":\"recursive\"}",
                         reason, sizeof(reason)),
               "reject unknown registry mode");
  require_true(!validate("rtq_execute", "{\"file_sha256\":\"abc\"}",
                         reason, sizeof(reason)),
               "reject malformed RTQ SHA256");
  require_true(validate("velo_query", "{\"scope\":\"inspect_process\",\"pid\":42,\"limit\":100,\"backend\":\"local_collector\",\"provider_requested\":\"auto\",\"fallback_reason\":\"\",\"initiated_by\":\"operator\"}", reason, sizeof(reason)),
               "current backend velo payload satisfies strict contract");
  require_true(validate("REFRESH_ATTACK_SURFACE", "{\"reason\":\"manual attack surface refresh\"}",
                        reason, sizeof(reason)),
               "current backend attack surface refresh payload satisfies strict contract");
  require_true(!validate("REFRESH_ATTACK_SURFACE", "{\"reason\":\"manual\",\"requested_at\":\"now\"}",
                         reason, sizeof(reason)),
               "reject the retired attack surface requested_at field");
  require_true(validate("forensic_deep", "{\"scope\":2,\"initiated_by\":\"operator\"}", reason, sizeof(reason)),
               "current deep-forensic payload satisfies strict contract");
  require_true(validate("forensic_targeted", "{\"scope\":\"targeted\",\"reason\":\"triage\",\"timeout_ms\":60000,\"items\":[{\"type\":\"file\",\"path\":\"C:\\\\Temp\\\\a.bin\"}],\"initiated_by\":\"operator\"}", reason, sizeof(reason)),
               "current targeted-forensic payload satisfies strict nested contract");
  require_true(validate("yara_scan", "{\"target_path\":\"C:\\\\Temp\",\"target_type\":\"directory\",\"recursive\":true,\"max_files\":500,\"max_depth\":8,\"max_file_mb\":50,\"exclude_paths\":[\"C:\\\\Temp\\\\skip\"],\"result_detail\":\"full\",\"rule_source\":\"inline\",\"rule_ids\":[\"rule-1\"],\"rules\":\"rule x { condition: true }\",\"timeout_ms\":60000,\"initiated_by\":\"operator\"}", reason, sizeof(reason)),
               "current YARA payload satisfies strict contract");
  require_true(validate("put_file", "{\"path\":\"C:\\\\Temp\\\\empty.bin\",\"data_b64\":\"\",\"offset\":0}", reason, sizeof(reason)),
               "empty file put remains supported by strict contract");
  require_true(!validate("forensic", "quick", reason, sizeof(reason)),
               "reject legacy raw non-JSON forensic payload");
  require_true(validate("ping", NULL, reason, sizeof(reason)), "empty ping payload");
  require_true(!validate("ping", "[]", reason, sizeof(reason)), "reject non-object ping payload");
  require_true(!validate("ping", "{} trailing", reason, sizeof(reason)),
               "reject trailing JSON data");
  require_true(!validate("not_registered", "{}", reason, sizeof(reason)),
               "reject unknown command type");
  printf("ok\n");
  return 0;
}
