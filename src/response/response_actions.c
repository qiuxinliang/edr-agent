#include "edr/response.h"

#include "edr/command_util.h"
#include "edr/deep_collector.h"
#include "edr/shell_exec.h"

#include <stdio.h>
#include <string.h>

void edr_response_deep_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "forensic_deep: rejected (dangerous disabled)");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 0,
                          "dangerous commands disabled");
    return;
  }

  if (edr_response_forensic_external_enabled()) {
    char collector_detail[512];
    collector_detail[0] = '\0';
    int accepted = edr_response_forensic_async_accept(
        cmd_id, "deep_forensic", sm, "deep_forensic", pl, len, "tar.gz", 1,
        collector_detail, sizeof(collector_detail));
    if (accepted == 0) {
      edr_command_audit_both(cmd_id, "deep_forensic: accepted(async)");
      return;
    }
    edr_cmd_inc_exec_fail();
    char failure[600];
    snprintf(failure, sizeof(failure), "deep_forensic external failed rc=%d: %.460s",
             accepted, collector_detail);
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 6, failure);
    return;
  }

  EdrDeepCollectorParams params;
  memset(&params, 0, sizeof(params));
  params.scope = "standard";
  params.timeout_s = 900u;
  char scope[64];
  scope[0] = '\0';
  (void)edr_parse_json_string(pl, len, "scope", scope, sizeof(scope));
  int scope_number = 0;
  (void)edr_parse_json_int(pl, len, "scope", &scope_number);
  if (strcmp(scope, "triage") == 0 || strcmp(scope, "light") == 0 || scope_number == 1) {
    params.scope = "triage";
  } else if (strcmp(scope, "full") == 0 || scope_number == 3) {
    params.scope = "full";
  }

  int rc = edr_deep_collector_launch(&params);
  if (rc != EDR_DC_OK) {
    edr_cmd_inc_exec_fail();
    char detail[128];
    snprintf(detail, sizeof(detail), "forensic_deep: launch failed, err=%d", rc);
    edr_command_audit_both(cmd_id, detail);
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, rc, detail);
    return;
  }

  edr_cmd_inc_handled();
  edr_cmd_inc_exec_ok();
  char detail[128];
  snprintf(detail, sizeof(detail), "forensic_deep launched, scope=%s", params.scope);
  edr_command_audit_both(cmd_id, "forensic_deep: launched");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}
