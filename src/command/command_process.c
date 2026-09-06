#include "edr/command.h"
#include "edr/command_cancel.h"
#include "edr/command_util.h"
#include "edr/policy_v2.h"
#include "edr/process_generation.h"
#include "cJSON.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int edr_ransom_auto_response_enabled(void) {
  const char *value = getenv("EDR_RANSOM_AUTO_ISOLATE");
  return (value && strcmp(value, "1") == 0) ||
         edr_policy_v2_mode_for_category("impact") == EDR_POLICY_MODE_BLOCK;
}

static int auto_terminate_enabled(void) {
  const char *value = getenv("EDR_RANSOM_AUTO_TERMINATE");
  return value && strcmp(value, "1") == 0;
}

static EdrCommandExecutionStatus process_result(const char *id, const EdrSoarCommandMeta *meta,
    uint32_t pid, uint64_t creation, EdrCommandExecutionStatus status, int exit_code,
    const char *reason) {
  /* Reasons are owned by this module/process_generation, never target input.
   * Keep identity as a decimal string so JSON consumers cannot round uint64. */
  char detail[768];
  int verified = status == EdrCmdExecOk && strcmp(reason, "process_exit_verified") == 0;
  snprintf(detail, sizeof(detail),
      "{\"schema\":\"edr.process_response.v1\",\"action\":\"kill_process\","
      "\"pid\":%u,\"process_creation_filetime_100ns\":\"%llu\","
      "\"reason\":\"%s\",\"enforcement_verified\":%s}",
      (unsigned)pid, (unsigned long long)creation, reason, verified ? "true" : "false");
  int persisted = edr_command_emit_always_typed_status(id, "kill_process", meta, status, exit_code, detail,
      exit_code == 130 ? "cancelled" : status == EdrCmdExecOk ? "ok" : status == EdrCmdExecRejected ? "denied" : "failed");
  return persisted == 0 ? status : EdrCmdExecFailed;
}

EdrCommandExecutionStatus edr_command_kill_process(const char *id,
    const uint8_t *payload, size_t payload_len, const EdrSoarCommandMeta *meta) {
  char reason[160] = {0};
  uint64_t creation = 0;
  uint32_t pid = 0;
  cJSON *root = payload ? cJSON_ParseWithLength((const char *)payload, payload_len) : NULL;
  const cJSON *pid_value = cJSON_GetObjectItemCaseSensitive(root, "pid");
  const cJSON *creation_value = cJSON_GetObjectItemCaseSensitive(root, "process_creation_filetime_100ns");
  if (cJSON_IsNumber(pid_value) && pid_value->valuedouble > 0 &&
      pid_value->valuedouble <= 2147483647.0 &&
      (double)(uint32_t)pid_value->valuedouble == pid_value->valuedouble) {
    pid = (uint32_t)pid_value->valuedouble;
  }
  if (cJSON_IsString(creation_value) && creation_value->valuestring[0] &&
      strspn(creation_value->valuestring, "0123456789") == strlen(creation_value->valuestring)) {
    errno = 0;
    creation = strtoull(creation_value->valuestring, NULL, 10);
    if (errno) creation = 0;
  }
  cJSON_Delete(root);
  if (!pid || !creation) {
    return process_result(id, meta, pid, creation, EdrCmdExecRejected, 2, "observed_process_identity_required");
  }
  int automatic = meta && strcmp(meta->initiated_by, "agent_auto") == 0 &&
      id && strncmp(id, "auto-ransom-", 12u) == 0;
  if (!edr_command_dangerous_enabled() ||
      (automatic && (!edr_ransom_auto_response_enabled() || !auto_terminate_enabled()))) {
    return process_result(id, meta, pid, creation, EdrCmdExecRejected, 1, "policy_disabled");
  }
  if (pid <= 4u || !edr_command_kill_pid_allowed((long)pid)) {
    return process_result(id, meta, pid, creation, EdrCmdExecRejected, 7, "protected_or_disallowed_process");
  }
  if (edr_command_cancel_requested(id)) {
    return process_result(id, meta, pid, creation, EdrCmdExecFailed, 130, "cancelled_before_execution");
  }
  int ok = edr_process_terminate_checked(pid, creation, 5000u, reason, sizeof(reason));
  if (ok && strcmp(reason, "process_exit_verified") == 0) {
    return process_result(id, meta, pid, creation, EdrCmdExecOk, 0, reason);
  }
  /* An already absent PID is a no-op, not evidence that we stopped encryption. */
  int denied = strcmp(reason, "process_already_gone") == 0 ||
      strcmp(reason, "process_generation_mismatch") == 0 ||
      strcmp(reason, "invalid_or_self_process_target") == 0 ||
      strcmp(reason, "protected_process_target") == 0 ||
      strcmp(reason, "verified_termination_unsupported_platform") == 0;
  return process_result(id, meta, pid, creation, denied ? EdrCmdExecRejected : EdrCmdExecFailed,
      denied ? 7 : 4, reason[0] ? reason : "process_termination_unverified");
}

void edr_isolate_auto_from_ransom_alarm(const EdrBehaviorRecord *record) {
  if (!record || !edr_ransom_auto_response_enabled()) return;
  EdrSoarCommandMeta meta;
  memset(&meta, 0, sizeof(meta));
  snprintf(meta.soar_correlation_id, sizeof(meta.soar_correlation_id), "%s", record->event_id);
  snprintf(meta.playbook_run_id, sizeof(meta.playbook_run_id), "%s", "ransom-auto");
  snprintf(meta.initiated_by, sizeof(meta.initiated_by), "%s", "agent_auto");
  meta.deadline_ms = 30000u;
  uint64_t creation = record->process_creation_filetime_100ns;
  /* Missing identity gets a rejection tied to this evidence occurrence, never
   * a live PID lookup that could silently bind to a replacement process. */
  uint64_t identity = creation ? creation : (uint64_t)record->event_time_ns;
  char id[128], payload[128];
  if (auto_terminate_enabled()) {
    snprintf(id, sizeof(id), "auto-ransom-%u-%llu-terminate", (unsigned)record->pid, (unsigned long long)identity);
    snprintf(meta.idempotency_key, sizeof(meta.idempotency_key), "%s", id);
    snprintf(meta.playbook_step_id, sizeof(meta.playbook_step_id), "%s", "terminate");
    if (!record->pid || !creation) {
      (void)process_result(id, &meta, record->pid, creation, EdrCmdExecRejected, 2, "observed_process_identity_required");
    } else {
      snprintf(payload, sizeof(payload), "{\"pid\":%u,\"process_creation_filetime_100ns\":\"%llu\"}",
          (unsigned)record->pid, (unsigned long long)creation);
      edr_command_on_internal_envelope(id, "kill_process", (const uint8_t *)payload, strlen(payload), &meta);
    }
  }
  snprintf(id, sizeof(id), "auto-ransom-%u-%llu-isolate", (unsigned)record->pid, (unsigned long long)identity);
  snprintf(meta.idempotency_key, sizeof(meta.idempotency_key), "%s", id);
  snprintf(meta.playbook_step_id, sizeof(meta.playbook_step_id), "%s", "isolate");
  edr_command_on_internal_envelope(id, "isolate_host", (const uint8_t *)"{}", 2u, &meta);
}
