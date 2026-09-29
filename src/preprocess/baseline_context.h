#ifndef EDR_BASELINE_CONTEXT_H
#define EDR_BASELINE_CONTEXT_H

#include "cJSON.h"
#include <string.h>

/* Shared decision-owner contract for consumers of ordinary baseline facts.
 * Missing, changed or positive signals must retain the evidence. */
static int baseline_context_has_no_server_signal(const cJSON *root,
                                               int uncombined_tool_file) {
  static const char *const positive_signals[] = {
      "remote", "ransom_note", "tls_anomaly", "ransom_canary",
      "script_sensor", "process_context", "ransom_behavior",
      "rmm_policy_match", "extension_changed", "ransom_note_burst",
      "suspicious_parent", "webshell_semantic", "persistence_change",
      "high_content_entropy", "cert_revoked_ancestor",
      "security_product_kill", "ransom_recovery_tamper",
      "silverfox_attack_chain"};
  if (!cJSON_IsObject(root)) return 0;
  const cJSON *signals = cJSON_GetObjectItemCaseSensitive(root, "signals");
  const cJSON *control = cJSON_GetObjectItemCaseSensitive(root, "ransom_control");
  const cJSON *quality = cJSON_GetObjectItemCaseSensitive(root, "event_quality");
  const cJSON *phase = cJSON_GetObjectItemCaseSensitive(control, "phase");
  const cJSON *kind = cJSON_GetObjectItemCaseSensitive(control, "kind");
  const cJSON *rate = cJSON_GetObjectItemCaseSensitive(control, "file_rate_per_min");
  const cJSON *chain = cJSON_GetObjectItemCaseSensitive(signals, "ransom_chain_score");
  const cJSON *reasons = cJSON_GetObjectItemCaseSensitive(quality, "signal_reasons");
  if (!cJSON_IsObject(signals) || !cJSON_IsObject(control) ||
      !cJSON_IsObject(quality) || !cJSON_IsString(phase) ||
      strcmp(phase->valuestring, "baseline") != 0 ||
      !cJSON_IsString(kind) || kind->valuestring[0] ||
      !cJSON_IsNumber(rate) || rate->valuedouble < 0.0 ||
      rate->valuedouble >= 80.0 ||
      /* The decision owner assigns exactly 20 for the tool identity alone.
       * Any additional or inherited chain contribution keeps the upload. */
      !cJSON_IsNumber(chain) ||
      chain->valuedouble != (uncombined_tool_file ? 20.0 : 0.0) ||
      !cJSON_IsArray(reasons) ||
      cJSON_GetArraySize(reasons) != (uncombined_tool_file ? 1 : 0) ||
      !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "canary")) ||
      !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "extension_changed"))) {
    return 0;
  }
  if (uncombined_tool_file) {
    const cJSON *reason = cJSON_GetArrayItem(reasons, 0);
    if (!cJSON_IsString(reason) || strcmp(reason->valuestring, "lolbin") != 0 ||
        !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "tracking_saturated")) ||
        !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "state_transition")) ||
        !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "periodic_summary"))) {
      return 0;
    }
  }
  for (size_t i = 0u; i < sizeof(positive_signals) / sizeof(positive_signals[0]); i++) {
    if (!cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(signals,
                                                       positive_signals[i]))) return 0;
  }
  return 1;
}

#endif
