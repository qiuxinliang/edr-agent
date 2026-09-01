#include "edr/alert_governor.h"
#include "edr/behavior_alert_emit.h"
#include "edr/storage_queue.h"

#include <stdio.h>
#include <string.h>

static unsigned s_emitted_frames;

static int count_governor_callback(void *context) {
  unsigned *count = context;
  if (!count) return 0;
  (*count)++;
  return 1;
}

void edr_preprocess_copy_agent_ids(char *endpoint_id, size_t endpoint_cap,
                                   char *tenant_id, size_t tenant_cap) {
  snprintf(endpoint_id, endpoint_cap, "endpoint-release-gate");
  snprintf(tenant_id, tenant_cap, "tenant-release-gate");
}

int edr_event_batch_push(const uint8_t *wire, size_t wire_len) {
  if (!wire || wire_len == 0u) return -1;
  s_emitted_frames++;
  return 0;
}

/* This cardinality test has no persistent queue fixture. Combined P0 delivery
 * must therefore fail closed rather than receiving a fake durable success. */
int edr_storage_queue_is_open(void) { return 0; }
EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,
                                   size_t payload_len, int compressed, int severity) {
  (void)batch_id; (void)payload; (void)payload_len; (void)compressed; (void)severity;
  return EDR_ERR_INVALID_ARG;
}

static void make_alert(AVEBehaviorAlert *alert, int rule, int critical) {
  memset(alert, 0, sizeof(*alert));
  snprintf(alert->process_name, sizeof(alert->process_name), "sample-%d.exe", rule);
  snprintf(alert->user_subject_json, sizeof(alert->user_subject_json),
           "{\"rule_id\":\"%srule-%d\"}", critical ? "CANARY-" : "", rule);
}

static void make_long_tactic_alert(AVEBehaviorAlert *alert, char suffix) {
  memset(alert, 0, sizeof(*alert));
  memset(alert->triggered_tactics, 't', sizeof(alert->triggered_tactics) - 1u);
  alert->triggered_tactics[sizeof(alert->triggered_tactics) - 2u] = suffix;
}

static void make_long_process_alert(AVEBehaviorAlert *alert, char suffix) {
  memset(alert, 0, sizeof(*alert));
  memset(alert->process_name, 'p', sizeof(alert->process_name) - 1u);
  alert->process_name[sizeof(alert->process_name) - 2u] = suffix;
}

static void make_long_json_rule_alert(AVEBehaviorAlert *alert, char suffix,
                                      int escape_first_character) {
  static const char json_prefix[] = "{\"rule_id\":\"";
  static const char escaped_r[] = "\\u0072";
  enum { rule_id_len = 128 };
  size_t offset = sizeof(json_prefix) - 1u;

  memset(alert, 0, sizeof(*alert));
  memcpy(alert->user_subject_json, json_prefix, offset);
  for (size_t i = 0u; i < rule_id_len; ++i) {
    if (escape_first_character && i == 0u) {
      memcpy(alert->user_subject_json + offset, escaped_r, sizeof(escaped_r) - 1u);
      offset += sizeof(escaped_r) - 1u;
    } else {
      alert->user_subject_json[offset++] = i + 1u == rule_id_len ? suffix : 'r';
    }
  }
  alert->user_subject_json[offset++] = '"';
  alert->user_subject_json[offset++] = '}';
  alert->user_subject_json[offset] = '\0';
}

static int test_long_rule_ids_do_not_merge_budgets(const AVEBehaviorAlert *first,
                                                   const AVEBehaviorAlert *second,
                                                   const char *expected_prefix,
                                                   int error_base) {
  EdrAlertGovernorDecision decision;
  char first_rule_id[sizeof(decision.rule_id)];
  unsigned callback_count = 0u;

  edr_alert_governor_reset_for_test();
  for (unsigned i = 0u; i < 30u; ++i) {
    if (edr_alert_governor_admit_and_emit(first, 720, count_governor_callback,
                                           &callback_count, &decision) !=
            EDR_ALERT_GOVERNOR_EMIT_ACCEPTED ||
        !decision.allow_original) {
      fprintf(stderr, "long rule identity admission %u failed\n", i + 1u);
      return error_base + 1;
    }
  }
  if (strncmp(decision.rule_id, expected_prefix, strlen(expected_prefix)) != 0 ||
      !decision.rule_id[0]) {
    fprintf(stderr, "long rule identity fallback missing expected prefix %s\n", expected_prefix);
    return error_base + 2;
  }
  memcpy(first_rule_id, decision.rule_id, sizeof(first_rule_id));
  if (edr_alert_governor_admit_and_emit(second, 720, count_governor_callback,
                                         &callback_count, &decision) !=
          EDR_ALERT_GOVERNOR_EMIT_ACCEPTED ||
      !decision.allow_original || strcmp(first_rule_id, decision.rule_id) == 0 ||
      callback_count != 31u) {
    fprintf(stderr, "distinct long rule identities merged into one budget\n");
    return error_base + 3;
  }
  return 0;
}

static int test_long_rule_identity_contract(void) {
  AVEBehaviorAlert first;
  AVEBehaviorAlert second;
  int rc;

  make_long_tactic_alert(&first, 'A');
  make_long_tactic_alert(&second, 'B');
  rc = test_long_rule_ids_do_not_merge_budgets(&first, &second, "tactic-sha256:", 20);
  if (rc != 0) return rc;

  make_long_process_alert(&first, 'A');
  make_long_process_alert(&second, 'B');
  rc = test_long_rule_ids_do_not_merge_budgets(&first, &second, "process-sha256:", 30);
  if (rc != 0) return rc;

  make_long_json_rule_alert(&first, 'A', 0);
  make_long_json_rule_alert(&second, 'B', 0);
  return test_long_rule_ids_do_not_merge_budgets(&first, &second, "rule-sha256:", 40);
}

static int test_escaped_json_rule_id_is_canonical(void) {
  AVEBehaviorAlert literal;
  AVEBehaviorAlert escaped;
  EdrAlertGovernorDecision decision;
  unsigned callback_count = 0u;

  memset(&literal, 0, sizeof(literal));
  memcpy(literal.user_subject_json, "{\"rule_id\":\"R-ESC-001\"}",
         sizeof("{\"rule_id\":\"R-ESC-001\"}"));
  memset(&escaped, 0, sizeof(escaped));
  memcpy(escaped.user_subject_json, "{\"rule_id\":\"R\\u002dESC\\u002d001\"}",
         sizeof("{\"rule_id\":\"R\\u002dESC\\u002d001\"}"));

  edr_alert_governor_reset_for_test();
  for (unsigned i = 0u; i < 30u; ++i) {
    if (edr_alert_governor_admit_and_emit(&literal, 780, count_governor_callback,
                                           &callback_count, &decision) !=
            EDR_ALERT_GOVERNOR_EMIT_ACCEPTED ||
        strcmp(decision.rule_id, "R-ESC-001") != 0) {
      fprintf(stderr, "short rule id did not retain its canonical value\n");
      return 50;
    }
  }
  if (edr_alert_governor_admit_and_emit(&escaped, 780, count_governor_callback,
                                         &callback_count, &decision) !=
          EDR_ALERT_GOVERNOR_EMIT_SUPPRESSED ||
      strcmp(decision.rule_id, "R-ESC-001") != 0 || callback_count != 30u) {
    fprintf(stderr, "escaped JSON rule id bypassed its canonical rule budget\n");
    return 51;
  }

  make_long_json_rule_alert(&literal, 'A', 0);
  make_long_json_rule_alert(&escaped, 'A', 1);
  edr_alert_governor_reset_for_test();
  for (unsigned i = 0u; i < 30u; ++i) {
    if (edr_alert_governor_admit_and_emit(&literal, 840, count_governor_callback,
                                           &callback_count, &decision) !=
            EDR_ALERT_GOVERNOR_EMIT_ACCEPTED) {
      fprintf(stderr, "long canonical rule id admission failed\n");
      return 52;
    }
  }
  if (edr_alert_governor_admit_and_emit(&escaped, 840, count_governor_callback,
                                         &callback_count, &decision) !=
          EDR_ALERT_GOVERNOR_EMIT_SUPPRESSED ||
      strncmp(decision.rule_id, "rule-sha256:", strlen("rule-sha256:")) != 0) {
    fprintf(stderr, "escaped long JSON rule id bypassed its canonical rule budget\n");
    return 53;
  }
  return 0;
}

static int test_long_canary_and_invalid_fallback_contract(void) {
  AVEBehaviorAlert alert;
  EdrAlertGovernorDecision decision;
  EdrAlertGovernorStats stats;
  unsigned callback_count = 0u;

  make_long_tactic_alert(&alert, 'Z');
  memcpy(alert.triggered_tactics, "CANARY-", sizeof("CANARY-") - 1u);
  edr_alert_governor_reset_for_test();
  for (unsigned i = 0u; i < 31u; ++i) {
    if (edr_alert_governor_admit_and_emit(&alert, 900, count_governor_callback,
                                           &callback_count, &decision) !=
            EDR_ALERT_GOVERNOR_EMIT_ACCEPTED ||
        strncmp(decision.rule_id, "canary-tactic-sha256:",
                strlen("canary-tactic-sha256:")) != 0) {
      fprintf(stderr, "long CANARY rule lost its critical bypass\n");
      return 60;
    }
  }
  edr_alert_governor_get_stats(&stats);
  if (callback_count != 31u || stats.critical_bypassed != 31u) {
    fprintf(stderr, "long CANARY critical admission accounting failed\n");
    return 61;
  }

  memset(&alert, 0, sizeof(alert));
  memcpy(alert.user_subject_json, "{\"rule_id\":\"unterminated",
         sizeof("{\"rule_id\":\"unterminated"));
  edr_alert_governor_reset_for_test();
  {
    EdrAlertGovernorEmitOutcome outcome = edr_alert_governor_admit_and_emit(
        &alert, 960, count_governor_callback, &callback_count, &decision);
    if (outcome != EDR_ALERT_GOVERNOR_EMIT_ACCEPTED ||
        strcmp(decision.rule_id, "unclassified") != 0 || !decision.rule_id[0]) {
      fprintf(stderr, "invalid rule-id fallback outcome=%d key=%s\n", (int)outcome,
              decision.rule_id);
      return 62;
    }
  }
  return 0;
}

static int test_same_rule_thirtieth_suppresses_thirty_first_and_recovers(void) {
  AVEBehaviorAlert alert;
  EdrAlertGovernorDecision decision;
  EdrAlertGovernorStats stats;
  unsigned callback_count = 0;

  edr_alert_governor_reset_for_test();
  make_alert(&alert, 77, 0);
  for (unsigned i = 0; i < 30u; ++i) {
    EdrAlertGovernorEmitOutcome outcome = edr_alert_governor_admit_and_emit(
        &alert, 600, count_governor_callback, &callback_count, &decision);
    if (outcome != EDR_ALERT_GOVERNOR_EMIT_ACCEPTED || !decision.allow_original) {
      fprintf(stderr, "same-rule admission %u failed outcome=%d allow=%d\n", i + 1u,
              (int)outcome, decision.allow_original);
      return 10;
    }
  }
  if (callback_count != 30u) {
    fprintf(stderr, "same-rule callback count=%u want=30\n", callback_count);
    return 11;
  }
  if (edr_alert_governor_admit_and_emit(&alert, 600, count_governor_callback,
                                         &callback_count, &decision) !=
          EDR_ALERT_GOVERNOR_EMIT_SUPPRESSED ||
      decision.allow_original || callback_count != 30u) {
    fprintf(stderr, "31st same-rule event was not governor-suppressed\n");
    return 12;
  }
  edr_alert_governor_get_stats(&stats);
  if (stats.admitted != 30u || stats.suppressed != 1u) {
    fprintf(stderr, "same-rule stats admitted=%llu suppressed=%llu\n",
            (unsigned long long)stats.admitted, (unsigned long long)stats.suppressed);
    return 13;
  }
  if (edr_alert_governor_admit_and_emit(&alert, 660, count_governor_callback,
                                         &callback_count, &decision) !=
          EDR_ALERT_GOVERNOR_EMIT_ACCEPTED ||
      !decision.emit_summary || decision.summary_suppressed != 1u || callback_count != 31u) {
    fprintf(stderr, "next-window recovery/summary failed\n");
    return 14;
  }
  return 0;
}

int main(void) {
  AVEBehaviorAlert alert;
  EdrAlertGovernorDecision decision;
  EdrAlertGovernorStats stats;
  unsigned ordinary_emitted = 0;
  unsigned critical_emitted = 0;

  {
    int rc = test_same_rule_thirtieth_suppresses_thirty_first_and_recovers();
    if (rc != 0) return rc;
  }
  {
    int rc = test_long_rule_identity_contract();
    if (rc != 0) return rc;
  }
  {
    int rc = test_escaped_json_rule_id_is_canonical();
    if (rc != 0) return rc;
  }
  {
    int rc = test_long_canary_and_invalid_fallback_contract();
    if (rc != 0) return rc;
  }

  edr_alert_governor_reset_for_test();
  for (int i = 0; i < 250; i++) {
    make_alert(&alert, i % 5, 0);
    alert.pid = (uint32_t)(1000 + i);
    snprintf(alert.process_name, sizeof(alert.process_name), "unique-sample-%d.exe", i);
    edr_behavior_alert_emit_to_batch(&alert);
  }
  ordinary_emitted = s_emitted_frames;
  if (ordinary_emitted != 120) {
    fprintf(stderr, "ordinary alert SLO mismatch: emitted=%u want=120\n", ordinary_emitted);
    return 1;
  }

  for (int i = 0; i < 5; i++) {
    make_alert(&alert, i, 1);
    unsigned before = s_emitted_frames;
    edr_behavior_alert_emit_to_batch(&alert);
    critical_emitted += s_emitted_frames - before;
  }
  if (critical_emitted != 5) {
    fprintf(stderr, "critical canary alerts were suppressed: emitted=%u\n", critical_emitted);
    return 2;
  }

  edr_alert_governor_reset_for_test();
  for (int i = 0; i < 40; i++) {
    make_alert(&alert, 0, 0);
    edr_alert_governor_admit(&alert, 600, &decision);
  }
  {
    uint64_t suppressed = 0;
    if (!edr_alert_governor_poll_summary(660, &suppressed) || suppressed == 0) {
      fprintf(stderr, "period summary contract failed: suppressed=%llu\n",
              (unsigned long long)suppressed);
      return 3;
    }
    if (edr_alert_governor_poll_summary(660, &suppressed)) {
      fprintf(stderr, "period summary emitted more than once\n");
      return 3;
    }
  }

  edr_alert_governor_get_stats(&stats);
  if (stats.suppressed == 0 || stats.summaries != 1) {
    fprintf(stderr, "unexpected governor stats: suppressed=%llu summaries=%llu critical=%llu\n",
            (unsigned long long)stats.suppressed, (unsigned long long)stats.summaries,
            (unsigned long long)stats.critical_bypassed);
    return 4;
  }
  return 0;
}
