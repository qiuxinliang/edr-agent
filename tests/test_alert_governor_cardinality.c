#include "edr/alert_governor.h"
#include "edr/behavior_alert_emit.h"

#include <stdio.h>
#include <string.h>

static unsigned s_emitted_frames;

size_t edr_behavior_alert_encode_protobuf(const AVEBehaviorAlert *alert,
                                          const char *endpoint_id, const char *tenant_id,
                                          uint8_t *out, size_t out_cap) {
  (void)alert; (void)endpoint_id; (void)tenant_id;
  if (!out || out_cap == 0u) return 0u;
  out[0] = 1u;
  return 1u;
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

static void make_alert(AVEBehaviorAlert *alert, int rule, int critical) {
  memset(alert, 0, sizeof(*alert));
  snprintf(alert->process_name, sizeof(alert->process_name), "sample-%d.exe", rule);
  snprintf(alert->user_subject_json, sizeof(alert->user_subject_json),
           "{\"rule_id\":\"%srule-%d\"}", critical ? "CANARY-" : "", rule);
}

int main(void) {
  AVEBehaviorAlert alert;
  EdrAlertGovernorDecision decision;
  EdrAlertGovernorStats stats;
  unsigned ordinary_emitted = 0;
  unsigned critical_emitted = 0;

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
