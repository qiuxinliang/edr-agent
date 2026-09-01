#ifndef EDR_ALERT_GOVERNOR_H
#define EDR_ALERT_GOVERNOR_H

#include "edr/ave_sdk.h"

#include <stdint.h>

typedef struct EdrAlertGovernorDecision {
  int allow_original;
  int emit_summary;
  uint64_t summary_suppressed;
  char rule_id[96];
} EdrAlertGovernorDecision;

typedef struct EdrAlertGovernorStats {
  uint64_t admitted;
  uint64_t suppressed;
  uint64_t summaries;
  uint64_t critical_bypassed;
} EdrAlertGovernorStats;

typedef int (*EdrAlertGovernorEmitFn)(void *context);

typedef enum EdrAlertGovernorEmitOutcome {
  EDR_ALERT_GOVERNOR_EMIT_ACCEPTED = 1,
  EDR_ALERT_GOVERNOR_EMIT_SUPPRESSED = 2,
  EDR_ALERT_GOVERNOR_EMIT_CALLBACK_FAILED = 3,
  EDR_ALERT_GOVERNOR_EMIT_INVALID = 4,
} EdrAlertGovernorEmitOutcome;

void edr_alert_governor_admit(const AVEBehaviorAlert *alert, int64_t now_s,
                              EdrAlertGovernorDecision *decision);
/* The callback runs only after a locked capacity reservation has succeeded,
 * and always runs without the governor lock. A callback failure releases that
 * reservation; successful delivery commits the admission counter. The outcome
 * distinguishes ordinary governor suppression from a callback/queue failure. */
EdrAlertGovernorEmitOutcome edr_alert_governor_admit_and_emit(
    const AVEBehaviorAlert *alert, int64_t now_s, EdrAlertGovernorEmitFn emit,
    void *context, EdrAlertGovernorDecision *decision);
int edr_alert_governor_poll_summary(int64_t now_s, uint64_t *suppressed_count);
void edr_alert_governor_get_stats(EdrAlertGovernorStats *stats);
void edr_alert_governor_reset_for_test(void);

#endif
