#ifndef EDR_DETECTION_DECISION_H
#define EDR_DETECTION_DECISION_H

#include "edr/behavior_record.h"

#include <stdint.h>

typedef struct EdrDetectionDecision {
  float confidence;
  float confidence_before_suppression;
  uint8_t suppress;
  uint8_t drop;
  uint8_t has_remote;
  uint8_t suspicious_parent;
  uint8_t allowlisted_path;
  uint8_t context_correlated;
  uint8_t persistence_change;
  uint8_t trigger_pmfe_scan;
  uint8_t trigger_single_process_minidump;
  char detection_profile[32];
  char suppression_reason[96];
  char suppression_policy_version[64];
  char suppression_rollback_version[64];
  uint32_t suppression_hit_count;
  char trigger_reason[192];
  char reason[256];
} EdrDetectionDecision;

void edr_detection_decision_evaluate(EdrBehaviorRecord *r, EdrDetectionDecision *out);

#endif
