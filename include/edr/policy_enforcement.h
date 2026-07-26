#ifndef EDR_POLICY_ENFORCEMENT_H
#define EDR_POLICY_ENFORCEMENT_H

#include "edr/behavior_record.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  int requested;
  int attempted;
  int succeeded;
  uint32_t error_code;
  char action[32];
  char message[128];
} EdrPolicyEnforcementResult;

void edr_policy_enforce_alert(const EdrBehaviorRecord *record,
                              const char *triggered_tactics,
                              const char *rule_id,
                              EdrPolicyEnforcementResult *result);

#ifdef __cplusplus
}
#endif

#endif
