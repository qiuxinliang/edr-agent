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
  /* Immutable intent selected by the side-effect-free plan. `action` is the
   * observed execution result and therefore may remain "none" before run. */
  char planned_action[32];
  char action[32];
  char message[128];
} EdrPolicyEnforcementResult;

void edr_policy_enforce_alert(const EdrBehaviorRecord *record,
                              const char *triggered_tactics,
                              const char *rule_id,
                              EdrPolicyEnforcementResult *result);
/* Planning is side-effect free.  P0 callers use it before their durable
 * ownership handoff; execution is deliberately a separate operation. */
void edr_policy_enforcement_plan(const EdrBehaviorRecord *record,
                                 const char *triggered_tactics,
                                 const char *rule_id,
                                 EdrPolicyEnforcementResult *result);
void edr_policy_enforcement_execute(const EdrBehaviorRecord *record,
                                    EdrPolicyEnforcementResult *result);
#ifdef EDR_P0_DIRECT_EMIT_TESTING
typedef void (*EdrPolicyEnforcementTestExecuteHook)(const EdrBehaviorRecord *record,
                                                    EdrPolicyEnforcementResult *result);
void edr_policy_enforcement_test_set_execute_hook(EdrPolicyEnforcementTestExecuteHook hook);
#endif

#ifdef __cplusplus
}
#endif

#endif
