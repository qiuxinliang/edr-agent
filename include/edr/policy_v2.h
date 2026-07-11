#ifndef EDR_POLICY_V2_H
#define EDR_POLICY_V2_H

#include "edr/config.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
  EDR_POLICY_MODE_OFF = 0,
  EDR_POLICY_MODE_OBSERVE = 1,
  EDR_POLICY_MODE_ALERT = 2,
  EDR_POLICY_MODE_BLOCK = 3
};

void edr_policy_v2_configure(const EdrConfig *cfg);
int edr_policy_v2_apply_remote(EdrConfig *current, const EdrConfig *remote);
int edr_policy_v2_alert_allowed(const char *triggered_tactics, const char *subject_json);
int edr_policy_v2_mode_for_category(const char *category);
int edr_policy_v2_ransomware_enabled(const char *control);

#ifdef __cplusplus
}
#endif

#endif
