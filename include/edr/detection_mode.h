#ifndef EDR_DETECTION_MODE_H
#define EDR_DETECTION_MODE_H

#include "edr/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Apply product detection modes to concrete sensors in the live config. */
void edr_detection_apply_profile(EdrConfig *cfg);

/* Copy and apply a remotely parsed detection section. Returns 1 when modes changed. */
int edr_detection_apply_remote_modes(EdrConfig *current, const EdrConfig *remote);

#ifdef __cplusplus
}
#endif

#endif
