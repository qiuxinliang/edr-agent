#ifndef EDR_DETECTION_PROFILE_H
#define EDR_DETECTION_PROFILE_H

#include "edr/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Apply the lightweight [detection] profile onto concrete engine switches.
 * Mode semantics:
 *   0  force off
 *   1  force on
 *  -1  adaptive, conservative auto-enable
 */
void edr_detection_apply_profile(EdrConfig *cfg);

#ifdef __cplusplus
}
#endif

#endif
