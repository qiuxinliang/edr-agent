#ifndef EDR_REGISTRY_NAME_OBSERVATION_H
#define EDR_REGISTRY_NAME_OBSERVATION_H
#include "edr/types.h"
#include <string.h>
/* A complete producer read must survive the ETW1 identity boundary exactly.
 * Empty text alone, including baseline notifications, proves no observation. */
static inline uint8_t edr_registry_captured_name_observation(
    const char *name, const char *emitted, int captured) {
  if (!captured || !name || !emitted || strcmp(name, emitted))
    return EDR_REG_NAME_UNKNOWN;
  return name[0] ? EDR_REG_NAME_OBSERVED : EDR_REG_NAME_DEFAULT;
}
#endif
