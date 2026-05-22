#ifndef EDR_DETECTION_PROFILE_H
#define EDR_DETECTION_PROFILE_H

#include "edr/behavior_record.h"

#include <stdint.h>

struct EdrDetectionDecision;

typedef struct EdrDetectionProfile {
  char name[32];
  uint8_t server_asset;
  uint8_t high_value_asset;
  uint8_t aggressive;
  uint8_t pmfe_auto_enabled;
  uint8_t minidump_enabled;
  float pmfe_confidence_threshold;
  float minidump_confidence_threshold;
} EdrDetectionProfile;

typedef struct EdrDetectionTrigger {
  char profile_name[32];
  uint8_t pmfe_scan;
  uint8_t single_process_minidump;
  uint8_t targeted_files;
  uint8_t ioc_lookup;
  char reason[192];
} EdrDetectionTrigger;

void edr_detection_profile_load(EdrDetectionProfile *out);
void edr_detection_trigger_evaluate(const EdrBehaviorRecord *r, const struct EdrDetectionDecision *d,
                                    EdrDetectionTrigger *out);
int edr_detection_trigger_should_auto_pmfe(const EdrBehaviorRecord *r, const struct EdrDetectionDecision *d);

#endif
