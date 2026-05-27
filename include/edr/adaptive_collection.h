#ifndef EDR_ADAPTIVE_COLLECTION_H
#define EDR_ADAPTIVE_COLLECTION_H

#include "edr/behavior_record.h"
#include "edr/config.h"
#include "edr/sensor_interest.h"

#include <stdint.h>

typedef struct {
  int enabled;
  int active;
  uint32_t ttl_s;
  uint32_t remaining_s;
  uint32_t min_severity;
  int level;
  uint64_t boosts;
  uint64_t last_boost_unix_ms;
  char last_rule_id[64];
} EdrAdaptiveCollectionStatus;

void edr_adaptive_collection_configure(const EdrConfig *cfg);
void edr_adaptive_collection_raise(int severity, const char *rule_id, uint32_t pid,
                                   uint32_t parent_pid, const char *process_name);
int edr_adaptive_collection_active(void);
int edr_adaptive_collection_should_admit_interest(const EdrSensorInterestEvent *event);
int edr_adaptive_collection_should_admit_record(const EdrBehaviorRecord *record);
void edr_adaptive_collection_get_status(EdrAdaptiveCollectionStatus *out_status);

#endif
