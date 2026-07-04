#ifndef EDR_SENSOR_INTEREST_H
#define EDR_SENSOR_INTEREST_H

#include "edr/types.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
  EdrEventType type;
  char provider[32];
  uint16_t event_id;
  uint8_t opcode;
  uint32_t pid;
  uint32_t parent_pid;
  uint32_t remote_port;
  char process_name[256];
  char parent_process_name[256];
  char path[1024];
  char registry_path[1024];
} EdrSensorInterestEvent;

typedef struct {
  int enabled;
  int loaded;
  char version[128];
  char rules_version[128];
  uint32_t process_name_count;
  uint32_t process_prefix_count;
  uint32_t port_count;
  uint32_t file_prefix_count;
  uint32_t file_contains_count;
  uint32_t registry_prefix_count;
  uint32_t registry_contains_count;
  uint32_t cmd_token_count;
  uint32_t parent_child_pair_count;
  uint32_t attack_stage_required_field_count;
  uint64_t checked;
  uint64_t matched;
  uint64_t dropped;
  uint64_t provider_hits;
  uint64_t adaptive_hits;
  uint64_t process_hits;
  uint64_t port_hits;
  uint64_t path_hits;
  uint64_t registry_hits;
  uint64_t parent_child_hits;
} EdrSensorInterestStatus;

void edr_sensor_interest_lazy_init(void);
void edr_sensor_interest_reload(void);
int edr_sensor_interest_should_admit(const EdrSensorInterestEvent *event);
void edr_sensor_interest_get_status(EdrSensorInterestStatus *out_status);
int edr_sensor_interest_default_path(char *out, size_t cap);
int edr_sensor_interest_replace_manifest_from_file(const char *src_path);

#endif
