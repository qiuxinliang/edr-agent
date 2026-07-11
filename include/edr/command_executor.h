#ifndef EDR_COMMAND_EXECUTOR_H
#define EDR_COMMAND_EXECUTOR_H

#include <stdint.h>

#include "edr/command_registry.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EdrCommandExecutorHealth {
  int started;
  int accepting;
  int active;
  uint32_t worker_count;
  uint32_t queue_capacity;
  uint32_t queue_critical_reserve;
  uint32_t pending_count;
  uint32_t admission_reservations;
  uint64_t wake_count;
  uint64_t executed_count;
  uint64_t replay_error_count;
  uint64_t queue_rejected_count;
  uint64_t lane_executed[EDR_COMMAND_LANE_COUNT];
} EdrCommandExecutorHealth;

int edr_command_executor_start(void);
void edr_command_executor_wake(void);
void edr_command_executor_shutdown(void);
void edr_command_executor_get_health(EdrCommandExecutorHealth *out_health);
int edr_command_executor_admit(const char *command_type);
void edr_command_executor_release_admission(void);

#ifdef __cplusplus
}
#endif

#endif
