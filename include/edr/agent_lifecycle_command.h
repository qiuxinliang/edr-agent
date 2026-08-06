#ifndef EDR_AGENT_LIFECYCLE_COMMAND_H
#define EDR_AGENT_LIFECYCLE_COMMAND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDR_AGENT_LIFECYCLE_EXIT_UNSUPPORTED 95
#define EDR_AGENT_LIFECYCLE_EXIT_LAUNCHED 96
#define EDR_AGENT_LIFECYCLE_EXIT_HANDOFF 97

typedef struct EdrAgentLifecycleRecovery {
  char task_id[129];
  char command_id[181];
  char action[16];
  char status[32];
  char detail[512];
  int succeeded;
  int exit_code;
} EdrAgentLifecycleRecovery;

int edr_agent_lifecycle_execute(const char *command_id, const uint8_t *payload,
                                size_t payload_len, char *detail, size_t detail_cap);
int edr_agent_lifecycle_recover(const char *command_id, const uint8_t *payload,
                                size_t payload_len, EdrAgentLifecycleRecovery *out);

#ifdef __cplusplus
}
#endif

#endif
