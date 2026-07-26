#ifndef EDR_AGENT_UPDATE_COMMAND_H
#define EDR_AGENT_UPDATE_COMMAND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDR_AGENT_UPDATE_EXIT_UNSUPPORTED 95
#define EDR_AGENT_UPDATE_EXIT_LAUNCHED 96
#define EDR_AGENT_UPDATE_MAX_ARTIFACT_BYTES (256u * 1024u * 1024u)

typedef struct EdrAgentUpdateRecovery {
  char status[32];
  char stage[64];
  char detail[1024];
  int succeeded;
  int exit_code;
} EdrAgentUpdateRecovery;

typedef struct EdrAgentUpdateRequest {
  char artifact_url[2049];
  char sha256[65];
  char target_version[65];
  char architecture[16];
  char internal_name[65];
  char publisher_thumbprint[129];
  char publisher_subject[257];
  char min_current_version[65];
  char max_current_version[65];
  char runtime_manifest_url[2049];
  char runtime_manifest_sha256[65];
  char deployment_mode[24];
  char scheduled_task_name[129];
  char scheduled_task_path[129];
  char service_name[129];
  uint64_t min_free_bytes;
} EdrAgentUpdateRequest;

int edr_agent_update_parse_request(const uint8_t *payload, size_t payload_len,
                                   EdrAgentUpdateRequest *out,
                                   char *reason, size_t reason_cap);
int edr_agent_update_semver_compare(const char *left, const char *right, int *comparison);
int edr_agent_update_journal_is_terminal(const char *status);
int edr_agent_update_journal_blocks_replacement(const char *stage);
int edr_agent_update_parse_journal(const char *json, EdrAgentUpdateRecovery *out);
int edr_agent_update_execute(const char *command_id, const uint8_t *payload,
                             size_t payload_len, char *detail, size_t detail_cap);
int edr_agent_update_recover(const char *command_id, EdrAgentUpdateRecovery *out);

#ifdef __cplusplus
}
#endif

#endif
