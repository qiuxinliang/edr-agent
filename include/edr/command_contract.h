#ifndef EDR_COMMAND_CONTRACT_H
#define EDR_COMMAND_CONTRACT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int edr_command_contract_validate(const char *command_type, const uint8_t *payload,
                                  size_t payload_len, char *reason, size_t reason_cap);
int edr_command_contract_signature_required(const char *command_id, const char *command_type);

/* Exact child lifetime and bounded fields for the existing read-only command.
 * Field bits match EdrParentContextQuery; identity is always returned. */
typedef struct EdrParentContextRequest {
  char endpoint_id[128];
  char source_event_id[96];
  uint32_t child_pid;
  uint64_t child_process_start_key;
  uint64_t child_creation_filetime_100ns;
  int64_t from_ns;
  int64_t until_ns;
  uint32_t fields;
  uint32_t max_bytes;
} EdrParentContextRequest;
int edr_command_parent_context_request_parse(const uint8_t *payload, size_t payload_len,
    EdrParentContextRequest *out, char *reason, size_t reason_cap);

#ifdef __cplusplus
}
#endif

#endif
