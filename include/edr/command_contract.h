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

#ifdef __cplusplus
}
#endif

#endif
