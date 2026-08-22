#ifndef EDR_COMMAND_SIGNATURE_H
#define EDR_COMMAND_SIGNATURE_H

#include <stddef.h>
#include <stdint.h>
#include "edr/command.h"

typedef struct {
  int required;
} CommandSignaturePolicy;

int edr_command_signature_verify(const char *cmd_id, const char *cmd_type,
                                 const uint8_t *payload, size_t payload_len,
                                 const EdrSoarCommandMeta *sm,
                                 const CommandSignaturePolicy *policy,
                                 char *reason, size_t reason_cap);

#endif
