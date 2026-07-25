#ifndef EDR_FORENSIC_RESULT_CONTRACT_H
#define EDR_FORENSIC_RESULT_CONTRACT_H

#include "edr/command.h"

#include <stddef.h>

const char *edr_command_normalize_forensic_result(const char *command_type,
                                                  EdrCommandExecutionStatus status,
                                                  int exit_code,
                                                  const char *detail,
                                                  char *out, size_t out_cap);

#endif
