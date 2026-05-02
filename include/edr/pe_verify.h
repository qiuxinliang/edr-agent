#ifndef EDR_PE_VERIFY_H
#define EDR_PE_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int edr_pe_verify(const uint8_t *data, size_t len, char *pe_info, size_t pe_info_len);

const char *edr_pe_machine_name(uint16_t machine);

#ifdef __cplusplus
}
#endif

#endif
