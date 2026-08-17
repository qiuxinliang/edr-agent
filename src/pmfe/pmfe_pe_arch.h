#ifndef EDR_PMFE_PE_ARCH_H
#define EDR_PMFE_PE_ARCH_H

#include <stdint.h>

/* Returns the architecture encoded in the PE COFF Machine field. */
const char *edr_pmfe_pe_machine_arch(uint16_t machine);

#endif
