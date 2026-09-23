#ifndef EDR_PMFE_EVIDENCE_H
#define EDR_PMFE_EVIDENCE_H

#include "edr/pmfe.h"
#include <stddef.h>
#include <stdint.h>

/* Structural header evidence only: neither a full-image validation nor proof
 * of malicious execution. Truncated or signature-only samples fail closed. */
int edr_pmfe_image_header_valid(const uint8_t *bytes, size_t length);
int edr_pmfe_windows_private_executable(uint32_t memory_type, uint32_t protection);
void edr_pmfe_region_note_sample(EdrPmfeScanResult *result,
                                  EdrPmfeRegionResult *region,
                                  const uint8_t *bytes, size_t length);
int edr_pmfe_region_note_thread(EdrPmfeScanResult *result,
                                 uint32_t tid, uint64_t address);

#endif
