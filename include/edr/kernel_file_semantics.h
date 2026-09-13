#ifndef EDR_KERNEL_FILE_SEMANTICS_H
#define EDR_KERNEL_FILE_SEMANTICS_H

#include <stdint.h>

/* Pure descriptor boundary shared by the Windows collector and its native
 * fixture. Kernel File/Create (12) is an open-or-create request used for
 * object lifetime tracking; only CreateNewFile (30) is emitted as create. */
static inline int edr_kernel_file_descriptor_is_create_new(
    uint16_t event_id, uint16_t task, uint8_t opcode, uint8_t version,
    uint64_t keywords) {
  return event_id == 30u && task == 30u && opcode == 0u && version <= 1u &&
         (keywords & UINT64_C(0x1000)) == UINT64_C(0x1000);
}

#endif
