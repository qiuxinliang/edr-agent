#include "edr/pe_verify.h"
#include <stdio.h>
#include <string.h>

int edr_pe_verify(const uint8_t *data, size_t len, char *pe_info, size_t pe_info_len) {
  if (!data || len < 64 || pe_info_len < 16) return 0;

  if (data[0] != 0x4D || data[1] != 0x5A) {
    snprintf(pe_info, pe_info_len, "NOT_PE: missing MZ header");
    return 0;
  }

  uint32_t pe_offset = *(const uint32_t *)(data + 0x3C);
  if (pe_offset + 4 > len) {
    snprintf(pe_info, pe_info_len, "NOT_PE: e_lfanew out of range");
    return 0;
  }

  if (data[pe_offset] != 0x50 || data[pe_offset + 1] != 0x45 ||
      data[pe_offset + 2] != 0x00 || data[pe_offset + 3] != 0x00) {
    snprintf(pe_info, pe_info_len, "NOT_PE: missing PE\\0\\0 signature");
    return 0;
  }

  uint32_t coff = pe_offset + 4;
  uint16_t machine = *(const uint16_t *)(data + coff);
  uint16_t num_sections = *(const uint16_t *)(data + coff + 2);
  uint32_t timestamp = *(const uint32_t *)(data + coff + 4);
  uint16_t opt_hdr_size = *(const uint16_t *)(data + coff + 16);

  uint32_t opt = coff + 20;
  uint16_t magic = *(const uint16_t *)(data + opt);

  uint32_t entry_point = 0;
  uint64_t image_base = 0;
  uint16_t subsystem = 0;
  const char *pe_kind = "PE32";

  if (magic == 0x20B) {
    pe_kind = "PE64";
    if (opt + 112 <= len) {
      entry_point = *(const uint32_t *)(data + opt + 16);
      image_base = *(const uint64_t *)(data + opt + 24);
      subsystem = *(const uint16_t *)(data + opt + 68);
    }
  } else {
    if (opt + 96 <= len) {
      entry_point = *(const uint32_t *)(data + opt + 16);
      image_base = *(const uint32_t *)(data + opt + 28);
      subsystem = *(const uint16_t *)(data + opt + 44);
    }
  }

  snprintf(pe_info, pe_info_len,
           "%s Machine=0x%04X Sections=%u EntryPoint=0x%X "
           "ImageBase=0x%llX Subsystem=%u TSD=0x%08X",
           pe_kind, machine, num_sections, entry_point,
           (unsigned long long)image_base, subsystem, timestamp);

  return 1;
}
