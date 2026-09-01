#include "edr/pe_verify.h"
#include <stdio.h>

static uint16_t read_le16(const uint8_t *data) {
  return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static uint32_t read_le32(const uint8_t *data) {
  return (uint32_t)data[0] |
         ((uint32_t)data[1] << 8) |
         ((uint32_t)data[2] << 16) |
         ((uint32_t)data[3] << 24);
}

static uint64_t read_le64(const uint8_t *data) {
  return (uint64_t)data[0] |
         ((uint64_t)data[1] << 8) |
         ((uint64_t)data[2] << 16) |
         ((uint64_t)data[3] << 24) |
         ((uint64_t)data[4] << 32) |
         ((uint64_t)data[5] << 40) |
         ((uint64_t)data[6] << 48) |
         ((uint64_t)data[7] << 56);
}

int edr_pe_verify(const uint8_t *data, size_t len, char *pe_info, size_t pe_info_len) {
  if (!data || !pe_info || len < 64 || pe_info_len < 16) return 0;

  if (data[0] != 0x4D || data[1] != 0x5A) {
    snprintf(pe_info, pe_info_len, "NOT_PE: missing MZ header");
    return 0;
  }

  size_t pe_offset = (size_t)read_le32(data + 0x3Cu);
  if (pe_offset > len || len - pe_offset < 4u) {
    snprintf(pe_info, pe_info_len, "NOT_PE: e_lfanew out of range");
    return 0;
  }

  if (data[pe_offset] != 0x50 || data[pe_offset + 1] != 0x45 ||
      data[pe_offset + 2] != 0x00 || data[pe_offset + 3] != 0x00) {
    snprintf(pe_info, pe_info_len, "NOT_PE: missing PE\\0\\0 signature");
    return 0;
  }

  size_t coff = pe_offset + 4u;
  if (len - coff < 20u) {
    snprintf(pe_info, pe_info_len, "NOT_PE: COFF header out of range");
    return 0;
  }
  uint16_t machine = read_le16(data + coff);
  uint16_t num_sections = read_le16(data + coff + 2u);
  uint32_t timestamp = read_le32(data + coff + 4u);
  uint16_t opt_hdr_size = read_le16(data + coff + 16u);

  size_t opt = coff + 20u;
  if (opt_hdr_size < sizeof(uint16_t) || (size_t)opt_hdr_size > len - opt) {
    snprintf(pe_info, pe_info_len, "NOT_PE: optional header out of range");
    return 0;
  }
  uint16_t magic = read_le16(data + opt);

  uint32_t entry_point = 0;
  uint64_t image_base = 0;
  uint16_t subsystem = 0;
  const char *pe_kind = "PE32";

  if (magic == 0x20B) {
    pe_kind = "PE64";
    if (opt_hdr_size < 112u) {
      snprintf(pe_info, pe_info_len, "NOT_PE: PE64 optional header too small");
      return 0;
    }
    entry_point = read_le32(data + opt + 16u);
    image_base = read_le64(data + opt + 24u);
    subsystem = read_le16(data + opt + 68u);
  } else if (magic == 0x10B) {
    if (opt_hdr_size < 96u) {
      snprintf(pe_info, pe_info_len, "NOT_PE: PE32 optional header too small");
      return 0;
    }
    entry_point = read_le32(data + opt + 16u);
    image_base = read_le32(data + opt + 28u);
    subsystem = read_le16(data + opt + 44u);
  } else {
    snprintf(pe_info, pe_info_len, "NOT_PE: unsupported optional header magic");
    return 0;
  }

  snprintf(pe_info, pe_info_len,
           "%s Machine=0x%04X Sections=%u EntryPoint=0x%X "
           "ImageBase=0x%llX Subsystem=%u TSD=0x%08X",
           pe_kind, machine, num_sections, entry_point,
           (unsigned long long)image_base, subsystem, timestamp);

  return 1;
}
