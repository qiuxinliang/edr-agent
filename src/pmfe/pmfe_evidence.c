#include "pmfe_evidence.h"
#include <string.h>

static uint16_t read16(const uint8_t *p, int little) {
  return little ? (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8)
                : (uint16_t)((uint16_t)p[1] | (uint16_t)p[0] << 8);
}

static uint32_t read32(const uint8_t *p, int little) {
  return little ? (uint32_t)p[0] | (uint32_t)p[1] << 8 |
                     (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24
                : (uint32_t)p[3] | (uint32_t)p[2] << 8 |
                     (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
}

int edr_pmfe_image_header_valid(const uint8_t *b, size_t n) {
  if (!b || n < 64u) return 0;
  if (b[0] == 'M' && b[1] == 'Z') {
    uint32_t offset = read32(b + 0x3cu, 1);
    if (offset < 64u || (uint64_t)offset + 24u > n ||
        memcmp(b + offset, "PE\0\0", 4u) != 0) return 0;
    const uint8_t *coff = b + offset + 4u;
    uint16_t sections = read16(coff + 2u, 1);
    uint16_t optional_length = read16(coff + 16u, 1);
    if (!read16(coff, 1) || !sections || sections > 96u ||
        optional_length < 96u ||
        (uint64_t)offset + 24u + optional_length + (uint64_t)sections * 40u > n) return 0;
    const uint8_t *optional = coff + 20u;
    uint16_t magic = read16(optional, 1);
    if (magic != 0x10bu && magic != 0x20bu) return 0;
    if (magic == 0x20bu && optional_length < 112u) return 0;
    uint32_t image_size = read32(optional + 56u, 1);
    uint32_t header_size = read32(optional + 60u, 1);
    uint64_t table_end = (uint64_t)offset + 24u + optional_length + (uint64_t)sections * 40u;
    return header_size >= table_end && image_size >= header_size &&
           read32(optional + 16u, 1) < image_size;
  }
  if (memcmp(b, "\177ELF", 4u) == 0) {
    int is64 = b[4] == 2u;
    if ((b[4] != 1u && !is64) || (b[5] != 1u && b[5] != 2u) || b[6] != 1u) return 0;
    int little = b[5] == 1u;
    uint16_t type = read16(b + 16u, little);
    if ((type != 2u && type != 3u) || !read16(b + 18u, little) || read32(b + 20u, little) != 1u) return 0;
    size_t header_size = is64 ? 64u : 52u;
    if (read16(b + (is64 ? 52u : 40u), little) != header_size) return 0;
    uint64_t program_offset = read32(b + 28u, little);
    if (is64) {
      program_offset = little ? ((uint64_t)read32(b + 36u, 1) << 32) | read32(b + 32u, 1)
                              : ((uint64_t)read32(b + 32u, 0) << 32) | read32(b + 36u, 0);
    }
    uint16_t entry_size = read16(b + (is64 ? 54u : 42u), little);
    uint16_t entry_count = read16(b + (is64 ? 56u : 44u), little);
    if (entry_size != (is64 ? 56u : 32u) || !entry_count ||
        program_offset < header_size || program_offset > n) return 0;
    return (uint64_t)entry_size * entry_count <= (uint64_t)n - program_offset;
  }
  return 0;
}

int edr_pmfe_windows_private_executable(uint32_t type, uint32_t protection) {
  const uint32_t access = protection & 0xffu;
  return type == 0x20000u && !(protection & 0x100u) &&
         (access == 0x10u || access == 0x20u || access == 0x40u || access == 0x80u);
}

void edr_pmfe_region_note_sample(EdrPmfeScanResult *result,
                                  EdrPmfeRegionResult *region,
                                  const uint8_t *bytes, size_t length) {
  if (!result || !region) return;
  region->image_header_valid = (uint8_t)edr_pmfe_image_header_valid(bytes, length);
  if (region->private_executable && region->image_header_valid) {
    result->private_exec_image_hits++;
  }
}

int edr_pmfe_region_note_thread(EdrPmfeScanResult *result,
                                 uint32_t tid, uint64_t address) {
  if (!result || !address) return 0;
  for (uint8_t i = 0; i < result->region_count; ++i) {
    EdrPmfeRegionResult *region = &result->regions[i];
    if (address < region->base || address - region->base >= region->size_bytes) continue;
    if (region->thread_start_count < EDR_PMFE_MAX_THREAD_STARTS) {
      EdrPmfeThreadStart *start = &region->thread_starts[region->thread_start_count++];
      start->tid = tid;
      start->start_address = address;
    }
    result->thread_start_matches++;
    if (region->private_executable) {
      result->private_exec_thread_starts++;
      if (region->score < 0.92f) region->score = 0.92f;
    }
    if (!strstr(region->reason, "thread_start")) {
      strncat(region->reason, ",thread_start", sizeof(region->reason) - strlen(region->reason) - 1u);
    }
    return 1;
  }
  return 0;
}
