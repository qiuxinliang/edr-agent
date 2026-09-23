#include "pmfe_evidence.h"
#include <assert.h>
#include <string.h>

static void put16(uint8_t *p, uint16_t value) {
  p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8);
}
static void put32(uint8_t *p, uint32_t value) {
  put16(p, (uint16_t)value); put16(p + 2, (uint16_t)(value >> 16));
}

static void valid_pe(uint8_t *bytes, uint16_t machine, int is64) {
  memset(bytes, 0, 512u);
  memcpy(bytes, "MZ", 2u);
  put32(bytes + 0x3cu, 0x80u);
  memcpy(bytes + 0x80u, "PE\0\0", 4u);
  put16(bytes + 0x84u, machine);
  put16(bytes + 0x86u, 1u);
  put16(bytes + 0x94u, is64 ? 240u : 224u);
  put16(bytes + 0x98u, is64 ? 0x20bu : 0x10bu);
  put32(bytes + 0x98u + 16u, 0x1000u);
  put32(bytes + 0x98u + 56u, 0x2000u);
  put32(bytes + 0x98u + 60u, 0x200u);
}

int main(void) {
  uint8_t pe[512];
  valid_pe(pe, 0x8664u, 1);
  assert(edr_pmfe_image_header_valid(pe, sizeof(pe)));
  assert(!edr_pmfe_image_header_valid(pe, 128u));
  assert(!edr_pmfe_image_header_valid(pe, 300u));
  valid_pe(pe, 0x014cu, 0);
  assert(edr_pmfe_image_header_valid(pe, sizeof(pe)));
  valid_pe(pe, 0xaa64u, 1);
  assert(edr_pmfe_image_header_valid(pe, sizeof(pe)));
  pe[0x80u] = 'X';
  assert(!edr_pmfe_image_header_valid(pe, sizeof(pe)));
  put32(pe + 0x3cu, UINT32_MAX);
  assert(!edr_pmfe_image_header_valid(pe, sizeof(pe)));
  memset(pe, 0, sizeof(pe)); memcpy(pe, "MZ", 2u);
  assert(!edr_pmfe_image_header_valid(pe, sizeof(pe)));

  uint8_t elf[128] = {0};
  memcpy(elf, "\177ELF", 4u); elf[4] = 2; elf[5] = 1; elf[6] = 1;
  put16(elf + 16u, 3u); put16(elf + 18u, 0x3eu); put32(elf + 20u, 1u);
  put32(elf + 32u, 64u); put16(elf + 52u, 64u);
  put16(elf + 54u, 56u); put16(elf + 56u, 1u);
  assert(edr_pmfe_image_header_valid(elf, sizeof(elf)));
  assert(!edr_pmfe_image_header_valid(elf, 64u));
  elf[5] = 0;
  assert(!edr_pmfe_image_header_valid(elf, sizeof(elf)));

  assert(edr_pmfe_windows_private_executable(0x20000u, 0x20u));
  assert(!edr_pmfe_windows_private_executable(0x1000000u, 0x20u));
  assert(!edr_pmfe_windows_private_executable(0x20000u, 0x120u));
  assert(!edr_pmfe_windows_private_executable(0x20000u, 0x04u));

  EdrPmfeScanResult result;
  memset(&result, 0, sizeof(result));
  result.region_count = 2u; result.private_exec = 1u;
  EdrPmfeRegionResult *jit = &result.regions[0], *module = &result.regions[1];
  jit->base = 0x1000u; jit->size_bytes = 0x1000u; jit->private_executable = 1u;
  module->base = 0x4000u; module->size_bytes = 0x1000u;
  valid_pe(pe, 0x8664u, 1);
  edr_pmfe_region_note_sample(&result, module, pe, sizeof(pe));
  assert(module->image_header_valid && result.private_exec_image_hits == 0u);
  /* A separate JIT region cannot borrow a normal image's PE or thread. */
  assert(edr_pmfe_region_note_thread(&result, 1u, 0x4100u));
  assert(result.thread_start_matches == 1u && result.private_exec_thread_starts == 0u);
  assert(module->score == 0.0f);
  assert(!edr_pmfe_region_note_thread(&result, 2u, 0x5000u));
  assert(edr_pmfe_region_note_thread(&result, 3u, 0x1100u));
  assert(result.private_exec_thread_starts == 1u);
  edr_pmfe_region_note_sample(&result, jit, pe, sizeof(pe));
  assert(result.private_exec_image_hits == 1u);
  jit->base = UINT64_MAX - 15u; jit->size_bytes = 16u;
  assert(edr_pmfe_region_note_thread(&result, 4u, UINT64_MAX));
  assert(!edr_pmfe_region_note_thread(&result, 5u, 1u));
  assert(edr_pmfe_evidence_score(0, 0, 0, 0, 0, 0, 0, 0, 0) == 0.f);
  assert(edr_pmfe_evidence_score(0, 0, 0, 0, 1, 0, 0, 0, 0) == 0.90f);
  assert(edr_pmfe_evidence_score(0, 0, 0, 0, 0, 1, 0, 0, 0) == 0.92f);
  assert(edr_pmfe_evidence_score(0, 0, 0, 0, 0, 0, 1, 0, 0) == 0.94f);
  return 0;
}
