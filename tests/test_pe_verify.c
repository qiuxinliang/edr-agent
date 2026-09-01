#include "edr/pe_verify.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void expect_true(int condition) {
  if (!condition) {
    abort();
  }
}

static void put_le16(uint8_t *out, uint16_t value) {
  out[0] = (uint8_t)(value & 0xffu);
  out[1] = (uint8_t)(value >> 8);
}

static void put_le32(uint8_t *out, uint32_t value) {
  out[0] = (uint8_t)(value & 0xffu);
  out[1] = (uint8_t)((value >> 8) & 0xffu);
  out[2] = (uint8_t)((value >> 16) & 0xffu);
  out[3] = (uint8_t)(value >> 24);
}

static void set_pe_signature(uint8_t *data, size_t pe_offset) {
  data[0] = 'M';
  data[1] = 'Z';
  put_le32(data + 0x3cu, (uint32_t)pe_offset);
  data[pe_offset] = 'P';
  data[pe_offset + 1u] = 'E';
}

static void test_rejects_truncated_coff_header(void) {
  uint8_t data[80];
  char info[128];
  memset(data, 0, sizeof(data));
  set_pe_signature(data, 64u);
  expect_true(edr_pe_verify(data, sizeof(data), info, sizeof(info)) == 0);
  expect_true(strstr(info, "COFF header out of range") != NULL);
}

static void test_rejects_truncated_optional_header(void) {
  uint8_t data[90];
  char info[128];
  memset(data, 0, sizeof(data));
  set_pe_signature(data, 64u);
  put_le16(data + 64u + 4u + 16u, 96u);
  put_le16(data + 64u + 4u + 20u, 0x10bu);
  expect_true(edr_pe_verify(data, sizeof(data), info, sizeof(info)) == 0);
  expect_true(strstr(info, "optional header out of range") != NULL);
}

static void make_minimal_pe32(uint8_t *data) {
  const size_t pe_offset = 64u;
  const size_t coff = pe_offset + 4u;
  const size_t opt = coff + 20u;
  set_pe_signature(data, pe_offset);
  put_le16(data + coff, 0x14cu);
  put_le16(data + coff + 2u, 1u);
  put_le16(data + coff + 16u, 96u);
  put_le16(data + opt, 0x10bu);
  put_le32(data + opt + 16u, 0x1000u);
  put_le32(data + opt + 28u, 0x400000u);
  put_le16(data + opt + 44u, 3u);
}

static void test_accepts_minimal_bounded_pe32(void) {
  uint8_t data[184];
  char info[256];
  memset(data, 0, sizeof(data));
  make_minimal_pe32(data);
  expect_true(edr_pe_verify(data, sizeof(data), info, sizeof(info)) == 1);
  expect_true(strstr(info, "PE32 Machine=0x014C") != NULL);
}

static void test_accepts_misaligned_pe32_buffer(void) {
  uint8_t storage[185];
  char info[256];
  memset(storage, 0, sizeof(storage));
  make_minimal_pe32(storage + 1u);
  expect_true(edr_pe_verify(storage + 1u, sizeof(storage) - 1u, info, sizeof(info)) == 1);
  expect_true(strstr(info, "ImageBase=0x400000") != NULL);
}

static void test_rejects_unknown_optional_header_magic(void) {
  uint8_t data[184];
  char info[128];
  const size_t opt = 64u + 4u + 20u;
  memset(data, 0, sizeof(data));
  make_minimal_pe32(data);
  put_le16(data + opt, 0x107u);
  expect_true(edr_pe_verify(data, sizeof(data), info, sizeof(info)) == 0);
  expect_true(strstr(info, "unsupported optional header magic") != NULL);
}

int main(void) {
  test_rejects_truncated_coff_header();
  test_rejects_truncated_optional_header();
  test_accepts_minimal_bounded_pe32();
  test_accepts_misaligned_pe32_buffer();
  test_rejects_unknown_optional_header_magic();
  return 0;
}
