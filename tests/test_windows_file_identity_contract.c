#include "edr/windows_file_identity.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char k_file_a[] =
    "win-fileid-v1:0000000000000001:0123456789abcdef0123456789abcdef";
static const char k_file_b[] =
    "win-fileid-v1:0000000000000002:fedcba9876543210fedcba9876543210";

static void test_lossless_format_and_xor_collision_pair(void) {
  /* The old value was `(volume_serial << 32) ^ file_index`. These different
   * (volume,index) pairs collide at 0x1111222233334444, so neither legacy
   * string may cross an authoritative P0 boundary. */
  const uint32_t volume_a = UINT32_C(0x11112222);
  const uint32_t volume_b = UINT32_C(0x11112223);
  const uint64_t index_a = UINT64_C(0x0000000033334444);
  const uint64_t index_b = UINT64_C(0x0000000133334444);
  const char legacy_a[] = "1111222333334444";
  const char legacy_b[] = "1111222333334444";
  assert(volume_a != volume_b && index_a != index_b);
  assert((((uint64_t)volume_a << 32u) ^ index_a) ==
         (((uint64_t)volume_b << 32u) ^ index_b));
  assert(edr_windows_file_identity_valid(k_file_a));
  assert(edr_windows_file_identity_valid(k_file_b));
  assert(strcmp(k_file_a, k_file_b) != 0);
  assert(!edr_windows_file_identity_valid(legacy_a));
  assert(!edr_windows_file_identity_valid(legacy_b));
  assert(!edr_windows_file_identity_valid(
      "win-fileid-v1:0000000000000001:0123456789ABCDEF0123456789abcdef"));
}

static void test_path_snapshot_race_rejection(void) {
  const uint64_t a_write_time = UINT64_C(133700000000000000);
  const uint64_t b_write_time = UINT64_C(133700000000000001);
  /* A captured -> pathname B, and B -> A reversion, both fail before an
   * evidence result can publish. A modified file whose write time differs
   * also fails; the Windows held-handle test covers a writer attempting to
   * restore the original FILETIME while the owner is live. */
  assert(edr_windows_file_identity_snapshot_matches(k_file_a, a_write_time,
                                                     k_file_a, a_write_time));
  assert(!edr_windows_file_identity_snapshot_matches(k_file_a, a_write_time,
                                                      k_file_b, b_write_time));
  assert(!edr_windows_file_identity_snapshot_matches(k_file_a, a_write_time,
                                                      k_file_a, b_write_time));
  assert(!edr_windows_file_identity_snapshot_matches(k_file_a, a_write_time,
                                                      "", a_write_time));
}

int main(void) {
  test_lossless_format_and_xor_collision_pair();
  test_path_snapshot_race_rejection();
  puts("windows file identity contract: ok");
  return 0;
}
