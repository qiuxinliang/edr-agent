#include "edr/file_key_lifetime.h"
#include <assert.h>
#include <stdio.h>

static void test_newer_closed_name_cannot_revive_old_path(void) {
  const uint64_t names[2][2] = {{100, 300}, {300, 100}};
  const uint64_t ends[2][2] = {{0, 400}, {400, 0}};
  for (unsigned order = 0u; order < 2u; ++order) {
    uint64_t selected = 0u;
    int resolved = 0;
    for (unsigned i = 0u; i < 2u; ++i) {
      if (!edr_file_key_lifetime_is_newer(names[order][i], 450, selected)) continue;
      selected = names[order][i];
      resolved = edr_file_key_lifetime_contains(selected, ends[order][i], 450);
    }
    assert(selected == 300 && !resolved);
  }
  assert(!edr_file_key_lifetime_is_newer(0, 450, 0));
  assert(!edr_file_key_lifetime_is_newer(500, 450, 100));
  assert(!edr_file_key_lifetime_is_newer(100, 450, 300));
  assert(edr_file_key_lifetime_is_newer(100, 150, 0));
  assert(edr_file_key_lifetime_end(100, 0, 300) == 300);
  assert(edr_file_key_lifetime_end(100, 200, 300) == 200);
  assert(edr_file_key_lifetime_end(100, 400, 300) == 300);
  assert(edr_file_key_lifetime_end(300, 0, 100) == 0);
  assert(edr_file_key_lifetime_end(100, 0, 100) == 0);
  /* Even after B's history expires, A remains closed and expires as well. */
  assert(!edr_file_key_lifetime_contains(100, edr_file_key_lifetime_end(100, 0, 300), 900));
  assert(edr_file_key_lifetime_expired(edr_file_key_lifetime_end(100, 0, 300), 900, 500));
}

int main(void) {
  test_newer_closed_name_cannot_revive_old_path();
  const uint64_t minute = 60ULL * 1000000000ULL;
  /* An open name, including another handle still using it after a Close,
   * remains valid well past the old five-minute absolute TTL. */
  assert(edr_file_key_lifetime_contains(1, 0, 60 * minute));
  assert(!edr_file_key_lifetime_expired(0, 60 * minute, 5 * minute));
  /* Late decode may resolve a Read before NameDelete, never at/after it. */
  assert(edr_file_key_lifetime_contains(100, 200, 199));
  assert(!edr_file_key_lifetime_contains(100, 200, 200));
  assert(!edr_file_key_lifetime_contains(100, 200, 201));
  assert(!edr_file_key_lifetime_contains(100, 0, 99));
  assert(!edr_file_key_lifetime_contains(0, 0, 100));
  /* Reused keys need the matching interval, not the newer path. */
  assert(!edr_file_key_lifetime_contains(300, 0, 150));
  assert(edr_file_key_lifetime_contains(300, 0, 301));
  assert(!edr_file_key_lifetime_contains(100, 200, 301));
  assert(!edr_file_key_lifetime_expired(200, 199, 5 * minute));
  assert(!edr_file_key_lifetime_expired(200, 200 + 5 * minute, 5 * minute));
  assert(edr_file_key_lifetime_expired(200, 201 + 5 * minute, 5 * minute));
  puts("FileKey lifetime contracts passed");
  return 0;
}
