#include "edr/file_key_lifetime.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
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
