#include "pmfe_linux_scan_util.h"

#include <assert.h>
#include <string.h>

int main(void) {
  uint64_t lo = 0, hi = 0;
  char perms[5] = {0};
  char path[256];

  assert(edr_pmfe_linux_parse_maps_line(
             "7f100000-7f110000 rwxp 00000000 00:01 42 /memfd:stage (deleted)\n",
             &lo, &hi, perms, path, sizeof(path)) == 0);
  assert(lo == 0x7f100000ull && hi == 0x7f110000ull);
  assert(strcmp(perms, "rwxp") == 0);
  assert(edr_pmfe_linux_path_is_memfd(path));
  assert(edr_pmfe_linux_path_is_deleted(path));
  assert(edr_pmfe_linux_map_candidate_score(perms, lo, hi, path, 1) > 100.f);

  assert(edr_pmfe_linux_map_candidate_score("r-xp", lo, hi, "/usr/bin/bash", 1) == 0.f);
  assert(edr_pmfe_linux_map_candidate_score("r-xp", lo, hi, "/tmp/payload (deleted)", 1) > 80.f);
  return 0;
}
