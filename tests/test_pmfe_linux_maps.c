/* Linux-only：maps 解析与候选打分纯逻辑测试（不访问 /proc） */

#if !defined(__linux__)
int main(void) { return 0; }
#else

#include "pmfe_linux_scan_util.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  uint64_t lo = 0, hi = 0;
  char perms[5];
  char path[512];

  {
    const char *line = "7f8a2c000000-7f8a2c200000 r-xp 00000000 fd:01 12345 /usr/bin/bash\n";
    assert(edr_pmfe_linux_parse_maps_line(line, &lo, &hi, perms, path, sizeof(path)) == 0);
    assert(lo == 0x7f8a2c000000ull);
    assert(hi == 0x7f8a2c200000ull);
    assert(strcmp(perms, "r-xp") == 0);
    assert(strcmp(path, "/usr/bin/bash") == 0);
    float s = edr_pmfe_linux_map_candidate_score(perms, lo, hi, path, 0);
    assert(s >= 20.f);
    assert(edr_pmfe_linux_map_candidate_score(perms, lo, hi, path, 1) == 0.f);
  }

  {
    const char *line = "7f1234000000-7f1234100000 rwxp 00000000 00:00 0\n";
    assert(edr_pmfe_linux_parse_maps_line(line, &lo, &hi, perms, path, sizeof(path)) == 0);
    assert(path[0] == '\0');
    float s = edr_pmfe_linux_map_candidate_score(perms, lo, hi, path, 0);
    assert(s >= 20.f);
    assert(edr_pmfe_linux_map_candidate_score(perms, lo, hi, path, 1) >= 20.f);
  }

  {
    const char *line = "ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0 [vdso]\n";
    assert(edr_pmfe_linux_parse_maps_line(line, &lo, &hi, perms, path, sizeof(path)) == 0);
    assert(strncmp(path, "[vdso]", 6u) == 0);
    assert(edr_pmfe_linux_map_candidate_score(perms, lo, hi, path, 1) >= 20.f);
  }

  fprintf(stderr, "test_pmfe_linux_maps ok\n");
  return 0;
}

#endif
