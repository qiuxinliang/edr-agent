#include "pmfe_linux_scan_util.h"

#include <string.h>

const char *edr_pmfe_linux_skip_ws(const char *p) {
  while (*p == ' ' || *p == '\t') {
    p++;
  }
  return p;
}

int edr_pmfe_linux_parse_maps_line(const char *line, uint64_t *lo, uint64_t *hi, char perms[5], char *path,
                                   size_t path_cap) {
  unsigned long long a = 0, b = 0;
  if (sscanf(line, "%llx-%llx", &a, &b) != 2) {
    return -1;
  }
  *lo = (uint64_t)a;
  *hi = (uint64_t)b;
  const char *p = strchr(line, '-');
  if (!p) {
    return -1;
  }
  p = strchr(p + 1, ' ');
  if (!p) {
    return -1;
  }
  p = edr_pmfe_linux_skip_ws(p + 1);
  if (sscanf(p, "%4s", perms) != 1) {
    return -1;
  }
  p += strcspn(p, " \t");
  p = edr_pmfe_linux_skip_ws(p);
  /* offset */
  p += strcspn(p, " \t");
  p = edr_pmfe_linux_skip_ws(p);
  /* dev */
  p += strcspn(p, " \t");
  p = edr_pmfe_linux_skip_ws(p);
  /* inode */
  p += strcspn(p, " \t");
  p = edr_pmfe_linux_skip_ws(p);
  path[0] = '\0';
  if (*p && *p != '\n') {
    size_t i = 0;
    while (p[i] && p[i] != '\n' && i + 1u < path_cap) {
      path[i] = p[i];
      i++;
    }
    path[i] = '\0';
  }
  return 0;
}

float edr_pmfe_linux_map_candidate_score(const char *perms, uint64_t lo, uint64_t hi, const char *path,
                                         int anon_exec_only) {
  if (!perms || strlen(perms) < 4u) {
    return 0.f;
  }
  if (perms[2] != 'x' || perms[3] != 'p') {
    return 0.f;
  }
  int anon = (!path || path[0] == '\0' || path[0] == '[');
  if (anon_exec_only && !anon) {
    return 0.f;
  }
  uint64_t sz = hi > lo ? hi - lo : 0u;
  float s = 35.f;
  if (anon) {
    s += 45.f;
  }
  if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
    s += 28.f;
  }
  if (sz >= 4096ull && sz <= 256ull * 1024ull * 1024ull) {
    float add = (float)(sz / (1024ull * 1024ull));
    if (add > 18.f) {
      add = 18.f;
    }
    s += add;
  }
  return s;
}
