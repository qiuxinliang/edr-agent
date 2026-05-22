#include "edr/config.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
  const char *fn = "edr_test_cfg_fp.toml";
  FILE *f = fopen(fn, "wb");
  if (!f) {
    return 1;
  }
  fprintf(f, "[agent]\nendpoint_id = \"t\"\n");
  fclose(f);
  char fp[80];
  edr_config_fingerprint(fn, fp, sizeof(fp));
  (void)remove(fn);
  return fp[0] ? 0 : 1;
}
