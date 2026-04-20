#include "edr/ave.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
  const char *fn = "edr_test_ave_fp.bin";
  FILE *f = fopen(fn, "wb");
  if (!f) {
    return 1;
  }
  (void)fwrite("hello", 1, 5, f);
  fclose(f);
  char hex[40];
  int r = edr_ave_file_fingerprint(fn, hex, sizeof(hex));
  (void)remove(fn);
  return (r == 0 && hex[0]) ? 0 : 1;
}
