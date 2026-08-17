#include "pmfe_pe_arch.h"

#include <assert.h>
#include <string.h>

int main(void) {
  assert(strcmp(edr_pmfe_pe_machine_arch(0x014c), "x86") == 0);
  assert(strcmp(edr_pmfe_pe_machine_arch(0x8664), "x64") == 0);
  assert(strcmp(edr_pmfe_pe_machine_arch(0xa641), "arm64ec") == 0);
  assert(strcmp(edr_pmfe_pe_machine_arch(0xaa64), "arm64") == 0);
  assert(strcmp(edr_pmfe_pe_machine_arch(0xffff), "other") == 0);
  return 0;
}
