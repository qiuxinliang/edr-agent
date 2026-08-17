#include "pmfe_pe_arch.h"

enum {
  EDR_IMAGE_FILE_MACHINE_I386 = 0x014c,
  EDR_IMAGE_FILE_MACHINE_AMD64 = 0x8664,
  EDR_IMAGE_FILE_MACHINE_ARM64EC = 0xa641,
  EDR_IMAGE_FILE_MACHINE_ARM64 = 0xaa64
};

const char *edr_pmfe_pe_machine_arch(uint16_t machine) {
  switch (machine) {
    case EDR_IMAGE_FILE_MACHINE_I386:
      return "x86";
    case EDR_IMAGE_FILE_MACHINE_AMD64:
      /* An x64 process running under ARM64 emulation remains an AMD64 PE. */
      return "x64";
    case EDR_IMAGE_FILE_MACHINE_ARM64EC:
      return "arm64ec";
    case EDR_IMAGE_FILE_MACHINE_ARM64:
      return "arm64";
    default:
      return "other";
  }
}
