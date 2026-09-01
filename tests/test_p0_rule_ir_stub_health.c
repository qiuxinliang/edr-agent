#include "edr/p0_rule_ir.h"

#include <stdio.h>
#include <string.h>

int main(void) {
  char reason[64];
  char one_byte[1] = {'x'};

  if (edr_p0_rule_ir_is_ready() != 0) {
    fprintf(stderr, "non-production P0 IR stub unexpectedly reports ready\n");
    return 1;
  }
  if (edr_p0_rule_ir_artifact_healthy(reason, sizeof(reason)) != 0) {
    fprintf(stderr, "non-production P0 IR stub unexpectedly reports healthy\n");
    return 1;
  }
  if (strcmp(reason, "p0_rule_ir_unavailable_nonproduction_stub") != 0) {
    fprintf(stderr, "unexpected non-production P0 IR stub reason: %s\n", reason);
    return 1;
  }
  if (edr_p0_rule_ir_artifact_healthy(one_byte, sizeof(one_byte)) != 0 ||
      one_byte[0] != '\0') {
    fprintf(stderr, "non-production P0 IR stub reason truncation contract failed\n");
    return 1;
  }
  return 0;
}
