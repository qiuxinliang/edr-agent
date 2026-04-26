/* 与 p0_golden_vectors_data.inc + p0_golden_vectors.json 对拍；失败时 exit 1。 */
#include "edr/p0_rule_match.h"

#include <stdio.h>
#include <stdlib.h>

#include "p0_golden_vectors_data.inc"

int main(void) {
  for (int i = 0; i < P0_GOLDEN_N; i++) {
    int got = edr_p0_rule_matches(p0_golden_rule_id[i], p0_golden_process_name[i], p0_golden_cmdline[i]);
    if (got != p0_golden_expect[i]) {
      fprintf(stderr,
              "[p0_golden] fail i=%d rule=%s expect=%d got=%d pn=%s cmd=%s\n",
              i, p0_golden_rule_id[i], p0_golden_expect[i], got, p0_golden_process_name[i],
              p0_golden_cmdline[i]);
      return 1;
    }
  }
  fprintf(stderr, "[p0_golden] ok %d cases\n", P0_GOLDEN_N);
  return 0;
}
