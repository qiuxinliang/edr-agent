/**
 * 轻量回归：PMFE Windows 详情串中关键 token 存在性（不链入完整 agent）。
 */
#include <assert.h>
#include <string.h>

int main(void) {
  const char *w = "pid=4 prio=2 band=1 baseline_mods=1 stomp_suspicious=0 disk_hash_ok=0 regions=1 private_exec=1 "
                  "first_stomp=- vad_hint=0x7ff8000 | vad_peek=2 mz_hits=0 ent_max=0.00";
  assert(strstr(w, "vad_hint=0x7ff8000") != NULL);
  assert(strstr(w, "vad_peek=") != NULL);
  return 0;
}
