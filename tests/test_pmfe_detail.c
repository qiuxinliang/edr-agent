/**
 * 轻量回归：PMFE Windows 详情串中关键 token 存在性（不链入完整 agent）。
 */
#include <assert.h>
#include <string.h>

int main(void) {
  const char *w = "pid=4 prio=2 band=1 baseline_mods=1 stomp_suspicious=0 disk_hash_ok=0 regions=1 private_exec=1 "
                  "first_stomp=- thread_start=unknown executable_private_page=1 private_page_origin=unknown "
                  "cross_process_write=unknown module_path_consistency=ok module_signature=unknown "
                  "vad_hint=0x7ff8000 | vad_peek=2 mz_hits=0 ent_max=0.00";
  assert(strstr(w, "vad_hint=0x7ff8000") != NULL);
  assert(strstr(w, "vad_peek=") != NULL);
  assert(strstr(w, "thread_start=") != NULL);
  assert(strstr(w, "executable_private_page=") != NULL);
  assert(strstr(w, "cross_process_write=") != NULL);
  assert(strstr(w, "module_path_consistency=") != NULL);
  return 0;
}
