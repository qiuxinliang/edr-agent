/* §A shellcode YARA 规则：bundled 规则可加载（有 YARA 时），且已知漏洞可命中。
 * 规则目录路径由 CMake 经 EDR_SHELLCODE_RULES_DIR 传入。无 YARA 时验证内置匹配器回退。 */

#include "edr/shellcode_known.h"
#include "edr/proto_parse.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef EDR_SHELLCODE_RULES_DIR
#define EDR_SHELLCODE_RULES_DIR ""
#endif

static int fail(const char *msg) {
  fprintf(stderr, "fail: %s\n", msg);
  return 1;
}

int main(void) {
  const char *rules_dir = EDR_SHELLCODE_RULES_DIR;
  int rc = edr_shellcode_known_init(rules_dir);
  if (rc < 0) {
    return fail("shellcode_known_init returned error");
  }

  EdrShellcodeRulesStatus st;
  memset(&st, 0, sizeof(st));
  edr_shellcode_known_get_status(&st);

#ifdef EDR_HAVE_YARA
  /* 有 YARA 且目录非空：应加载到规则、source=yara、覆盖家族数 >= 4。 */
  if (rules_dir[0]) {
    if (st.yara_enabled != 1) {
      return fail("yara should be enabled when rules dir provided");
    }
    if (strcmp(st.source, "yara") != 0) {
      fprintf(stderr, "note: source=%s files_loaded=%u err=%s\n", st.source, st.files_loaded, st.last_error);
      return fail("expected yara source after loading bundled rules");
    }
    if (st.files_loaded < 1u) {
      return fail("expected >=1 yara rule file loaded");
    }
  }
#endif

  /* EternalBlue DoublePulsar 内核 ping 特征：YARA 命中或内置匹配器回退都应识别。 */
  uint8_t buf[64];
  memset(buf, 0, sizeof(buf));
  buf[0] = 0x81;
  buf[1] = 0xF1;
  buf[2] = 0x13;
  buf[3] = 0x00;
  buf[4] = 0x00;
  buf[5] = 0x00;
  buf[6] = 0x49; /* kDoublePulsar 序列 */
  char rule[96];
  rule[0] = '\0';
  int hit = edr_shellcode_match_known_exploit(buf, (uint32_t)sizeof(buf), EDR_PROTO_KIND_SMB1, rule, sizeof(rule));
  if (!hit || rule[0] == '\0') {
    return fail("EternalBlue doublepulsar pattern should match (yara or builtin)");
  }
  printf("ok: shellcode known-exploit match rule=%s source=%s files=%u\n", rule, st.source, st.files_loaded);

  edr_shellcode_known_shutdown();
  return 0;
}
