/* P0 IR：非 process_create 时与 p0_golden_vectors.json 子集对拍（需 PCRE2 + 可解析 IR JSON）。 */
#include "edr/behavior_record.h"
#include "edr/p0_rule_ir.h"
#include "edr/types.h"

#include <stdio.h>
#include <string.h>

static int find_rule_index(const char *want_id) {
  int n = edr_p0_rule_ir_rule_count();
  int i;
  for (i = 0; i < n; i++) {
    const char *id = NULL;
    if (edr_p0_rule_ir_rule_id_at(i, &id) && id && strcmp(id, want_id) == 0) {
      return i;
    }
  }
  return -1;
}

static int check_br(const char *ctx, EdrBehaviorRecord *br, int idx, int want) {
  int g = edr_p0_rule_ir_br_matches_index(br, idx) ? 1 : 0;
  if (g != want) {
    fprintf(
        stderr, "[p0_ir_record] fail %s: want br_matches_index=%d got %d (rule index %d)\n", ctx, want,
        g, idx
    );
    return 0;
  }
  return 1;
}

int main(void) {
  edr_p0_rule_ir_lazy_init();
  if (!edr_p0_rule_ir_is_ready()) {
    fprintf(
        stderr,
        "[p0_ir_record] IR not loaded (need PCRE2 build + p0_rule_bundle_ir_v1.json / EDR_P0_IR_PATH)\n"
    );
    return 1;
  }
  int i_cred3 = find_rule_index("R-CRED-003");
  int i_web = find_rule_index("R-WEBSHELL-001");
  int i_lmove = find_rule_index("R-LMOVE-001");
  int i_def = find_rule_index("R-DEFENSE-001");
  if (i_cred3 < 0 || i_web < 0 || i_lmove < 0 || i_def < 0) {
    fprintf(stderr, "[p0_ir_record] missing expected rule in bundle (indices)\n");
    return 1;
  }
  EdrBehaviorRecord br;
  edr_behavior_record_init(&br);

  /* R-CRED-003 file_read */
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_FILE_READ;
  snprintf(
      br.file_path, sizeof(br.file_path), "%s",
      "C:\\Users\\x\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
  );
  if (!check_br("CRED-003 hit", &br, i_cred3, 1)) {
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_FILE_READ;
  snprintf(br.file_path, sizeof(br.file_path), "%s", "C:\\safe\\notes.txt");
  if (!check_br("CRED-003 miss", &br, i_cred3, 0)) {
    return 1;
  }

  /* R-WEBSHELL-001 file_write */
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_FILE_WRITE;
  snprintf(br.process_name, sizeof(br.process_name), "w3wp.exe");
  snprintf(br.file_path, sizeof(br.file_path), "%s", "C:\\inetpub\\wwwroot\\x\\shell.aspx");
  if (!check_br("WEBSHELL-001 hit", &br, i_web, 1)) {
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_FILE_WRITE;
  snprintf(br.process_name, sizeof(br.process_name), "w3wp.exe");
  snprintf(br.file_path, sizeof(br.file_path), "%s", "C:\\inetpub\\wwwroot\\x\\data.txt");
  if (!check_br("WEBSHELL-001 miss", &br, i_web, 0)) {
    return 1;
  }

  /* R-LMOVE-001 network_connect */
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_NET_CONNECT;
  br.net_dport = 445u;
  if (!check_br("LMOVE-001 hit", &br, i_lmove, 1)) {
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_NET_CONNECT;
  br.net_dport = 80u;
  if (!check_br("LMOVE-001 miss", &br, i_lmove, 0)) {
    return 1;
  }

  /* R-DEFENSE-001 registry_set */
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_REG_SET_VALUE;
  snprintf(
      br.reg_key_path, sizeof(br.reg_key_path), "%s",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
  );
  snprintf(br.reg_value_name, sizeof(br.reg_value_name), "EnableLUA");
  snprintf(br.reg_value_data, sizeof(br.reg_value_data), "0");
  if (!check_br("DEFENSE-001 hit", &br, i_def, 1)) {
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_REG_SET_VALUE;
  snprintf(
      br.reg_key_path, sizeof(br.reg_key_path), "%s",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
  );
  snprintf(br.reg_value_name, sizeof(br.reg_value_name), "EnableLUA");
  snprintf(br.reg_value_data, sizeof(br.reg_value_data), "1");
  if (!check_br("DEFENSE-001 miss", &br, i_def, 0)) {
    return 1;
  }

  fprintf(
      stderr,
      "[p0_ir_record] ok (file_read / file_write / network_connect / registry_set; see network_aux_path for "
      "net+path 规则)\n"
  );
  return 0;
}
