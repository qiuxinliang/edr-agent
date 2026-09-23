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
  int i_net = find_rule_index("R-NET-001");
  int i_lmove015 = find_rule_index("R-LMOVE-015");
  int i_def = find_rule_index("R-DEFENSE-001");
  int i_def4 = find_rule_index("R-DEFENSE-004");
  int i_t1138 = find_rule_index("R-MITRE-WIN-T1138");
  int i_lolbin10 = find_rule_index("R-LOLBIN-010");
  int i_exec3 = find_rule_index("R-EXEC-003");
  int i_anom = find_rule_index("R-ANOM-001");
  if (i_cred3 < 0 || i_web < 0 || i_lmove < 0 || i_net < 0 || i_lmove015 < 0 || i_def < 0 || i_def4 < 0 ||
      i_t1138 < 0 || i_lolbin10 < 0 || i_exec3 < 0 || i_anom < 0) {
    fprintf(stderr, "[p0_ir_record] missing expected rule in bundle (indices)\n");
    return 1;
  }
  EdrBehaviorRecord br;
  uint64_t path_projection_epoch = 0u;
  uint64_t reloaded_path_projection_epoch = 0u;
  edr_behavior_record_init(&br);

  /* Kernel-File NameCreate sees a path before reliable process identity.  Its
   * projection must retain every file_read P0 path while safely proving an
   * unrelated path ordinary; it intentionally ignores later process/user
   * predicates. */
  if (!edr_p0_rule_ir_file_read_path_may_match(
          "C:\\Users\\x\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
          &path_projection_epoch) ||
      !edr_p0_rule_ir_file_read_path_may_match("C:\\ntds.dit", NULL) ||
      !edr_p0_rule_ir_file_read_path_may_match("C:\\Google\\Chrome\\ \\Cookies", NULL) ||
      !edr_p0_rule_ir_file_read_path_may_match("C:\\Windows\\System32\\config\\SAM", NULL) ||
      !edr_p0_rule_ir_file_read_path_may_match("C:\\Users\\x\\.aws\\credentials", NULL) ||
      edr_p0_rule_ir_file_read_path_may_match("C:\\safe\\ordinary.txt", NULL) ||
      path_projection_epoch == 0u) {
    fprintf(stderr, "[p0_ir_record] FileRead path projection violated\n");
    return 1;
  }
  edr_p0_rule_ir_reload();
  if (!edr_p0_rule_ir_file_read_path_may_match(
          "C:\\Users\\x\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
          &reloaded_path_projection_epoch) ||
      reloaded_path_projection_epoch <= path_projection_epoch) {
    fprintf(stderr, "[p0_ir_record] FileRead path projection did not bind a new IR epoch\n");
    return 1;
  }

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

  /* Linux inotify maps file modifications to priority=1 FILE_WRITE records.
   * Under resource pressure the preprocess gate must retain a real IR hit,
   * rather than returning before P0 evaluation.  R-PERSIST-008 is path-only
   * and therefore a valid inotify-style positive case. */
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_FILE_WRITE;
  snprintf(br.file_path, sizeof(br.file_path), "%s",
           "C:\\Users\\x\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\dropper.ps1");
  if (!edr_p0_rule_ir_br_matches_any(&br)) {
    fprintf(stderr, "[p0_ir_record] Linux inotify-style startup write must remain a P0 candidate under pressure\n");
    return 1;
  }

  /* The pressure gate runs after enrichment: parent and chain fields may turn
   * an otherwise raw-looking ProcessCreate into a P0 positive. */
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_PROCESS_CREATE;
  snprintf(br.process_name, sizeof(br.process_name), "cmd.exe");
  snprintf(br.parent_name, sizeof(br.parent_name), "winword.exe");
  if (!check_br("EXEC-003 enriched parent hit", &br, i_exec3, 1) ||
      !edr_p0_rule_ir_br_matches_any(&br)) {
    fprintf(stderr, "[p0_ir_record] enriched parent must not be pressure-shed\n");
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_PROCESS_CREATE;
  br.process_chain_depth = 81u;
  if (!check_br("ANOM-001 enriched chain hit", &br, i_anom, 1) ||
      !edr_p0_rule_ir_br_matches_any(&br)) {
    fprintf(stderr, "[p0_ir_record] enriched chain must not be pressure-shed\n");
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_FILE_WRITE;
  snprintf(br.file_path, sizeof(br.file_path), "C:\\safe\\ordinary.txt");
  if (edr_p0_rule_ir_br_matches_any(&br)) {
    fprintf(stderr, "[p0_ir_record] ordinary pressure record must remain a proven IR miss\n");
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

  /* Network rules combine their process predicate and port predicate. A
   * benign executable at the same port must not inherit a tunnelling or data
   * service rule solely from that port. */
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_NET_CONNECT;
  br.net_dport = 1080u;
  snprintf(br.process_name, sizeof(br.process_name), "chisel.exe");
  if (!check_br("NET-001 named tool hit", &br, i_net, 1)) {
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_NET_CONNECT;
  br.net_dport = 1080u;
  snprintf(br.process_name, sizeof(br.process_name), "svchost.exe");
  if (!check_br("NET-001 ordinary process miss", &br, i_net, 0)) {
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_NET_CONNECT;
  br.net_dport = 1433u;
  snprintf(br.process_name, sizeof(br.process_name), "sqlcmd.exe");
  if (!check_br("LMOVE-015 named tool hit", &br, i_lmove015, 1)) {
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_NET_CONNECT;
  br.net_dport = 1433u;
  snprintf(br.process_name, sizeof(br.process_name), "svchost.exe");
  if (!check_br("LMOVE-015 ordinary process miss", &br, i_lmove015, 0)) {
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
  {
    const struct { const char *data; int want; } cases[] = {
      {"0",1},{"000",1},{"0x00000000",1},{"0 (0x00000000)",1},
      {" \t0 (0X00000000)\r\n",1},{"1 (0x00000001)",0},{"4294967296",0},
      {"0x100000000",0},{"0 (0x00000001)",0},{"1 (0x00000000)",0},
      {"0 (0x100000000)",0},{"0 garbage",0},{"0x",0},{"-0",0},{"+0",0},
      {"",0},{"0x0 (0x0)",0},{"0(0x0)",0},{"1.0",0},{"0 (0x0) tail",0}
    };
    for (size_t i=0; i<sizeof(cases)/sizeof(cases[0]); ++i) {
      snprintf(br.reg_value_data,sizeof(br.reg_value_data),"%s",cases[i].data);
      if (!check_br(cases[i].data,&br,i_def,cases[i].want)) return 1;
    }
  }
  {
    const struct { const char *path; const char *name; const char *data; int want; } cases[] = {
      {"HKLM\\SYSTEM\\CurrentControlSet\\Services\\MpsSvc","Start","4 (0x00000004)",1},
      {"HKLM\\SYSTEM\\CurrentControlSet\\Services\\MpsSvc","Start","2",0},
      {"HKLM\\SYSTEM\\CurrentControlSet\\Services\\MpsSvc ","Start","4",0},
      {"HKLM\\SYSTEM\\CurrentControlSet\\Services\\MpsSvc","EnableFirewall","0",0},
      {"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile","EnableFirewall","0x00000000",1},
      {"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile","Start","4",0},
      {"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender","DisableAntiSpyware","1 (0x00000001)",1},
      {"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender","DisableAntiSpyware","0",0},
      {"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender","Start","4",0},
      {"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection","DisableRealtimeMonitoring","1",1},
      {"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection","DisableRealtimeMonitoring","0",0}
    };
    for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
      snprintf(br.reg_key_path,sizeof(br.reg_key_path),"%s",cases[i].path);
      snprintf(br.reg_value_name,sizeof(br.reg_value_name),"%s",cases[i].name);
      snprintf(br.reg_value_data,sizeof(br.reg_value_data),"%s",cases[i].data);
      if (!check_br(cases[i].path,&br,i_def4,cases[i].want)) return 1;
    }
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_REG_DELETE_KEY;
  snprintf(
      br.reg_key_path, sizeof(br.reg_key_path), "%s",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
  );
  snprintf(br.reg_value_name, sizeof(br.reg_value_name), "EnableLUA");
  snprintf(br.reg_value_data, sizeof(br.reg_value_data), "0");
  snprintf(br.reg_op, sizeof(br.reg_op), "delete_value");
  if (!check_br("DEFENSE-001 delete is not registry_set", &br, i_def, 0)) {
    return 1;
  }

  /* R-MITRE-WIN-T1138 Application Shimming: maintenance scan must not alert. */
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_PROCESS_CREATE;
  br.pid = 4242u;
  snprintf(br.process_name, sizeof(br.process_name), "sdbinst.exe");
  snprintf(br.exe_path, sizeof(br.exe_path), "%s", "C:\\Windows\\System32\\sdbinst.exe");
  snprintf(br.cmdline, sizeof(br.cmdline), "%s", "C:\\WINDOWS\\System32\\sdbinst.exe -m -bg");
  snprintf(br.parent_name, sizeof(br.parent_name), "svchost.exe");
  if (!check_br("T1138 maintenance miss", &br, i_t1138, 0)) {
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_PROCESS_CREATE;
  br.pid = 4243u;
  snprintf(br.process_name, sizeof(br.process_name), "sdbinst.exe");
  snprintf(br.exe_path, sizeof(br.exe_path), "%s", "C:\\Windows\\System32\\sdbinst.exe");
  snprintf(br.cmdline, sizeof(br.cmdline), "%s", "sdbinst.exe C:\\Users\\Public\\payload.sdb /q");
  snprintf(br.parent_name, sizeof(br.parent_name), "cmd.exe");
  if (!check_br("T1138 suspicious hit", &br, i_t1138, 1)) {
    return 1;
  }

  /* R-LOLBIN-010 必须检查实际映像路径，而不是把临时脚本参数误当成临时二进制。 */
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_PROCESS_CREATE;
  snprintf(br.process_name, sizeof(br.process_name), "powershell.exe");
  snprintf(br.exe_path, sizeof(br.exe_path), "%s",
           "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(br.cmdline, sizeof(br.cmdline), "%s",
           "powershell.exe -File C:\\Windows\\Temp\\edr-agent-post-upgrade-verify.ps1");
  if (!check_br("LOLBIN-010 maintenance script argument miss", &br, i_lolbin10, 0)) {
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_PROCESS_CREATE;
  snprintf(br.process_name, sizeof(br.process_name), "powershell.exe");
  snprintf(br.exe_path, sizeof(br.exe_path), "%s", "C:\\Windows\\Temp\\powershell.exe");
  snprintf(br.cmdline, sizeof(br.cmdline), "%s", "C:\\Windows\\Temp\\powershell.exe -EncodedCommand AAAA");
  if (!check_br("LOLBIN-010 temp image hit", &br, i_lolbin10, 1)) {
    return 1;
  }

  fprintf(
      stderr,
      "[p0_ir_record] ok (file_read / file_write / network_connect / registry_set / process path golden)\n"
  );
  return 0;
}
