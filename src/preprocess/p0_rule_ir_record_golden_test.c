/* P0 IR：非 process_create 时与 p0_golden_vectors.json 子集对拍（需 PCRE2 + 可解析 IR JSON）。 */
#include "edr/behavior_record.h"
#include "edr/p0_rule_ir.h"
#include "edr/types.h"

#include <stdio.h>
#include <stdlib.h>
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

static int evaluated_rule_with_facts(const EdrBehaviorRecord *br,
                                     const EdrCommandFacts *facts, const char *rule_id) {
  EdrP0RuleIrEvaluation evaluation;
  int found = 0;
  if (!edr_p0_rule_ir_evaluate_record(br, facts, &evaluation)) return -1;
  for (uint32_t i = 0; i < evaluation.match_count; ++i) {
    EdrP0RuleIrMatch match;
    if (!edr_p0_rule_ir_evaluation_get_match(&evaluation, i, &match)) {
      found = -1;
      break;
    }
    if (strcmp(match.rule_id, rule_id) == 0) found = 1;
  }
  edr_p0_rule_ir_evaluation_free(&evaluation);
  return found;
}

static int evaluated_rule(const EdrBehaviorRecord *br, const char *rule_id) {
  return evaluated_rule_with_facts(br, NULL, rule_id);
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
  int i_cred11 = find_rule_index("R-CRED-011");
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
  if (i_cred3 < 0 || i_cred11 < 0 || i_web < 0 || i_lmove < 0 || i_net < 0 || i_lmove015 < 0 || i_def < 0 || i_def4 < 0 ||
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
  edr_behavior_mark_source_truncated(&br, "source.parent_cmdline");
  if (evaluated_rule(&br, "R-CRED-003") != 1) {
    fprintf(stderr, "[p0_ir_record] unrelated parent preview withheld file rule\n");
    return 1;
  }
  edr_behavior_mark_source_truncated(&br, "source.current_directory");
  if (evaluated_rule(&br, "R-CRED-003") != 1) {
    fprintf(stderr, "[p0_ir_record] known unrelated CWD truncation withheld file rule\n");
    return 1;
  }
  edr_behavior_mark_source_truncated(&br, "source.image_path_resolution_status");
  if (evaluated_rule(&br, "R-CRED-003") != 0) {
    fprintf(stderr, "[p0_ir_record] truncated resolution status matched file rule\n");
    return 1;
  }
  edr_behavior_resolve_source_truncated(&br, "source.image_path_resolution_status");
  edr_behavior_mark_source_truncated(&br, "source.process_generation_source");
  if (evaluated_rule(&br, "R-CRED-003") != 0) {
    fprintf(stderr, "[p0_ir_record] truncated generation source matched file rule\n");
    return 1;
  }
  edr_behavior_resolve_source_truncated(&br, "source.process_generation_source");
  snprintf(br.source_truncated_fields, sizeof(br.source_truncated_fields), "%s",
           "source.parent_cmdline,source.unrecognized_field");
  if (evaluated_rule(&br, "R-CRED-003") != 0) {
    fprintf(stderr, "[p0_ir_record] unknown mixed quality marker matched file rule\n");
    return 1;
  }
  snprintf(br.source_truncated_fields, sizeof(br.source_truncated_fields), "%s",
           "source.parent_cmdline");
  edr_behavior_mark_source_truncated(&br, "source.file_path");
  if (evaluated_rule(&br, "R-CRED-003") != 0) {
    fprintf(stderr, "[p0_ir_record] truncated target path matched file rule\n");
    return 1;
  }
  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_FILE_READ;
  snprintf(br.file_path, sizeof(br.file_path), "%s", "C:\\safe\\notes.txt");
  if (!check_br("CRED-003 miss", &br, i_cred3, 0)) {
    return 1;
  }

  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_FILE_READ;
  snprintf(br.process_name, sizeof(br.process_name), "%s", "powershell.exe");
  snprintf(br.file_path, sizeof(br.file_path), "%s", "C:\\Chrome\\Network\\Cookies");
  edr_behavior_mark_source_truncated(&br, "source.parent_cmdline");
  if (evaluated_rule(&br, "R-CRED-011") != 1) {
    fprintf(stderr, "[p0_ir_record] unrelated parent preview withheld CRED-011\n");
    return 1;
  }
  edr_behavior_mark_source_truncated(&br, "source.process_name");
  if (evaluated_rule(&br, "R-CRED-011") != 0) {
    fprintf(stderr, "[p0_ir_record] truncated actor name matched CRED-011\n");
    return 1;
  }

  edr_behavior_record_init(&br);
  br.type = EDR_EVENT_PROCESS_CREATE;
  snprintf(br.process_name, sizeof(br.process_name), "%s", "powershell.exe");
  snprintf(br.cmdline, sizeof(br.cmdline), "%s", "powershell.exe -enc PREVIEW");
  edr_behavior_mark_source_truncated(&br, "source.cmdline");
  if (evaluated_rule(&br, "R-EXEC-001") != 0) {
    fprintf(stderr, "[p0_ir_record] incomplete command preview matched command rule\n");
    return 1;
  }

  /* Preview ends at a word boundary. Only the complete generation-bound
   * command can decide whether -enc is a whole option or a longer word. */
  br.pid = 4477u;
  br.process_start_key = 119u;
  br.process_creation_filetime_100ns = UINT64_C(134346486201851986);
  strcpy(br.tenant_id, "quality-gate-test");
  strcpy(br.endpoint_id, "quality-gate-endpoint");
  strcpy(br.cmdline, "powershell.exe safe-preview");
  EdrCommandFacts hard_gate_fact = {"powershell.exe safe-preview -enc payload", NULL};
  strcpy(br.source_completeness, "NOT_EVALUABLE");
  if (evaluated_rule_with_facts(&br, &hard_gate_fact, "R-EXEC-001") != 1 ||
      !edr_behavior_p0_source_quality_hard_reject(&br)) {
    fprintf(stderr, "[p0_ir_record] NOT_EVALUABLE complete command escaped hard source gate\n");
    return 1;
  }
  strcpy(br.source_completeness, "TRUNCATED");
  if (edr_behavior_p0_source_quality_hard_reject(&br)) {
    fprintf(stderr, "[p0_ir_record] named preview truncation hit hard source gate\n");
    return 1;
  }
  char *command = malloc(12718u);
  if (!command) return 1;
  memset(command, 'x', 8191u);
  memcpy(command, "powershell.exe ", 15u);
  memcpy(command + 8187u, "-enc", 4u);
  command[8191u] = '\0';
  memcpy(br.cmdline, command, 8192u);
  EdrCommandFacts facts = {command, NULL};
  if (evaluated_rule_with_facts(&br, &facts, "R-EXEC-001") != 0) {
    fprintf(stderr, "[p0_ir_record] preview-only command was accepted as full fact\n");
    free(command); return 1;
  }
  edr_behavior_resolve_source_truncated(&br, "source.cmdline");
  edr_behavior_mark_source_truncated(&br, "source.cmdline_quality_unknown");
  if (evaluated_rule_with_facts(&br, &facts, "R-EXEC-001") != 1) {
    fprintf(stderr, "[p0_ir_record] verified equal-length command fact was ignored\n");
    free(command); return 1;
  }
  edr_behavior_resolve_source_truncated(&br, "source.cmdline_quality_unknown");
  edr_behavior_mark_source_truncated(&br, "source.cmdline");
  memcpy(command + 8191u, "oding", 6u);
  if (evaluated_rule_with_facts(&br, &facts, "R-EXEC-001") != 0) {
    fprintf(stderr, "[p0_ir_record] preview word boundary caused a false command hit\n");
    free(command); return 1;
  }
  memcpy(command + 8191u, " tail", 6u);
  if (evaluated_rule_with_facts(&br, &facts, "R-EXEC-001") != 1) {
    fprintf(stderr, "[p0_ir_record] complete 8196-byte command did not match\n");
    free(command); return 1;
  }
  memset(command + 8191u, 'x', 12717u - 8191u);
  memcpy(command + 12712u, " -enc", 5u);
  command[12717u] = '\0';
  if (evaluated_rule_with_facts(&br, &facts, "R-EXEC-001") != 1) {
    fprintf(stderr, "[p0_ir_record] 12717-byte command tail was not evaluated\n");
    free(command); return 1;
  }
  free(command);

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
  br.type = EDR_EVENT_NET_LISTEN;
  edr_behavior_mark_source_truncated(&br, "source.process_name");
  if (evaluated_rule(&br, "R-NET-001") != 0) {
    fprintf(stderr, "[p0_ir_record] listen family used truncated process name\n");
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
  br.type = EDR_EVENT_REG_CREATE_KEY;
  edr_behavior_mark_source_truncated(&br, "source.reg_value_data");
  if (evaluated_rule(&br, "R-DEFENSE-001") != 0) {
    fprintf(stderr, "[p0_ir_record] registry create used truncated DWORD data\n");
    return 1;
  }
  edr_behavior_resolve_source_truncated(&br, "source.reg_value_data");
  edr_behavior_mark_source_truncated(&br, "source.parent_cmdline");
  if (evaluated_rule(&br, "R-DEFENSE-001") != 1) {
    fprintf(stderr, "[p0_ir_record] unrelated preview withheld registry rule\n");
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
