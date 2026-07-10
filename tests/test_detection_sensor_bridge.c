#include "edr/behavior_from_slot.h"
#include "edr/detection_decision.h"
#include "edr/windows_event_policy.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <stdlib.h>
static void test_setenv(const char *k, const char *v) { _putenv_s(k, v); }
static void test_unsetenv(const char *k) { _putenv_s(k, ""); }
#else
static void test_setenv(const char *k, const char *v) { setenv(k, v, 1); }
static void test_unsetenv(const char *k) { unsetenv(k); }
#endif

void edr_isolate_auto_from_ransom_alarm(uint32_t pid) { (void)pid; }

static void fill_slot(EdrEventSlot *slot, EdrEventType type, const char *text) {
  memset(slot, 0, sizeof(*slot));
  slot->type = type;
  slot->priority = 1u;
  slot->timestamp_ns = 1779338400000000000LL;
  snprintf((char *)slot->data, sizeof(slot->data), "%s", text);
  slot->size = (uint32_t)strlen((const char *)slot->data);
}

static void eval_slot(const EdrEventSlot *slot, EdrBehaviorRecord *r, EdrDetectionDecision *d) {
  edr_behavior_from_slot(slot, r);
  edr_detection_decision_evaluate(r, d);
  assert(!d->drop);
}

static void write_high_entropy_fixture(const char *path) {
  FILE *f = fopen(path, "wb");
  assert(f != NULL);
  for (int i = 0; i < 8192; i++) {
    fputc(i & 0xff, f);
  }
  fclose(f);
}

static void test_scriptblock_sensor_bridge(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_SCRIPT_POWERSHELL,
            "ETW1\n"
            "prov=powershell\n"
            "pid=4301\n"
            "ppid=2100\n"
            "img=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            "cmd=powershell.exe -nop -enc SQBFAFgA\n"
            "sensor=scriptblock\n"
            "provider=Microsoft-Windows-PowerShell\n"
            "scriptblock_id=9\n"
            "amsi_content=IEX DownloadString AmsiUtils amsiInitFailed\n");
  eval_slot(&slot, &r, &d);
  assert(strstr(r.script_snippet, "sensor=scriptblock") != NULL);
  assert(strstr(r.script_snippet, "amsi_content=IEX_DownloadString_AmsiUtils_amsiInitFailed") != NULL);
  assert(strstr(d.reason, "script_sensor_content") != NULL);
  assert(strstr(r.detection_context, "\"script_sensor\":true") != NULL);
}

static void test_amsi_sensor_bridge(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_SCRIPT_POWERSHELL,
            "ETW1\n"
            "prov=amsi\n"
            "pid=4302\n"
            "img=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            "sensor=amsi\n"
            "provider=Microsoft-Antimalware-Scan-Interface\n"
            "app_name=PowerShell\n"
            "amsi_content=IEX DownloadString AmsiScanBuffer disable-amsi\n"
            "amsi_result=detected\n");
  eval_slot(&slot, &r, &d);
  assert(strstr(r.script_snippet, "sensor=amsi") != NULL);
  assert(strstr(r.script_snippet, "provider=Microsoft-Antimalware-Scan-Interface") != NULL);
  assert(strstr(d.reason, "script_sensor_content") != NULL);
  assert(strstr(r.detection_context, "\"script_sensor\":true") != NULL);
}

static void test_tls_sensor_bridge(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_NET_TLS_HANDSHAKE,
            "ETW1\n"
            "prov=tls\n"
            "pid=4666\n"
            "img=C:\\Windows\\System32\\rundll32.exe\n"
            "dst=203.0.113.44\n"
            "dpt=443\n"
            "proto=tls\n"
            "ja3=72a589da586844d7f0818ce684948eea\n"
            "ja3_rare=1\n"
            "sni=cdn-login.example\n"
            "sni_mismatch=1\n"
            "cert_self_signed=1\n"
            "cert_revoked_ancestor=1\n");
  eval_slot(&slot, &r, &d);
  assert(r.net_dport == 443u);
  assert(r.cert_revoked_ancestor == 1u);
  assert(strstr(r.script_snippet, "ja3_rare=1") != NULL);
  assert(strstr(d.reason, "tls_ja3_sni_cert_anomaly") != NULL);
  assert(strstr(r.detection_context, "\"tls_anomaly\":true") != NULL);
}

static void test_schannel_cert_error_bridge(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_NET_TLS_HANDSHAKE,
            "ETW1\n"
            "prov=schannel\n"
            "sensor=tls_etw\n"
            "provider=Microsoft-Windows-Schannel\n"
            "pid=4667\n"
            "tls_sni=bad.example\n"
            "tls_error=0x800B0109\n"
            "cert_subject=CN=bad.example\n"
            "cert_issuer=CN=Untrusted\n");
  eval_slot(&slot, &r, &d);
  assert(strstr(r.script_snippet, "tls_error=0x800B0109") != NULL);
  assert(strstr(d.reason, "tls_ja3_sni_cert_anomaly") != NULL);
  assert(strstr(r.detection_context, "\"tls_anomaly\":true") != NULL);
}

static void test_ransom_counter_bridge(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_FILE_WRITE,
            "ETW1\n"
            "prov=file_counter\n"
            "pid=4777\n"
            "img=C:\\Users\\alice\\AppData\\Roaming\\backup_update.exe\n"
            "file=C:\\Users\\alice\\Documents\\q1.locked\n"
            "ransom_counter=1\n"
            "file_rate=140\n"
            "ext_burst=31\n"
            "entropy_delta=2.4\n"
            "extension_burst=1\n");
  eval_slot(&slot, &r, &d);
  assert(strstr(r.script_snippet, "file_rate=140") != NULL);
  assert(strstr(d.reason, "ransom_behavior_counter") != NULL);
  assert(strstr(r.detection_context, "\"ransom_behavior\":true") != NULL);
}

static void test_ransom_sliding_window_counter(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrBehaviorRecord signal_record;
  EdrDetectionDecision d;
  int signal_count = 0;
  memset(&signal_record, 0, sizeof(signal_record));

  for (int i = 0; i < 85; i++) {
    char payload[768];
    snprintf(payload, sizeof(payload),
             "ETW1\n"
             "prov=kfile\n"
             "pid=4888\n"
             "img=C:\\Users\\alice\\AppData\\Roaming\\sync_update.exe\n"
             "file=C:\\Users\\alice\\Documents\\quarterly\\doc%02d.%02dlock\n",
             i, i);
    fill_slot(&slot, EDR_EVENT_FILE_WRITE, payload);
    slot.timestamp_ns = 1779338500000000000LL + (int64_t)i * 10000000LL;
    edr_behavior_from_slot(&slot, &r);
    if (strstr(r.script_snippet, "ransom_counter=1") != NULL) {
      signal_record = r;
      signal_count++;
    }
  }

  assert(signal_count >= 1);
  assert(signal_count <= 2);
  edr_detection_decision_evaluate(&signal_record, &d);
  assert(!d.drop);
  assert(strstr(signal_record.script_snippet, "file_rate=") != NULL);
  assert(strstr(signal_record.script_snippet, "ext_burst=") != NULL);
  assert(strstr(signal_record.script_snippet, "ransom_counter_transition=1") != NULL);
  assert(strstr(d.reason, "ransom_behavior_counter") != NULL);
  assert(strstr(signal_record.detection_context, "\"ransom_behavior\":true") != NULL);
  assert(strstr(signal_record.detection_context, "\"state_transition\":true") != NULL);
}

static void test_ransom_alert_volume_is_bounded(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  int signal_count = 0;
  int transition_count = 0;
  int summary_count = 0;

  test_setenv("EDR_RANSOM_COUNTER_WINDOW_S", "600");
  test_setenv("EDR_RANSOM_COUNTER_SUMMARY_S", "30");
  for (int i = 0; i < 1000; i++) {
    char payload[768];
    snprintf(payload, sizeof(payload),
             "ETW1\n"
             "prov=kfile\n"
             "pid=5098\n"
             "img=C:\\Users\\alice\\AppData\\Roaming\\sync_update.exe\n"
             "file=C:\\Users\\alice\\Documents\\bulk\\d%02d\\doc%04d.e%02d\n",
             i % 16, i, i % 20);
    fill_slot(&slot, EDR_EVENT_FILE_WRITE, payload);
    slot.timestamp_ns = 1779338900000000000LL + (int64_t)i * 100000000LL;
    edr_behavior_from_slot(&slot, &r);
    edr_windows_event_policy_apply(&r);
    if (strstr(r.script_snippet, "ransom_counter=1") == NULL) {
      continue;
    }
    signal_count++;
    transition_count += strstr(r.script_snippet, "ransom_counter_transition=1") != NULL;
    summary_count += strstr(r.script_snippet, "ransom_counter_summary=1") != NULL;
    assert(r.priority == 0u);
    edr_detection_decision_evaluate(&r, &d);
    assert(strstr(d.reason, "ransom_behavior_counter") != NULL);
  }
  test_unsetenv("EDR_RANSOM_COUNTER_WINDOW_S");
  test_unsetenv("EDR_RANSOM_COUNTER_SUMMARY_S");

  assert(signal_count >= 3);
  assert(signal_count <= 5);
  assert(transition_count >= 1);
  assert(transition_count <= 2);
  assert(summary_count <= 3);
}

static void test_invalid_file_path_does_not_raise_ransom_counter(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_FILE_WRITE,
            "ETW1\n"
            "prov=kfile\n"
            "pid=4889\n"
            "img=C:\\Program Files (x86)\\Sangfor\\SSL\\ECAgent\\ECAgent.exe\n"
            "file=badname\n");
  edr_behavior_from_slot(&slot, &r);
  edr_detection_decision_evaluate(&r, &d);
  assert(strstr(r.script_snippet, "invalid_file_path=1") != NULL);
  assert(strstr(r.script_snippet, "ransom_counter_suppressed=1") != NULL);
  assert(strstr(r.script_snippet, "ransom_counter=1") == NULL);
  assert(strstr(d.reason, "ransom_behavior_counter") == NULL);
  assert(strstr(d.reason, "ransom_kill_chain_candidate") == NULL);
}

static void test_low_value_process_does_not_raise_ransom_counter(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;

  for (int i = 0; i < 90; i++) {
    char payload[768];
    snprintf(payload, sizeof(payload),
             "ETW1\n"
             "prov=kfile\n"
             "pid=4890\n"
             "img=C:\\Program Files (x86)\\Sangfor\\SSL\\ECAgent\\ECAgent.exe\n"
             "file=C:\\ProgramData\\Sangfor\\SSL\\cache\\doc%02d.%02dlock\n",
             i, i);
    fill_slot(&slot, EDR_EVENT_FILE_WRITE, payload);
    slot.timestamp_ns = 1779338550000000000LL + (int64_t)i * 10000000LL;
    edr_behavior_from_slot(&slot, &r);
  }

  edr_detection_decision_evaluate(&r, &d);
  assert(strstr(r.script_snippet, "low_value_ransom_process=1") != NULL);
  assert(strstr(r.script_snippet, "ransom_counter_suppressed=1") != NULL);
  assert(strstr(r.script_snippet, "ransom_counter=1") == NULL);
  assert(strstr(d.reason, "ransom_behavior_counter") == NULL);
  assert(strstr(d.reason, "ransom_kill_chain_candidate") == NULL);
}

static void test_ransom_note_burst_counter(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;

  for (int i = 0; i < 2; i++) {
    char payload[768];
    snprintf(payload, sizeof(payload),
             "ETW1\n"
             "prov=kfile\n"
             "pid=4998\n"
             "img=C:\\Users\\alice\\AppData\\Roaming\\sync_update.exe\n"
             "file=C:\\Users\\alice\\Documents\\HOW_TO_RESTORE_%02d.txt\n",
             i);
    fill_slot(&slot, EDR_EVENT_FILE_WRITE, payload);
    slot.timestamp_ns = 1779338600000000000LL + (int64_t)i * 1000000000LL;
    edr_behavior_from_slot(&slot, &r);
  }

  edr_detection_decision_evaluate(&r, &d);
  assert(!d.drop);
  assert(strstr(r.script_snippet, "ransom_note_count=2") != NULL);
  assert(strstr(r.script_snippet, "ransom_note_burst=1") != NULL);
  assert(strstr(d.reason, "ransom_note_burst") != NULL);
  assert(strstr(r.detection_context, "\"ransom_note_burst\":true") != NULL);
}

static void test_ransom_canary_deterministic_context(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  test_setenv("EDR_RANSOM_CANARY_PATH", "C:\\Users\\Public\\~$canary.docx");
  fill_slot(&slot, EDR_EVENT_FILE_WRITE,
            "ETW1\n"
            "prov=kfile\n"
            "pid=5008\n"
            "img=C:\\Users\\alice\\AppData\\Roaming\\sync_update.exe\n"
            "file=C:\\Users\\Public\\~$canary.docx\n");
  eval_slot(&slot, &r, &d);
  test_unsetenv("EDR_RANSOM_CANARY_PATH");
  assert(r.priority == 0u);
  assert(strstr(r.script_snippet, "ransom_canary=1") != NULL);
  assert(strstr(d.reason, "ransom_canary_deterministic_encryption") != NULL);
  assert(strstr(r.detection_context, "\"kind\":\"DETERMINISTIC_ENCRYPTION\"") != NULL);
  assert(strstr(r.detection_context, "\"canary\":true") != NULL);
  assert(strstr(r.detection_context, "\"severity\":4") != NULL);
}

static void test_ransom_generic_canary_filename_is_not_deterministic(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  test_unsetenv("EDR_RANSOM_CANARY_PATH");
  test_unsetenv("EDR_RANSOM_CANARY_TOKENS");
  fill_slot(&slot, EDR_EVENT_FILE_WRITE,
            "ETW1\n"
            "prov=kfile\n"
            "pid=5009\n"
            "img=C:\\Users\\alice\\AppData\\Roaming\\word.exe\n"
            "file=C:\\Users\\alice\\Documents\\canary.docx\n");
  eval_slot(&slot, &r, &d);
  assert(strstr(r.script_snippet, "ransom_canary=1") == NULL);
  assert(strstr(d.reason, "ransom_canary_deterministic_encryption") == NULL);
}

static void test_ransom_counter_allowlist_suppresses_rate_only(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  test_setenv("EDR_RANSOM_COUNTER_ALLOWLIST", "C:\\Program Files\\TrustedBackup\\trustedbackup.exe");
  for (int i = 0; i < 90; i++) {
    char payload[768];
    snprintf(payload, sizeof(payload),
             "ETW1\n"
             "prov=kfile\n"
             "pid=5018\n"
             "img=C:\\Program Files\\TrustedBackup\\trustedbackup.exe\n"
             "file=C:\\Users\\alice\\Documents\\bulk\\doc%02d.%02dlock\n",
             i, i);
    fill_slot(&slot, EDR_EVENT_FILE_WRITE, payload);
    slot.timestamp_ns = 1779338700000000000LL + (int64_t)i * 10000000LL;
    edr_behavior_from_slot(&slot, &r);
  }
  edr_detection_decision_evaluate(&r, &d);
  test_unsetenv("EDR_RANSOM_COUNTER_ALLOWLIST");
  assert(!d.drop);
  assert(strstr(r.script_snippet, "ransom_counter_allowlisted=1") != NULL);
  assert(strstr(r.script_snippet, "ransom_counter=1") == NULL);
  assert(strstr(r.detection_context, "\"ransom_counter_allowlisted\":true") != NULL);
  assert(strstr(r.detection_context, "\"counter_suppressed\":true") != NULL);
}

static void test_ransom_allowlist_does_not_match_similar_identity(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  test_setenv("EDR_RANSOM_COUNTER_ALLOWLIST", "C:\\Program Files\\TrustedBackup\\trustedbackup.exe");
  fill_slot(&slot, EDR_EVENT_FILE_WRITE,
            "ETW1\n"
            "prov=kfile\n"
            "pid=5019\n"
            "img=C:\\Program Files\\TrustedBackup\\trustedbackup.exe.bak\n"
            "file=C:\\Users\\alice\\Documents\\bulk\\doc01.locked\n");
  edr_behavior_from_slot(&slot, &r);
  edr_detection_decision_evaluate(&r, &d);
  test_unsetenv("EDR_RANSOM_COUNTER_ALLOWLIST");
  assert(strstr(r.script_snippet, "ransom_counter_allowlisted=1") == NULL);
  assert(strstr(r.detection_context, "\"counter_suppressed\":true") == NULL);
}

static void test_ransom_content_entropy_and_extension_change(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  const char *tmp = getenv("TMPDIR");
  if (!tmp || !tmp[0]) {
    tmp = "/tmp";
  }
  char path[512];
  snprintf(path, sizeof(path), "%s/edr_ransom_entropy_fixture.locked", tmp);
  write_high_entropy_fixture(path);
  char payload[1024];
  snprintf(payload, sizeof(payload),
           "ETW1\n"
           "prov=kfile\n"
           "pid=5028\n"
           "ppid=4028\n"
           "parent_img=C:\\Users\\alice\\AppData\\Roaming\\dropper.exe\n"
           "img=C:\\Users\\alice\\AppData\\Roaming\\encryptor.exe\n"
           "old_file=C:\\Users\\alice\\Documents\\report.docx\n"
           "file=%s\n",
           path);
  fill_slot(&slot, EDR_EVENT_FILE_RENAME, payload);
  eval_slot(&slot, &r, &d);
  remove(path);
  assert(strstr(r.script_snippet, "old_ext=docx") != NULL);
  assert(strstr(r.script_snippet, "new_ext=locked") != NULL);
  assert(strstr(r.script_snippet, "ext_changed=1") != NULL);
  assert(strstr(r.script_snippet, "content_entropy_ok=1") != NULL);
  assert(strstr(r.detection_context, "\"extension_changed\":true") != NULL);
  assert(strstr(r.detection_context, "\"content_entropy\":") != NULL);
  assert(strstr(r.detection_context, "\"attribution_key\":\"tree:4028\"") != NULL);
}

static void test_ransom_signer_path_allowlist_suppresses_counter(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  test_setenv("EDR_RANSOM_SIGNER_ALLOWLIST", "TrustedBackup_Corp");
  test_setenv("EDR_RANSOM_SIGNED_PATH_ALLOWLIST", "C:\\Program Files\\TrustedBackup\\trustedbackup.exe");
  fill_slot(&slot, EDR_EVENT_FILE_WRITE,
            "ETW1\n"
            "prov=kfile\n"
            "pid=5038\n"
            "img=C:\\Program Files\\TrustedBackup\\trustedbackup.exe\n"
            "signer=TrustedBackup Corp\n"
            "signature_status=trusted\n"
            "file=C:\\Users\\alice\\Documents\\bulk\\doc01.locked\n");
  eval_slot(&slot, &r, &d);
  test_unsetenv("EDR_RANSOM_SIGNER_ALLOWLIST");
  test_unsetenv("EDR_RANSOM_SIGNED_PATH_ALLOWLIST");
  assert(strstr(r.script_snippet, "ransom_counter_allowlisted=1") != NULL);
  assert(strstr(r.script_snippet, "ransom_signer_allowlisted=1") != NULL);
  assert(strstr(r.detection_context, "\"ransom_signer_allowlisted\":true") != NULL);
  assert(strstr(r.detection_context, "\"signer_allowlisted\":true") != NULL);
}

static void test_webshell_semantic_bridge_keeps_yara_evidence(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_WEBSHELL_DETECTED,
            "ETW1\n"
            "prov=webshell\n"
            "detector=yara\n"
            "rule=PHP_Webshell_Eval\n"
            "score=0.91\n"
            "proto=http\n"
            "mitre=T1505.003\n"
            "file=/var/www/html/upload/shell.php\n"
            "script=service=nginx action=write\n"
            "ast_score=0.91\n"
            "token_score=0.88\n"
            "ast=webshell\n"
            "token=webshell\n"
            "features=base64_decode,assert,cmd\n");
  eval_slot(&slot, &r, &d);
  assert(strstr(r.script_snippet, "detector=yara") != NULL);
  assert(strstr(r.script_snippet, "ast_score=0.91") != NULL);
  assert(strstr(r.script_snippet, "features=base64_decode,assert,cmd") != NULL);
  assert(strstr(r.detection_context, "\"engine\":\"webshell\"") != NULL);
  assert(strstr(r.detection_context, "\"webshell_semantic\":true") != NULL);
}

static void test_sensor_alias_bridge(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_NET_TLS_HANDSHAKE,
            "ETW1\n"
            "prov=tls_sensor\n"
            "pid=4999\n"
            "img=C:\\Windows\\System32\\rundll32.exe\n"
            "dst=198.51.100.24\n"
            "dpt=443\n"
            "remote_url=https://login-cdn.example/a\n"
            "ja3_hash=abcd1234\n"
            "tls_sni=login-cdn.example\n"
            "cert_chain_anomaly=1\n"
            "sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "cert_untrusted=1\n");
  eval_slot(&slot, &r, &d);
  assert(strstr(r.dns_query, "https://login-cdn.example/a") != NULL);
  assert(strstr(r.exe_hash, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") != NULL);
  assert(strstr(r.script_snippet, "ja3_hash=abcd1234") != NULL);
  assert(strstr(r.script_snippet, "tls_sni=login-cdn.example") != NULL);
  assert(strstr(d.reason, "tls_ja3_sni_cert_anomaly") != NULL);
  assert(strstr(r.detection_context, "\"tls_anomaly\":true") != NULL);

  fill_slot(&slot, EDR_EVENT_FILE_WRITE,
            "ETW1\n"
            "prov=webshell_semantic\n"
            "pid=5001\n"
            "img=C:\\php\\php-cgi.exe\n"
            "file=C:\\inetpub\\wwwroot\\upload\\img.php\n"
            "semantic_score=0.92\n"
            "ast_tokens=eval,base64_decode\n"
            "token_features=cmd,assert\n");
  eval_slot(&slot, &r, &d);
  assert(strstr(r.script_snippet, "semantic_score=0.92") != NULL);
  assert(strstr(d.reason, "webshell_ast_token_semantic") != NULL);
  assert(strstr(r.detection_context, "\"webshell_semantic\":true") != NULL);
}

static void test_integer_ip_fields_are_normalized(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_NET_CONNECT,
            "ETW1\n"
            "prov=net\n"
            "pid=6001\n"
            "img=C:\\Windows\\System32\\CheckNetIsolation.exe\n"
            "dest_ip=16777343\n"
            "dpt=80\n"
            "src_ip=16777343\n"
            "spt=50123\n");
  eval_slot(&slot, &r, &d);
  assert(strcmp(r.net_dst, "127.0.0.1") == 0);
  assert(strcmp(r.net_src, "127.0.0.1") == 0);
  assert(r.net_dport == 80u);
  assert(r.net_sport == 50123u);

  fill_slot(&slot, EDR_EVENT_NET_CONNECT,
            "ETW1\n"
            "prov=net\n"
            "pid=6002\n"
            "img=C:\\Windows\\System32\\svchost.exe\n"
            "dst=203.0.113.44\n"
            "dpt=443\n");
  eval_slot(&slot, &r, &d);
  assert(strcmp(r.net_dst, "203.0.113.44") == 0);
}

static void test_registry_persistence_alias_bridge(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_REG_SET_VALUE,
            "ETW1\n"
            "prov=registry\n"
            "pid=5101\n"
            "ppid=2100\n"
            "img=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            "cmd=powershell.exe Set-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run Updater\n"
            "registry_path=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "value_name=Updater\n"
            "value_data=powershell.exe_-w_hidden_-enc_SQBFAFgA\n"
            "operation=set_value\n");
  eval_slot(&slot, &r, &d);
  assert(strstr(r.reg_key_path, "CurrentVersion\\Run") != NULL);
  assert(strstr(r.reg_value_name, "Updater") != NULL);
  assert(strstr(d.reason, "persistence_change_indicator") != NULL);
  assert(strstr(r.detection_context, "\"registry\"") != NULL);
  assert(strstr(r.detection_context, "\"persistence_change\":true") != NULL);
  assert(strstr(r.detection_context, "persistence_changes") != NULL);
}

int main(void) {
  test_scriptblock_sensor_bridge();
  test_amsi_sensor_bridge();
  test_tls_sensor_bridge();
  test_schannel_cert_error_bridge();
  test_ransom_counter_bridge();
  test_ransom_sliding_window_counter();
  test_ransom_alert_volume_is_bounded();
  test_invalid_file_path_does_not_raise_ransom_counter();
  test_low_value_process_does_not_raise_ransom_counter();
  test_ransom_note_burst_counter();
  test_ransom_canary_deterministic_context();
  test_ransom_generic_canary_filename_is_not_deterministic();
  test_ransom_counter_allowlist_suppresses_rate_only();
  test_ransom_allowlist_does_not_match_similar_identity();
  test_ransom_content_entropy_and_extension_change();
  test_ransom_signer_path_allowlist_suppresses_counter();
  test_webshell_semantic_bridge_keeps_yara_evidence();
  test_sensor_alias_bridge();
  test_integer_ip_fields_are_normalized();
  test_registry_persistence_alias_bridge();
  puts("detection_sensor_bridge ok");
  return 0;
}
