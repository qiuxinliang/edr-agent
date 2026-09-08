#include "edr/behavior_from_slot.h"
#include "edr/detection_decision.h"
#include "edr/windows_event_policy.h"
#include "edr/process_generation.h"
#include "cJSON.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <stdlib.h>
static void test_setenv(const char *k, const char *v) { _putenv_s(k, v); }
static void test_unsetenv(const char *k) { _putenv_s(k, ""); }
#else
#include <unistd.h>
static void test_setenv(const char *k, const char *v) { setenv(k, v, 1); }
static void test_unsetenv(const char *k) { unsetenv(k); }
#endif

static unsigned ransom_response_calls;
void edr_isolate_auto_from_ransom_alarm(const EdrBehaviorRecord *record) { assert(record); ransom_response_calls++; }

static void fill_slot(EdrEventSlot *slot, EdrEventType type, const char *text) {
  memset(slot, 0, sizeof(*slot));
  slot->type = type;
  slot->priority = 1u;
  slot->timestamp_ns = 1779338400000000000LL;
  snprintf((char *)slot->data, sizeof(slot->data), "%s", text);
  slot->size = (uint32_t)strlen((const char *)slot->data);
}

/* Counter tests supply an already-bound actor fixture. Separate tests below
 * exercise raw parsing and rejection before that trusted boundary. */
static void enrich_slot_fixture(const EdrEventSlot *slot, EdrBehaviorRecord *r) {
  edr_behavior_from_slot(slot, r);
  if (r->kernel_file_activity) {
    r->file_actor_generation_validated = 1u;
    if (!r->process_start_key) r->process_start_key = ((uint64_t)r->pid << 32u) | 1u;
    if (!r->process_creation_filetime_100ns) {
      r->process_creation_filetime_100ns = 116444736000000001ULL;
    }
  }
  edr_behavior_enrich_file_activity(r);
}

static void eval_slot(const EdrEventSlot *slot, EdrBehaviorRecord *r, EdrDetectionDecision *d) {
  enrich_slot_fixture(slot, r);
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
    enrich_slot_fixture(&slot, &r);
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
  assert(strstr(signal_record.detection_context, "ENCRYPTION_CONFIRMED") == NULL);
  assert(strstr(signal_record.detection_context, "\"content_changed_file_count\":0") != NULL);
}

static void test_ransom_repeated_file_and_non_mutations(void) {
  const EdrEventType types[] = {EDR_EVENT_FILE_WRITE, EDR_EVENT_FILE_CREATE, EDR_EVENT_FILE_DELETE};
  unsigned before = ransom_response_calls;
  for (unsigned type = 0; type < sizeof(types) / sizeof(types[0]); ++type) {
    for (unsigned i = 0; i < 220; ++i) {
      EdrEventSlot slot;
      EdrBehaviorRecord r;
      EdrDetectionDecision d;
      char payload[768];
      snprintf(payload, sizeof(payload),
               "ETW1\nprov=kfile\npid=%u\nimg=C:\\Tools\\copyworker.exe\n"
               "file=C:\\Fixture\\d%u\\ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.e%u\n",
               59000u + type, type ? i : 0u, type ? i : 0u);
      fill_slot(&slot, types[type], payload);
      slot.timestamp_ns += (int64_t)i * 100000000LL;
      eval_slot(&slot, &r, &d);
      assert(strstr(r.script_snippet, "ransom_counter=1") == NULL);
      assert(strstr(r.detection_context, "ENCRYPTION_CONFIRMED") == NULL);
    }
  }
  assert(ransom_response_calls == before);
}

static void test_ransom_generation_and_file_key_dedup(void) {
  unsigned before = ransom_response_calls;
  for (unsigned i = 0; i < 100; ++i) {
    EdrEventSlot slot;
    EdrBehaviorRecord r;
    char payload[768];
    /* One object renamed repeatedly is one file, not a hundred victims. */
    snprintf(payload, sizeof(payload),
             "ETW1\nprov=kfile\npid=59010\nprocess_start_key=8001\nfile_key=0x12345\n"
             "img=C:\\Tools\\copyworker.exe\nfile=C:\\Fixture\\doc%u.e%u\n"
             "old_file=C:\\Fixture\\doc%u.e%u\n", i, i, i ? i - 1u : 0u, i ? i - 1u : 0u);
    fill_slot(&slot, EDR_EVENT_FILE_RENAME, payload);
    slot.timestamp_ns += (int64_t)i * 100000000LL;
    enrich_slot_fixture(&slot, &r);
    assert(strstr(r.script_snippet, "ransom_counter=1") == NULL);
  }
  for (unsigned i = 0; i < 30; ++i) {
    EdrEventSlot slot;
    EdrBehaviorRecord r;
    char payload[768];
    /* Each generation has only ten files; PID reuse must not merge them. */
    snprintf(payload, sizeof(payload),
             "ETW1\nprov=kfile\npid=59011\nprocess_start_key=%u\n"
             "img=C:\\Tools\\copyworker.exe\nfile=C:\\Fixture\\doc%u.txt\n", 9000u + i / 10u, i);
    fill_slot(&slot, EDR_EVENT_FILE_WRITE, payload);
    slot.timestamp_ns += (int64_t)i * 100000000LL;
    enrich_slot_fixture(&slot, &r);
    assert(strstr(r.script_snippet, "ransom_counter=1") == NULL);
  }
  assert(ransom_response_calls == before);
}

static void test_ransom_content_change_contract(void) {
  char dir[512];
#ifdef _WIN32
  char temp_path[MAX_PATH];
  assert(GetTempPathA(sizeof(temp_path), temp_path) > 0);
  assert(GetTempFileNameA(temp_path, "edr", 0, dir) != 0);
  assert(DeleteFileA(dir));
  assert(CreateDirectoryA(dir, NULL));
#else
  const char *tmp = getenv("TMPDIR");
  snprintf(dir, sizeof(dir), "%s/edr-ransom-contract.XXXXXX", tmp && tmp[0] ? tmp : "/tmp");
  assert(mkdtemp(dir) != NULL);
#endif
  test_setenv("EDR_RANSOM_CONTENT_ENTROPY_ALWAYS", "1");
  test_setenv("EDR_RANSOM_RATE_CONFIRM_FILES", "20");
  for (int changed = 0; changed < 3; ++changed) {
    unsigned before = ransom_response_calls;
    int confirmations = 0;
    for (int pass = 0; pass < 3; ++pass) {
      for (int i = 0; i < 20; ++i) {
        EdrEventSlot slot;
        EdrBehaviorRecord r;
        EdrDetectionDecision d;
        char path[768], payload[1200];
        snprintf(path, sizeof(path), "%s/doc%02d.bin", dir, i);
        if (pass == 0 && changed) {
          FILE *f = fopen(path, "wb");
          assert(f != NULL);
          for (int n = 0; n < 8192; ++n) assert(fputc('a', f) != EOF);
          assert(fclose(f) == 0);
        } else {
          write_high_entropy_fixture(path);
        }
        snprintf(payload, sizeof(payload),
                 "ETW1\nprov=kfile\npid=%u\nprocess_start_key=9500\n"
                 "img=C:\\Tools\\fixture.exe\nfile=%s\n", 59020u + (unsigned)changed, path);
        fill_slot(&slot, EDR_EVENT_FILE_WRITE, payload);
        slot.timestamp_ns += (int64_t)(pass * 20 + i) * 1000000000LL;
        if (changed == 2) {
          /* Native Create supplies the baseline without a FileKey. Subsequent
           * opens may reuse the same kernel key for different file paths. */
          slot.type = EDR_EVENT_FILE_CREATE;
          enrich_slot_fixture(&slot, &r);
          if (pass == 0) continue;
          slot.type = EDR_EVENT_FILE_WRITE;
          size_t n = strlen((const char *)slot.data);
          snprintf((char *)slot.data + n, sizeof(slot.data) - n, "file_key=0xabc\n");
          slot.size = (uint32_t)strlen((const char *)slot.data);
          slot.timestamp_ns += 1LL;
        }
        eval_slot(&slot, &r, &d);
        if (strstr(r.detection_context, "\"kind\":\"ENCRYPTION_CONFIRMED\"")) {
          assert(changed && pass > 0);
          assert(strstr(r.detection_context, "\"evidence_version\":3"));
          assert(strstr(r.detection_context, "\"confirmation_basis\":\"content_change\""));
          assert(strstr(r.detection_context, "\"unique_file_count\":20"));
          assert(strstr(r.detection_context, "\"content_changed_file_count\":20"));
          confirmations++;
        }
      }
    }
    assert(changed ? confirmations > 0 : confirmations == 0);
    assert(ransom_response_calls == before + (unsigned)(changed != 0));
  }
  test_unsetenv("EDR_RANSOM_CONTENT_ENTROPY_ALWAYS");
  test_unsetenv("EDR_RANSOM_RATE_CONFIRM_FILES");
  for (int i = 0; i < 20; ++i) {
    char path[768];
    snprintf(path, sizeof(path), "%s/doc%02d.bin", dir, i);
    assert(remove(path) == 0);
  }
#ifdef _WIN32
  assert(RemoveDirectoryA(dir));
#else
  assert(rmdir(dir) == 0);
#endif
}

static void test_ransom_tracking_capacity_is_explicit(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  unsigned before = ransom_response_calls;
  for (unsigned i = 0; i < 2050; ++i) {
    char payload[768];
    snprintf(payload, sizeof(payload),
             "ETW1\nprov=kfile\npid=59030\nimg=C:\\Tools\\copyworker.exe\n"
             "file=C:\\Fixture\\doc%u.txt\n", i);
    fill_slot(&slot, EDR_EVENT_FILE_WRITE, payload);
    slot.timestamp_ns += (int64_t)i * 1000000LL;
    enrich_slot_fixture(&slot, &r);
    assert(strstr(r.script_snippet, "ENCRYPTION_CONFIRMED") == NULL);
  }
  edr_detection_decision_evaluate(&r, &d);
  assert(strstr(r.detection_context, "\"tracking_saturated\":true"));
  assert(ransom_response_calls == before);
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
    enrich_slot_fixture(&slot, &r);
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
  enrich_slot_fixture(&slot, &r);
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
    enrich_slot_fixture(&slot, &r);
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
    enrich_slot_fixture(&slot, &r);
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
  assert(strstr(r.detection_context, "\"confirmation_basis\":\"canary_mutation\"") != NULL);
  test_setenv("EDR_RANSOM_CANARY_PATH", "C:\\Users\\Public\\~$canary.docx");
  unsigned before = ransom_response_calls;
  slot.type = EDR_EVENT_FILE_CREATE;
  eval_slot(&slot, &r, &d);
  test_unsetenv("EDR_RANSOM_CANARY_PATH");
  assert(strstr(r.detection_context, "\"canary\":true") == NULL);
  assert(ransom_response_calls == before);
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
    enrich_slot_fixture(&slot, &r);
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
  enrich_slot_fixture(&slot, &r);
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
            "old_value_data=cmd.exe_/c_old\n"
            "value_data=powershell.exe_-w_hidden_-enc_SQBFAFgA\n"
            "operation=set_value\n"
            "registry_source=security_4657\n"
            "registry_attribution=process_id\n"
            "registry_detail_status=captured\n");
  eval_slot(&slot, &r, &d);
  assert(strstr(r.reg_key_path, "CurrentVersion\\Run") != NULL);
  assert(strstr(r.reg_value_name, "Updater") != NULL);
  assert(strcmp(r.reg_source, "security_4657") == 0);
  assert(strcmp(r.reg_attribution, "process_id") == 0);
  assert(strcmp(r.reg_detail_status, "captured") == 0);
  assert(strstr(r.reg_old_value_data, "cmd.exe") != NULL);
  assert(strstr(d.reason, "persistence_change_indicator") != NULL);
  assert(strstr(r.detection_context, "\"registry\"") != NULL);
  assert(strstr(r.detection_context, "\"source\":\"security_4657\"") != NULL);
  assert(strstr(r.detection_context, "\"attribution\":\"process_id\"") != NULL);
  assert(strstr(r.detection_context, "\"old_value_data\":\"cmd.exe_/c_old\"") != NULL);
  assert(strstr(r.detection_context, "\"persistence_change\":true") != NULL);
  assert(strstr(r.detection_context, "persistence_changes") != NULL);
}

static void test_pmfe_followup_bridge_preserves_link_without_false_mitre(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_PMFE_SCAN_RESULT,
            "ETW1\n"
            "prov=pmfe\n"
            "pid=864\n"
            "cmd_id=etw:shellcode:sc-bridge-1\n"
            "followup_only=1\n"
            "source_alert_id=sc-bridge-1\n"
            "pmfe_status=completed_clean\n"
            "pmfe_verdict=clean\n"
            "score=0.05\n"
            "mitre=-\n"
            "detector=pmfe\n");
  eval_slot(&slot, &r, &d);
  assert(r.pid == 864u);
  assert(strstr(r.script_snippet, "source_alert_id=sc-bridge-1") != NULL);
  assert(strstr(r.script_snippet, "pmfe_status=completed_clean") != NULL);
  assert(r.mitre_ttp_count == 0);
  assert(d.suppress);
  assert(strcmp(d.selection_action, "emit_context") == 0);
  assert(strstr(r.detection_context, "\"source_alert_id\":\"sc-bridge-1\"") != NULL);
}

static void test_pmfe_structured_signals_reach_detection_context(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_PMFE_SCAN_RESULT,
            "ETW1\n"
            "prov=pmfe\n"
            "pid=865\n"
            "pmfe_status=completed_suspicious\n"
            "pmfe_verdict=suspicious\n"
            "private_exec=2\n"
            "memfd_exec=1\n"
            "deleted_exec=1\n"
            "mz_hits=1\n"
            "stomp_suspicious=1\n"
            "thread_start_matches=1\n"
            "read_failures=3\n"
            "injection_observed=1\n"
            "score=0.94\n"
            "mitre=T1055\n"
            "detector=pmfe\n");
  eval_slot(&slot, &r, &d);
  assert(!d.drop);
  assert(strstr(r.script_snippet, "private_exec=2") != NULL);
  assert(strstr(r.detection_context, "\"private_exec\":2") != NULL);
  assert(strstr(r.detection_context, "\"memfd_exec\":1") != NULL);
  assert(strstr(r.detection_context, "\"deleted_exec\":1") != NULL);
  assert(strstr(r.detection_context, "\"mz_hits\":1") != NULL);
  assert(strstr(r.detection_context, "\"stomp_suspicious\":1") != NULL);
  assert(strstr(r.detection_context, "\"thread_start_matches\":1") != NULL);
  assert(strstr(r.detection_context, "\"read_failures\":3") != NULL);
  assert(strstr(r.detection_context, "\"injection_observed\":true") != NULL);
}

static void test_kernel_file_read_generation_bridge(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;

  /* Windows collector seam: a manifest Read is emitted only after the
   * NameCreate FileKey binding and exact StartKey actor cache have populated
   * this typed payload. */
  fill_slot(&slot, EDR_EVENT_FILE_READ,
            "ETW1\n"
            "prov=kfile\n"
            "pid=7211\n"
            "img=C:\\ProgramData\\P0Validation\\reader.exe\n"
            "img_canonical=C:\\ProgramData\\P0Validation\\reader.exe\n"
            "img_resolution_status=RESOLVED\n"
            "img_resolution_source=exact_process_start_key_cache\n"
            "cmd=reader.exe --read-once\n"
            "file=C:\\Users\\fixture\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\n"
            "file_key=0x7f00aa11\n"
            "file_read_binding_quality=etw_filekey_namecreate\n"
            "process_start_key=723401\n"
            "process_creation_filetime_100ns=133777777770000000\n"
            "process_generation_source=etw_start_key_live_telemetry\n"
            "file_read_actor_quality=exact_process_start_key_cache\n"
            "source_completeness=COALESCED\n");
  enrich_slot_fixture(&slot, &r);
  assert(r.type == EDR_EVENT_FILE_READ);
  assert(strcmp(r.file_op, "read") == 0);
  assert(strcmp(r.file_path,
                "C:\\Users\\fixture\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data") == 0);
  assert(r.pid == 7211u);
  assert(r.process_start_key == 723401u);
  assert(r.process_creation_filetime_100ns == 133777777770000000ULL);
  assert(strcmp(r.process_generation_source, "etw_start_key_live_telemetry") == 0);
  assert(strcmp(r.image_path_canonical, "C:\\ProgramData\\P0Validation\\reader.exe") == 0);
  assert(strcmp(r.source_completeness, "COALESCED") == 0);

  /* A provider that cannot return ProcessStartKey remains source-only.  It
   * must not acquire a fabricated generation from PID or callback time. */
  fill_slot(&slot, EDR_EVENT_FILE_READ,
            "ETW1\n"
            "prov=kfile\n"
            "pid=7211\n"
            "file=C:\\Users\\fixture\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\n"
            "file_key=0x7f00aa11\n"
            "file_read_binding_quality=etw_filekey_namecreate\n"
            "process_generation_source=etw_process_start_key_unavailable\n"
            "file_read_generation_quality=process_start_key_unavailable\n"
            "source_completeness=NOT_EVALUABLE\n");
  enrich_slot_fixture(&slot, &r);
  assert(r.process_start_key == 0u);
  assert(r.process_creation_filetime_100ns == 0u);
  assert(strcmp(r.source_completeness, "NOT_EVALUABLE") == 0);
}

static void test_windows_image_resolution_and_4688_identity(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  fill_slot(&slot, EDR_EVENT_PROCESS_CREATE,
            "ETW1\n"
            "prov=sec\n"
            "eid=4688\n"
            "epid=4096\n"
            "img=\\Device\\HarddiskVolume7\\Windows\\Temp\\powershell.exe\n"
            "img_raw=\\Device\\HarddiskVolume7\\Windows\\Temp\\powershell.exe\n"
            "img_canonical=C:\\Windows\\Temp\\powershell.exe\n"
            "img_namespace=nt_device\n"
            "img_resolution_status=RESOLVED\n"
            "img_resolution_source=querydosdevice_cache\n"
            "source_completeness=ENRICHMENT_ONLY\n"
            "evidence_revision=2\n"
            "process_creation_time=2026-08-30T00:00:00Z\n"
            "process_creation_filetime_100ns=0x1d0000000000000\n"
            "user=alice\n"
            "user_domain=CONTOSO\n"
            "user_sid=S-1-5-21-100\n"
            "logon_id=0xabc\n"
            "creator_user=svc\n"
            "creator_domain=CONTOSO\n");
  enrich_slot_fixture(&slot, &r);
  assert(r.is_security_4688 == 1u);
  assert(strcmp(r.exe_path, "C:\\Windows\\Temp\\powershell.exe") == 0);
  assert(strcmp(r.image_path_raw, "\\Device\\HarddiskVolume7\\Windows\\Temp\\powershell.exe") == 0);
  assert(strcmp(r.image_path_resolution_status, "RESOLVED") == 0);
  assert(strcmp(r.source_completeness, "ENRICHMENT_ONLY") == 0);
  assert(r.evidence_revision == 2u);
  assert(r.process_creation_filetime_100ns == 0x1d0000000000000ULL);
  assert(strcmp(r.username, "CONTOSO\\alice") == 0);
  assert(strcmp(r.creator_username, "svc") == 0);

  fill_slot(&slot, EDR_EVENT_PROCESS_CREATE,
            "ETW1\nprov=sec\neid=4688\nepid=4096\n"
            "img=C:\\Windows\\Temp\\cmd.exe\n"
            "creator_user=launcher\ncreator_domain=CONTOSO\ncreator_sid=S-1-5-21-creator\n");
  enrich_slot_fixture(&slot, &r);
  assert(strcmp(r.creator_username, "launcher") == 0);
  assert(strcmp(r.creator_sid, "S-1-5-21-creator") == 0);
  assert(!r.username[0] && !r.user_sid[0]);
  assert(strcmp(r.identity_quality, "creator_fallback") == 0);

  fill_slot(&slot, EDR_EVENT_PROCESS_CREATE,
            "ETW1\nprov=sec\neid=4688\nepid=4098\n"
            "img=C:\\Windows\\Temp\\placeholder.exe\n"
            "user=-\nuser_domain=-\nuser_sid=S-1-0-0\nlogon_id=0x0\n"
            "creator_user=SYSTEM\ncreator_domain=NT AUTHORITY\n"
            "creator_sid=S-1-5-18\ncreator_logon_id=0x3e7\n");
  enrich_slot_fixture(&slot, &r);
  assert(!r.username[0] && !r.user_sid[0] && !r.logon_id[0]);
  assert(strcmp(r.creator_sid, "S-1-5-18") == 0);
  assert(strcmp(r.identity_quality, "creator_fallback") == 0);

  fill_slot(&slot, EDR_EVENT_PROCESS_CREATE,
            "ETW1\nprov=kproc\npid=4097\n"
            "img=\\Device\\HarddiskVolume99\\Temp\\powershell.exe\n"
            "img_raw=\\Device\\HarddiskVolume99\\Temp\\powershell.exe\n"
            "img_namespace=nt_device\n"
            "img_resolution_status=NOT_EVALUABLE\n"
            "img_resolution_source=device_map_miss\n");
  enrich_slot_fixture(&slot, &r);
  assert(strcmp(r.image_path_resolution_status, "NOT_EVALUABLE") == 0);
  assert(strcmp(r.exe_path, "\\Device\\HarddiskVolume99\\Temp\\powershell.exe") == 0);

  /* The generic EventHeader PID is not target-process authority.  Preserve
   * the Kernel Process payload target PID end to end. */
  fill_slot(&slot, EDR_EVENT_PROCESS_CREATE,
            "ETW1\nprov=kproc\npid=3764\nepid=8200\nppid=3764\n"
            "img=C:\\Windows\\Temp\\P0CASE\\powershell.exe\n"
            "cmd=powershell.exe -NoProfile -Command exit 0\n"
            "process_start_key=6473924464403231\n"
            "process_creation_filetime_100ns=134170000000000000\n"
            "process_generation_source=kernel_process_payload\n");
  enrich_slot_fixture(&slot, &r);
  assert(r.pid == 8200u);
  assert(r.ppid == 3764u);
  assert(r.process_start_key == 6473924464403231ULL);
  assert(strcmp(r.process_name, "powershell.exe") == 0);
}

static void test_source_truncation_withholds_and_names_rule_fields(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  char payload[sizeof(slot.data)];
  char long_basename[320];
  char long_generation[96];
  char long_hash[80];
  char long_registry_key[1600];
  int written;

  memset(long_basename, 'p', sizeof(long_basename) - 1u);
  long_basename[sizeof(long_basename) - 1u] = '\0';
  memset(long_generation, 'g', sizeof(long_generation) - 1u);
  long_generation[sizeof(long_generation) - 1u] = '\0';
  memset(long_hash, 'a', sizeof(long_hash) - 1u);
  long_hash[sizeof(long_hash) - 1u] = '\0';
  memset(long_registry_key, 'k', sizeof(long_registry_key) - 1u);
  long_registry_key[sizeof(long_registry_key) - 1u] = '\0';

  written = snprintf(payload, sizeof(payload),
                     "ETW1\n"
                     "prov=kproc\n"
                     "pid=9001\n"
                     "img=C:\\Temp\\%s\n"
                     "process_generation_source=%s\n"
                     "sha256=%s\n"
                     "regkey=%s\n",
                     long_basename, long_generation, long_hash, long_registry_key);
  assert(written > 0 && (size_t)written < sizeof(payload));
  fill_slot(&slot, EDR_EVENT_PROCESS_CREATE, payload);
  enrich_slot_fixture(&slot, &r);

  assert(r.process_name[0] == '\0');
  assert(r.process_generation_source[0] == '\0');
  assert(r.exe_hash[0] == '\0');
  assert(r.reg_key_path[0] == '\0');
  assert(strcmp(r.source_completeness, "TRUNCATED") == 0);
  assert(strstr(r.source_truncated_fields, "source.process_name") != NULL);
  assert(strstr(r.source_truncated_fields, "source.process_generation_source") != NULL);
  assert(strstr(r.source_truncated_fields, "source.exe_hash") != NULL);
  assert(strstr(r.source_truncated_fields, "source.reg_key_path") != NULL);
}

static void test_file_write_identity_and_parse_purity(const char *binding_quality, unsigned pid) {
  EdrEventSlot slot;
  EdrBehaviorRecord record;
  unsigned before = ransom_response_calls;
  char payload[1024];
  test_setenv("EDR_RANSOM_CANARY_PATH", "C:\\Fixture\\write-canary.txt");
  snprintf(payload, sizeof(payload),
            "ETW1\nprov=kfile\neid=16\npid=%u\nfile_key=0x987654321\n"
            "file=C:\\Fixture\\write-canary.txt\n"
            "file_write_binding_quality=%s\nfile_write_file_object=0x123456789\n"
            "img=C:\\Fixture\\writer.exe\nprocess_start_key=98765\n"
            "process_creation_filetime_100ns=134238120000000000\n"
            "file_actor_generation_validated=1\n", pid, binding_quality);
  fill_slot(&slot, EDR_EVENT_FILE_WRITE, payload);
  for (int i = 0; i < 10; ++i) {
    edr_behavior_from_slot(&slot, &record);
    assert(record.kernel_file_write && !record.file_actor_generation_validated);
    assert(record.pid == pid && record.file_key == 0x987654321ULL);
    assert(edr_behavior_file_activity_priority(&record) == 0);
    assert(strstr(record.script_snippet, binding_quality));
    assert(strstr(record.script_snippet, "file_write_file_object=0x123456789"));
    assert(strstr(record.script_snippet, "file_write_file_key=0x987654321"));
    assert(!strstr(record.script_snippet, "ransom_counter=1"));
  }
  assert(ransom_response_calls == before);
  edr_behavior_enrich_file_activity(&record);
  assert(strstr(record.script_snippet, "file_write_actor_unverified=1"));
  assert(!strstr(record.script_snippet, "ransom_canary=1"));
  assert(ransom_response_calls == before);

  edr_behavior_from_slot(&slot, &record);
  record.file_actor_generation_validated = 1u; /* Verified-handle boundary. */
  edr_behavior_enrich_file_activity(&record);
  assert(strstr(record.script_snippet, "confirmation_basis=canary_mutation"));
  assert(strstr(record.script_snippet, "file_event_count=1"));
  assert(ransom_response_calls == before + 1u);
  edr_behavior_enrich_file_activity(&record);
  assert(ransom_response_calls == before + 1u);
  assert(!strstr(record.script_snippet, "file_event_count=2"));

  edr_behavior_from_slot(&slot, &record);
  record.file_actor_generation_validated = 1u;
  record.process_creation_filetime_100ns = 0u;
  edr_behavior_enrich_file_activity(&record);
  assert(strstr(record.script_snippet, "file_write_actor_unverified=1"));
  assert(ransom_response_calls == before + 1u);
  test_unsetenv("EDR_RANSOM_CANARY_PATH");

  const uint64_t epoch = 116444736000000000ULL;
  assert(edr_process_generation_contains_event(epoch + 20u, 2000u));
  assert(edr_process_generation_contains_event(epoch + 20u, 2100u));
  assert(!edr_process_generation_contains_event(epoch + 21u, 2000u));
  assert(!edr_process_generation_contains_event(0u, 2000u));
  assert(!edr_process_generation_contains_event(epoch, 2000u));
  assert(!edr_process_generation_contains_event(UINT64_MAX, 2000u));
  assert(!edr_process_generation_contains_event(epoch + 20u, 0u));
}

static void test_unbound_create_cannot_reset_writer_window(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord record;
  unsigned before = ransom_response_calls;
  for (unsigned i = 0; i < 20; ++i) {
    char payload[512];
    snprintf(payload, sizeof(payload),
             "ETW1\nprov=kfile\npid=59500\nimg=C:\\Fixture\\writer.exe\n"
             "file=C:\\Fixture\\mixed%u.dat\n", i);
    fill_slot(&slot, EDR_EVENT_FILE_CREATE, payload);
    slot.timestamp_ns += (int64_t)i * 1000000LL;
    edr_behavior_from_slot(&slot, &record);
    edr_behavior_enrich_file_activity(&record);
    slot.type = EDR_EVENT_FILE_WRITE;
    enrich_slot_fixture(&slot, &record);
  }
  assert(strstr(record.script_snippet, "file_event_count=20"));
  assert(strstr(record.script_snippet, "unique_file_count=20"));
  assert(ransom_response_calls == before);
}

static void test_mutation_identity_and_bounded_context(void) {
  test_setenv("EDR_RANSOM_CANARY_PATH", "C:\\Fixture\\mutation-canary.txt");
  const EdrEventType types[] = {EDR_EVENT_FILE_RENAME, EDR_EVENT_FILE_DELETE};
  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
    EdrEventSlot slot;
    EdrBehaviorRecord r;
    EdrDetectionDecision d;
    char payload[512];
    snprintf(payload, sizeof(payload),
             "ETW1\nprov=kfile\npid=%u\nimg=C:\\Fixture\\mutator.exe\n"
             "file=%s\nold_file=%s\n", 59600u + (unsigned)i,
             i == 0u ? "C:\\Fixture\\renamed.txt" : "C:\\Fixture\\mutation-canary.txt",
             i == 0u ? "C:\\Fixture\\mutation-canary.txt" : "");
    fill_slot(&slot, types[i], payload);
    unsigned before = ransom_response_calls;
    edr_behavior_from_slot(&slot, &r);
    assert(r.kernel_file_activity && !r.file_actor_generation_validated);
    assert(edr_behavior_file_activity_priority(&r) == 0);
    edr_behavior_enrich_file_activity(&r);
    assert(strstr(r.script_snippet, "file_actor_unverified=1"));
    assert(ransom_response_calls == before);
    enrich_slot_fixture(&slot, &r);
    assert(ransom_response_calls == before + 1u);
    memset(r.cmdline, '\\', sizeof(r.cmdline) - 1u);
    memset(r.reg_key_path, '\\', sizeof(r.reg_key_path) - 1u);
    memset(r.reg_value_data, '\\', sizeof(r.reg_value_data) - 1u);
    memset(r.reg_old_value_data, '\\', sizeof(r.reg_old_value_data) - 1u);
    edr_detection_decision_evaluate(&r, &d);
    cJSON *root = cJSON_ParseWithOpts(r.detection_context, NULL, 1);
    assert(root && !cJSON_GetObjectItemCaseSensitive(root, "context_error"));
    cJSON *control = cJSON_GetObjectItemCaseSensitive(root, "ransom_control");
    assert(cJSON_IsObject(control));
    assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(control, "canary")));
    assert(cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(root, "omitted_fields")));
    assert(cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(root, "signals")));
    cJSON_Delete(root);
  }
  test_unsetenv("EDR_RANSOM_CANARY_PATH");
}

static void test_parent_directory_is_not_a_ransom_note(void) {
  EdrEventSlot slot;
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  fill_slot(&slot, EDR_EVENT_FILE_WRITE,
            "ETW1\nprov=kfile\npid=59700\nimg=C:\\Fixture\\writer.exe\n"
            "file=C:\\RansomTests\\invoice.txt\nwin_policy_tags=ransomware_behavior\n");
  eval_slot(&slot, &r, &d);
  cJSON *root = cJSON_ParseWithOpts(r.detection_context, NULL, 1);
  assert(root);
  assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(
      cJSON_GetObjectItemCaseSensitive(root, "signals"), "ransom_note")));
  cJSON_Delete(root);
}

int main(void) {
  test_mutation_identity_and_bounded_context();
  test_parent_directory_is_not_a_ransom_note();
  test_unbound_create_cannot_reset_writer_window();
  test_file_write_identity_and_parse_purity("etw_filekey_namecreate", 59400u);
  test_file_write_identity_and_parse_purity("etw_fileobject_create", 59401u);
  test_scriptblock_sensor_bridge();
  test_amsi_sensor_bridge();
  test_tls_sensor_bridge();
  test_schannel_cert_error_bridge();
  test_ransom_counter_bridge();
  test_ransom_sliding_window_counter();
  test_ransom_repeated_file_and_non_mutations();
  test_ransom_generation_and_file_key_dedup();
  test_ransom_content_change_contract();
  test_ransom_tracking_capacity_is_explicit();
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
  test_pmfe_followup_bridge_preserves_link_without_false_mitre();
  test_pmfe_structured_signals_reach_detection_context();
  test_kernel_file_read_generation_bridge();
  test_windows_image_resolution_and_4688_identity();
  test_source_truncation_withholds_and_names_rule_fields();
  puts("detection_sensor_bridge ok");
  return 0;
}
