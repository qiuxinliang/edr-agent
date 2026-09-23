#include "edr/ave_sdk.h"
#include "edr/ave_cross_engine_feed.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_feed_count;
static AVEBehaviorEvent g_last_event;

AVE_EXPORT int AVE_CALL AVE_FeedEventEx(const AVEBehaviorEvent *event, size_t event_size) {
  assert(event != NULL);
  assert(event_size == sizeof(*event));
  g_last_event = *event;
  g_feed_count++;
  return AVE_OK;
}

static void reset_capture(void) {
  memset(&g_last_event, 0, sizeof(g_last_event));
  g_feed_count = 0;
}

static void make_enriched_record(EdrBehaviorRecord *r, EdrEventType type, uint32_t pid) {
  edr_behavior_record_init(r);
  r->type = type;
  r->pid = pid;
  r->ppid = 100u;
  snprintf(r->process_name, sizeof(r->process_name), "%s", "powershell.exe");
  snprintf(r->exe_path, sizeof(r->exe_path), "%s",
           "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(r->cmdline, sizeof(r->cmdline), "%s", "powershell.exe -NoP -Command hostname");
}

static void make_long_text(char *out, size_t out_cap, char fill) {
  assert(out != NULL);
  assert(out_cap > 1u);
  memset(out, (unsigned char)fill, out_cap - 1u);
  out[out_cap - 1u] = '\0';
}

static void expect_atomic_reject(const EdrBehaviorRecord *r) {
  reset_capture();
  edr_ave_cross_engine_feed_from_record(r);
  assert(g_feed_count == 0);
  assert(g_last_event.pid == 0u);
  assert(g_last_event.process_name[0] == '\0');
  assert(g_last_event.process_path[0] == '\0');
  assert(g_last_event.cmdline[0] == '\0');
  assert(g_last_event.target_path[0] == '\0');
  assert(g_last_event.target_ip[0] == '\0');
  assert(g_last_event.target_domain[0] == '\0');
}

static void test_rejects_pid_only_process_create(void) {
  EdrBehaviorRecord r;
  edr_behavior_record_init(&r);
  r.type = EDR_EVENT_PROCESS_CREATE;
  r.pid = 4242u;

  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 0);
}

static void test_accepts_enriched_process_create(void) {
  EdrBehaviorRecord r;
  edr_behavior_record_init(&r);
  r.type = EDR_EVENT_PROCESS_CREATE;
  r.pid = 4243u;
  r.ppid = 100u;
  snprintf(r.process_name, sizeof(r.process_name), "%s", "powershell.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s", "powershell.exe -NoP -Command hostname");

  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 1);
  assert(g_last_event.pid == 4243u);
  assert(g_last_event.ppid == 100u);
  assert(g_last_event.event_type == AVE_EVT_PROCESS_CREATE);
  assert(strstr(g_last_event.target_path, "powershell.exe") != NULL);
}

static void test_rejects_file_without_process_identity(void) {
  EdrBehaviorRecord r;
  edr_behavior_record_init(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  r.pid = 5000u;
  snprintf(r.file_path, sizeof(r.file_path), "%s", "C:\\Users\\test\\AppData\\Local\\Temp\\a.tmp");

  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 0);
}

static void test_accepts_enriched_file_signal(void) {
  EdrBehaviorRecord r;
  edr_behavior_record_init(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  r.pid = 5001u;
  snprintf(r.process_name, sizeof(r.process_name), "%s", "powershell.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(r.file_path, sizeof(r.file_path), "%s", "C:\\Users\\test\\AppData\\Local\\Temp\\note.locked");
  snprintf(r.file_op, sizeof(r.file_op), "%s", "write");

  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 1);
  assert(g_last_event.event_type == AVE_EVT_FILE_WRITE);
  assert(strstr(g_last_event.target_path, "note.locked") != NULL);
  assert(g_last_event.suspicious_extension_burst == 1u);
  assert(g_last_event.ransom_counter_score > 0.17f && g_last_event.ransom_counter_score < 0.19f);
}

static void test_ransom_ext_requires_final_extension(void) {
  EdrBehaviorRecord r;
  edr_behavior_record_init(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  r.pid = 5002u;
  snprintf(r.process_name, sizeof(r.process_name), "%s", "backup.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Tools\\backup.exe");
  snprintf(r.file_path, sizeof(r.file_path), "%s", "C:\\Users\\test\\Documents\\encrypted_notes.txt");
  snprintf(r.file_op, sizeof(r.file_op), "%s", "write");

  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 1);
  assert(g_last_event.suspicious_extension_burst == 0u);
  assert(g_last_event.ransom_counter_score == 0.f);
}

static void test_rejects_oversized_event_fields_atomically_and_recovers(void) {
  EdrBehaviorRecord r;

  make_enriched_record(&r, EDR_EVENT_PROCESS_CREATE, 5100u);
  make_long_text(r.exe_path, sizeof(r.exe_path), 'x');
  expect_atomic_reject(&r);

  make_enriched_record(&r, EDR_EVENT_PROCESS_CREATE, 5101u);
  make_long_text(r.cmdline, sizeof(r.cmdline), 'c');
  expect_atomic_reject(&r);

  make_enriched_record(&r, EDR_EVENT_FILE_WRITE, 5102u);
  snprintf(r.file_op, sizeof(r.file_op), "%s", "write");
  make_long_text(r.file_path, sizeof(r.file_path), 'f');
  expect_atomic_reject(&r);

  make_enriched_record(&r, EDR_EVENT_NET_CONNECT, 5103u);
  make_long_text(r.net_dst, sizeof(r.net_dst), '1');
  r.net_dport = 443u;
  expect_atomic_reject(&r);

  make_enriched_record(&r, EDR_EVENT_NET_DNS_QUERY, 5104u);
  make_long_text(r.dns_query, sizeof(r.dns_query), 'd');
  expect_atomic_reject(&r);

  make_enriched_record(&r, EDR_EVENT_REG_SET_VALUE, 5105u);
  make_long_text(r.reg_key_path, sizeof(r.reg_key_path), 'r');
  expect_atomic_reject(&r);

  make_enriched_record(&r, EDR_EVENT_PROCESS_CREATE, 5106u);
  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 1);
  assert(g_last_event.pid == 5106u);
  assert(strcmp(g_last_event.process_name, "powershell.exe") == 0);
  assert(strstr(g_last_event.process_path, "powershell.exe") != NULL);
  assert(strstr(g_last_event.cmdline, "hostname") != NULL);
}

static void test_pmfe_image_hint_requires_same_region_validation(void) {
  EdrBehaviorRecord r;
  make_enriched_record(&r, EDR_EVENT_PMFE_SCAN_RESULT, 5200u);
  snprintf(r.cmdline, sizeof(r.cmdline), "%s", "private_exec=1 mz_hits=1");
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s", "score=0.35;thread_start_matches=1");
  snprintf(r.pmfe_snapshot, sizeof(r.pmfe_snapshot), "%s", "{\"mz\":1,\"elf\":1,\"stomp\":1}");
  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 1);
  assert(g_last_event.pmfe_pe_found == 0u);
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s", "score=0.90;private_exec_image_hits=1");
  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 1);
  assert(g_last_event.pmfe_pe_found == 1u);
  assert(g_last_event.pmfe_confidence == 0.90f);
}

static void test_linux_syscall_outcomes_do_not_create_injection_verdicts(void) {
  EdrBehaviorRecord r;
  make_enriched_record(&r, EDR_EVENT_PROCESS_INJECT, 5210u);
  /* Existing Windows input retains the same feed semantics. */
  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 1 && g_last_event.event_type == AVE_EVT_PROCESS_INJECT);
  strcpy(r.syscall_sensor, "auditd");
  expect_atomic_reject(&r); /* old producer: name/outcome absent */
  strcpy(r.syscall_name, "process_vm_writev");
  expect_atomic_reject(&r);
  r.syscall_result_known = 1;
  r.syscall_result = 4096;
  expect_atomic_reject(&r); /* return value alone is not trusted success */
  r.syscall_success_known = 1;
  expect_atomic_reject(&r); /* explicit failure */
  r.syscall_success = 1;
  r.syscall_result = -1;
  expect_atomic_reject(&r);
  r.syscall_result = 0;
  expect_atomic_reject(&r);
  r.syscall_result = 4096;
  reset_capture();
  edr_ave_cross_engine_feed_from_record(&r);
  assert(g_feed_count == 1 && g_last_event.event_type == AVE_EVT_PROCESS_INJECT);
  const char *not_injection[] = {"memfd_create", "process_vm_readv", "ptrace"};
  for (size_t i=0; i<sizeof(not_injection)/sizeof(not_injection[0]); ++i) {
    strcpy(r.syscall_name, not_injection[i]);
    expect_atomic_reject(&r);
  }
}

int main(void) {
  test_linux_syscall_outcomes_do_not_create_injection_verdicts();
  test_pmfe_image_hint_requires_same_region_validation();
  test_rejects_pid_only_process_create();
  test_accepts_enriched_process_create();
  test_rejects_file_without_process_identity();
  test_accepts_enriched_file_signal();
  test_ransom_ext_requires_final_extension();
  test_rejects_oversized_event_fields_atomically_and_recovers();
  puts("ave_cross_engine_feed_quality ok");
  return 0;
}
