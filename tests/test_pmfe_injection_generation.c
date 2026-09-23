#include "edr/correlation_engine.h"
#include "edr/ave_sdk.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

uint64_t edr_monotonic_ns(void) { return UINT64_C(20000000000); }
static unsigned emitted;
void edr_behavior_alert_emit_to_batch(const AVEBehaviorAlert *alert) {
  assert(strstr(alert->user_subject_json, "R-CORR-INJECT-C2-001") != NULL);
  emitted++;
}

static void verify_syscall_outcomes_do_not_seed_injection_sequences(void) {
  const char *names[] = {"process_vm_writev", "process_vm_writev", "memfd_create",
                        "process_vm_writev", "ptrace", "process_vm_writev", ""};
  const int64_t results[] = {-1, 32, 3, 0, 0, 32, 0};
  edr_correlation_configure(1, 1);
  edr_correlation_reload();
  for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    EdrBehaviorRecord record;
    memset(&record, 0, sizeof(record));
    record.type = EDR_EVENT_PROCESS_INJECT;
    record.pid = 6000u + i;
    record.event_time_ns = INT64_C(20000000000) + (int64_t)i * INT64_C(2000000000);
    snprintf(record.process_name, sizeof(record.process_name), "%s", "test.exe");
    if (names[i][0]) {
      snprintf(record.syscall_sensor, sizeof(record.syscall_sensor), "%s", "auditd");
      snprintf(record.syscall_name, sizeof(record.syscall_name), "%s", names[i]);
      record.syscall_result = results[i];
      record.syscall_result_known = i == 1u ? 0u : 1u;
      record.syscall_success_known = record.syscall_result_known;
      record.syscall_success = results[i] >= 0;
    }
    edr_correlation_evaluate(&record);
    record.type = EDR_EVENT_NET_CONNECT;
    record.event_time_ns += INT64_C(1000000000);
    snprintf(record.net_dst, sizeof(record.net_dst), "%s", "203.0.113.7");
    record.net_dport = 443u;
    edr_correlation_evaluate(&record);
    assert(emitted == (i < 5u ? 0u : i - 4u));
  }
}

int main(void) {
  const uint64_t epoch = UINT64_C(116444736000000000);
  EdrLiveProcessGeneration a = {4242u, 1001u, epoch + UINT64_C(100000000)};
  EdrLiveProcessGeneration b = {4242u, 1002u, epoch + UINT64_C(120000000)};
  EdrCorrelationInjectionObservation observation;
  const int64_t second = INT64_C(1000000000);
  edr_correlation_configure(0, 1);
  edr_correlation_note_injection_for_generation(a.pid, &a, "a.exe", 11 * second, "hollowing");
  assert(edr_correlation_latest_injection(&a, 13 * second, 2 * second, &observation));
  assert(observation.process_start_key == a.process_start_key);
  assert(!edr_correlation_latest_injection(&b, 13 * second, 2 * second, &observation));
  assert(!edr_correlation_latest_injection(&a, 13 * second, second, &observation));
  assert(!edr_correlation_latest_injection(&a, 10 * second, 2 * second, &observation));
  /* Even a caller-provided generation cannot bind an event before its birth. */
  edr_correlation_note_injection_for_generation(b.pid, &b, "b.exe", 11 * second, "invalid");
  assert(!edr_correlation_latest_injection(&b, 13 * second, 2 * second, &observation));
  edr_correlation_note_injection_for_generation(b.pid, &b, "b.exe", 13 * second, "current");
  edr_correlation_note_injection_for_generation(a.pid, &a, "a.exe", 11 * second, "late_old");
  assert(edr_correlation_latest_injection(&b, 14 * second, 2 * second, &observation));
  assert(strcmp(observation.technique, "current") == 0);
  /* Arrival order must not hide the newest event time of the same generation. */
  edr_correlation_note_injection_for_generation(b.pid, &b, "b.exe", 12 * second, "out_of_order");
  assert(edr_correlation_latest_injection(&b, 14 * second, 2 * second, &observation));
  assert(strcmp(observation.technique, "current") == 0);
  EdrLiveProcessGeneration unknown = b;
  unknown.process_start_key = 0;
  assert(!edr_correlation_latest_injection(&unknown, 14 * second, 2 * second, &observation));
  unknown = b; unknown.creation_filetime_100ns++;
  assert(!edr_correlation_latest_injection(&unknown, 14 * second, 2 * second, &observation));
  assert(!edr_correlation_latest_injection(NULL, 14 * second, 2 * second, &observation));
  verify_syscall_outcomes_do_not_seed_injection_sequences();
  return 0;
}
