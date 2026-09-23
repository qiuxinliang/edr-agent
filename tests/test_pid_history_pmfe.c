#include "edr/pid_history_pmfe.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_history_enabled(int enabled) {
#ifdef _WIN32
  if (enabled) {
    (void)_putenv_s("EDR_PMFE_PID_HISTORY", "");
  } else {
    (void)_putenv_s("EDR_PMFE_PID_HISTORY", "0");
  }
#else
  if (enabled) {
    (void)unsetenv("EDR_PMFE_PID_HISTORY");
  } else {
    (void)setenv("EDR_PMFE_PID_HISTORY", "0", 1);
  }
#endif
}

static EdrBehaviorRecord record_for(uint32_t pid, uint64_t start_key,
                                    uint64_t creation) {
  EdrBehaviorRecord record;
  memset(&record, 0, sizeof(record));
  record.pid = pid;
  record.process_start_key = start_key;
  record.process_creation_filetime_100ns = creation;
  return record;
}

int main(void) {
  const uint32_t reused_pid = 4242u;
  const uint64_t a_start_key = UINT64_C(0x100001);
  const uint64_t a_creation = UINT64_C(133700000000000001);
  const uint64_t b_start_key = UINT64_C(0x200002);
  const uint64_t b_creation = UINT64_C(133700000000000002);
  const char *a_detail =
      "pid=4242 private_exec_image_hits=2 stomp_suspicious=1 dns_ascii_hits=0 dns_utf16_hits=0 "
      "dns_wire_hits=0 mz_hits=0 elf_hits=0 private_exec=1 memfd_exec=0 "
      "deleted_exec=0 vm_read_failures=0 ave_max_score=0.100 dns_best=0";
  const char *b_detail =
      "pid=4242 stomp_suspicious=2 dns_ascii_hits=0 dns_utf16_hits=0 "
      "dns_wire_hits=0 mz_hits=0 elf_hits=0 private_exec=2 memfd_exec=0 "
      "deleted_exec=0 vm_read_failures=0 ave_max_score=0.200 dns_best=0";
  const char *late_a_detail =
      "pid=4242 stomp_suspicious=3 dns_ascii_hits=0 dns_utf16_hits=0 "
      "dns_wire_hits=0 mz_hits=0 elf_hits=0 private_exec=3 memfd_exec=0 "
      "deleted_exec=0 vm_read_failures=0 ave_max_score=0.300 dns_best=0";

  set_history_enabled(1);
  edr_pid_history_pmfe_init();

  edr_pid_history_pmfe_ingest_scan_detail(
      reused_pid, a_start_key, a_creation, a_detail);
  EdrBehaviorRecord a = record_for(reused_pid, a_start_key, a_creation);
  edr_pid_history_pmfe_fill_record(&a);
  assert(strstr(a.pmfe_snapshot, "\"stomp\":1") != NULL);
  assert(strstr(a.pmfe_snapshot, "\"image_hits\":2") != NULL);

  EdrBehaviorRecord b = record_for(reused_pid, b_start_key, b_creation);
  snprintf(b.pmfe_snapshot, sizeof(b.pmfe_snapshot), "%s", "stale");
  edr_pid_history_pmfe_fill_record(&b);
  assert(b.pmfe_snapshot[0] == '\0');

  edr_pid_history_pmfe_ingest_scan_detail(
      reused_pid, b_start_key, b_creation, b_detail);
  edr_pid_history_pmfe_fill_record(&b);
  assert(strstr(b.pmfe_snapshot, "\"stomp\":2") != NULL);

  /* A late completion for the old process lifetime must neither replace nor
   * hide B's same-PID snapshot. */
  edr_pid_history_pmfe_ingest_scan_detail(
      reused_pid, a_start_key, a_creation, late_a_detail);
  memset(b.pmfe_snapshot, 0, sizeof(b.pmfe_snapshot));
  edr_pid_history_pmfe_fill_record(&b);
  assert(strstr(b.pmfe_snapshot, "\"stomp\":2") != NULL);
  memset(a.pmfe_snapshot, 0, sizeof(a.pmfe_snapshot));
  edr_pid_history_pmfe_fill_record(&a);
  assert(strstr(a.pmfe_snapshot, "\"stomp\":3") != NULL);

  /* Neither an unbound scan nor an unbound record may fall back to PID. */
  edr_pid_history_pmfe_ingest_scan_detail(
      reused_pid, 0u, b_creation, late_a_detail);
  EdrBehaviorRecord unbound = record_for(reused_pid, 0u, b_creation);
  snprintf(unbound.pmfe_snapshot, sizeof(unbound.pmfe_snapshot), "%s", "stale");
  edr_pid_history_pmfe_fill_record(&unbound);
  assert(unbound.pmfe_snapshot[0] == '\0');

  /* Detail values longer than the exported JSON fields remain bounded and
   * NUL-terminated for an exact generation. */
  char long_detail[1024];
  char sample[300];
  memset(sample, 'a', sizeof(sample) - 1u);
  sample[sizeof(sample) - 1u] = '\0';
  (void)snprintf(
      long_detail, sizeof(long_detail),
      "stomp_suspicious=0 dns_ascii_hits=1 dns_utf16_hits=0 dns_wire_hits=0 "
      "mz_hits=0 elf_hits=0 private_exec=0 memfd_exec=0 deleted_exec=0 "
      "vm_read_failures=0 ave_max_score=0.5 dns_best=0.6 dns_sample=%s "
      "dns_owner=-",
      sample);
  edr_pid_history_pmfe_ingest_scan_detail(
      reused_pid, b_start_key, b_creation, long_detail);
  memset(b.pmfe_snapshot, 0, sizeof(b.pmfe_snapshot));
  edr_pid_history_pmfe_fill_record(&b);
  assert(strlen(b.pmfe_snapshot) < sizeof(b.pmfe_snapshot));
  assert(strstr(b.pmfe_snapshot, "\"dns\":1") != NULL);
  assert(strstr(b.pmfe_snapshot, "\"sample\":\"aaaaaaaa") != NULL);

  set_history_enabled(0);
  snprintf(b.pmfe_snapshot, sizeof(b.pmfe_snapshot), "%s", "stale");
  edr_pid_history_pmfe_fill_record(&b);
  assert(b.pmfe_snapshot[0] == '\0');
  set_history_enabled(1);

  edr_pid_history_pmfe_shutdown();
  snprintf(b.pmfe_snapshot, sizeof(b.pmfe_snapshot), "%s", "stale");
  edr_pid_history_pmfe_fill_record(&b);
  assert(b.pmfe_snapshot[0] == '\0');
  edr_pid_history_pmfe_init();
  edr_pid_history_pmfe_fill_record(&b);
  assert(b.pmfe_snapshot[0] == '\0');
  edr_pid_history_pmfe_shutdown();
  return 0;
}
