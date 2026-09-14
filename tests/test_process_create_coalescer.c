#include "edr/process_create_coalescer.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#include <pthread.h>
#endif

#define WINDOW_NS (3000ULL * 1000000ULL)

static void rec(EdrBehaviorRecord *record, uint32_t pid, int security,
                uint64_t start_key, const char *path, int64_t event_time_ns) {
  memset(record, 0, sizeof(*record));
  record->type = EDR_EVENT_PROCESS_CREATE;
  record->pid = pid;
  record->ppid = 4u;
  record->is_security_4688 = (uint8_t)security;
  record->event_time_ns = event_time_ns;
  if (!security) record->process_start_key = start_key;
  snprintf(record->exe_path, sizeof(record->exe_path), "%s", path ? path : "");
  snprintf(record->image_path_canonical, sizeof(record->image_path_canonical), "%s",
           path ? path : "");
  snprintf(record->process_name, sizeof(record->process_name), "%s", "cmd.exe");
  if (security) {
    snprintf(record->cmdline, sizeof(record->cmdline), "%s /c x.cmd", path ? path : "");
    snprintf(record->user_sid, sizeof(record->user_sid), "%s", "S-1-5-21-target");
    snprintf(record->logon_id, sizeof(record->logon_id), "%s", "0x0000000000000021");
    snprintf(record->identity_source, sizeof(record->identity_source), "%s", "target_4688");
    snprintf(record->identity_quality, sizeof(record->identity_quality), "%s", "target_4688");
  }
}

static void make_kernel_independent(EdrBehaviorRecord *record) {
  if (!record) return;
  record->process_creation_filetime_100ns = 133801632000000000ULL;
  snprintf(record->cmdline, sizeof(record->cmdline), "%s", "trusted.exe --same-generation");
  snprintf(record->command_line_origin, sizeof(record->command_line_origin), "%s",
           "live_same_generation");
  snprintf(record->parent_path, sizeof(record->parent_path), "%s", "C:\\parent.exe");
  snprintf(record->parent_creation_time, sizeof(record->parent_creation_time), "%s",
           "2026-09-02T00:00:00Z");
  snprintf(record->username, sizeof(record->username), "%s", "SYSTEM");
  snprintf(record->user_sid, sizeof(record->user_sid), "%s", "S-1-5-18");
  snprintf(record->identity_source, sizeof(record->identity_source), "%s", "token_query");
  snprintf(record->identity_quality, sizeof(record->identity_quality), "%s", "token_sid");
}

static int need(int value, const char *what) {
  if (!value) fprintf(stderr, "FAIL: %s\n", what);
  return value;
}

#if !defined(_WIN32)
typedef struct {
  uint32_t pid_base;
  int failed;
} CoalescerStressArgs;

/* Exercise submit/poll/reset/metrics interleaving under TSAN. The test does
 * not assert a correlation outcome while reset races it; it asserts that all
 * returned enum values and bounded metric snapshots stay valid. */
static void *coalescer_submit_stress(void *opaque) {
  CoalescerStressArgs *args = (CoalescerStressArgs *)opaque;
  for (uint32_t i = 0u; i < 4000u; ++i) {
    EdrBehaviorRecord kernel;
    EdrBehaviorRecord security;
    EdrBehaviorRecord out;
    rec(&kernel, args->pid_base + (i % 32u), 0, i + 1u,
        "C:\\stress.exe", 9000000000LL + (int64_t)i * 10LL);
    rec(&security, args->pid_base + (i % 32u), 1, 0u,
        "C:\\stress.exe", 9000000001LL + (int64_t)i * 10LL);
    EdrProcessCoalesceResult first = edr_process_coalescer_submit(&kernel, 1, i, &out);
    EdrProcessCoalesceResult second = edr_process_coalescer_submit(&security, 1, i + 1u, &out);
    if (first < EDR_PROCESS_COALESCE_PASS || first > EDR_PROCESS_COALESCE_READY ||
        second < EDR_PROCESS_COALESCE_PASS || second > EDR_PROCESS_COALESCE_READY) {
      args->failed = 1;
      break;
    }
  }
  return NULL;
}

static void *coalescer_poll_stress(void *opaque) {
  CoalescerStressArgs *args = (CoalescerStressArgs *)opaque;
  for (uint32_t i = 0u; i < 4000u; ++i) {
    EdrBehaviorRecord out;
    int result = edr_process_coalescer_poll(10000000000ULL + i, &out);
    if (result != 0 && result != 1) args->failed = 1;
  }
  return NULL;
}

static void *coalescer_reset_stress(void *opaque) {
  CoalescerStressArgs *args = (CoalescerStressArgs *)opaque;
  for (uint32_t i = 0u; i < 400u; ++i) edr_process_coalescer_reset();
  (void)args;
  return NULL;
}

static void *coalescer_metrics_stress(void *opaque) {
  CoalescerStressArgs *args = (CoalescerStressArgs *)opaque;
  for (uint32_t i = 0u; i < 4000u; ++i) {
    EdrProcessCoalescerMetrics metrics;
    edr_process_coalescer_get_metrics(&metrics);
    if (metrics.capacity != 128u || metrics.slots_used > metrics.capacity) {
      args->failed = 1;
      break;
    }
  }
  return NULL;
}
#endif

int main(void) {
  static EdrBehaviorRecord out;
  int ok = 1;

  /* A failed EvtRender must remain non-correlatable. Once the real recorded
   * timestamp is available, the same source pair may merge; callback time is
   * never an acceptable substitute and no safety gate is relaxed. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 4532u, 0, 0xa1u, "C:\\powershell.exe",
                                    1789252694245704300LL);
    rec(&security, 4532u, 1, 0u, "C:\\powershell.exe", 0);
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "kernel waits for recorded-time enrichment");
    ok &= need(edr_process_coalescer_submit(&security, 1, 20u, &out) == EDR_PROCESS_COALESCE_PASS,
               "zero-time Security event cannot participate in correlation");
    security.event_time_ns = 1789252694245719700LL;
    ok &= need(edr_process_coalescer_submit(&security, 1, 30u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "valid recorded time enables generation-bound correlation");
    ok &= need(edr_process_coalescer_poll(WINDOW_NS + 30u, &out) == 1 &&
                   strcmp(out.source_completeness, "COALESCED") == 0 &&
                   out.event_time_ns == kernel.event_time_ns &&
                   out.process_start_key == kernel.process_start_key &&
                   strcmp(out.cmdline, security.cmdline) == 0,
               "recovered source time merges command context without replacing kernel identity");
  }

  /* Kernel -> 4688: keep both pending through the window so another raw
   * StartKey can invalidate an apparent PID/path match. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 9u, 0, 0xa1u, "C:\\a.exe", 1000000000LL);
    rec(&security, 9u, 1, 0u, "C:\\a.exe", 1000000100LL);
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "kernel first holds for raw-generation correlation");
    ok &= need(edr_process_coalescer_submit(&security, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "4688 is retained instead of immediately merged");
    ok &= need(edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.source_completeness, "COALESCED") == 0 &&
                   strcmp(out.user_sid, "S-1-5-21-target") == 0,
               "kernel to 4688 emits one target-subject correlation at deadline");
    ok &= need(edr_process_coalescer_submit(&security, 1, WINDOW_NS + 30u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&kernel, 1, WINDOW_NS + 40u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 40u, &out) == 0,
               "late 4688 and duplicate kernel callbacks are consumed by the emitted-generation tombstone");
  }

  /* Windows Security audit delivery was observed roughly two seconds after
   * Kernel-Process on ARM64.  That source-time skew must still form one
   * generation-bound record. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 19u, 0, 0xa19u, "C:\\slow4688.exe", 1000000000LL);
    rec(&security, 19u, 1, 0u, "C:\\slow4688.exe", 3000000000LL);
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&security, 1, 20u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.source_completeness, "COALESCED") == 0,
               "two-second ARM64 Security audit skew coalesces within the bounded window");
  }

  /* PID and normalized path are not unique across process generations.  The
   * creator/parent PID must also agree before 4688 may enrich a raw start. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord wrong_parent;
    rec(&kernel, 20u, 0, 0xa20u, "C:\\parent-bound.exe", 1000000000LL);
    rec(&wrong_parent, 20u, 1, 0u, "C:\\parent-bound.exe", 1000000100LL);
    wrong_parent.ppid = 5u;
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&wrong_parent, 1, 20u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.source_completeness, "CORRELATION_MISSING") == 0 &&
                   !out.user_sid[0] && !out.cmdline[0],
               "4688 with a different parent PID remains separate source-only evidence");
  }

  /* On the affected ARM64 host Security 4688 source time preceded the Kernel
   * ProcessStart by up to 2.8 seconds.  That advisory record is rejected, but
   * it cannot revoke command/token/parent evidence captured from the exact
   * live StartKey/FILETIME generation. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord older_security;
    rec(&kernel, 119u, 0, 0xa119u, "C:\\complete.exe", 4000000000LL);
    rec(&older_security, 119u, 1, 0u, "C:\\complete.exe", 1300000000LL);
    EdrProcessCoalescerMetrics metrics;
    make_kernel_independent(&kernel);
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&older_security, 1, 20u, &out) ==
                   EDR_PROCESS_COALESCE_PASS &&
                   edr_process_coalescer_poll(WINDOW_NS + 10u, &out) == 1 &&
                   strcmp(out.source_completeness, "CORRELATION_MISSING") == 0 &&
                   strcmp(out.command_line_origin, "live_same_generation") == 0 &&
                   strcmp(out.user_sid, "S-1-5-18") == 0,
               "negative 4688 skew cannot downgrade independently complete kernel evidence");
    edr_process_coalescer_get_metrics(&metrics);
    ok &= need(metrics.ambiguous_rejects >= 1u,
               "rejected negative-skew enrichment remains observable");
  }

  /* The same invariant holds when the negatively-skewed audit callback is
   * delivered first: it stays source-only in its own slot. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord older_security;
    static EdrBehaviorRecord kernel;
    rec(&older_security, 120u, 1, 0u, "C:\\arrival-complete.exe", 1300000000LL);
    rec(&kernel, 120u, 0, 0xa120u, "C:\\arrival-complete.exe", 4000000000LL);
    make_kernel_independent(&kernel);
    ok &= need(edr_process_coalescer_submit(&older_security, 1, 10u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&kernel, 1, 20u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.source_completeness, "CORRELATION_MISSING") == 0 &&
                   strcmp(out.command_line_origin, "live_same_generation") == 0,
               "arrival-first negative 4688 cannot contaminate complete kernel evidence");
  }

  /* An already validated target token is stronger than advisory 4688 Target
   * Subject data and must survive the merge. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 29u, 0, 0xa29u, "C:\\token.exe", 1000000000LL);
    rec(&security, 29u, 1, 0u, "C:\\token.exe", 1000000100LL);
    snprintf(kernel.user_sid, sizeof(kernel.user_sid), "%s", "S-1-5-21-live-token");
    snprintf(kernel.identity_source, sizeof(kernel.identity_source), "%s", "token_query");
    snprintf(kernel.identity_quality, sizeof(kernel.identity_quality), "%s", "token_sid");
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&security, 1, 20u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.user_sid, "S-1-5-21-live-token") == 0 &&
                   strcmp(out.identity_quality, "token_sid") == 0,
               "coalescing preserves stronger live token identity");
  }

  /* A merge intentionally records `COALESCED`, but it must preserve source
   * omissions from both observations. Security-owned token fields must follow
   * the same generation-safe join instead of disappearing at coalescing. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 91u, 0, 0xa11u, "C:\\truncated.exe", 1100000000LL);
    rec(&security, 91u, 1, 0u, "C:\\truncated.exe", 1100000100LL);
    snprintf(kernel.source_completeness, sizeof(kernel.source_completeness), "%s", "TRUNCATED");
    snprintf(kernel.source_truncated_fields, sizeof(kernel.source_truncated_fields), "%s",
             "source.process_name,source.exe_hash");
    snprintf(security.source_completeness, sizeof(security.source_completeness), "%s", "TRUNCATED");
    snprintf(security.source_truncated_fields, sizeof(security.source_truncated_fields), "%s",
             "source.cmdline,source.exe_hash");
    snprintf(security.integrity_level, sizeof(security.integrity_level), "%s", "S-1-16-16384");
    security.token_elevation = 1u;
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&security, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.source_completeness, "COALESCED") == 0 &&
                   strcmp(out.source_truncated_fields,
                          "source.process_name,source.exe_hash,source.cmdline") == 0 &&
                   strcmp(out.integrity_level, "S-1-16-16384") == 0 &&
                   out.token_elevation == 1u && out.process_start_key == 0xa11u,
               "coalescing preserves source omissions and token evidence on the raw generation");
  }

  /* A complete generation-bound Kernel/live command is the selected value;
   * a clipped 4688 prefix must not revoke it merely because other 4688 fields
   * are useful enrichment. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 911u, 0, 0xa111u, "C:\\kernel-complete.exe", 1110000000LL);
    rec(&security, 911u, 1, 0u, "C:\\kernel-complete.exe", 1110000100LL);
    snprintf(kernel.cmdline, sizeof(kernel.cmdline), "%s", "kernel-complete.exe --trusted-full-command");
    snprintf(kernel.command_line_origin, sizeof(kernel.command_line_origin), "%s",
             "live_same_generation");
    snprintf(security.cmdline, sizeof(security.cmdline), "%s", "kernel-complete.exe --clipped");
    snprintf(security.source_truncated_fields, sizeof(security.source_truncated_fields), "%s",
             "source.cmdline,source.exe_hash");
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&security, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.cmdline, kernel.cmdline) == 0 &&
                   strcmp(out.command_line_origin, "live_same_generation") == 0 &&
                   out.source_truncated_fields[0] == '\0',
               "complete Kernel fields ignore unused 4688 truncation provenance");
  }

  /* When Kernel has no command, the 4688 prefix becomes the selected value and
   * its truncation declaration must remain attached to that value. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 912u, 0, 0xa112u, "C:\\security-prefix.exe", 1120000000LL);
    rec(&security, 912u, 1, 0u, "C:\\security-prefix.exe", 1120000100LL);
    snprintf(security.source_truncated_fields, sizeof(security.source_truncated_fields), "%s",
             "source.cmdline");
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&security, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.cmdline, security.cmdline) == 0 &&
                   strstr(out.source_truncated_fields, "source.cmdline") != NULL,
               "selected truncated 4688 command keeps source.cmdline provenance");
  }

  /* A complete 4688 command can replace a clipped Kernel value from the same
   * bounded correlation. Only the superseded command marker is removed; other
   * Kernel source omissions remain conservative. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 913u, 0, 0xa113u, "C:\\security-complete.exe", 1130000000LL);
    rec(&security, 913u, 1, 0u, "C:\\security-complete.exe", 1130000100LL);
    snprintf(kernel.cmdline, sizeof(kernel.cmdline), "%s", "security-complete.exe --kernel-prefix");
    snprintf(kernel.source_completeness, sizeof(kernel.source_completeness), "%s", "TRUNCATED");
    snprintf(kernel.source_truncated_fields, sizeof(kernel.source_truncated_fields), "%s",
             "source.cmdline");
    snprintf(security.cmdline, sizeof(security.cmdline), "%s",
             "security-complete.exe --complete-security-command");
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&security, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.cmdline, security.cmdline) == 0 &&
                   !strstr(out.source_truncated_fields, "source.cmdline"),
               "complete 4688 command replaces truncated Kernel command and clears its marker");
  }

  /* Overflow cannot prove which field was omitted. It follows an adopted 4688
   * value and remains a fail-closed declaration for downstream consumers. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 914u, 0, 0xa114u, "C:\\overflow-command.exe", 1140000000LL);
    rec(&security, 914u, 1, 0u, "C:\\overflow-command.exe", 1140000100LL);
    snprintf(security.source_truncated_fields, sizeof(security.source_truncated_fields), "%s",
             "source.list_overflow");
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&security, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.cmdline, security.cmdline) == 0 &&
                   strcmp(out.source_truncated_fields, "source.list_overflow") == 0,
               "adopted 4688 command propagates unknown source-list overflow conservatively");
  }

  /* An overflow on the stronger Kernel record is uncertainty, not proof that
   * its command was clipped. Keep the generation-bound live command, preserve
   * overflow, and let downstream policy remain fail-closed. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 915u, 0, 0xa115u, "C:\\kernel-overflow.exe", 1150000000LL);
    rec(&security, 915u, 1, 0u, "C:\\kernel-overflow.exe", 1150000100LL);
    snprintf(kernel.cmdline, sizeof(kernel.cmdline), "%s", "kernel-overflow.exe --trusted-live");
    snprintf(kernel.command_line_origin, sizeof(kernel.command_line_origin), "%s",
             "live_same_generation");
    snprintf(kernel.source_truncated_fields, sizeof(kernel.source_truncated_fields), "%s",
             "source.list_overflow");
    snprintf(security.cmdline, sizeof(security.cmdline), "%s",
             "kernel-overflow.exe --security-complete");
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&security, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.cmdline, kernel.cmdline) == 0 &&
                   strcmp(out.command_line_origin, "live_same_generation") == 0 &&
                   strcmp(out.source_truncated_fields, "source.list_overflow") == 0,
               "unknown Kernel overflow cannot authorize weaker 4688 command replacement");
  }

  /* A same-generation Security observation may fill missing token evidence,
   * but cannot downgrade an already validated kernel/live-token value. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 92u, 0, 0xa12u, "C:\\strong-token.exe", 1200000000LL);
    rec(&security, 92u, 1, 0u, "C:\\strong-token.exe", 1200000100LL);
    snprintf(kernel.integrity_level, sizeof(kernel.integrity_level), "%s", "High");
    kernel.token_elevation = 2u;
    snprintf(security.integrity_level, sizeof(security.integrity_level), "%s", "S-1-16-8192");
    security.token_elevation = 1u;
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&security, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.integrity_level, "High") == 0 && out.token_elevation == 2u &&
                   out.process_start_key == 0xa12u,
               "4688 merge cannot downgrade stronger same-generation token evidence");
  }

  /* 4688 -> kernel must use the same pending-window rule. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord security;
    static EdrBehaviorRecord kernel;
    rec(&security, 10u, 1, 0u, "C:\\b.exe", 2000000200LL);
    rec(&kernel, 10u, 0, 0xb1u, "C:\\b.exe", 2000000000LL);
    ok &= need(edr_process_coalescer_submit(&security, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "4688 first holds as unbound enrichment");
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "kernel inherits no generation from 4688");
    ok &= need(edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   out.process_start_key == 0xb1u &&
                   strcmp(out.identity_quality, "target_4688") == 0,
               "4688 to kernel keeps raw StartKey owned by kernel event");
  }

  /* The same direction rule applies when Security arrives first: an older A
   * audit must not be adopted when a later raw B generation is received. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord late_a;
    static EdrBehaviorRecord kernel_b;
    rec(&late_a, 100u, 1, 0u, "C:\\arrival-first.exe", 2400000050LL);
    rec(&kernel_b, 100u, 0, 0xb01u, "C:\\arrival-first.exe", 2400000100LL);
    ok &= need(edr_process_coalescer_submit(&late_a, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&kernel_b, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.source_completeness, "NOT_EVALUABLE") == 0 &&
                   !out.user_sid[0] && !out.cmdline[0],
               "arrival-first old 4688 cannot merge into later raw generation B");
  }

  /* A 4688 timestamp cannot predate the kernel ProcessStart it enriches.
   * Arrival order is irrelevant: a late A audit with an older event time
   * makes PID-reused B source-only instead of lending B A's command/SID. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord late_a;
    rec(&kernel, 101u, 0, 0xb11u, "C:\\direction.exe", 2500000100LL);
    rec(&late_a, 101u, 1, 0u, "C:\\direction.exe", 2500000050LL);
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&late_a, 1, 20u, &out) == EDR_PROCESS_COALESCE_PASS &&
                   edr_process_coalescer_poll(WINDOW_NS + 10u, &out) == 1 &&
                   strcmp(out.source_completeness, "NOT_EVALUABLE") == 0 &&
                   !out.user_sid[0] && !out.cmdline[0],
               "pre-kernel 4688 is rejected rather than merged into a newer raw generation");
  }

  /* No 4688 is correlation missing, not inherently unevaluable: the live
   * StartKey/FILETIME/path/file-id token gate gets the final decision. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    rec(&kernel, 11u, 0, 0xc1u, "C:\\c.exe", 3000000000LL);
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "no-4688 kernel starts bounded window");
    ok &= need(edr_process_coalescer_poll(WINDOW_NS + 10u, &out) == 1 &&
                   strcmp(out.source_completeness, "CORRELATION_MISSING") == 0,
               "no-4688 is passed to generation-revalidated token lookup");
  }

  /* Do not rely on an arbitrary tombstone extension: when B arrives after A
   * tombstone expiry, the directed event-time invariant still rejects late A
   * 4688 and makes B non-evaluable without A subject/command/action data. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel_a;
    static EdrBehaviorRecord kernel_b;
    static EdrBehaviorRecord delayed_a;
    rec(&kernel_a, 132u, 0, 0xe21u, "C:\\late-reuse.exe", 5200000000LL);
    rec(&kernel_b, 132u, 0, 0xe22u, "C:\\late-reuse.exe", 5200000100LL);
    rec(&delayed_a, 132u, 1, 0u, "C:\\late-reuse.exe", 5200000050LL);
    ok &= need(edr_process_coalescer_submit(&kernel_a, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 10u, &out) == 1 &&
                   edr_process_coalescer_submit(&kernel_b, 1, 2u * WINDOW_NS + 10u, &out) ==
                       EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&delayed_a, 1, 2u * WINDOW_NS + 20u, &out) ==
                       EDR_PROCESS_COALESCE_PASS &&
                   edr_process_coalescer_poll(3u * WINDOW_NS + 10u, &out) == 1 &&
                   out.process_start_key == 0xe22u &&
                   strcmp(out.source_completeness, "NOT_EVALUABLE") == 0 &&
                   !out.user_sid[0] && !out.cmdline[0],
               "late A 4688 cannot borrow B's new receipt window after A tombstone expires");
  }

  /* A exits then the PID/path is reused by B. A delayed 4688 cannot select
   * either raw generation, so neither record obtains target identity. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel_a;
    static EdrBehaviorRecord kernel_b;
    static EdrBehaviorRecord delayed_a_4688;
    rec(&kernel_a, 12u, 0, 0xd1u, "C:\\reuse.exe", 4000000000LL);
    rec(&kernel_b, 12u, 0, 0xd2u, "C:\\reuse.exe", 4000000100LL);
    rec(&delayed_a_4688, 12u, 1, 0u, "C:\\reuse.exe", 4000000150LL);
    EdrProcessCoalescerMetrics metrics;
    ok &= need(edr_process_coalescer_submit(&kernel_a, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "generation A holds");
    ok &= need(edr_process_coalescer_submit(&kernel_b, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "reused PID generation B holds without replacing A");
    ok &= need(edr_process_coalescer_submit(&delayed_a_4688, 1, 30u, &out) == EDR_PROCESS_COALESCE_PASS,
               "ambiguous delayed 4688 is never assigned to B");
    ok &= need(edr_process_coalescer_poll(WINDOW_NS + 30u, &out) == 1 &&
                   strcmp(out.source_completeness, "NOT_EVALUABLE") == 0 && !out.user_sid[0],
               "first ambiguous generation has no target token identity");
    ok &= need(edr_process_coalescer_poll(WINDOW_NS + 30u, &out) == 1 &&
                   strcmp(out.source_completeness, "NOT_EVALUABLE") == 0 && !out.user_sid[0],
               "second ambiguous generation has no target token identity or action path");
    edr_process_coalescer_get_metrics(&metrics);
    ok &= need(metrics.ambiguous_rejects >= 1u, "PID reuse ambiguity is observable");
  }

  /* A late Security event is not allowed to join a slot after its deadline. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    rec(&kernel, 13u, 0, 0xe1u, "C:\\expired.exe", 5000000000LL);
    rec(&security, 13u, 1, 0u, "C:\\expired.exe", 5000000100LL);
    EdrProcessCoalescerMetrics metrics;
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "kernel deadline is armed");
    ok &= need(edr_process_coalescer_submit(&security, 1, WINDOW_NS + 11u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD,
               "expired 4688 is retained separately rather than merged");
    ok &= need(edr_process_coalescer_poll(WINDOW_NS + 11u, &out) == 1 &&
                   strcmp(out.source_completeness, "CORRELATION_MISSING") == 0 && !out.user_sid[0],
               "expired 4688 cannot change emitted kernel target identity");
    edr_process_coalescer_get_metrics(&metrics);
    ok &= need(metrics.stale_rejects >= 1u, "deadline rejection is observable");
  }

  /* Once A has expired and been emitted, B is marked ambiguous as soon as it
   * collides with A's tombstone.  This remains true when delayed A 4688
   * arrives after the tombstone expires but before B reaches its deadline. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel_a;
    static EdrBehaviorRecord kernel_b;
    static EdrBehaviorRecord delayed_a;
    rec(&kernel_a, 131u, 0, 0xe11u, "C:\\tombstone.exe", 5100000000LL);
    rec(&kernel_b, 131u, 0, 0xe12u, "C:\\tombstone.exe", 5100000100LL);
    rec(&delayed_a, 131u, 1, 0u, "C:\\tombstone.exe", 5100000050LL);
    ok &= need(edr_process_coalescer_submit(&kernel_a, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 10u, &out) == 1 &&
                   strcmp(out.source_completeness, "CORRELATION_MISSING") == 0,
               "expired A becomes a correlation tombstone");
    ok &= need(edr_process_coalescer_submit(&kernel_b, 1, WINDOW_NS + 20u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD,
               "B is held but permanently ambiguous after colliding with A tombstone");
    ok &= need(edr_process_coalescer_submit(&delayed_a, 1, 2u * WINDOW_NS + 15u, &out) ==
                   EDR_PROCESS_COALESCE_PASS,
               "late A 4688 after tombstone expiry cannot merge into already-ambiguous B");
    ok &= need(edr_process_coalescer_poll(2u * WINDOW_NS + 20u, &out) == 1 &&
                   out.process_start_key == 0xe12u &&
                   strcmp(out.source_completeness, "NOT_EVALUABLE") == 0 && !out.user_sid[0] &&
                   !out.cmdline[0],
               "B never receives A target identity, command line, or an evaluable action path");
  }

  /* Creator metadata must never become created-process identity. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord creator;
    rec(&kernel, 14u, 0, 0xf1u, "C:\\creator.exe", 6000000000LL);
    rec(&creator, 14u, 1, 0u, "C:\\creator.exe", 6000000100LL);
    creator.user_sid[0] = '\0';
    creator.logon_id[0] = '\0';
    snprintf(creator.creator_sid, sizeof(creator.creator_sid), "%s", "S-1-5-21-creator");
    snprintf(creator.identity_source, sizeof(creator.identity_source), "%s", "creator_fallback");
    snprintf(creator.identity_quality, sizeof(creator.identity_quality), "%s", "creator_fallback");
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&creator, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   !out.user_sid[0] && strcmp(out.creator_sid, "S-1-5-21-creator") == 0,
               "creator-only 4688 does not rescue target identity");
  }

  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord missing_key;
    rec(&missing_key, 15u, 0, 0u, "C:\\missing.exe", 7000000000LL);
    ok &= need(edr_process_coalescer_submit(&missing_key, 1, 10u, &out) == EDR_PROCESS_COALESCE_READY &&
                   strcmp(out.source_completeness, "NOT_EVALUABLE") == 0,
               "missing raw ProcessStartKey fails closed");
  }

  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord ordinary;
    rec(&ordinary, 16u, 0, 0x101u, "C:\\ordinary.exe", 8000000000LL);
    ok &= need(edr_process_coalescer_submit(&ordinary, 0, 10u, &out) == EDR_PROCESS_COALESCE_PASS,
               "non-P0 process avoids coalescer/evidence hold");
  }

  /* A missing Kernel-Process callback must not erase the only observation.
   * 4688 stays explicitly non-authoritative and cannot independently trigger
   * a P0 action, but remains available for collection-gap diagnosis. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord security;
    rec(&security, 17u, 1, 0u, "C:\\security-only.exe", 8100000000LL);
    ok &= need(edr_process_coalescer_submit(&security, 1, 10u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 10u, &out) == 1 &&
                   out.is_security_4688 && out.process_start_key == 0u &&
                   strcmp(out.source_completeness, "ENRICHMENT_ONLY") == 0 &&
                   strcmp(out.user_sid, "S-1-5-21-target") == 0,
               "Security-only process evidence remains visible but non-authoritative");
  }

  /* Shutdown is an ownership boundary, not a synthetic timeout. Drain an
   * unexpired merged generation exactly once while preserving the kernel
   * generation identity and Security-only enrichment contract. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    static EdrBehaviorRecord security;
    EdrProcessCoalescerMetrics metrics;
    rec(&kernel, 18u, 0, 0x181u, "C:\\shutdown-paired.exe", 8200000000LL);
    rec(&security, 18u, 1, 0u, "C:\\shutdown-paired.exe", 8200000100LL);
    kernel.process_creation_filetime_100ns = 133801632000000181ULL;
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&security, 1, 20u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_drain_stopping(&out) == 1 &&
                   out.process_start_key == 0x181u &&
                   out.process_creation_filetime_100ns == 133801632000000181ULL &&
                   strcmp(out.source_completeness, "COALESCED") == 0 &&
                   strcmp(out.user_sid, "S-1-5-21-target") == 0 &&
                   edr_process_coalescer_drain_stopping(&out) == 0,
               "shutdown drain emits one merged unexpired kernel generation");
    edr_process_coalescer_get_metrics(&metrics);
    ok &= need(metrics.shutdown_drained == 1u && metrics.timed_out == 0u &&
                   metrics.slots_used == 0u,
               "shutdown drain is distinct from timeout and empties paired state");
  }

  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord security;
    EdrProcessCoalescerMetrics metrics;
    rec(&security, 21u, 1, 0u, "C:\\shutdown-security.exe", 8300000000LL);
    ok &= need(edr_process_coalescer_submit(&security, 1, 10u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_drain_stopping(&out) == 1 &&
                   out.is_security_4688 && out.process_start_key == 0u &&
                   strcmp(out.source_completeness, "ENRICHMENT_ONLY") == 0 &&
                   strcmp(out.user_sid, "S-1-5-21-target") == 0 &&
                   edr_process_coalescer_drain_stopping(&out) == 0,
               "shutdown drain preserves Security-only enrichment evidence");
    edr_process_coalescer_get_metrics(&metrics);
    ok &= need(metrics.shutdown_drained == 1u && metrics.timed_out == 0u &&
                   metrics.slots_used == 0u,
               "Security-only shutdown drain has distinct accounting");
  }

  /* A normal timeout leaves a correlation tombstone. Stop-time drain clears
   * that tombstone but must not emit the already-delivered generation again. */
  edr_process_coalescer_reset();
  {
    static EdrBehaviorRecord kernel;
    EdrProcessCoalescerMetrics metrics;
    rec(&kernel, 22u, 0, 0x221u, "C:\\shutdown-tombstone.exe", 8400000000LL);
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) ==
                   EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 10u, &out) == 1 &&
                   out.process_start_key == 0x221u &&
                   edr_process_coalescer_drain_stopping(&out) == 0,
               "shutdown drain never duplicates a generation retained as a tombstone");
    edr_process_coalescer_get_metrics(&metrics);
    ok &= need(metrics.timed_out == 1u && metrics.shutdown_drained == 0u &&
                   metrics.slots_used == 0u,
               "tombstone cleanup is not counted as a shutdown-drained record");
  }

  edr_process_coalescer_reset();
  for (uint32_t i = 0u; i < 128u; ++i) {
    static EdrBehaviorRecord fill;
    rec(&fill, 1000u + i, 0, 0x1000u + i, "C:\\bounded.exe",
        9000000000LL + (int64_t)i);
    ok &= need(edr_process_coalescer_submit(&fill, 1, 1u + i, &out) == EDR_PROCESS_COALESCE_HOLD,
               "capacity fill retains each raw generation");
  }
  {
    static EdrBehaviorRecord overflow;
    rec(&overflow, 3000u, 0, 0x3000u, "C:\\overflow.exe", 10000000000LL);
    EdrProcessCoalescerMetrics metrics;
    ok &= need(edr_process_coalescer_submit(&overflow, 1, 200u, &out) == EDR_PROCESS_COALESCE_READY &&
                   strcmp(out.source_completeness, "COALESCE_BACKPRESSURE") == 0,
               "full coalescer emits explicit backpressure candidate");
    edr_process_coalescer_get_metrics(&metrics);
    ok &= need(metrics.kernel_backpressure == 1u, "backpressure is observable");
  }

#if !defined(_WIN32)
  {
    pthread_t submitter, poller, resetter, metrics_reader;
    CoalescerStressArgs submit_args = {5000u, 0};
    CoalescerStressArgs poll_args = {0u, 0};
    CoalescerStressArgs reset_args = {0u, 0};
    CoalescerStressArgs metrics_args = {0u, 0};
    edr_process_coalescer_reset();
    ok &= need(pthread_create(&submitter, NULL, coalescer_submit_stress, &submit_args) == 0,
               "concurrent submit thread starts");
    ok &= need(pthread_create(&poller, NULL, coalescer_poll_stress, &poll_args) == 0,
               "concurrent poll thread starts");
    ok &= need(pthread_create(&resetter, NULL, coalescer_reset_stress, &reset_args) == 0,
               "concurrent reset thread starts");
    ok &= need(pthread_create(&metrics_reader, NULL, coalescer_metrics_stress, &metrics_args) == 0,
               "concurrent metrics thread starts");
    (void)pthread_join(submitter, NULL);
    (void)pthread_join(poller, NULL);
    (void)pthread_join(resetter, NULL);
    (void)pthread_join(metrics_reader, NULL);
    ok &= need(!submit_args.failed && !poll_args.failed && !metrics_args.failed,
               "coalescer concurrent state remains bounded");
  }
#endif
  return ok ? 0 : 1;
}
