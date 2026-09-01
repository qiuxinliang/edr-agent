#include "edr/process_create_coalescer.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#include <pthread.h>
#endif

#define WINDOW_NS (300ULL * 1000000ULL)

static EdrBehaviorRecord rec(uint32_t pid, int security, uint64_t start_key,
                             const char *path, int64_t event_time_ns) {
  EdrBehaviorRecord record;
  memset(&record, 0, sizeof(record));
  record.type = EDR_EVENT_PROCESS_CREATE;
  record.pid = pid;
  record.is_security_4688 = (uint8_t)security;
  record.event_time_ns = event_time_ns;
  if (!security) record.process_start_key = start_key;
  snprintf(record.exe_path, sizeof(record.exe_path), "%s", path ? path : "");
  snprintf(record.image_path_canonical, sizeof(record.image_path_canonical), "%s",
           path ? path : "");
  snprintf(record.process_name, sizeof(record.process_name), "%s", "cmd.exe");
  if (security) {
    snprintf(record.cmdline, sizeof(record.cmdline), "%s /c x.cmd", path ? path : "");
    snprintf(record.user_sid, sizeof(record.user_sid), "%s", "S-1-5-21-target");
    snprintf(record.logon_id, sizeof(record.logon_id), "%s", "0x0000000000000021");
    snprintf(record.identity_source, sizeof(record.identity_source), "%s", "target_4688");
    snprintf(record.identity_quality, sizeof(record.identity_quality), "%s", "target_4688");
  }
  return record;
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
    EdrBehaviorRecord kernel = rec(args->pid_base + (i % 32u), 0, i + 1u,
                                   "C:\\stress.exe", 9000000000LL + (int64_t)i * 10LL);
    EdrBehaviorRecord security = rec(args->pid_base + (i % 32u), 1, 0u,
                                     "C:\\stress.exe", 9000000001LL + (int64_t)i * 10LL);
    EdrBehaviorRecord out;
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
  EdrBehaviorRecord out;
  int ok = 1;

  /* Kernel -> 4688: keep both pending through the window so another raw
   * StartKey can invalidate an apparent PID/path match. */
  edr_process_coalescer_reset();
  {
    EdrBehaviorRecord kernel = rec(9u, 0, 0xa1u, "C:\\a.exe", 1000000000LL);
    EdrBehaviorRecord security = rec(9u, 1, 0u, "C:\\a.exe", 1000000100LL);
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "kernel first holds for raw-generation correlation");
    ok &= need(edr_process_coalescer_submit(&security, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD,
               "4688 is retained instead of immediately merged");
    ok &= need(edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.source_completeness, "COALESCED") == 0 &&
                   strcmp(out.user_sid, "S-1-5-21-target") == 0,
               "kernel to 4688 emits one target-subject correlation at deadline");
  }

  /* A merge intentionally records `COALESCED`, but it must preserve source
   * omissions from the raw kernel observation. The direct P0 contract tests
   * that this retained list remains fail-closed for alert/action evaluation. */
  edr_process_coalescer_reset();
  {
    EdrBehaviorRecord kernel = rec(91u, 0, 0xa11u, "C:\\truncated.exe", 1100000000LL);
    EdrBehaviorRecord security = rec(91u, 1, 0u, "C:\\truncated.exe", 1100000100LL);
    snprintf(kernel.source_completeness, sizeof(kernel.source_completeness), "%s", "TRUNCATED");
    snprintf(kernel.source_truncated_fields, sizeof(kernel.source_truncated_fields), "%s",
             "source.process_name,source.exe_hash");
    ok &= need(edr_process_coalescer_submit(&kernel, 1, 10u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_submit(&security, 1, 20u, &out) == EDR_PROCESS_COALESCE_HOLD &&
                   edr_process_coalescer_poll(WINDOW_NS + 20u, &out) == 1 &&
                   strcmp(out.source_completeness, "COALESCED") == 0 &&
                   strcmp(out.source_truncated_fields,
                          "source.process_name,source.exe_hash") == 0,
               "coalescing preserves source omissions after status replacement");
  }

  /* 4688 -> kernel must use the same pending-window rule. */
  edr_process_coalescer_reset();
  {
    EdrBehaviorRecord security = rec(10u, 1, 0u, "C:\\b.exe", 2000000200LL);
    EdrBehaviorRecord kernel = rec(10u, 0, 0xb1u, "C:\\b.exe", 2000000000LL);
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
    EdrBehaviorRecord late_a = rec(100u, 1, 0u, "C:\\arrival-first.exe", 2400000050LL);
    EdrBehaviorRecord kernel_b = rec(100u, 0, 0xb01u, "C:\\arrival-first.exe", 2400000100LL);
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
    EdrBehaviorRecord kernel = rec(101u, 0, 0xb11u, "C:\\direction.exe", 2500000100LL);
    EdrBehaviorRecord late_a = rec(101u, 1, 0u, "C:\\direction.exe", 2500000050LL);
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
    EdrBehaviorRecord kernel = rec(11u, 0, 0xc1u, "C:\\c.exe", 3000000000LL);
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
    EdrBehaviorRecord kernel_a = rec(132u, 0, 0xe21u, "C:\\late-reuse.exe", 5200000000LL);
    EdrBehaviorRecord kernel_b = rec(132u, 0, 0xe22u, "C:\\late-reuse.exe", 5200000100LL);
    EdrBehaviorRecord delayed_a = rec(132u, 1, 0u, "C:\\late-reuse.exe", 5200000050LL);
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
    EdrBehaviorRecord kernel_a = rec(12u, 0, 0xd1u, "C:\\reuse.exe", 4000000000LL);
    EdrBehaviorRecord kernel_b = rec(12u, 0, 0xd2u, "C:\\reuse.exe", 4000000100LL);
    EdrBehaviorRecord delayed_a_4688 = rec(12u, 1, 0u, "C:\\reuse.exe", 4000000150LL);
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
    EdrBehaviorRecord kernel = rec(13u, 0, 0xe1u, "C:\\expired.exe", 5000000000LL);
    EdrBehaviorRecord security = rec(13u, 1, 0u, "C:\\expired.exe", 5000000100LL);
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
    EdrBehaviorRecord kernel_a = rec(131u, 0, 0xe11u, "C:\\tombstone.exe", 5100000000LL);
    EdrBehaviorRecord kernel_b = rec(131u, 0, 0xe12u, "C:\\tombstone.exe", 5100000100LL);
    EdrBehaviorRecord delayed_a = rec(131u, 1, 0u, "C:\\tombstone.exe", 5100000050LL);
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
    EdrBehaviorRecord kernel = rec(14u, 0, 0xf1u, "C:\\creator.exe", 6000000000LL);
    EdrBehaviorRecord creator = rec(14u, 1, 0u, "C:\\creator.exe", 6000000100LL);
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
    EdrBehaviorRecord missing_key = rec(15u, 0, 0u, "C:\\missing.exe", 7000000000LL);
    ok &= need(edr_process_coalescer_submit(&missing_key, 1, 10u, &out) == EDR_PROCESS_COALESCE_READY &&
                   strcmp(out.source_completeness, "NOT_EVALUABLE") == 0,
               "missing raw ProcessStartKey fails closed");
  }

  edr_process_coalescer_reset();
  {
    EdrBehaviorRecord ordinary = rec(16u, 0, 0x101u, "C:\\ordinary.exe", 8000000000LL);
    ok &= need(edr_process_coalescer_submit(&ordinary, 0, 10u, &out) == EDR_PROCESS_COALESCE_PASS,
               "non-P0 process avoids coalescer/evidence hold");
  }

  edr_process_coalescer_reset();
  for (uint32_t i = 0u; i < 128u; ++i) {
    EdrBehaviorRecord fill = rec(1000u + i, 0, 0x1000u + i, "C:\\bounded.exe",
                                 9000000000LL + (int64_t)i);
    ok &= need(edr_process_coalescer_submit(&fill, 1, 1u + i, &out) == EDR_PROCESS_COALESCE_HOLD,
               "capacity fill retains each raw generation");
  }
  {
    EdrBehaviorRecord overflow = rec(3000u, 0, 0x3000u, "C:\\overflow.exe", 10000000000LL);
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
