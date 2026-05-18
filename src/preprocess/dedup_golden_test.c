#include "edr/dedup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
static int g_pass = 0;

#define T_ASSERT(expr, msg) do { \
    if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); g_fail++; } \
    else { g_pass++; } \
} while (0)

static EdrBehaviorRecord make_record(uint32_t pid, EdrEventType ty,
                                       const char *cmdline,
                                       int64_t time_ns, uint32_t priority) {
  EdrBehaviorRecord r;
  memset(&r, 0, sizeof(r));
  r.pid = pid;
  r.type = ty;
  r.priority = priority;
  r.event_time_ns = time_ns;
  strncpy(r.process_name, "test.exe", sizeof(r.process_name) - 1);
  if (cmdline) {
    strncpy(r.cmdline, cmdline, sizeof(r.cmdline) - 1);
  } else {
    strncpy(r.cmdline, "test.exe -a", sizeof(r.cmdline) - 1);
  }
  return r;
}

int main(void) {
  edr_dedup_configure(30u, 100u);
  edr_dedup_init();

  /* priority==0 always emits */
  {
    EdrBehaviorRecord r = make_record(1000u, EDR_EVENT_PROCESS_CREATE,
                                       "cmd.exe /c whoami", 1000000000LL, 0u);
    int got = edr_preprocess_should_emit(&r);
    T_ASSERT(got == 1, "priority==0 should emit");
  }

  /* same event within 30s window → deduped */
  {
    EdrBehaviorRecord r1 = make_record(1000u, EDR_EVENT_SCRIPT_POWERSHELL,
                                        "powershell -enc AAA", 2000000000LL, 1u);
    int got1 = edr_preprocess_should_emit(&r1);
    T_ASSERT(got1 == 1, "first unique event should emit");

    EdrBehaviorRecord r2 = make_record(1000u, EDR_EVENT_SCRIPT_POWERSHELL,
                                        "powershell -enc AAA", 2500000000LL, 1u);
    int got2 = edr_preprocess_should_emit(&r2);
    T_ASSERT(got2 == 0, "same event within 30s should dedup");
  }

  /* different cmdline → different fingerprint → emits */
  {
    EdrBehaviorRecord r1 = make_record(2000u, EDR_EVENT_SCRIPT_POWERSHELL,
                                        "python evil.py", 3000000000LL, 1u);
    int got1 = edr_preprocess_should_emit(&r1);
    T_ASSERT(got1 == 1, "different cmdline should emit as unique");

    EdrBehaviorRecord r2 = make_record(2000u, EDR_EVENT_SCRIPT_POWERSHELL,
                                        "python ok.py", 3500000000LL, 1u);
    int got2 = edr_preprocess_should_emit(&r2);
    T_ASSERT(got2 == 1, "different fingerprint should not dedup");
  }

  /* different pid → different dedup key → emits */
  {
    EdrBehaviorRecord r1 = make_record(3000u, EDR_EVENT_PROCESS_CREATE,
                                        "cmd.exe /c a", 4000000000LL, 1u);
    int got1 = edr_preprocess_should_emit(&r1);
    T_ASSERT(got1 == 1, "pid=3000 first emit should pass");

    EdrBehaviorRecord r2 = make_record(3001u, EDR_EVENT_PROCESS_CREATE,
                                        "cmd.exe /c a", 4500000000LL, 1u);
    int got2 = edr_preprocess_should_emit(&r2);
    T_ASSERT(got2 == 1, "different pid same cmdline should emit");
  }

  /* same event after window expiration → emits */
  {
    EdrBehaviorRecord r1 = make_record(4000u, EDR_EVENT_NET_CONNECT,
                                        "curl evil.com", 5000000000LL, 1u);
    int got1 = edr_preprocess_should_emit(&r1);
    T_ASSERT(got1 == 1, "first net event should emit");

    EdrBehaviorRecord r2 = make_record(4000u, EDR_EVENT_NET_CONNECT,
                                        "curl evil.com", 35000000000LL, 1u);
    int got2 = edr_preprocess_should_emit(&r2);
    T_ASSERT(got2 == 1, "same event after 30s+ window should emit");
  }

  /* high-frequency rate limiting: >100/sec for same pid+type, different cmdline */
  {
    int emitted = 0;
    for (int i = 0; i < 200; i++) {
      char buf[64];
      snprintf(buf, sizeof(buf), "write test %d", i);
      EdrBehaviorRecord r = make_record(5000u, EDR_EVENT_FILE_WRITE,
                                         buf, 6000000000LL + (int64_t)i * 1000000LL, 1u);
      if (edr_preprocess_should_emit(&r)) {
        emitted++;
      }
    }
    T_ASSERT(emitted <= 101, "rate limit: emitted should be <=101");
    T_ASSERT(emitted >= 100, "rate limit: emitted should be >=100 (first 100 allowed)");
  }

  /* stats counters are populated (check before reset) */
  {
    uint64_t dedup_drops = 0, rate_drops = 0;
    edr_dedup_get_stats(&dedup_drops, &rate_drops);
    T_ASSERT(dedup_drops > 0, "dedup_drops counter should be >0");
    T_ASSERT(rate_drops > 0, "rate_drops counter should be >0");

    uint64_t junk = edr_dedup_junk_parse_failed_drops();
    T_ASSERT(junk >= 0, "junk_parse_failed_drops should be accessible");
  }

  /* edr_dedup_reset clears state */
  {
    edr_dedup_reset();
    uint64_t dedup_drops = 999, rate_drops = 999;
    edr_dedup_get_stats(&dedup_drops, &rate_drops);
    T_ASSERT(dedup_drops == 0, "after reset, dedup_drops should be 0");
    T_ASSERT(rate_drops == 0, "after reset, rate_drops should be 0");

    EdrBehaviorRecord r = make_record(1000u, EDR_EVENT_PROCESS_CREATE,
                                       "cmd.exe /c whoami", 1000000000LL, 1u);
    int got = edr_preprocess_should_emit(&r);
    T_ASSERT(got == 1, "after reset, first event should emit again");
  }

  fprintf(stderr, "[dedup_golden] %d PASS, %d FAIL\n", g_pass, g_fail);
  return g_fail > 0 ? 1 : 0;
}