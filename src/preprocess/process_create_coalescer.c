#include "edr/process_create_coalescer.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
static SRWLOCK s_coalescer_lock = SRWLOCK_INIT;
static void coalescer_lock(void) { AcquireSRWLockExclusive(&s_coalescer_lock); }
static void coalescer_unlock(void) { ReleaseSRWLockExclusive(&s_coalescer_lock); }
#else
#include <pthread.h>
static pthread_mutex_t s_coalescer_lock = PTHREAD_MUTEX_INITIALIZER;
static void coalescer_lock(void) { (void)pthread_mutex_lock(&s_coalescer_lock); }
static void coalescer_unlock(void) { (void)pthread_mutex_unlock(&s_coalescer_lock); }
#endif

#define EDR_PROCESS_COALESCE_SLOTS 128u
#define EDR_PROCESS_COALESCE_DEADLINE_NS (3000ULL * 1000000ULL)

/* A kernel record has a target ProcessStartKey; a 4688 record deliberately
 * does not. Keep a pair pending through the entire three-second window so a same-PID,
 * same-path reuse with a different raw key makes the association ambiguous
 * before any token lookup or action can use the 4688 identity. */
typedef struct {
  EdrBehaviorRecord kernel;
  EdrBehaviorRecord security;
  uint64_t deadline_ns;
  uint8_t occupied;
  uint8_t have_kernel;
  uint8_t have_security;
  uint8_t ambiguous;
  /* After a kernel candidate is emitted, keep its raw StartKey/path/event
   * identity for one further correlation window.  A delayed 4688 that also
   * matches a newly reused PID/path is then ambiguous rather than assigned to
   * the newer process generation. */
  uint8_t tombstone;
} EdrProcessCoalesceSlot;

static EdrProcessCoalesceSlot s_slots[EDR_PROCESS_COALESCE_SLOTS];
static EdrProcessCoalescerMetrics s_metrics;

static char fold(char c) { return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c; }

static int same_ci(const char *a, const char *b) {
  if (!a || !b || !a[0] || !b[0]) return 0;
  while (*a && *b && fold(*a) == fold(*b)) { ++a; ++b; }
  return *a == '\0' && *b == '\0';
}

static const char *record_path(const EdrBehaviorRecord *record) {
  if (!record) return "";
  return record->image_path_canonical[0] ? record->image_path_canonical : record->exe_path;
}

static int same_correlation_window(const EdrBehaviorRecord *a,
                                   const EdrBehaviorRecord *b) {
  uint64_t at, bt, delta;
  if (!a || !b || !a->pid || a->pid != b->pid ||
      !record_path(a)[0] || !record_path(b)[0] ||
      !same_ci(record_path(a), record_path(b))) {
    return 0;
  }
  at = a->event_time_ns > 0 ? (uint64_t)a->event_time_ns : 0u;
  bt = b->event_time_ns > 0 ? (uint64_t)b->event_time_ns : 0u;
  if (!at || !bt) return 0;
  delta = at >= bt ? at - bt : bt - at;
  return delta <= EDR_PROCESS_COALESCE_DEADLINE_NS;
}

/* A Security 4688 record is an audit of an already-created process.  Both
 * sources use the collector's UTC system-time event clock, so accepting a
 * 4688 recorded before a candidate kernel ProcessStart would let an older A
 * record attach to a PID-reused B.  Treat that ordering as ambiguous rather
 * than guessing from callback delivery order. */
static int security_follows_kernel(const EdrBehaviorRecord *kernel,
                                   const EdrBehaviorRecord *security) {
  uint64_t kernel_time;
  uint64_t security_time;
  if (!same_correlation_window(kernel, security)) return 0;
  kernel_time = kernel->event_time_ns > 0 ? (uint64_t)kernel->event_time_ns : 0u;
  security_time = security->event_time_ns > 0 ? (uint64_t)security->event_time_ns : 0u;
  return security_time >= kernel_time &&
         security_time - kernel_time <= EDR_PROCESS_COALESCE_DEADLINE_NS;
}

static int record_has_correlation_fields(const EdrBehaviorRecord *record) {
  return record && record->pid && record_path(record)[0] && record->event_time_ns > 0;
}

static void merge_4688(EdrBehaviorRecord *kernel, const EdrBehaviorRecord *security) {
  if (!kernel || !security) return;
  if (!kernel->cmdline[0]) memcpy(kernel->cmdline, security->cmdline, sizeof(kernel->cmdline));
  if (!kernel->parent_name[0]) memcpy(kernel->parent_name, security->parent_name,
                                      sizeof(kernel->parent_name));
  if (!kernel->parent_path[0]) memcpy(kernel->parent_path, security->parent_path,
                                      sizeof(kernel->parent_path));
  if (!kernel->creator_username[0]) memcpy(kernel->creator_username, security->creator_username,
                                            sizeof(kernel->creator_username));
  if (!kernel->creator_domain[0]) memcpy(kernel->creator_domain, security->creator_domain,
                                          sizeof(kernel->creator_domain));
  if (!kernel->creator_sid[0]) memcpy(kernel->creator_sid, security->creator_sid,
                                       sizeof(kernel->creator_sid));
  if (!kernel->creator_logon_id[0]) memcpy(kernel->creator_logon_id,
                                            security->creator_logon_id,
                                            sizeof(kernel->creator_logon_id));
  /* Creator identity is provenance only. Only Target Subject may become the
   * created process identity. */
  if (strcmp(security->identity_quality, "target_4688") == 0 &&
      strcmp(kernel->identity_quality, "token_sid") != 0) {
    if (!kernel->username[0]) memcpy(kernel->username, security->username,
                                     sizeof(kernel->username));
    if (!kernel->domain[0]) memcpy(kernel->domain, security->domain, sizeof(kernel->domain));
    if (!kernel->user_sid[0]) memcpy(kernel->user_sid, security->user_sid,
                                     sizeof(kernel->user_sid));
    if (!kernel->logon_id[0]) memcpy(kernel->logon_id, security->logon_id,
                                     sizeof(kernel->logon_id));
    snprintf(kernel->identity_source, sizeof(kernel->identity_source), "%s", "target_4688");
    snprintf(kernel->identity_quality, sizeof(kernel->identity_quality), "%s", "target_4688");
  } else if (!kernel->identity_quality[0] && security->identity_quality[0]) {
    snprintf(kernel->identity_source, sizeof(kernel->identity_source), "%s", "creator_fallback");
    snprintf(kernel->identity_quality, sizeof(kernel->identity_quality), "%s", "creator_fallback");
  }
  snprintf(kernel->source_completeness, sizeof(kernel->source_completeness), "%s", "COALESCED");
  kernel->evidence_revision++;
}

static EdrProcessCoalesceSlot *reserve_slot(void) {
  for (uint32_t i = 0u; i < EDR_PROCESS_COALESCE_SLOTS; ++i) {
    if (!s_slots[i].occupied) return &s_slots[i];
  }
  return NULL;
}

static void mark_kernel_ambiguity(EdrProcessCoalesceSlot *slot) {
  if (slot && slot->have_kernel) slot->ambiguous = 1u;
}

void edr_process_coalescer_reset(void) {
  coalescer_lock();
  memset(s_slots, 0, sizeof(s_slots));
  memset(&s_metrics, 0, sizeof(s_metrics));
  coalescer_unlock();
}

void edr_process_coalescer_get_metrics(EdrProcessCoalescerMetrics *out) {
  if (!out) return;
  coalescer_lock();
  *out = s_metrics;
  out->capacity = EDR_PROCESS_COALESCE_SLOTS;
  for (uint32_t i = 0u; i < EDR_PROCESS_COALESCE_SLOTS; ++i) {
    if (s_slots[i].occupied) out->slots_used++;
  }
  coalescer_unlock();
}

static EdrProcessCoalesceResult submit_kernel(const EdrBehaviorRecord *record,
                                               int p0_candidate, uint64_t now,
                                               EdrBehaviorRecord *out) {
  EdrProcessCoalesceSlot *security_match = NULL;
  EdrProcessCoalesceSlot *same_key = NULL;
  EdrProcessCoalesceSlot *free_slot;
  uint32_t security_matches = 0u;
  int conflict = 0;
  int stale = 0;
  int duplicate_tombstone = 0;

  if (!record->process_start_key || !record_has_correlation_fields(record)) {
    *out = *record;
    snprintf(out->source_completeness, sizeof(out->source_completeness), "%s", "NOT_EVALUABLE");
    coalescer_lock();
    s_metrics.ambiguous_rejects++;
    coalescer_unlock();
    return EDR_PROCESS_COALESCE_READY;
  }
  if (!p0_candidate) return EDR_PROCESS_COALESCE_PASS;

  coalescer_lock();
  for (uint32_t i = 0u; i < EDR_PROCESS_COALESCE_SLOTS; ++i) {
    EdrProcessCoalesceSlot *slot = &s_slots[i];
    if (!slot->occupied) continue;
    if (slot->tombstone && now >= slot->deadline_ns) {
      memset(slot, 0, sizeof(*slot));
      continue;
    }
    if (now >= slot->deadline_ns) {
      stale = 1;
      continue;
    }
    if (slot->have_kernel && same_correlation_window(&slot->kernel, record)) {
      if (slot->kernel.process_start_key == record->process_start_key) {
        if (slot->tombstone) {
          /* This raw generation has already emitted.  A duplicate kernel
           * record must not reopen it as a new candidate. */
          duplicate_tombstone = 1;
        } else {
          same_key = slot;
        }
      } else {
        /* A tombstone is still a raw generation in the correlation window.
         * Mark the incoming B as permanently ambiguous now, before A's
         * delayed 4688 can arrive after the tombstone deadline. */
        if (!slot->tombstone) mark_kernel_ambiguity(slot);
        conflict = 1;
      }
    }
    if (!slot->have_kernel && slot->have_security &&
        same_correlation_window(&slot->security, record)) {
      if (security_follows_kernel(record, &slot->security)) {
        security_match = slot;
        security_matches++;
      } else {
        /* Security may arrive before kernel delivery, but its recorded event
         * time may not predate the raw ProcessStart it enriches.  Preserve it
         * as source-only and permanently reject the incoming generation. */
        conflict = 1;
      }
    }
  }
  if (same_key) {
    coalescer_unlock();
    return EDR_PROCESS_COALESCE_HOLD;
  }
  if (duplicate_tombstone) {
    s_metrics.stale_rejects++;
    coalescer_unlock();
    return EDR_PROCESS_COALESCE_PASS;
  }
  if (security_matches > 1u) conflict = 1;
  if (conflict) s_metrics.ambiguous_rejects++;
  if (stale) s_metrics.stale_rejects++;
  free_slot = security_matches == 1u && !conflict ? security_match : reserve_slot();
  if (!free_slot) {
    *out = *record;
    snprintf(out->source_completeness, sizeof(out->source_completeness), "%s", "COALESCE_BACKPRESSURE");
    s_metrics.kernel_backpressure++;
    coalescer_unlock();
    return EDR_PROCESS_COALESCE_READY;
  }
  if (free_slot != security_match) {
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->occupied = 1u;
    free_slot->deadline_ns = now + EDR_PROCESS_COALESCE_DEADLINE_NS;
  }
  free_slot->kernel = *record;
  free_slot->have_kernel = 1u;
  if (conflict) free_slot->ambiguous = 1u;
  coalescer_unlock();
  return EDR_PROCESS_COALESCE_HOLD;
}

static EdrProcessCoalesceResult submit_security(const EdrBehaviorRecord *record,
                                                 uint64_t now) {
  EdrProcessCoalesceSlot *kernel_match = NULL;
  EdrProcessCoalesceSlot *same_security = NULL;
  EdrProcessCoalesceSlot *free_slot;
  uint32_t kernel_matches = 0u;
  int stale = 0;
  int direction_conflict = 0;

  if (!record_has_correlation_fields(record)) return EDR_PROCESS_COALESCE_PASS;
  coalescer_lock();
  for (uint32_t i = 0u; i < EDR_PROCESS_COALESCE_SLOTS; ++i) {
    EdrProcessCoalesceSlot *slot = &s_slots[i];
    if (!slot->occupied) continue;
    if (slot->tombstone && now >= slot->deadline_ns) {
      memset(slot, 0, sizeof(*slot));
      continue;
    }
    if (now >= slot->deadline_ns) {
      stale = 1;
      continue;
    }
    if (slot->have_kernel && same_correlation_window(&slot->kernel, record)) {
      if (security_follows_kernel(&slot->kernel, record)) {
        kernel_match = slot;
        kernel_matches++;
      } else if (!slot->tombstone) {
        /* The apparent 4688 predates this raw StartKey.  It could be a
         * delayed prior PID generation, so this generation is permanently
         * source-only even if a later token query happens to succeed. */
        mark_kernel_ambiguity(slot);
        direction_conflict = 1;
      }
    }
    if (!slot->have_kernel && slot->have_security &&
        same_correlation_window(&slot->security, record)) {
      same_security = slot;
    }
  }
  if (stale) s_metrics.stale_rejects++;
  if (direction_conflict) {
    s_metrics.ambiguous_rejects++;
    coalescer_unlock();
    return EDR_PROCESS_COALESCE_PASS;
  }
  if (kernel_matches == 1u && kernel_match->tombstone) {
    /* The only matching generation has already emitted.  Never turn this
     * late 4688 into a fresh process observation. */
    s_metrics.stale_rejects++;
    coalescer_unlock();
    return EDR_PROCESS_COALESCE_PASS;
  }
  if (kernel_matches == 1u && !kernel_match->ambiguous) {
    kernel_match->security = *record;
    kernel_match->have_security = 1u;
    s_metrics.security_stored++;
    coalescer_unlock();
    return EDR_PROCESS_COALESCE_HOLD;
  }
  if (kernel_matches > 1u) {
    for (uint32_t i = 0u; i < EDR_PROCESS_COALESCE_SLOTS; ++i) {
      EdrProcessCoalesceSlot *slot = &s_slots[i];
      if (slot->occupied && !slot->tombstone && slot->have_kernel &&
          same_correlation_window(&slot->kernel, record)) mark_kernel_ambiguity(slot);
    }
    s_metrics.ambiguous_rejects++;
    coalescer_unlock();
    return EDR_PROCESS_COALESCE_PASS;
  }
  if (same_security) {
    coalescer_unlock();
    return EDR_PROCESS_COALESCE_HOLD;
  }
  free_slot = reserve_slot();
  if (!free_slot) {
    s_metrics.security_backpressure++;
    coalescer_unlock();
    return EDR_PROCESS_COALESCE_PASS;
  }
  memset(free_slot, 0, sizeof(*free_slot));
  free_slot->occupied = 1u;
  free_slot->have_security = 1u;
  free_slot->security = *record;
  free_slot->deadline_ns = now + EDR_PROCESS_COALESCE_DEADLINE_NS;
  s_metrics.security_stored++;
  coalescer_unlock();
  return EDR_PROCESS_COALESCE_HOLD;
}

EdrProcessCoalesceResult edr_process_coalescer_submit(const EdrBehaviorRecord *record,
                                                       int p0_candidate,
                                                       uint64_t monotonic_ns,
                                                       EdrBehaviorRecord *out_ready) {
  if (!record || !out_ready || record->type != EDR_EVENT_PROCESS_CREATE) {
    return EDR_PROCESS_COALESCE_PASS;
  }
  if (record->is_security_4688) return submit_security(record, monotonic_ns);
  return submit_kernel(record, p0_candidate, monotonic_ns, out_ready);
}

int edr_process_coalescer_poll(uint64_t monotonic_ns, EdrBehaviorRecord *out_ready) {
  if (!out_ready) return 0;
  coalescer_lock();
  for (uint32_t i = 0u; i < EDR_PROCESS_COALESCE_SLOTS; ++i) {
    EdrProcessCoalesceSlot *slot = &s_slots[i];
    if (!slot->occupied) continue;
    if (slot->tombstone) {
      if (monotonic_ns >= slot->deadline_ns) memset(slot, 0, sizeof(*slot));
      continue;
    }
    if (monotonic_ns < slot->deadline_ns) continue;
    if (!slot->have_kernel) {
      memset(slot, 0, sizeof(*slot)); /* Security source-only observation. */
      continue;
    }
    *out_ready = slot->kernel;
    if (slot->have_security && !slot->ambiguous) {
      merge_4688(out_ready, &slot->security);
    } else if (!slot->have_security && !slot->ambiguous) {
      /* Absence of 4688 is a missing optional correlation, not proof that
       * the kernel process instance is unusable.  The downstream token query
       * may still establish target identity after StartKey/FILETIME/path and
       * file identity have all been validated. */
      snprintf(out_ready->source_completeness, sizeof(out_ready->source_completeness), "%s",
               "CORRELATION_MISSING");
    } else {
      snprintf(out_ready->source_completeness, sizeof(out_ready->source_completeness), "%s",
               "NOT_EVALUABLE");
    }
    /* Do not free this raw generation immediately.  The tombstone prevents a
     * delayed A 4688 from being bound to a same-PID/path B that starts just
     * after A's deadline. */
    slot->have_security = 0u;
    slot->security = (EdrBehaviorRecord){0};
    slot->ambiguous = 0u;
    slot->tombstone = 1u;
    slot->deadline_ns = monotonic_ns + EDR_PROCESS_COALESCE_DEADLINE_NS;
    s_metrics.timed_out++;
    coalescer_unlock();
    return 1;
  }
  coalescer_unlock();
  return 0;
}
