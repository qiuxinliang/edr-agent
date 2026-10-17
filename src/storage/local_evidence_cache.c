#include "edr/egress_request_policy.h"
#include "edr/validation_trace.h"
#include "edr/local_evidence_cache.h"
#include "edr/command.h"
#include "edr/storage_physical_guard.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
#ifdef EDR_HAVE_LZ4
#include "lz4.h"
#endif

#include "edr/p0_rule_ir.h"
#include "edr/p0_rule_match.h"
#include "edr/process_tree_cache.h"
#include "edr/process_generation.h"
#include "edr/resource.h"
#include "edr/sha256.h"
#include "edr/egress_batch_policy.h"
#include "edr/time_util.h"
#include "edr/windows_event_policy.h"
#include "../preprocess/baseline_context.h"

#include "cJSON.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif

#if defined(EDR_HAVE_SQLITE)
#include <sqlite3.h>
#include "edr/v1/event.pb.h"
#include <pb_decode.h>
#include "evidence_context_store.h"
#include <sys/stat.h>
#endif

#define EDR_EVIDENCE_PROC_SLOTS 1024u
#define EDR_EVIDENCE_RING_SLOTS 1024u
#define EDR_EVIDENCE_CONTEXT_RING_SLOTS 256u
#define EDR_EVIDENCE_CONTEXT_WINDOWS 256u
#define EDR_EVIDENCE_METRIC_SLOTS 180u
#define EDR_EVIDENCE_CANDIDATE_DEDUP_SLOTS 512u
#define EDR_EVIDENCE_AGG_SLOTS 512u
/* Context has at most 32 RingSlot records. Escape expansion is at most six
 * bytes/source byte. One item has <=1032 bytes of variable text
 * (47 endpoint + 63 self source + 63 parent source + 31 source status +
 * 383 source omissions + 127 name + 255 path + 63 network), and <=450 bytes
 * of fixed keys, quotes, commas, and decimal fields. Thus
 * 32 * 6 * 1482 < 279 KiB. The pre root is <6 KiB before escaping (<36 KiB),
 * so a maximum pre manifest remains <315 KiB. The post root (4095 path +
 * 511 DNS + 1023 registry key + 511 registry value + source omissions and
 * all remaining fields) is <8 KiB before escaping, or <48 KiB. Retain a
 * fixed 1 MiB envelope (well below the 4 MiB cap) for cJSON allocation and
 * structural headroom; never use a 4096-B truncation path. */
#define EDR_EVIDENCE_MANIFEST_MAX_BYTES (1024u * 1024u)

/* A PID is only a routing hint.  Every cross-record association in this
 * module uses this exact ProcessStartKey + creation FILETIME tuple; the
 * event-time selector is retained only to decide whether an incoming ProcSlot
 * update is newer than the one already stored. */
typedef struct {
  uint64_t process_start_key;
  uint64_t creation_filetime_100ns;
  uint64_t start_time_ns;
} EvidenceProcessGeneration;

typedef struct {
  uint32_t pid;
  uint32_t ppid;
  uint8_t parent_pid_state;
  EvidenceProcessGeneration generation;
  EvidenceProcessGeneration parent_generation;
  char process_generation_source[64];
  char parent_process_generation_source[64];
  int64_t last_seen_ns;
  char endpoint_id[48];
  char tenant_id[64];
  char name[256];
  char path[EDR_BR_STR_LONG];
  char cmdline[EDR_BR_STR_CMDLINE];
  char parent_name[256];
  char parent_path[512];
  char parent_cmdline[EDR_BR_STR_CMDLINE];
  /* Only provenance for fields retained by this cache is stored.  Keeping
   * each origin list separate lets a later complete update replace one fact
   * without erasing or inheriting another field's omission. */
  char path_truncated_fields[160];
  char cmdline_truncated_fields[64];
  char parent_path_truncated_fields[64];
  char parent_cmdline_truncated_fields[64];
  uint32_t grandparent_pid;
  char grandparent_name[EDR_BR_STR_SHORT];
  char grandparent_path[EDR_BR_STR_MID];
  char grandparent_path_truncated_fields[64];
  char username[256];
  char domain[256];
  char user_sid[256];
  char logon_id[64];
  char creator_username[256];
  char creator_domain[256];
  char creator_sid[256];
  char creator_logon_id[64];
  char identity_source[32];
  char identity_quality[32];
  char integrity_level[32];
  uint32_t token_elevation;
  char exe_hash[65];
  char current_directory[1024];
  char process_creation_time[64];
} ProcSlot;

typedef struct {
  uint8_t used;
  int64_t event_time_ns;
  uint32_t type;
  uint32_t pid;
  uint32_t ppid;
  uint8_t parent_pid_state;
  EvidenceProcessGeneration generation;
  EvidenceProcessGeneration parent_generation;
  char endpoint_id[48];
  char tenant_id[64];
  char process_generation_source[64];
  char parent_process_generation_source[64];
  char source_completeness[32];
  char source_truncated_fields[EDR_BR_SOURCE_TRUNCATED_FIELDS_LEN];
  char process_name[128];
  char file_path[256];
  char net_dst[64];
  uint32_t net_dport;
} RingSlot;

typedef struct {
  uint32_t pid;
  int64_t from_ns;
  int64_t until_ns;
  uint64_t created_mono_ns;
  EvidenceProcessGeneration generation;
  char endpoint_id[48];
  char tenant_id[64];
  char candidate_id[160];
} ContextWindowSlot;

#define METRIC_ORDINARY_BASE 4u
#define METRIC_CANDIDATE_BASE (METRIC_ORDINARY_BASE + EDR_EVIDENCE_ORDINARY_REASON_COUNT)
#define METRIC_CONTEXT_BASE (METRIC_CANDIDATE_BASE + EDR_EVIDENCE_FAILURE_REASON_COUNT)
#define METRIC_COUNT (METRIC_CONTEXT_BASE + EDR_EVIDENCE_FAILURE_REASON_COUNT)
static const char *const metric_names[METRIC_COUNT] = {
  "file_drops", "registry_drops", "network_drops", "other_drops",
  "ordinary_policy_filtered", "ordinary_pressure_skipped", "ordinary_coalesced", "ordinary_hot_ring_only",
  "candidate_no_database", "candidate_capacity_refused", "candidate_write_budget_refused",
  "candidate_resource_failed", "candidate_invalid", "candidate_storage_failed", "candidate_unclassified_failure",
  "context_no_database", "context_capacity_refused", "context_write_budget_refused",
  "context_resource_failed", "context_invalid", "context_storage_failed", "context_unclassified_failure"
};
/* Protected by the cache owner mutex; reset for each persistence operation. */
static EdrEvidenceFailureReason s_persistence_failure = EDR_EVIDENCE_FAILURE_UNCLASSIFIED;
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
static unsigned s_test_manifest_allocation_failures;
static EdrEvidenceCacheQueryCost s_test_pmfe_query_cost[2];
#endif

typedef struct {
  int64_t minute_unix;
  char endpoint_id[48];
  uint64_t file_drops;
  uint64_t registry_drops;
  uint64_t network_drops;
  uint64_t other_drops;
  uint64_t reasons[METRIC_COUNT - METRIC_ORDINARY_BASE];
  uint64_t committed[METRIC_COUNT];
} MetricSlot;

typedef struct {
  uint8_t used;
  int64_t last_ns;
  uint32_t pid;
  uint32_t type;
  char endpoint_id[48];
  /* Raw source-record tuple presence is distinct from a generation resolved
   * through the event-time process-tree snapshot. Cross-provider enrichment
   * uses these shape bits; PID-reuse safety continues to use `generation`. */
  uint8_t source_generation_shapes;
  uint8_t generation_known;
  EvidenceProcessGeneration generation;
  char candidate_id[160];
  /* Exact source-event or atomic-behavior commitment.  It is a local
   * evidence reuse key, not an alert-suppression or cross-restart cache key. */
  char signal[65];
  /* Different providers may emit the same atomic process observation with
   * different event ids while only one source carries a raw generation. Keep a
   * second, enrichment-insensitive commitment for that narrow two-second
   * bridge; the source commitment above remains authoritative for exact
   * replay, and two known generations are never bridged. */
  char semantic_signal[65];
  char source_event_id[EDR_BR_ID_LEN];
  /* The bridge is deliberately limited to one cross-provider pair. Retaining
   * the second id lets either source replay reuse the pair without allowing a
   * third distinct atomic event to collapse into it. */
  char bridged_source_event_id[EDR_BR_ID_LEN];
  char bridged_signal[65];
} CandidateDedupeSlot;

enum {
  CANDIDATE_DEDUPE_REJECT_GENERATION_CONFLICT = 1u << 0,
  CANDIDATE_DEDUPE_REJECT_SOURCE_SHAPE = 1u << 1,
  CANDIDATE_DEDUPE_REJECT_SEMANTIC_MISMATCH = 1u << 2,
  CANDIDATE_DEDUPE_REJECT_SKEW = 1u << 3
};

enum {
  CANDIDATE_SOURCE_GENERATION_MISSING = 1u << 0,
  CANDIDATE_SOURCE_GENERATION_BOUND = 1u << 1
};

typedef struct {
  uint8_t used;
  int64_t minute_unix;
  uint32_t pid;
  uint32_t kind;
  char endpoint_id[48];
  char prefix[160];
  char semantic_digest[65];
  uint64_t count;
  /* behavior_summary 上报所需的聚合上下文。 */
  int64_t first_seen_ns;
  int64_t last_seen_ns;
  uint32_t event_type;
  char tenant_id[64];
  char process_name[256];
  char suppression_reason[96];
} OrdinaryAggregateSlot;

static ProcSlot s_proc[EDR_EVIDENCE_PROC_SLOTS];
/* candidate/context ring: RTQ-visible, bounded, and fed only by P0/P1 candidates. */
static RingSlot s_ring[EDR_EVIDENCE_RING_SLOTS];
/* hot ring: never persisted as raw rows; used to build P0 context packages. */
static RingSlot s_context_ring[EDR_EVIDENCE_CONTEXT_RING_SLOTS];
static ContextWindowSlot s_context_windows[EDR_EVIDENCE_CONTEXT_WINDOWS];
static MetricSlot s_metrics[EDR_EVIDENCE_METRIC_SLOTS];
static uint64_t s_metric_retry_after_ns;
static CandidateDedupeSlot s_candidate_dedupe[EDR_EVIDENCE_CANDIDATE_DEDUP_SLOTS];
static OrdinaryAggregateSlot s_ordinary_agg[EDR_EVIDENCE_AGG_SLOTS];
static uint32_t s_ring_pos;
static uint32_t s_context_ring_pos;
static uint32_t s_context_window_next;
static EdrEvidenceCacheStatus s_status;
static atomic_uint_fast64_t s_query_pin_exhausted;
static uint64_t s_last_maintenance_ns;
static uint64_t s_last_capacity_failure_ns;
static int64_t s_write_budget_minute;
static uint32_t s_write_budget_count;
static uint32_t s_write_budget_ordinary_context_count;

typedef enum {
  EVIDENCE_WRITE_CRITICAL_CONTEXT = 0,
  EVIDENCE_WRITE_ORDINARY_CONTEXT = 1,
} EvidenceWriteClass;

#define EDR_EVIDENCE_CACHE_LOCK_HIST_BUCKETS 64u

typedef struct {
  uint64_t samples;
  uint64_t wait_total_ns;
  uint64_t wait_max_ns;
  uint64_t hold_total_ns;
  uint64_t hold_max_ns;
  uint64_t wait_histogram[EDR_EVIDENCE_CACHE_LOCK_HIST_BUCKETS];
  uint64_t hold_histogram[EDR_EVIDENCE_CACHE_LOCK_HIST_BUCKETS];
} EvidenceCacheLockTiming;

typedef struct {
  uint64_t acquired_ns;
  uint64_t wait_ns;
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  uint8_t suppress_sample;
#endif
} EvidenceCacheLockTls;

static EvidenceCacheLockTiming s_evidence_cache_lock_timing;
#ifdef _MSC_VER
static __declspec(thread) EvidenceCacheLockTls s_evidence_cache_lock_tls;
#else
static _Thread_local EvidenceCacheLockTls s_evidence_cache_lock_tls;
#endif

static uint64_t evidence_cache_clock_ns(void) {
#if defined(_WIN32)
  LARGE_INTEGER frequency;
  LARGE_INTEGER counter;
  if (!QueryPerformanceFrequency(&frequency) || !QueryPerformanceCounter(&counter) ||
      frequency.QuadPart <= 0 || counter.QuadPart < 0) {
    return 0u;
  }
  return (uint64_t)(((long double)counter.QuadPart * 1000000000.0L) /
                    (long double)frequency.QuadPart);
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0u;
  }
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static uint64_t evidence_cache_elapsed_ns(uint64_t start_ns, uint64_t end_ns) {
  return end_ns >= start_ns ? end_ns - start_ns : 0u;
}

static void evidence_cache_add_saturating(uint64_t *value, uint64_t addend) {
  if (!value || UINT64_MAX - *value < addend) {
    if (value) *value = UINT64_MAX;
    return;
  }
  *value += addend;
}

static unsigned evidence_cache_log2_bucket(uint64_t value) {
  unsigned bucket = 0u;
  while (value > 1u && bucket + 1u < EDR_EVIDENCE_CACHE_LOCK_HIST_BUCKETS) {
    value >>= 1u;
    bucket++;
  }
  return bucket;
}

static uint64_t evidence_cache_histogram_percentile(const uint64_t *histogram,
                                                     uint64_t samples,
                                                     unsigned percentile) {
  uint64_t base;
  uint64_t extra;
  uint64_t rank;
  uint64_t cumulative = 0u;
  if (!histogram || samples == 0u || percentile == 0u) {
    return 0u;
  }
  if (percentile > 100u) percentile = 100u;
  base = (samples / 100u) * (uint64_t)percentile;
  extra = ((samples % 100u) * (uint64_t)percentile + 99u) / 100u;
  rank = UINT64_MAX - base < extra ? UINT64_MAX : base + extra;
  if (rank == 0u) rank = 1u;
  for (unsigned i = 0u; i < EDR_EVIDENCE_CACHE_LOCK_HIST_BUCKETS; ++i) {
    if (UINT64_MAX - cumulative < histogram[i]) {
      cumulative = UINT64_MAX;
    } else {
      cumulative += histogram[i];
    }
    if (cumulative >= rank) {
      return i + 1u >= EDR_EVIDENCE_CACHE_LOCK_HIST_BUCKETS
                 ? UINT64_MAX
                 : (UINT64_C(1) << (i + 1u)) - 1u;
    }
  }
  return UINT64_MAX;
}

/* Called while the owner mutex is held. Keeping fixed buckets avoids a
 * second allocator, worker, configuration surface, or persistent metric. */
static void evidence_cache_record_lock_timing_locked(uint64_t wait_ns, uint64_t hold_ns) {
  EvidenceCacheLockTiming *timing = &s_evidence_cache_lock_timing;
  evidence_cache_add_saturating(&timing->samples, 1u);
  evidence_cache_add_saturating(&timing->wait_total_ns, wait_ns);
  evidence_cache_add_saturating(&timing->hold_total_ns, hold_ns);
  if (wait_ns > timing->wait_max_ns) timing->wait_max_ns = wait_ns;
  if (hold_ns > timing->hold_max_ns) timing->hold_max_ns = hold_ns;
  evidence_cache_add_saturating(
      &timing->wait_histogram[evidence_cache_log2_bucket(wait_ns)], 1u);
  evidence_cache_add_saturating(
      &timing->hold_histogram[evidence_cache_log2_bucket(hold_ns)], 1u);
}

/* This is the sole owner lock for the cache's bounded memory state and its
 * single SQLite connection. Collectors never call this module directly: the
 * public writers run from preprocess/worker paths, while health and RTQ read
 * through the same lock. No external callback or transport runs while held.
 * Lock timing is recorded on release, so a status snapshot reports only
 * completed samples and retains a genuine zero-sample state at startup. */
#if defined(_WIN32)
static SRWLOCK s_evidence_cache_lock = SRWLOCK_INIT;
static void evidence_cache_lock(void) {
  uint64_t started_ns = evidence_cache_clock_ns();
  AcquireSRWLockExclusive(&s_evidence_cache_lock);
  uint64_t acquired_ns = evidence_cache_clock_ns();
  s_evidence_cache_lock_tls.wait_ns = evidence_cache_elapsed_ns(started_ns, acquired_ns);
  s_evidence_cache_lock_tls.acquired_ns = acquired_ns;
}
static void evidence_cache_unlock(void) {
  uint64_t released_ns = evidence_cache_clock_ns();
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  if (s_evidence_cache_lock_tls.suppress_sample) {
    s_evidence_cache_lock_tls.suppress_sample = 0u;
  } else
#endif
  {
    evidence_cache_record_lock_timing_locked(
        s_evidence_cache_lock_tls.wait_ns,
        evidence_cache_elapsed_ns(s_evidence_cache_lock_tls.acquired_ns, released_ns));
  }
  s_evidence_cache_lock_tls.acquired_ns = 0u;
  s_evidence_cache_lock_tls.wait_ns = 0u;
  ReleaseSRWLockExclusive(&s_evidence_cache_lock);
}
#else
static pthread_mutex_t s_evidence_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static void evidence_cache_lock(void) {
  uint64_t started_ns = evidence_cache_clock_ns();
  (void)pthread_mutex_lock(&s_evidence_cache_lock);
  uint64_t acquired_ns = evidence_cache_clock_ns();
  s_evidence_cache_lock_tls.wait_ns = evidence_cache_elapsed_ns(started_ns, acquired_ns);
  s_evidence_cache_lock_tls.acquired_ns = acquired_ns;
}
static void evidence_cache_unlock(void) {
  uint64_t released_ns = evidence_cache_clock_ns();
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  if (s_evidence_cache_lock_tls.suppress_sample) {
    s_evidence_cache_lock_tls.suppress_sample = 0u;
  } else
#endif
  {
    evidence_cache_record_lock_timing_locked(
        s_evidence_cache_lock_tls.wait_ns,
        evidence_cache_elapsed_ns(s_evidence_cache_lock_tls.acquired_ns, released_ns));
  }
  s_evidence_cache_lock_tls.acquired_ns = 0u;
  s_evidence_cache_lock_tls.wait_ns = 0u;
  (void)pthread_mutex_unlock(&s_evidence_cache_lock);
}
#endif

#if defined(EDR_HAVE_SQLITE)
static sqlite3 *s_db;
static EdrContextStore s_context_store;
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
static unsigned s_test_commit_failures;
static unsigned s_test_live_size_query_failures;
static int s_test_commit_active;
static int s_test_force_original_memory_trim;

static int evidence_cache_test_deny_query(void *opaque, int action,
                                         const char *arg1, const char *arg2,
                                         const char *database, const char *trigger) {
  (void)opaque; (void)action; (void)arg1; (void)arg2;
  (void)database; (void)trigger;
  return SQLITE_DENY;
}

/* SQLite calls this synchronously from COMMIT. Returning non-zero aborts the
 * actual commit, so tests exercise the same accounting boundary as a durable
 * storage failure rather than a synthetic post-commit error. */
static int evidence_cache_test_commit_hook(void *opaque) {
  (void)opaque;
  if (s_test_commit_active && s_test_commit_failures > 0u) {
    s_test_commit_failures--;
    return 1;
  }
  return 0;
}
#endif
#endif

static void json_escape(char *dst, size_t cap, const char *s);
static void appendf(char *out, size_t cap, size_t *off, const char *fmt, ...);
static uint32_t evidence_context_window_s(void);
static int ring_related_to_record(const RingSlot *s, const EdrBehaviorRecord *r);
static int same_ci(const char *a, const char *b);

static int context_ref_write_sources_json_from_status(
    const EdrEvidenceCacheStatus *st, char *out, size_t cap) {
  size_t off = 0u;
  int first = 1;
  if (!st || !out || cap == 0u) {
    return -1;
  }
  appendf(out, cap, &off, "{");
  for (uint32_t type = 0u; type < EDR_LOCAL_EVIDENCE_EVENT_TYPE_BUCKETS; ++type) {
    uint64_t writes = st->context_ref_writes_by_event_type[type];
    if (writes == 0u) {
      continue;
    }
    appendf(out, cap, &off, "%s\"%u\":%llu", first ? "" : ",", type,
            (unsigned long long)writes);
    first = 0;
  }
  appendf(out, cap, &off, "}");
  if (off >= cap - 1u) {
    out[0] = '\0';
    return -1;
  }
  return (int)off;
}

static void set_error(const char *msg) {
#if defined(EDR_HAVE_SQLITE)
  if (s_db && sqlite3_errcode(s_db) == SQLITE_NOMEM)
    s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE;
#endif
  snprintf(s_status.last_error, sizeof(s_status.last_error), "%s", msg ? msg : "");
}

static const char *base_name(const char *path) {
  const char *b = path && path[0] ? path : "";
  for (const char *p = b; *p; p++) {
    if (*p == '/' || *p == '\\') {
      b = p + 1;
    }
  }
  return b;
}

static int copy_s(char *dst, size_t cap, const char *src) {
  const char *value = src ? src : "";
  size_t source_len;
  size_t copied;
  if (!dst || cap == 0u) {
    return 0;
  }
  source_len = strlen(value);
  copied = source_len < cap ? source_len : cap - 1u;
  if (copied > 0u) {
    memmove(dst, value, copied);
  }
  dst[copied] = '\0';
  if (copied != source_len) {
    s_status.bounded_string_truncations++;
    return 0;
  }
  return 1;
}

static int source_field_list_has(const char *list, const char *field) {
  const size_t field_len = field ? strlen(field) : 0u;
  const char *cursor = list;
  if (!cursor || !field_len) return 0;
  while (*cursor) {
    const char *end = strchr(cursor, ',');
    const size_t item_len = end ? (size_t)(end - cursor) : strlen(cursor);
    if (item_len == field_len && memcmp(cursor, field, field_len) == 0) return 1;
    if (!end) break;
    cursor = end + 1u;
  }
  return 0;
}

static void source_field_list_append(char *list, size_t cap, const char *field) {
  size_t used;
  size_t field_len;
  if (!list || cap == 0u || !field || !field[0] ||
      source_field_list_has(list, field)) {
    return;
  }
  used = strlen(list);
  field_len = strlen(field);
  if (used + (used ? 1u : 0u) + field_len >= cap) {
    return;
  }
  if (used) list[used++] = ',';
  memcpy(list + used, field, field_len + 1u);
}

static void capture_field_provenance(char *out, size_t cap,
                                     const EdrBehaviorRecord *record,
                                     const char *const *fields,
                                     size_t field_count,
                                     const char *cache_field,
                                     int copied_exactly) {
  if (!out || cap == 0u) return;
  out[0] = '\0';
  if (record) {
    for (size_t i = 0u; i < field_count; ++i) {
      if (source_field_list_has(record->source_truncated_fields, fields[i])) {
        source_field_list_append(out, cap, fields[i]);
      }
    }
    if (source_field_list_has(record->source_truncated_fields,
                              "source.list_overflow")) {
      source_field_list_append(out, cap, "source.list_overflow");
    }
  }
  if (!copied_exactly) source_field_list_append(out, cap, cache_field);
}

static void apply_cached_field_provenance(EdrBehaviorRecord *record,
                                          const char *fields) {
  const char *cursor = fields;
  if (!record || !cursor || !cursor[0]) return;
  while (*cursor) {
    const char *end = strchr(cursor, ',');
    const size_t item_len = end ? (size_t)(end - cursor) : strlen(cursor);
    char item[96];
    if (item_len > 0u && item_len < sizeof(item)) {
      memcpy(item, cursor, item_len);
      item[item_len] = '\0';
      source_field_list_append(record->source_truncated_fields,
                               sizeof(record->source_truncated_fields), item);
    }
    if (!end) break;
    cursor = end + 1u;
  }
  if (strcmp(record->source_completeness, "NOT_EVALUABLE") != 0) {
    copy_s(record->source_completeness,
           sizeof(record->source_completeness), "TRUNCATED");
  }
}

/* Compare command facts only after the caller admits the same lifetime.
 * Empty means no update; a known preview cannot replace a complete fact.
 * Between previews, only a compatible extension adds information. Complete
 * observations may legitimately change, including becoming shorter. NULL
 * provenance is legacy/unknown, never proof that the old command was complete. */
static int command_fact_should_replace(const char *current, const char *current_fields,
                                       const char *incoming, const char *incoming_fields) {
  size_t old_len, new_len;
  if (!incoming || !incoming[0]) return 0;
  if (!current || !current[0]) return 1;
  if (incoming_fields && !incoming_fields[0]) return 1;
  if (current_fields && !current_fields[0]) return 0;
  old_len = strlen(current);
  new_len = strlen(incoming);
  return new_len >= old_len && memcmp(current, incoming, old_len) == 0;
}

static void command_record_provenance(const EdrBehaviorRecord *r, char out[64]) {
  static const char *const fields[] = {"source.cmdline"};
  capture_field_provenance(out, 64u, r, fields, 1u, "source.cmdline", 1);
}

/* Private marker for NULL legacy provenance. It may be displayed as unknown
 * by RTQ, but must not be exported as a source truncation or complete fact. */
static int command_quality_known(const ProcSlot *p) {
  return p && !source_field_list_has(p->cmdline_truncated_fields,
                                     "source.cmdline_quality_unknown");
}

#if defined(EDR_HAVE_SQLITE)
static void hydrate_process_command(ProcSlot *p);
#endif

static int identity_quality_rank(const char *q) {
  if (!q) return 0;
  if (strcmp(q, "target_4688") == 0) return 4;
  if (strcmp(q, "token_sid") == 0) return 3;
  if (strcmp(q, "cache") == 0) return 2;
  if (strcmp(q, "creator_fallback") == 0) return 1;
  return 0;
}

#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
static int64_t s_test_now_unix_ns;
static int64_t s_test_retention_monotonic_ms = -1;
static int64_t s_test_retention_after_commit_ms = -1;

void edr_local_evidence_cache_test_set_now_unix_ns(int64_t now_ns) {
  evidence_cache_lock();
  s_test_now_unix_ns = now_ns;
  evidence_cache_unlock();
}

void edr_local_evidence_cache_test_set_retention_monotonic_ms(int64_t now_ms) {
  evidence_cache_lock();
  s_test_retention_monotonic_ms = now_ms;
  evidence_cache_unlock();
}

void edr_local_evidence_cache_test_set_retention_after_commit_monotonic_ms(int64_t now_ms) {
  evidence_cache_lock();
  s_test_retention_after_commit_ms = now_ms;
  evidence_cache_unlock();
}
#endif

static int64_t now_unix_ns(void) {
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  if (s_test_now_unix_ns > 0) return s_test_now_unix_ns;
#endif
  time_t t = time(NULL);
  return (int64_t)t * 1000000000LL;
}

static int64_t record_time_ns(const EdrBehaviorRecord *r) {
  if (r && r->event_time_ns > 0) {
    return r->event_time_ns;
  }
  return now_unix_ns();
}

static int generation_bound(const EvidenceProcessGeneration *generation) {
  return generation && generation->process_start_key != 0u &&
         generation->creation_filetime_100ns != 0u;
}

static int generation_equal(const EvidenceProcessGeneration *a,
                            const EvidenceProcessGeneration *b) {
  return generation_bound(a) && generation_bound(b) &&
         a->process_start_key == b->process_start_key &&
         a->creation_filetime_100ns == b->creation_filetime_100ns;
}

static int generation_birth_unix_ns(uint64_t creation_filetime_100ns,
                                    uint64_t *out) {
  const uint64_t epoch = UINT64_C(116444736000000000);
  if (!out || creation_filetime_100ns <= epoch ||
      creation_filetime_100ns - epoch > UINT64_MAX / 100u) {
    return 0;
  }
  *out = (creation_filetime_100ns - epoch) * 100u;
  return *out != 0u;
}

static uint8_t record_source_generation_shape(const EdrBehaviorRecord *r) {
  if (r && r->process_start_key != 0u &&
      r->process_creation_filetime_100ns != 0u) {
    return CANDIDATE_SOURCE_GENERATION_BOUND;
  }
  return CANDIDATE_SOURCE_GENERATION_MISSING;
}

static int generation_from_snapshot(uint32_t pid, int64_t event_time_ns,
                                    EvidenceProcessGeneration *out) {
  ProcessTreeEntry entry;
  if (!out || pid == 0u || event_time_ns <= 0 ||
      edr_pt_cache_snapshot_at(pid, (uint64_t)event_time_ns, &entry) != 0 ||
      entry.process_start_key == 0u || entry.creation_filetime_100ns == 0u) {
    return 0;
  }
  out->process_start_key = entry.process_start_key;
  out->creation_filetime_100ns = entry.creation_filetime_100ns;
  out->start_time_ns = entry.start_time_ns;
  return 1;
}

/* A timestamp can select a stale, still-open process-tree generation when an
 * exit notification was lost. A source record without its own generation may
 * use that snapshot only when it independently names the same actor image.
 * This prevents a reused PID's new display fields from being persisted with
 * the old process StartKey/creation FILETIME. */
static int generation_from_matching_record_snapshot(
    const EdrBehaviorRecord *r, EvidenceProcessGeneration *out) {
  ProcessTreeEntry entry;
  const char *record_path;
  if (!r || !out || r->pid == 0u || r->event_time_ns <= 0 ||
      edr_pt_cache_snapshot_at(r->pid, (uint64_t)r->event_time_ns, &entry) != 0 ||
      entry.process_start_key == 0u || entry.creation_filetime_100ns == 0u) {
    return 0;
  }
  record_path = r->image_path_canonical[0] ? r->image_path_canonical : r->exe_path;
  if (record_path[0] && entry.exe_path[0]) {
    if (!same_ci(record_path, entry.exe_path)) return 0;
  }
  if (r->process_name[0] && entry.process_name[0]) {
    if (!same_ci(r->process_name, entry.process_name)) return 0;
  }
  /* Metadata-only observations cannot overwrite image display fields and
   * retain the existing event-time fallback contract. Any independently
   * reported image field, however, must agree with the selected generation. */
  out->process_start_key = entry.process_start_key;
  out->creation_filetime_100ns = entry.creation_filetime_100ns;
  out->start_time_ns = entry.start_time_ns;
  return 1;
}

/* NET_CONNECT/NET_LISTEN bind the actor generation before entering this
 * cache.  If that bind failed, the pipeline deliberately clears the tuple.
 * Treating the cleared tuple as permission to use this cache's historical
 * PID/time fallback would undo that security decision and could attach a
 * stale open interval after PID reuse. */
static int network_actor_generation_unbound(const EdrBehaviorRecord *r) {
  return r &&
         (r->type == EDR_EVENT_NET_CONNECT ||
          r->type == EDR_EVENT_NET_LISTEN) &&
         (r->process_start_key == 0u ||
          r->process_creation_filetime_100ns == 0u);
}

/* Source-record generation wins when present; the historical process-tree
 * snapshot is an event-time fallback, never a current-PID lookup.  A partial
 * source tuple is deliberately not upgraded from another source. */
static int record_process_generation(const EdrBehaviorRecord *r,
                                     EvidenceProcessGeneration *out) {
  if (!r || !out || r->pid == 0u) {
    return 0;
  }
  memset(out, 0, sizeof(*out));
  if (network_actor_generation_unbound(r)) {
    return 0;
  }
  if (r->process_start_key != 0u || r->process_creation_filetime_100ns != 0u) {
    if (r->process_start_key == 0u || r->process_creation_filetime_100ns == 0u) {
      return 0;
    }
    out->process_start_key = r->process_start_key;
    out->creation_filetime_100ns = r->process_creation_filetime_100ns;
    /* Keep an event-time interval only when it independently proves the same
     * source tuple; it is not allowed to replace source generation facts. */
    {
      EvidenceProcessGeneration historical;
      if (generation_from_snapshot(r->pid, r->event_time_ns, &historical) &&
          generation_equal(out, &historical)) {
        out->start_time_ns = historical.start_time_ns;
      }
    }
    return 1;
  }
  return generation_from_matching_record_snapshot(r, out);
}

/* Parent ownership is a property of the child lifetime.  Later file/network
 * events can happen after the parent exits and its PID is reused, so their
 * own event timestamps are not allowed to move an already bound edge. */
static int record_parent_context_proven(const EdrBehaviorRecord *r);
static int parent_tuple_conflicted(uint32_t pid, uint64_t key, uint64_t creation) {
  uint64_t birth_ns;
  ProcessTreeEntry retained;
  return pid && key && generation_birth_unix_ns(creation, &birth_ns) &&
      edr_pt_cache_snapshot_generation_at(pid, key, birth_ns, &retained) == 0 &&
      retained.generation_conflict;
}

static int record_parent_snapshot(const EdrBehaviorRecord *r,
                                  ProcessTreeEntry *snapshot) {
  uint64_t child_birth_ns = 0u;
  uint64_t selector_ns;
  if (!edr_behavior_parent_pid_usable(r) || !snapshot ||
      network_actor_generation_unbound(r) ||
      strcmp(r->parent_resolution_source, "parent_generation_conflict") == 0 ||
      strcmp(r->parent_resolution_status, "CONFLICT") == 0) {
    return 0;
  }
  if (!generation_birth_unix_ns(r->process_creation_filetime_100ns, &child_birth_ns))
    return 0;
  selector_ns = child_birth_ns;
  memset(snapshot, 0, sizeof(*snapshot));
  if (record_parent_context_proven(r)) {
    if (parent_tuple_conflicted(r->ppid, r->parent_process_start_key,
                                r->parent_process_creation_filetime_100ns))
      return 0;
    /* An already captured exact edge survives cache eviction. This copies
     * retained facts, not a new alive observation or a PID-only inference. */
    snapshot->pid = r->ppid;
    snapshot->process_start_key = r->parent_process_start_key;
    snapshot->creation_filetime_100ns = r->parent_process_creation_filetime_100ns;
    if (!generation_birth_unix_ns(snapshot->creation_filetime_100ns,
                                  &snapshot->start_time_ns))
      return 0;
    copy_s(snapshot->process_name, sizeof(snapshot->process_name), r->parent_name);
    copy_s(snapshot->exe_path, sizeof(snapshot->exe_path), r->parent_path);
    copy_s(snapshot->cmdline, sizeof(snapshot->cmdline), r->parent_cmdline);
    if (edr_behavior_source_field_truncated(r, "source.parent_path"))
      snapshot->source_truncation_mask |= EDR_PTC_SOURCE_TRUNC_EXE_PATH;
    if (edr_behavior_source_field_truncated(r, "source.parent_cmdline"))
      snapshot->source_truncation_mask |= EDR_PTC_SOURCE_TRUNC_CMDLINE;
    return 1;
  }
  if (selector_ns == 0u ||
      edr_pt_cache_snapshot_parent_at(r->ppid, selector_ns, snapshot) != 0 ||
      snapshot->process_start_key == 0u ||
      snapshot->creation_filetime_100ns == 0u) {
    return 0;
  }
  if (r->process_creation_filetime_100ns != 0u &&
      snapshot->creation_filetime_100ns >
          r->process_creation_filetime_100ns) {
    memset(snapshot, 0, sizeof(*snapshot));
    return 0;
  }
  return 1;
}

static int record_parent_context_proven(const EdrBehaviorRecord *r) {
  return edr_behavior_parent_context_bound(r);
}

static int cached_parent_source_proven(const char *source) {
  return source &&
      (strcmp(source, "verified_child_birth_parent_snapshot") == 0 ||
       strcmp(source, "verified_late_child_birth_parent_snapshot") == 0);
}

static void apply_proven_parent_reference(EdrBehaviorRecord *r,
                                          const EvidenceProcessGeneration *parent) {
  uint64_t birth_ns;
  if (!edr_behavior_parent_pid_usable(r) || !parent ||
      !generation_bound(parent) ||
      parent->creation_filetime_100ns > r->process_creation_filetime_100ns ||
      !generation_birth_unix_ns(parent->creation_filetime_100ns, &birth_ns))
    return;
  r->parent_process_start_key = parent->process_start_key;
  r->parent_process_creation_filetime_100ns = parent->creation_filetime_100ns;
  edr_behavior_format_time_ns((int64_t)birth_ns,
      r->parent_creation_time, sizeof(r->parent_creation_time));
  if (strcmp(r->parent_resolution_source, "live_parent_generation") != 0)
    copy_s(r->parent_resolution_source, sizeof(r->parent_resolution_source),
           "process_tree_cache_verified");
  edr_behavior_bind_parent_context(r);
}

static int record_parent_generation(const EdrBehaviorRecord *r,
                                    EvidenceProcessGeneration *out) {
  ProcessTreeEntry snapshot;
  if (r && strcmp(r->parent_resolution_source, "parent_generation_conflict") == 0)
    return 0;
  if (!out || !record_parent_snapshot(r, &snapshot)) return 0;
  memset(out, 0, sizeof(*out));
  out->process_start_key = snapshot.process_start_key;
  out->creation_filetime_100ns = snapshot.creation_filetime_100ns;
  out->start_time_ns = snapshot.start_time_ns;
  return 1;
}

/* The source label is evidence metadata too: do not turn an event-time
 * process-tree lookup into a claim that the collector supplied a live ETW
 * start key.  A raw tuple without a label remains explicitly identifiable. */
static const char *record_process_generation_source(const EdrBehaviorRecord *r) {
  EvidenceProcessGeneration generation;
  if (!r) return "";
  if (r->process_start_key != 0u && r->process_creation_filetime_100ns != 0u) {
    return r->process_generation_source[0] ? r->process_generation_source : "source_record_tuple";
  }
  return record_process_generation(r, &generation)
             ? "process_tree_snapshot"
             : "";
}

static const char *record_parent_generation_source(const EdrBehaviorRecord *r) {
  ProcessTreeEntry snapshot;
  if (!record_parent_snapshot(r, &snapshot)) return "";
  return r->process_creation_filetime_100ns != 0u
             ? "verified_child_birth_parent_snapshot"
             : "";
}

static int proc_generation_matches_record(const ProcSlot *p,
                                          const EdrBehaviorRecord *r,
                                          const char **diagnostic_reason) {
  EvidenceProcessGeneration generation;
  if (!p || !record_process_generation(r, &generation)) {
    if (diagnostic_reason) *diagnostic_reason = p ? "cache_record_generation_unproven" : "cache_miss";
    return 0;
  }
  if (!generation_bound(&p->generation)) {
    if (diagnostic_reason) *diagnostic_reason = "cache_generation_incomplete";
    return 0;
  }
  if (!generation_equal(&p->generation, &generation)) {
    if (diagnostic_reason) *diagnostic_reason = "cache_generation_mismatch";
    return 0;
  }
  return 1;
}

static int proc_parent_generation_matches_record(const ProcSlot *p,
                                                 const EdrBehaviorRecord *r) {
  /* Once an exact child lifetime owns a parent edge, a later actor event does
   * not need the parent generation to remain in the short-lived process-tree
   * history.  Requiring another snapshot here made a valid edge disappear
   * after the parent exit grace, or change when that PID was reused. */
  return p && edr_behavior_parent_pid_usable(r) && p->parent_pid_state == EDR_PARENT_PID_KNOWN &&
         strcmp(r->parent_resolution_source, "parent_generation_conflict") != 0 &&
         proc_generation_matches_record(p, r, NULL) &&
         generation_bound(&p->parent_generation) &&
         cached_parent_source_proven(p->parent_process_generation_source) &&
         !parent_tuple_conflicted(p->ppid, p->parent_generation.process_start_key,
                                  p->parent_generation.creation_filetime_100ns) &&
         p->ppid == r->ppid &&
         (!r->parent_process_start_key ||
          (r->parent_process_start_key == p->parent_generation.process_start_key &&
           r->parent_process_creation_filetime_100ns ==
               p->parent_generation.creation_filetime_100ns));
}

static int same_endpoint(const ProcSlot *p, const EdrBehaviorRecord *r) {
  if (!p || !r) {
    return 0;
  }
  if (p->endpoint_id[0] && r->endpoint_id[0] && strcmp(p->endpoint_id, r->endpoint_id) != 0) {
    return 0;
  }
  return 1;
}

static ProcSlot *find_proc(uint32_t pid, const char *endpoint_id) {
  if (pid == 0u) {
    return NULL;
  }
  for (size_t i = 0; i < EDR_EVIDENCE_PROC_SLOTS; i++) {
    ProcSlot *p = &s_proc[i];
    if (p->pid != pid) {
      continue;
    }
    if (endpoint_id && endpoint_id[0] && p->endpoint_id[0] && strcmp(p->endpoint_id, endpoint_id) != 0) {
      continue;
    }
    return p;
  }
  return NULL;
}

static ProcSlot *alloc_proc(uint32_t pid, const EdrBehaviorRecord *r) {
  ProcSlot *empty = NULL;
  ProcSlot *oldest = &s_proc[0];
  for (size_t i = 0; i < EDR_EVIDENCE_PROC_SLOTS; i++) {
    ProcSlot *p = &s_proc[i];
    if (p->pid == pid && same_endpoint(p, r)) {
      return p;
    }
    if (p->pid == 0u && empty == NULL) {
      empty = p;
    }
    if (p->last_seen_ns < oldest->last_seen_ns) {
      oldest = p;
    }
  }
  ProcSlot *p = empty ? empty : oldest;
  if (!empty && p->pid != 0u) s_status.process_cache_evictions++;
  memset(p, 0, sizeof(*p));
  p->pid = pid;
  return p;
}

static int should_update_process_cache(const EdrBehaviorRecord *r) {
  if (!r || r->pid == 0u || network_actor_generation_unbound(r)) {
    return 0;
  }
  if (r->type == EDR_EVENT_PROCESS_CREATE) {
    return 1;
  }
  /* PPID and parent fields describe another process and cannot establish an
   * actor cache entry on their own.  Require metadata about this PID. */
  return r->process_name[0] || r->exe_path[0] || r->cmdline[0] ||
         r->username[0] || r->user_sid[0] || r->creator_username[0] ||
         r->creator_sid[0] || r->identity_quality[0] || r->domain[0] ||
         r->integrity_level[0] ||
         r->token_elevation != 0u || r->exe_hash[0] || r->current_directory[0] ||
         r->process_creation_time[0];
}

static void proc_slot_bind_parent_snapshot(ProcSlot *child,
                                           const ProcessTreeEntry *parent,
                                           const char *source) {
  EvidenceProcessGeneration generation;
  int changed;
  if (!child || !parent || parent->process_start_key == 0u ||
      parent->creation_filetime_100ns == 0u) {
    return;
  }
  memset(&generation, 0, sizeof(generation));
  generation.process_start_key = parent->process_start_key;
  generation.creation_filetime_100ns = parent->creation_filetime_100ns;
  generation.start_time_ns = parent->start_time_ns;
  changed = generation_bound(&child->parent_generation) &&
            !generation_equal(&child->parent_generation, &generation);
  if (changed) {
    child->parent_name[0] = '\0';
    child->parent_path[0] = '\0';
    child->parent_cmdline[0] = '\0';
    child->parent_path_truncated_fields[0] = '\0';
    child->parent_cmdline_truncated_fields[0] = '\0';
    child->grandparent_pid = 0u;
    child->grandparent_name[0] = '\0';
    child->grandparent_path[0] = '\0';
    child->grandparent_path_truncated_fields[0] = '\0';
  }
  child->parent_generation = generation;
  copy_s(child->parent_process_generation_source,
         sizeof(child->parent_process_generation_source), source);
  if (parent->process_name[0])
    copy_s(child->parent_name, sizeof(child->parent_name),
           parent->process_name);
  if (parent->exe_path[0]) {
    const int exact = copy_s(child->parent_path, sizeof(child->parent_path),
                             parent->exe_path);
    child->parent_path_truncated_fields[0] = '\0';
    if (!exact || (parent->source_truncation_mask &
                   EDR_PTC_SOURCE_TRUNC_EXE_PATH) != 0u) {
      source_field_list_append(child->parent_path_truncated_fields,
                               sizeof(child->parent_path_truncated_fields),
                               "source.parent_path");
    }
  }
  if (parent->cmdline[0]) {
    const int exact = copy_s(child->parent_cmdline,
                             sizeof(child->parent_cmdline), parent->cmdline);
    child->parent_cmdline_truncated_fields[0] = '\0';
    if (!exact || (parent->source_truncation_mask &
                   EDR_PTC_SOURCE_TRUNC_CMDLINE) != 0u) {
      source_field_list_append(child->parent_cmdline_truncated_fields,
                               sizeof(child->parent_cmdline_truncated_fields),
                               "source.parent_cmdline");
    }
  }
}

/* A real parent ProcessStart can be delivered after its child.  Repair only
 * children for which an event-time snapshot at the immutable child birth now
 * selects this exact parent generation.  Creation ordering prevents a later
 * PID reuse from being rewritten as the historical parent. */
static void repair_child_parent_edges(const EdrBehaviorRecord *parent,
                                      const EvidenceProcessGeneration *generation) {
  if (!parent || !generation_bound(generation) || parent->pid == 0u ||
      parent->type != EDR_EVENT_PROCESS_CREATE ||
      !edr_process_create_is_lifecycle_authoritative(parent)) {
    return;
  }
  for (size_t i = 0u; i < EDR_EVIDENCE_PROC_SLOTS; ++i) {
    ProcSlot *child = &s_proc[i];
    ProcessTreeEntry selected;
    uint64_t child_birth_ns;
    if (child->pid == 0u || child->pid == parent->pid ||
        strcmp(child->parent_process_generation_source, "parent_generation_conflict") == 0 ||
        child->ppid != parent->pid || child->parent_pid_state != EDR_PARENT_PID_KNOWN ||
        !generation_bound(&child->generation) ||
        generation->creation_filetime_100ns >
            child->generation.creation_filetime_100ns ||
        (child->endpoint_id[0] && parent->endpoint_id[0] &&
         strcmp(child->endpoint_id, parent->endpoint_id) != 0) ||
        !generation_birth_unix_ns(
            child->generation.creation_filetime_100ns, &child_birth_ns) ||
        edr_pt_cache_snapshot_parent_at(parent->pid, child_birth_ns, &selected) != 0 ||
        selected.process_start_key != generation->process_start_key ||
        selected.creation_filetime_100ns !=
            generation->creation_filetime_100ns) {
      continue;
    }
    if (generation_bound(&child->parent_generation) &&
        !generation_equal(&child->parent_generation, generation) &&
        generation->creation_filetime_100ns <=
            child->parent_generation.creation_filetime_100ns) {
      continue;
    }
    proc_slot_bind_parent_snapshot(child, &selected,
                                   "verified_late_child_birth_parent_snapshot");
  }
}

static void process_cache_update(const EdrBehaviorRecord *r) {
  if (!should_update_process_cache(r)) {
    return;
  }
  int has_identity = r->username[0] || r->domain[0] || r->user_sid[0] || r->logon_id[0] ||
                     r->creator_username[0] || r->creator_domain[0] || r->creator_sid[0] || r->creator_logon_id[0];
  EvidenceProcessGeneration incoming_generation;
  EvidenceProcessGeneration incoming_parent_generation;
  ProcessTreeEntry incoming_parent_snapshot;
  int incoming_generation_known = record_process_generation(r, &incoming_generation);
  int incoming_parent_generation_known =
      record_parent_snapshot(r, &incoming_parent_snapshot);
  memset(&incoming_parent_generation, 0, sizeof(incoming_parent_generation));
  if (incoming_parent_generation_known) {
    incoming_parent_generation.process_start_key =
        incoming_parent_snapshot.process_start_key;
    incoming_parent_generation.creation_filetime_100ns =
        incoming_parent_snapshot.creation_filetime_100ns;
    incoming_parent_generation.start_time_ns =
        incoming_parent_snapshot.start_time_ns;
  }
  int64_t incoming_time_ns = r->event_time_ns;
  if (strcmp(r->identity_quality, "target_4688") == 0) s_status.identity_target_4688++;
  else if (strcmp(r->identity_quality, "creator_fallback") == 0) s_status.identity_creator_fallback++;
  else if (strcmp(r->identity_quality, "token_sid") == 0) s_status.identity_token_sid++;
  else if (!r->identity_quality[0]) s_status.identity_none++;
  ProcSlot *p = find_proc(r->pid, r->endpoint_id);
  const int command_cache_cold = !p || !generation_bound(&p->generation) ||
      (incoming_generation_known && !generation_equal(&p->generation, &incoming_generation));
  if (!p && has_identity && !incoming_generation_known) {
    /* Do not create a generation-zero identity slot that a later PID reuse can inherit. */
    s_status.generation_unknown_update_rejects++;
    return;
  }
  if (!p) p = alloc_proc(r->pid, r);
  if (!p) return;
  if (generation_bound(&p->generation) && !incoming_generation_known) {
    s_status.generation_unknown_update_rejects++;
    return;
  }
  if (generation_bound(&p->generation) && incoming_generation_known &&
      !generation_equal(&p->generation, &incoming_generation)) {
    /* A source tuple differs.  Only a strictly later event may replace this
     * bounded slot; a delayed A event must never overwrite PID-reused B. */
    if (incoming_time_ns <= 0 || p->last_seen_ns <= 0 ||
        incoming_time_ns <= p->last_seen_ns ||
        (incoming_generation.start_time_ns != 0u && p->generation.start_time_ns != 0u &&
         incoming_generation.start_time_ns < p->generation.start_time_ns)) {
      s_status.generation_mismatch_update_rejects++;
      s_status.late_generation_rejects++;
      return;
    }
    memset(p, 0, sizeof(*p));
    p->pid = r->pid;
    p->generation = incoming_generation;
    s_status.generation_resets++;
  } else if (!generation_bound(&p->generation) && incoming_generation_known) {
    /* An unknown lifetime may contain only provisional display metadata.  A
     * first authoritative tuple starts a clean slot, never upgrades it. */
    int had_provisional_state = p->last_seen_ns != 0 || p->name[0] || p->path[0] ||
                                p->cmdline[0] || p->ppid != 0u || p->username[0] ||
                                p->user_sid[0] || p->creator_username[0] ||
                                p->creator_sid[0] || p->exe_hash[0];
    memset(p, 0, sizeof(*p));
    p->pid = r->pid;
    p->generation = incoming_generation;
    if (had_provisional_state) s_status.generation_resets++;
  } else if (incoming_generation_known) {
    p->generation = incoming_generation;
  }
  p->pid = r->pid;
  edr_parent_pid_merge(&p->ppid, &p->parent_pid_state, r->ppid, r->parent_pid_state);
  if (p->parent_pid_state == EDR_PARENT_PID_CONFLICT ||
      p->parent_pid_state == EDR_PARENT_PID_INVALID) {
    p->parent_name[0] = p->parent_path[0] = p->parent_cmdline[0] = '\0';
    p->parent_path_truncated_fields[0] = p->parent_cmdline_truncated_fields[0] = '\0';
    p->grandparent_pid = 0u;
    p->grandparent_name[0] = p->grandparent_path[0] = p->grandparent_path_truncated_fields[0] = '\0';
    memset(&p->parent_generation, 0, sizeof(p->parent_generation));
    p->parent_process_generation_source[0] = '\0';
    incoming_parent_generation_known = 0;
  }
  p->last_seen_ns = record_time_ns(r);
  if (strcmp(r->parent_resolution_source, "parent_generation_conflict") == 0) {
    copy_s(p->parent_process_generation_source,
           sizeof(p->parent_process_generation_source), "parent_generation_conflict");
  }
  if (incoming_parent_generation_known &&
      strcmp(p->parent_process_generation_source, "parent_generation_conflict") != 0 &&
      incoming_parent_generation.creation_filetime_100ns <=
          p->generation.creation_filetime_100ns &&
      (!generation_bound(&p->parent_generation) ||
       generation_equal(&p->parent_generation, &incoming_parent_generation) ||
       incoming_parent_generation.creation_filetime_100ns >
           p->parent_generation.creation_filetime_100ns)) {
    proc_slot_bind_parent_snapshot(p, &incoming_parent_snapshot,
                                   record_parent_generation_source(r));
  }
  if (incoming_generation_known) {
    copy_s(p->process_generation_source, sizeof(p->process_generation_source),
           record_process_generation_source(r));
  }
  if (r->endpoint_id[0]) {
    copy_s(p->endpoint_id, sizeof(p->endpoint_id), r->endpoint_id);
  }
  if (r->tenant_id[0]) {
    if (p->tenant_id[0] && strcmp(p->tenant_id, r->tenant_id) != 0) {
      p->cmdline[0] = '\0';
      p->cmdline_truncated_fields[0] = '\0';
    }
    copy_s(p->tenant_id, sizeof(p->tenant_id), r->tenant_id);
  }
  if (r->process_name[0]) {
    copy_s(p->name, sizeof(p->name), r->process_name);
  } else if (r->exe_path[0] && !p->name[0]) {
    copy_s(p->name, sizeof(p->name), base_name(r->exe_path));
  }
  if (r->exe_path[0]) {
    static const char *const path_fields[] = {
        "source.exe_path", "source.image_path_raw",
        "source.image_path_canonical"};
    const int exact = copy_s(p->path, sizeof(p->path), r->exe_path);
    capture_field_provenance(p->path_truncated_fields,
                             sizeof(p->path_truncated_fields), r,
                             path_fields,
                             sizeof(path_fields) / sizeof(path_fields[0]),
                             "source.exe_path", exact);
  }
#if defined(EDR_HAVE_SQLITE)
  /* Hydrate once per cold lifetime, including an empty first command, not on
   * every ordinary event/cache miss. Sparse metadata must not mask SQL facts. */
  if (command_cache_cold && !p->cmdline[0]) hydrate_process_command(p);
#else
  (void)command_cache_cold;
#endif
  if (r->cmdline[0]) {
    char fields[64];
    command_record_provenance(r, fields);
    if (command_fact_should_replace(p->cmdline, p->cmdline_truncated_fields,
                                    r->cmdline, fields)) {
      const int exact = copy_s(p->cmdline, sizeof(p->cmdline), r->cmdline);
      copy_s(p->cmdline_truncated_fields, sizeof(p->cmdline_truncated_fields), fields);
      if (!exact) source_field_list_append(p->cmdline_truncated_fields,
          sizeof(p->cmdline_truncated_fields), "source.cmdline");
    }
  }
  /* Grandparent display is retained only with the child lifecycle and the
   * exact parent edge selected at that child's birth.  It is never rebuilt
   * from a current numeric PID during later file/network enrichment. */
  if (incoming_generation_known && incoming_parent_generation_known &&
      r->type == EDR_EVENT_PROCESS_CREATE &&
      edr_process_create_is_lifecycle_authoritative(r) &&
      (r->grandparent_pid != 0u || r->grandparent_name[0] ||
       r->grandparent_path[0])) {
    static const char *const grandparent_path_fields[] = {
        "source.grandparent_path"};
    p->grandparent_pid = r->grandparent_pid;
    copy_s(p->grandparent_name, sizeof(p->grandparent_name),
           r->grandparent_name);
    {
      const int exact = copy_s(p->grandparent_path,
                               sizeof(p->grandparent_path),
                               r->grandparent_path);
      capture_field_provenance(
          p->grandparent_path_truncated_fields,
          sizeof(p->grandparent_path_truncated_fields), r,
          grandparent_path_fields, 1u, "source.grandparent_path", exact);
    }
  }
  if (r->username[0] || r->user_sid[0]) {
    int incoming = identity_quality_rank(r->identity_quality);
    int current = identity_quality_rank(p->identity_quality);
    if ((!p->username[0] && !p->user_sid[0]) || incoming > current || incoming == current) {
      if (p->identity_quality[0] && incoming > current) s_status.identity_upgrades++;
      if ((!p->username[0] && !p->user_sid[0]) || incoming > current) copy_s(p->username, sizeof(p->username), r->username);
      if (incoming > current || !p->identity_quality[0]) {
        copy_s(p->domain, sizeof(p->domain), r->domain);
        copy_s(p->user_sid, sizeof(p->user_sid), r->user_sid);
        copy_s(p->logon_id, sizeof(p->logon_id), r->logon_id);
        copy_s(p->identity_source, sizeof(p->identity_source), r->identity_source);
        copy_s(p->identity_quality, sizeof(p->identity_quality), r->identity_quality);
      } else if (incoming == current) {
        if (!p->domain[0]) copy_s(p->domain, sizeof(p->domain), r->domain);
        if (!p->user_sid[0]) copy_s(p->user_sid, sizeof(p->user_sid), r->user_sid);
        if (!p->logon_id[0]) copy_s(p->logon_id, sizeof(p->logon_id), r->logon_id);
      }
    }
  }
  if (r->creator_username[0]) copy_s(p->creator_username, sizeof(p->creator_username), r->creator_username);
  if (r->creator_domain[0]) copy_s(p->creator_domain, sizeof(p->creator_domain), r->creator_domain);
  if (r->creator_sid[0]) copy_s(p->creator_sid, sizeof(p->creator_sid), r->creator_sid);
  if (r->creator_logon_id[0]) copy_s(p->creator_logon_id, sizeof(p->creator_logon_id), r->creator_logon_id);
  if (r->integrity_level[0]) {
    copy_s(p->integrity_level, sizeof(p->integrity_level), r->integrity_level);
  }
  if (r->token_elevation != 0u) {
    p->token_elevation = r->token_elevation;
  }
  if (r->exe_hash[0]) {
    copy_s(p->exe_hash, sizeof(p->exe_hash), r->exe_hash);
  }
  if (r->current_directory[0]) {
    copy_s(p->current_directory, sizeof(p->current_directory), r->current_directory);
  }
  if (r->process_creation_time[0]) {
    copy_s(p->process_creation_time, sizeof(p->process_creation_time), r->process_creation_time);
  }
  repair_child_parent_edges(r, &incoming_generation);
}

#if defined(EDR_HAVE_SQLITE)
static int repair_child_parent_edges_sqlite(const EdrBehaviorRecord *parent,
                                           const EvidenceProcessGeneration *generation);
#endif

void edr_local_evidence_cache_observe_process(const EdrBehaviorRecord *r) {
  if (!r || network_actor_generation_unbound(r)) return;
  evidence_cache_lock();
  s_status.identity_observations_total++;
  process_cache_update(r);
#if defined(EDR_HAVE_SQLITE)
  if (r->type == EDR_EVENT_PROCESS_CREATE &&
      edr_process_create_is_lifecycle_authoritative(r)) {
    EvidenceProcessGeneration generation;
    if (record_process_generation(r,&generation))
      (void)repair_child_parent_edges_sqlite(r,&generation);
  }
#endif
  evidence_cache_unlock();
}

void edr_local_evidence_cache_enrich_behavior(EdrBehaviorRecord *r) {
  if (!r || network_actor_generation_unbound(r)) {
    if (r) edr_validation_trace_event(r, "parent_cache", "cache_actor_unbound");
    return;
  }
  const char *cache_reason = "cache_miss";
  evidence_cache_lock();
  if (strcmp(r->parent_resolution_status, "CONFLICT") == 0 ||
      (record_parent_context_proven(r) &&
       parent_tuple_conflicted(r->ppid, r->parent_process_start_key,
                                r->parent_process_creation_filetime_100ns))) {
    edr_behavior_clear_parent_context(r);
    copy_s(r->parent_resolution_source, sizeof(r->parent_resolution_source),
           "parent_generation_conflict");
    copy_s(r->parent_resolution_status, sizeof(r->parent_resolution_status), "NOT_EVALUABLE");
    cache_reason = "cache_parent_generation_conflict";
  }
  if (edr_behavior_parent_pid_usable(r) && !record_parent_context_proven(r) &&
      (r->parent_name[0] || r->parent_path[0] || r->parent_cmdline[0] ||
       r->parent_process_start_key || r->parent_process_creation_filetime_100ns)) {
    edr_behavior_clear_parent_context(r);
    copy_s(r->parent_resolution_source, sizeof(r->parent_resolution_source),
           "parent_generation_unproven");
    copy_s(r->parent_resolution_status, sizeof(r->parent_resolution_status), "NOT_EVALUABLE");
  }
  EvidenceProcessGeneration parent_ref;
  if (record_parent_generation(r, &parent_ref)) {
    apply_proven_parent_reference(r, &parent_ref);
  }
  s_status.identity_enrich_attempts++;
  ProcSlot *p = find_proc(r->pid, r->endpoint_id);
  if (p) {
    s_status.process_cache_hits++;
    int process_safe = proc_generation_matches_record(p, r, &cache_reason);
    if (!process_safe) {
      if (!generation_bound(&p->generation)) s_status.identity_generation_unknown_rejects++;
      else s_status.identity_generation_mismatch_rejects++;
      if (p->username[0] || p->user_sid[0]) {
        s_status.identity_stale_rejects++;
        if (!r->username[0] && !r->user_sid[0]) s_status.identity_cache_misses++;
      }
    } else {
      switch (edr_parent_pid_effective_state(p->ppid, p->parent_pid_state)) {
        case EDR_PARENT_PID_KNOWN: cache_reason = "cache_parent_known"; break;
        case EDR_PARENT_PID_EXPLICIT_ZERO: cache_reason = "cache_parent_explicit_zero"; break;
        case EDR_PARENT_PID_INVALID: cache_reason = "cache_parent_invalid"; break;
        case EDR_PARENT_PID_CONFLICT: cache_reason = "cache_parent_conflict"; break;
        default: cache_reason = "cache_parent_unknown"; break;
      }
      edr_parent_pid_merge(&r->ppid, &r->parent_pid_state, p->ppid, p->parent_pid_state);
      if (r->parent_pid_state == EDR_PARENT_PID_CONFLICT ||
          r->parent_pid_state == EDR_PARENT_PID_INVALID)
        edr_behavior_clear_parent_context(r);
      if (!r->process_name[0] && p->name[0]) {
        copy_s(r->process_name, sizeof(r->process_name), p->name);
      }
      if (!r->exe_path[0] && p->path[0]) {
        const int exact = copy_s(r->exe_path, sizeof(r->exe_path), p->path);
        apply_cached_field_provenance(r, p->path_truncated_fields);
        if (!exact) apply_cached_field_provenance(r, "source.exe_path");
      }
      if (!r->cmdline[0] && p->cmdline[0] && command_quality_known(p)) {
        const int exact = copy_s(r->cmdline, sizeof(r->cmdline), p->cmdline);
        apply_cached_field_provenance(r, p->cmdline_truncated_fields);
        if (!exact) apply_cached_field_provenance(r, "source.cmdline");
      }
      /* Parent display fields are a separate identity.  A self-generation
       * match is not permission to copy a PID-only parent observation. */
      if ((cached_parent_source_proven(p->parent_process_generation_source) &&
           generation_bound(&p->parent_generation) &&
           (parent_tuple_conflicted(p->ppid, p->parent_generation.process_start_key,
                                     p->parent_generation.creation_filetime_100ns) ||
            (record_parent_context_proven(r) &&
             (r->parent_process_start_key != p->parent_generation.process_start_key ||
              r->parent_process_creation_filetime_100ns !=
                  p->parent_generation.creation_filetime_100ns)))) ||
          strcmp(p->parent_process_generation_source, "parent_generation_conflict") == 0) {
        /* Keep the child and numeric PPID. A retained contradictory parent
         * tuple must not re-authorize text after the short PTC is evicted. */
        copy_s(p->parent_process_generation_source,
               sizeof(p->parent_process_generation_source), "parent_generation_conflict");
        edr_behavior_clear_parent_context(r);
        copy_s(r->parent_resolution_source, sizeof(r->parent_resolution_source),
               "parent_generation_conflict");
        copy_s(r->parent_resolution_status, sizeof(r->parent_resolution_status), "NOT_EVALUABLE");
        cache_reason = "cache_parent_generation_conflict";
      }
      if (proc_parent_generation_matches_record(p, r)) {
        apply_proven_parent_reference(r, &p->parent_generation);
        if (!r->parent_name[0] && p->parent_name[0]) {
          copy_s(r->parent_name, sizeof(r->parent_name), p->parent_name);
        }
        if (!r->parent_path[0] && p->parent_path[0]) {
          copy_s(r->parent_path, sizeof(r->parent_path), p->parent_path);
          apply_cached_field_provenance(r,
                                        p->parent_path_truncated_fields);
        }
        if (!r->parent_cmdline[0] && p->parent_cmdline[0]) {
          copy_s(r->parent_cmdline, sizeof(r->parent_cmdline), p->parent_cmdline);
          apply_cached_field_provenance(r,
                                        p->parent_cmdline_truncated_fields);
        }
        if (r->grandparent_pid == 0u) r->grandparent_pid = p->grandparent_pid;
        if (!r->grandparent_name[0] && p->grandparent_name[0])
          copy_s(r->grandparent_name, sizeof(r->grandparent_name),
                 p->grandparent_name);
        if (!r->grandparent_path[0] && p->grandparent_path[0]) {
          copy_s(r->grandparent_path, sizeof(r->grandparent_path),
                 p->grandparent_path);
          apply_cached_field_provenance(
              r, p->grandparent_path_truncated_fields);
        }
      }
      if (!r->username[0] && !r->user_sid[0] && (p->username[0] || p->user_sid[0])) {
        copy_s(r->username, sizeof(r->username), p->username);
        copy_s(r->domain, sizeof(r->domain), p->domain);
        copy_s(r->user_sid, sizeof(r->user_sid), p->user_sid);
        copy_s(r->logon_id, sizeof(r->logon_id), p->logon_id);
        /* Cache describes transport provenance, not evidence quality. */
        copy_s(r->identity_source, sizeof(r->identity_source), "cache");
        copy_s(r->identity_quality, sizeof(r->identity_quality), p->identity_quality);
        s_status.identity_cache_hits++;
      }
      if (!r->creator_username[0]) copy_s(r->creator_username, sizeof(r->creator_username), p->creator_username);
      if (!r->creator_domain[0]) copy_s(r->creator_domain, sizeof(r->creator_domain), p->creator_domain);
      if (!r->creator_sid[0]) copy_s(r->creator_sid, sizeof(r->creator_sid), p->creator_sid);
      if (!r->creator_logon_id[0]) copy_s(r->creator_logon_id, sizeof(r->creator_logon_id), p->creator_logon_id);
      if (!r->integrity_level[0] && p->integrity_level[0]) {
        copy_s(r->integrity_level, sizeof(r->integrity_level), p->integrity_level);
      }
      if (r->token_elevation == 0u && p->token_elevation != 0u) {
        r->token_elevation = p->token_elevation;
      }
      if (!r->exe_hash[0] && p->exe_hash[0]) {
        copy_s(r->exe_hash, sizeof(r->exe_hash), p->exe_hash);
      }
      if (!r->current_directory[0] && p->current_directory[0]) {
        copy_s(r->current_directory, sizeof(r->current_directory), p->current_directory);
      }
      if (!r->process_creation_time[0] && p->process_creation_time[0]) {
        copy_s(r->process_creation_time, sizeof(r->process_creation_time), p->process_creation_time);
      }
    }
  } else { s_status.process_cache_misses++; s_status.identity_cache_misses++; }
  if ((!r->parent_name[0] || !r->parent_path[0] || !r->parent_cmdline[0]) && edr_behavior_parent_pid_usable(r)) {
    ProcSlot *pp = find_proc(r->ppid, r->endpoint_id);
    EvidenceProcessGeneration parent_generation;
    if (pp && record_parent_generation(r, &parent_generation) &&
        generation_equal(&pp->generation, &parent_generation)) {
      if (pp->name[0]) {
        if (!r->parent_name[0]) copy_s(r->parent_name, sizeof(r->parent_name), pp->name);
      }
      if (pp->path[0]) {
        if (!r->parent_path[0]) {
          copy_s(r->parent_path, sizeof(r->parent_path), pp->path);
          if (pp->path_truncated_fields[0])
            apply_cached_field_provenance(r, "source.parent_path");
        }
      }
      if (pp->cmdline[0] && !r->parent_cmdline[0] && command_quality_known(pp)) {
        copy_s(r->parent_cmdline, sizeof(r->parent_cmdline), pp->cmdline);
        if (pp->cmdline_truncated_fields[0])
          apply_cached_field_provenance(r, "source.parent_cmdline");
      }
    }
  }
  if (!r->process_name[0] && r->exe_path[0]) {
    copy_s(r->process_name, sizeof(r->process_name), base_name(r->exe_path));
  }
  if (record_parent_context_proven(r))
    copy_s(r->parent_resolution_status, sizeof(r->parent_resolution_status),
           r->parent_name[0] && r->parent_path[0] &&
           !edr_behavior_source_field_truncated(r, "source.parent_path")
               ? "RESOLVED" : "NOT_EVALUABLE");
  evidence_cache_unlock();
  /* Only a closed owner result, after unlocking; no PID-only lookup or new
   * authority is introduced by this bounded local diagnostic. */
  edr_validation_trace_event(r, "parent_cache", cache_reason);
}

static int ring_record_to(RingSlot *ring, uint32_t slots, uint32_t *pos,
                          const EdrBehaviorRecord *r) {
  if (!ring || slots == 0u || !pos || !r) {
    return 0;
  }
  RingSlot *s = &ring[(*pos)++ % slots];
  int evicted = s->used ? 1 : 0;
  memset(s, 0, sizeof(*s));
  s->used = 1u;
  s->event_time_ns = record_time_ns(r);
  s->type = (uint32_t)r->type;
  s->pid = r->pid;
  s->ppid = r->ppid;
  s->parent_pid_state = edr_parent_pid_effective_state(r->ppid, r->parent_pid_state);
  (void)record_process_generation(r, &s->generation);
  (void)record_parent_generation(r, &s->parent_generation);
  s->net_dport = r->net_dport;
  copy_s(s->endpoint_id, sizeof(s->endpoint_id), r->endpoint_id);
  copy_s(s->tenant_id, sizeof(s->tenant_id), r->tenant_id);
  copy_s(s->process_generation_source, sizeof(s->process_generation_source),
         record_process_generation_source(r));
  copy_s(s->parent_process_generation_source,
         sizeof(s->parent_process_generation_source),
         record_parent_generation_source(r));
  copy_s(s->source_completeness, sizeof(s->source_completeness), r->source_completeness);
  copy_s(s->source_truncated_fields, sizeof(s->source_truncated_fields),
         r->source_truncated_fields);
  copy_s(s->process_name, sizeof(s->process_name), r->process_name);
  copy_s(s->file_path, sizeof(s->file_path), r->file_path);
  copy_s(s->net_dst, sizeof(s->net_dst), r->net_dst);
  return evicted;
}

static int ring_copy_to(RingSlot *ring, uint32_t slots, uint32_t *pos,
                        const RingSlot *src) {
  if (!ring || slots == 0u || !pos || !src || !src->used) {
    return 0;
  }
  RingSlot *dst = &ring[(*pos)++ % slots];
  int evicted = dst->used ? 1 : 0;
  *dst = *src;
  return evicted;
}

static void ring_record(const EdrBehaviorRecord *r) {
  if (ring_record_to(s_ring, EDR_EVIDENCE_RING_SLOTS, &s_ring_pos, r)) {
    s_status.ring_evictions++;
  }
}

static void context_ring_capture(const EdrBehaviorRecord *r) {
  if (ring_record_to(s_context_ring, EDR_EVIDENCE_CONTEXT_RING_SLOTS, &s_context_ring_pos, r)) {
    s_status.hot_ring_evictions++;
  }
}

static const char *engine_from_context(const char *ctx) {
  const char *p = ctx ? strstr(ctx, "\"engine\":\"") : NULL;
  static char e[32];
  e[0] = '\0';
  if (!p) {
    return "";
  }
  p += 10;
  size_t n = 0;
  while (p[n] && p[n] != '"' && n + 1u < sizeof(e)) {
    e[n] = p[n];
    n++;
  }
  e[n] = '\0';
  return e;
}

static int is_file_event_type(uint32_t type) {
  return type == (uint32_t)EDR_EVENT_FILE_READ ||
         type == (uint32_t)EDR_EVENT_FILE_CREATE ||
         type == (uint32_t)EDR_EVENT_FILE_WRITE ||
         type == (uint32_t)EDR_EVENT_FILE_DELETE ||
         type == (uint32_t)EDR_EVENT_FILE_RENAME ||
         type == (uint32_t)EDR_EVENT_FILE_PERMISSION_CHANGE;
}

static int is_registry_event_type(uint32_t type) {
  return type == (uint32_t)EDR_EVENT_REG_CREATE_KEY ||
         type == (uint32_t)EDR_EVENT_REG_SET_VALUE ||
         type == (uint32_t)EDR_EVENT_REG_DELETE_KEY;
}

static int is_network_event_type(uint32_t type) {
  return type == (uint32_t)EDR_EVENT_NET_CONNECT ||
         type == (uint32_t)EDR_EVENT_NET_LISTEN ||
         type == (uint32_t)EDR_EVENT_NET_DNS_QUERY ||
         type == (uint32_t)EDR_EVENT_NET_TLS_HANDSHAKE;
}

static uint64_t metric_slot_value(const MetricSlot *m, size_t index) {
  switch (index) {
  case 0: return m->file_drops;
  case 1: return m->registry_drops;
  case 2: return m->network_drops;
  case 3: return m->other_drops;
  default: return m->reasons[index - METRIC_ORDINARY_BASE];
  }
}

static int metric_slot_pending(const MetricSlot *m) {
  if (m->minute_unix == 0) return 0;
  for (size_t i = 0; i < METRIC_COUNT; ++i)
    if (metric_slot_value(m, i) != m->committed[i]) return 1;
  return 0;
}

#if defined(EDR_HAVE_SQLITE)
static int sqlite_flush_metrics(int final_attempt);
#endif

static MetricSlot *metric_slot_for(const EdrBehaviorRecord *r, int64_t event_time_ns) {
  int64_t minute = (event_time_ns / 1000000000LL) / 60LL;
  int64_t cutoff = (now_unix_ns() / 1000000000LL -
                    (int64_t)s_status.retention_hours * 3600LL) / 60LL;
  if (minute < cutoff) return NULL;
  const char *endpoint_id = (r && r->endpoint_id[0]) ? r->endpoint_id : "";
  MetricSlot *empty = NULL;
  MetricSlot *clean = NULL;
  MetricSlot *oldest = &s_metrics[0];
  for (size_t i = 0; i < EDR_EVIDENCE_METRIC_SLOTS; i++) {
    MetricSlot *m = &s_metrics[i];
    if (m->minute_unix == minute &&
        ((!m->endpoint_id[0] && !endpoint_id[0]) ||
         strcmp(m->endpoint_id, endpoint_id) == 0)) {
      return m;
    }
    if (m->minute_unix == 0 && !empty) {
      empty = m;
    }
    if (m->minute_unix < oldest->minute_unix) {
      oldest = m;
    }
    if (m->minute_unix != 0 && !metric_slot_pending(m) &&
        (!clean || m->minute_unix < clean->minute_unix)) {
      clean = m;
    }
  }
  /* Reuse committed slots before flushing. Otherwise a series of distinct
   * late minutes can make the newest dirty slot the next oldest victim and
   * force a database transaction for every event. */
  MetricSlot *m = empty ? empty : (clean ? clean : oldest);
#if defined(EDR_HAVE_SQLITE)
  if (!empty && metric_slot_pending(m) && (sqlite_flush_metrics(0) != 0 || metric_slot_pending(m))) {
    /* Existing slots can keep accumulating. Do not erase their pending counts
     * merely to accept another key while storage is unavailable. */
    s_status.metric_unrecorded++;
    return NULL;
  }
#endif
  if (!empty && m->minute_unix != 0) {
    s_status.metric_slot_evictions++;
  }
  memset(m, 0, sizeof(*m));
  m->minute_unix = minute;
  copy_s(m->endpoint_id, sizeof(m->endpoint_id), endpoint_id);
  return m;
}

static void record_metric_drop(const EdrBehaviorRecord *r, int64_t event_time_ns,
                               EdrEvidenceOrdinaryReason reason) {
  MetricSlot *m = metric_slot_for(r, event_time_ns);
  if (m) m->reasons[reason]++;
  s_status.ordinary_reasons[reason]++;
  edr_validation_trace_event(r, "local_retention", metric_names[METRIC_ORDINARY_BASE + reason]);
  uint32_t type = r ? (uint32_t)r->type : 0u;
  if (is_file_event_type(type)) {
    if (m) m->file_drops++;
    s_status.metric_file_drops++;
  } else if (is_registry_event_type(type)) {
    if (m) m->registry_drops++;
    s_status.metric_registry_drops++;
  } else if (is_network_event_type(type)) {
    if (m) m->network_drops++;
    s_status.metric_network_drops++;
  } else {
    if (m) m->other_drops++;
    s_status.metric_other_drops++;
  }
}

static void record_persistence_failure(const EdrBehaviorRecord *r, int64_t ts,
                                        int candidate, EdrEvidenceFailureReason reason) {
  MetricSlot *m = metric_slot_for(r, ts);
  size_t index = (candidate ? METRIC_CANDIDATE_BASE : METRIC_CONTEXT_BASE) + (size_t)reason;
  if (m) m->reasons[index - METRIC_ORDINARY_BASE]++;
  edr_validation_trace_event(r, "local_retention", metric_names[index]);
  if (candidate) s_status.candidate_failure_reasons[reason]++;
  else s_status.context_failure_reasons[reason]++;
}

static uint32_t metric_slots_used(void) {
  uint32_t n = 0;
  for (size_t i = 0; i < EDR_EVIDENCE_METRIC_SLOTS; i++) {
    if (s_metrics[i].minute_unix != 0) {
      n++;
    }
  }
  return n;
}

static void candidate_signal_for(const EdrBehaviorRecord *r, char *out, size_t cap);
static void candidate_semantic_signal_for(const EdrBehaviorRecord *r, char *out,
                                          size_t cap);
static uint32_t env_u32_clamped(const char *name, uint32_t fallback, uint32_t min_v,
                                uint32_t max_v);

static uint32_t candidate_dedupe_window_s(void) {
  return env_u32_clamped("EDR_EVIDENCE_CACHE_CANDIDATE_DEDUP_WINDOW_S",
                         60u, 1u, 600u);
}

#define EDR_EVIDENCE_CANDIDATE_ENRICHMENT_SKEW_NS 2000000000LL

static void candidate_digest_text(EdrSha256Ctx *ctx, const char *value) {
  uint32_t length = value ? (uint32_t)strlen(value) : 0u;
  uint8_t length_le[4];
  length_le[0] = (uint8_t)(length & 0xffu);
  length_le[1] = (uint8_t)((length >> 8u) & 0xffu);
  length_le[2] = (uint8_t)((length >> 16u) & 0xffu);
  length_le[3] = (uint8_t)((length >> 24u) & 0xffu);
  edr_sha256_update(ctx, length_le, sizeof(length_le));
  if (length) edr_sha256_update(ctx, (const uint8_t *)value, length);
}

static void candidate_digest_u64(EdrSha256Ctx *ctx, uint64_t value) {
  uint8_t bytes[8];
  for (size_t i = 0u; i < sizeof(bytes); ++i) {
    bytes[i] = (uint8_t)(value >> (i * 8u));
  }
  edr_sha256_update(ctx, bytes, sizeof(bytes));
}

/* A source event id is sufficient when carried through enrichment.  Without
 * it, fallback reuse is strictly local, PID-scoped, and generation-checked. */
static int candidate_identity_bound(const EdrBehaviorRecord *r) {
  return r && r->pid != 0u;
}

static void candidate_id_for(const EdrBehaviorRecord *r, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  char signal[65];
  EvidenceProcessGeneration generation;
  candidate_signal_for(r, signal, sizeof(signal));
  const char *endpoint = (r && r->endpoint_id[0]) ? r->endpoint_id : "unknown";
  if (r && r->event_id[0]) {
    snprintf(out, cap, "p0-%s-e-%s", endpoint, signal[0] ? signal : "invalid");
  } else if (record_process_generation(r, &generation)) {
    snprintf(out, cap, "p0-%s-g-%016llx-%016llx-%s", endpoint,
             (unsigned long long)generation.process_start_key,
             (unsigned long long)generation.creation_filetime_100ns,
             signal[0] ? signal : "invalid");
  } else {
    /* Unknown lifetimes must not durably collide.  A later known tuple can
     * reuse this id only through the short, in-memory skew bridge below. */
    snprintf(out, cap, "p0-%s-u-%lld-%s", endpoint, (long long)record_time_ns(r),
             signal[0] ? signal : "invalid");
  }
}

static uint32_t env_u32_clamped(const char *name, uint32_t fallback, uint32_t min_v,
                                uint32_t max_v) {
  const char *e = getenv(name);
  uint32_t v = fallback;
  if (e && e[0]) {
    char *end = NULL;
    unsigned long n = strtoul(e, &end, 10);
    if (end != e) {
      v = (n > 0xffffffffUL) ? 0xffffffffu : (uint32_t)n;
    }
  }
  if (v < min_v) {
    v = min_v;
  }
  if (v > max_v) {
    v = max_v;
  }
  return v;
}

static int extract_json_string_field(const char *s, const char *key, char *out, size_t cap) {
  if (!s || !key || !out || cap == 0u) {
    return 0;
  }
  out[0] = '\0';
  const char *p = strstr(s, key);
  if (!p) {
    return 0;
  }
  p += strlen(key);
  size_t n = 0;
  while (p[n] && p[n] != '"' && n + 1u < cap) {
    out[n] = p[n];
    n++;
  }
  out[n] = '\0';
  return n > 0u;
}

static void candidate_signal_for(const EdrBehaviorRecord *r, char *out, size_t cap) {
  EdrSha256Ctx ctx;
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  static const char hex[] = "0123456789abcdef";
  const char *canonical_image;
  const char *path_hash;
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!r || cap < 65u) {
    return;
  }
  canonical_image = r->image_path_canonical[0] ? r->image_path_canonical : r->exe_path;
  path_hash = r->process_path_hash[0] ? r->process_path_hash : r->exe_hash;
  /* A source event id is the preferred stable identity.  Its surrounding
   * enrichment (timestamps, revisions, source labels and completeness) must
   * not manufacture another P0 candidate for the same source event. */
  edr_sha256_init(&ctx);
  candidate_digest_text(&ctx, "edr-local-evidence-candidate-v3");
  candidate_digest_text(&ctx, r->endpoint_id);
  candidate_digest_text(&ctx, r->tenant_id);
  if (r->event_id[0]) {
    candidate_digest_text(&ctx, "source-event");
    candidate_digest_text(&ctx, r->event_id);
    goto finish;
  }
  /* A source without an event id may only reuse within a proven process
   * lifetime.  Retain the immutable atomic behavior semantics so two distinct
   * commands, file, network, or registry events in that lifetime remain
   * distinct candidates. */
  candidate_digest_text(&ctx, "atomic-semantic-source");
#define CANDIDATE_TEXT(field) candidate_digest_text(&ctx, r->field)
#define CANDIDATE_U64(field) candidate_digest_u64(&ctx, (uint64_t)r->field)
  CANDIDATE_U64(pid); CANDIDATE_U64(ppid); CANDIDATE_U64(type);
  CANDIDATE_TEXT(process_name);
  candidate_digest_text(&ctx, canonical_image); candidate_digest_text(&ctx, path_hash);
  CANDIDATE_TEXT(exe_hash); CANDIDATE_TEXT(image_path_raw); CANDIDATE_TEXT(cmdline);
  CANDIDATE_TEXT(file_op); CANDIDATE_TEXT(file_path); CANDIDATE_U64(file_key);
  CANDIDATE_U64(file_target_has_motw); CANDIDATE_TEXT(dns_query);
  CANDIDATE_TEXT(net_src); CANDIDATE_TEXT(net_dst); CANDIDATE_U64(net_sport);
  CANDIDATE_U64(net_dport); CANDIDATE_TEXT(net_proto); CANDIDATE_TEXT(network_aux_path);
  CANDIDATE_TEXT(reg_key_path); CANDIDATE_TEXT(reg_value_name); CANDIDATE_TEXT(reg_value_data);
  CANDIDATE_TEXT(reg_old_value_data); CANDIDATE_TEXT(reg_op); CANDIDATE_TEXT(reg_source);
  CANDIDATE_TEXT(reg_attribution); CANDIDATE_TEXT(reg_detail_status);
  CANDIDATE_TEXT(script_snippet); CANDIDATE_TEXT(powershell_script_block);
  CANDIDATE_TEXT(wmi_filter); CANDIDATE_TEXT(scheduled_task_path);
#undef CANDIDATE_TEXT
#undef CANDIDATE_U64
finish:
  edr_sha256_final(&ctx, digest);
  for (size_t i = 0u; i < sizeof(digest); ++i) {
    out[i * 2u] = hex[digest[i] >> 4u];
    out[i * 2u + 1u] = hex[digest[i] & 0x0fu];
  }
  out[64] = '\0';
}

/* Stable behavior identity used only to join a generation-bearing source to
 * its generation-missing enrichment copy.  Mutable enrichment (hashes,
 * resolution provenance, completeness and evidence revision) is excluded;
 * event-specific file/network/registry facts remain included so two real
 * actions by one process cannot collapse into one candidate. */
static void candidate_semantic_signal_for(const EdrBehaviorRecord *r, char *out,
                                          size_t cap) {
  EdrSha256Ctx ctx;
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  static const char hex[] = "0123456789abcdef";
  const char *canonical_image;
  if (!out || cap == 0u) return;
  out[0] = '\0';
  if (!r || cap < 65u) return;
  canonical_image = r->image_path_canonical[0] ? r->image_path_canonical : r->exe_path;
  edr_sha256_init(&ctx);
  candidate_digest_text(&ctx, "edr-local-evidence-enrichment-bridge-v1");
  candidate_digest_text(&ctx, r->tenant_id);
  candidate_digest_u64(&ctx, (uint64_t)r->type);
  candidate_digest_u64(&ctx, (uint64_t)r->ppid);
  candidate_digest_text(&ctx, r->process_name);
  candidate_digest_text(&ctx, canonical_image);
  candidate_digest_text(&ctx, r->cmdline);
  candidate_digest_text(&ctx, r->file_op);
  candidate_digest_text(&ctx, r->file_path);
  candidate_digest_u64(&ctx, r->file_key);
  candidate_digest_u64(&ctx, r->file_target_has_motw);
  candidate_digest_text(&ctx, r->dns_query);
  candidate_digest_text(&ctx, r->net_src);
  candidate_digest_text(&ctx, r->net_dst);
  candidate_digest_u64(&ctx, r->net_sport);
  candidate_digest_u64(&ctx, r->net_dport);
  candidate_digest_text(&ctx, r->net_proto);
  candidate_digest_text(&ctx, r->network_aux_path);
  candidate_digest_text(&ctx, r->reg_key_path);
  candidate_digest_text(&ctx, r->reg_value_name);
  candidate_digest_text(&ctx, r->reg_value_data);
  candidate_digest_text(&ctx, r->reg_old_value_data);
  candidate_digest_text(&ctx, r->reg_op);
  /* Provider provenance is expected to differ between copies of the same
   * atomic event (for example sec vs kproc); it is evidence metadata, not
   * behavior identity. */
  candidate_digest_text(&ctx, r->reg_attribution);
  candidate_digest_text(&ctx, r->reg_detail_status);
  edr_sha256_final(&ctx, digest);
  for (size_t i = 0u; i < sizeof(digest); ++i) {
    out[i * 2u] = hex[digest[i] >> 4u];
    out[i * 2u + 1u] = hex[digest[i] & 0x0fu];
  }
  out[64] = '\0';
}

static int ordinary_aggregate_kind(const EdrBehaviorRecord *r, uint32_t *kind_out) {
  if (!r || !kind_out) {
    return 0;
  }
  switch (r->type) {
  case EDR_EVENT_FILE_READ:
  case EDR_EVENT_FILE_CREATE:
  case EDR_EVENT_FILE_WRITE:
  case EDR_EVENT_FILE_DELETE:
  case EDR_EVENT_FILE_RENAME:
  case EDR_EVENT_FILE_PERMISSION_CHANGE:
    *kind_out = 1u;
    return 1;
  case EDR_EVENT_REG_CREATE_KEY:
  case EDR_EVENT_REG_SET_VALUE:
  case EDR_EVENT_REG_DELETE_KEY:
    *kind_out = 2u;
    return 1;
  case EDR_EVENT_NET_CONNECT:
  case EDR_EVENT_NET_LISTEN:
  case EDR_EVENT_NET_DNS_QUERY:
    *kind_out = 3u;
    return 1;
  default:
    return 0;
  }
}

static void normalize_prefix_copy(char *out, size_t cap, const char *s) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!s || !s[0]) {
    return;
  }
  size_t n = 0u;
  for (; s[n] && n + 1u < cap; n++) {
    unsigned char c = (unsigned char)s[n];
    out[n] = (char)tolower(c);
  }
  out[n] = '\0';
}

static void path_parent_prefix(char *out, size_t cap, const char *path) {
  if (!out || cap == 0u) {
    return;
  }
  char tmp[320];
  normalize_prefix_copy(tmp, sizeof(tmp), path);
  char *last = NULL;
  for (char *p = tmp; *p; p++) {
    if (*p == '/' || *p == '\\') {
      last = p;
    }
  }
  if (last && (size_t)(last - tmp) + 1u < sizeof(tmp)) {
    last[1] = '\0';
  }
  copy_s(out, cap, tmp);
}

static int ordinary_aggregate_prefix(const EdrBehaviorRecord *r, uint32_t kind,
                                     char *out, size_t cap) {
  if (!out || cap == 0u) {
    return 0;
  }
  out[0] = '\0';
  if (!r) {
    return 0;
  }
  if (kind == 1u) {
    path_parent_prefix(out, cap, r->file_path[0] ? r->file_path : r->exe_path);
  } else if (kind == 2u) {
    normalize_prefix_copy(out, cap, r->reg_key_path);
  } else if (kind == 3u) {
    char tmp[220];
    char port[16];
    size_t net_len = strlen(r->net_dst);
    size_t dns_len = strlen(r->dns_query);
    int port_len = snprintf(port, sizeof(port), "%u", r->net_dport);
    if (port_len < 0 || (size_t)port_len >= sizeof(port) ||
        net_len > sizeof(tmp) - 1u ||
        (size_t)port_len > sizeof(tmp) - net_len - 1u ||
        dns_len > sizeof(tmp) - net_len - 1u - (size_t)port_len - 1u) {
      s_status.bounded_string_truncations++;
      return 0;
    }
    memcpy(tmp, r->net_dst, net_len);
    tmp[net_len] = ':';
    memcpy(tmp + net_len + 1u, port, (size_t)port_len);
    tmp[net_len + 1u + (size_t)port_len] = ':';
    memcpy(tmp + net_len + 2u + (size_t)port_len, r->dns_query, dns_len);
    tmp[net_len + 2u + (size_t)port_len + dns_len] = '\0';
    normalize_prefix_copy(out, cap, tmp);
  }
  if (!out[0]) {
    int n = snprintf(out, cap, "kind=%u;type=%u", kind, (uint32_t)r->type);
    if (n < 0 || (size_t)n >= cap) {
      s_status.bounded_string_truncations++;
      out[0] = '\0';
      return 0;
    }
  }
  return 1;
}

/* This is bounded sampling of repeated ordinary behavior, not source-event
 * deduplication. Different source IDs can describe the same action/object, but
 * PID reuse, distinct operations and changes to captured object facts must
 * retain separate representatives. The human-readable summary prefix is not
 * an identity: it may be shortened, and a directory contains many objects. */
static int ordinary_aggregate_digest(const EdrBehaviorRecord *r, uint32_t kind,
                                     int64_t minute, char out[65]) {
  EvidenceProcessGeneration generation;
  EdrSha256Ctx ctx;
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  static const char hex[] = "0123456789abcdef";
  if (!r || r->event_time_ns <= 0 ||
      !record_process_generation(r, &generation) ||
      r->source_truncated_fields[0] ||
      strcmp(r->source_completeness, "TRUNCATED") == 0 ||
      strcmp(r->source_completeness, "NOT_EVALUABLE") == 0) {
    return 0;
  }
  if ((kind == 1u && (!r->file_path[0] ||
                      (r->type == EDR_EVENT_FILE_RENAME && !r->file_old_path[0]))) ||
      (kind == 2u && !r->reg_key_path[0]) ||
      (kind == 3u && r->type == EDR_EVENT_NET_DNS_QUERY && !r->dns_query[0]) ||
      (kind == 3u && r->type != EDR_EVENT_NET_DNS_QUERY &&
       (!r->net_proto[0] ||
        ((!r->net_dst[0] || !r->net_dport) &&
         (r->type != EDR_EVENT_NET_LISTEN || !r->net_src[0] || !r->net_sport))))) {
    return 0;
  }
  edr_sha256_init(&ctx);
  candidate_digest_text(&ctx, "edr-ordinary-behavior-v1");
  candidate_digest_text(&ctx, r->tenant_id);
  candidate_digest_text(&ctx, r->endpoint_id);
  candidate_digest_u64(&ctx, r->pid);
  candidate_digest_u64(&ctx, generation.process_start_key);
  candidate_digest_u64(&ctx, generation.creation_filetime_100ns);
  candidate_digest_u64(&ctx, (uint64_t)minute);
  candidate_digest_u64(&ctx, (uint64_t)r->type);
  candidate_digest_text(&ctx, r->source_completeness);
  if (kind == 1u) {
    candidate_digest_text(&ctx, r->file_op);
    candidate_digest_text(&ctx, r->file_path);
    candidate_digest_text(&ctx, r->file_old_path);
    candidate_digest_u64(&ctx, r->file_key);
    candidate_digest_u64(&ctx, r->file_target_has_motw);
  } else if (kind == 2u) {
    candidate_digest_text(&ctx, r->reg_op);
    candidate_digest_text(&ctx, r->reg_key_path);
    candidate_digest_text(&ctx, r->reg_value_name);
    candidate_digest_text(&ctx, r->reg_value_data);
    candidate_digest_text(&ctx, r->reg_old_value_data);
    candidate_digest_text(&ctx, r->reg_attribution);
    candidate_digest_text(&ctx, r->reg_detail_status);
  } else {
    candidate_digest_text(&ctx, r->net_src);
    candidate_digest_text(&ctx, r->net_dst);
    candidate_digest_u64(&ctx, r->net_sport);
    candidate_digest_u64(&ctx, r->net_dport);
    candidate_digest_text(&ctx, r->net_proto);
    candidate_digest_text(&ctx, r->dns_query);
    candidate_digest_text(&ctx, r->network_aux_path);
  }
  edr_sha256_final(&ctx, digest);
  for (size_t i = 0u; i < sizeof(digest); ++i) {
    out[i * 2u] = hex[digest[i] >> 4u];
    out[i * 2u + 1u] = hex[digest[i] & 0x0fu];
  }
  out[64] = '\0';
  return 1;
}

static int ordinary_aggregate_should_coalesce(const EdrBehaviorRecord *r, int64_t ts) {
  uint32_t kind = 0u;
  if (!ordinary_aggregate_kind(r, &kind)) {
    return 0;
  }
  char semantic_digest[65];
  int64_t minute = (ts / 1000000000LL) / 60LL;
  if (!ordinary_aggregate_digest(r, kind, minute, semantic_digest)) {
    return 0;
  }
  size_t replace_i = 0u;
  size_t empty_i = EDR_EVIDENCE_AGG_SLOTS;
  int64_t oldest = INT64_MAX;
  for (size_t i = 0; i < EDR_EVIDENCE_AGG_SLOTS; i++) {
    OrdinaryAggregateSlot *s = &s_ordinary_agg[i];
    if (!s->used) {
      if (empty_i == EDR_EVIDENCE_AGG_SLOTS) empty_i = i;
      continue;
    }
    if (s->minute_unix < oldest) {
      oldest = s->minute_unix;
      replace_i = i;
    }
    if (strcmp(s->semantic_digest, semantic_digest) == 0) {
      s->count++;
      if (ts > s->last_seen_ns) {
        s->last_seen_ns = ts;
      }
      if (s->process_name[0] == '\0' && r->process_name[0]) {
        copy_s(s->process_name, sizeof(s->process_name), r->process_name);
      }
      if (s->suppression_reason[0] == '\0' && r->detection_context[0]) {
        extract_json_string_field(r->detection_context, "\"reason\":\"", s->suppression_reason,
                                  sizeof(s->suppression_reason));
      }
      s_status.ordinary_coalesced++;
      if (kind == 1u) {
        s_status.file_coalesced++;
      } else if (kind == 2u) {
        s_status.registry_coalesced++;
      } else if (kind == 3u) {
        s_status.network_coalesced++;
      }
      return 1;
    }
  }
  if (empty_i != EDR_EVIDENCE_AGG_SLOTS) replace_i = empty_i;
  OrdinaryAggregateSlot *slot = &s_ordinary_agg[replace_i];
  if (slot->used) {
    s_status.aggregate_slot_evictions++;
  }
  memset(slot, 0, sizeof(*slot));
  slot->used = 1u;
  slot->minute_unix = minute;
  slot->pid = r ? r->pid : 0u;
  slot->kind = kind;
  slot->count = 1u;
  slot->first_seen_ns = ts;
  slot->last_seen_ns = ts;
  slot->event_type = r ? (uint32_t)r->type : 0u;
  copy_s(slot->endpoint_id, sizeof(slot->endpoint_id), r ? r->endpoint_id : "");
  copy_s(slot->tenant_id, sizeof(slot->tenant_id), r ? r->tenant_id : "");
  copy_s(slot->process_name, sizeof(slot->process_name), r ? r->process_name : "");
  (void)ordinary_aggregate_prefix(r, kind, slot->prefix, sizeof(slot->prefix));
  copy_s(slot->semantic_digest, sizeof(slot->semantic_digest), semantic_digest);
  if (r && r->detection_context[0]) {
    extract_json_string_field(r->detection_context, "\"reason\":\"", slot->suppression_reason,
                              sizeof(slot->suppression_reason));
  }
  return 0;
}

static int evidence_cache_pressure_active(void) {
  return edr_resource_preprocess_throttle_active() ? 1 : 0;
}

static unsigned summary_flush_min_count(void) {
  const char *v = getenv("EDR_SUMMARY_MIN_COUNT");
  if (v && v[0]) {
    long n = strtol(v, NULL, 10);
    if (n >= 1 && n <= 100000) {
      return (unsigned)n;
    }
  }
  return 5u;
}

void edr_local_evidence_cache_flush_summaries(int64_t now_ns,
                                              void (*emit)(const EdrBehaviorRecord *)) {
  int64_t cur_minute = (now_ns / 1000000000LL) / 60LL;
  unsigned threshold = summary_flush_min_count();
  for (size_t i = 0; i < EDR_EVIDENCE_AGG_SLOTS; i++) {
    EdrBehaviorRecord rec;
    int emit_one = 0;
    evidence_cache_lock();
    OrdinaryAggregateSlot *s = &s_ordinary_agg[i];
    if (!s->used) {
      evidence_cache_unlock();
      continue;
    }
    /* 仅 flush 已关闭的窗口（早于当前分钟），避免截断仍在累积的聚合。 */
    if (s->minute_unix >= cur_minute) {
      evidence_cache_unlock();
      continue;
    }
    if (s->count < (uint64_t)threshold) {
      /* 计数不足以成一条摘要：直接释放槽位，明细此前已被 coalesce 丢弃。 */
      memset(s, 0, sizeof(*s));
      evidence_cache_unlock();
      continue;
    }
    /* Production retains local coalescing counters but has no consumer for
     * these summaries. Drain closed slots without creating network frames. */
    if (!emit) {
      memset(s, 0, sizeof(*s));
      evidence_cache_unlock();
      continue;
    }
    char prefix_esc[200];
    char reason_esc[160];
    char proc_esc[280];
    json_escape(prefix_esc, sizeof(prefix_esc), s->prefix);
    json_escape(reason_esc, sizeof(reason_esc), s->suppression_reason);
    json_escape(proc_esc, sizeof(proc_esc), s->process_name);

    memset(&rec, 0, sizeof(rec));
    rec.type = EDR_EVENT_BEHAVIOR_SUMMARY;
    rec.priority = 2u; /* 低优先级，不进告警链路 */
    rec.pid = s->pid;
    rec.event_time_ns = s->last_seen_ns > 0 ? s->last_seen_ns : now_ns;
    copy_s(rec.endpoint_id, sizeof(rec.endpoint_id), s->endpoint_id);
    copy_s(rec.tenant_id, sizeof(rec.tenant_id), s->tenant_id);
    copy_s(rec.process_name, sizeof(rec.process_name), s->process_name);
    snprintf(rec.cmdline, sizeof(rec.cmdline),
             "behavior_summary kind=%u count=%llu key=%s", (unsigned)s->kind,
             (unsigned long long)s->count, s->prefix);
    snprintf(rec.detection_context, sizeof(rec.detection_context),
             "{\"type\":\"behavior_summary\",\"kind\":%u,\"event_type\":%u,\"pid\":%u,"
             "\"count\":%llu,\"first_seen_ns\":%lld,\"last_seen_ns\":%lld,"
             "\"process_name\":\"%s\",\"aggregate_key\":\"%s\",\"suppression_reason\":\"%s\"}",
             (unsigned)s->kind, (unsigned)s->event_type, (unsigned)s->pid,
             (unsigned long long)s->count, (long long)s->first_seen_ns,
             (long long)s->last_seen_ns, proc_esc, prefix_esc, reason_esc);
    s_status.summaries_emitted++;
    memset(s, 0, sizeof(*s));
    emit_one = 1;
    evidence_cache_unlock();
    /* The caller may encode/enqueue or otherwise re-enter cache APIs. The
     * aggregate slot was copied and released above, so no module lock spans
     * this external callback. */
    if (emit_one) emit(&rec);
  }
}

/* Only already-committed candidates may satisfy a reuse.  A failed write must
 * not populate this in-memory index, otherwise the next copy of the alert
 * could be hidden for the whole dedupe window. */
/* Returns 1 for a match, 0 for an unrelated slot, and -1 for a comparable
 * slot rejected by one or more guards. `reject_reasons` is a bitset and may
 * contain multiple failures from the same comparison. */
static int candidate_dedupe_slot_evaluate(
    const CandidateDedupeSlot *slot, const EdrBehaviorRecord *r, int64_t ts,
    const EvidenceProcessGeneration *generation, int generation_known,
    uint8_t source_generation_shape,
    const char *signal, const char *semantic_signal, uint32_t *reject_reasons) {
  const char *expected_source_signal = NULL;
  uint32_t reasons = 0u;
  if (reject_reasons) {
    *reject_reasons = 0u;
  }
  if (!slot || !slot->used || !r || slot->pid != r->pid ||
      slot->type != (uint32_t)r->type ||
      strncmp(slot->endpoint_id, r->endpoint_id, sizeof(slot->endpoint_id)) != 0) {
    return 0;
  }
  /* A source replay may enrich fields, but it may never rewrite a source id
   * onto another known process lifetime. */
  if (generation_known && slot->generation_known &&
      !generation_equal(&slot->generation, generation)) {
    reasons |= CANDIDATE_DEDUPE_REJECT_GENERATION_CONFLICT;
  }
  if (r->event_id[0] && slot->source_event_id[0] &&
      strncmp(slot->source_event_id, r->event_id,
              sizeof(slot->source_event_id)) == 0) {
    expected_source_signal = slot->signal;
  } else if (r->event_id[0] && slot->bridged_source_event_id[0] &&
             strncmp(slot->bridged_source_event_id, r->event_id,
                     sizeof(slot->bridged_source_event_id)) == 0) {
    expected_source_signal = slot->bridged_signal;
  }
  if (expected_source_signal) {
    if (!signal || !signal[0] ||
        strncmp(expected_source_signal, signal, sizeof(slot->signal)) != 0) {
      reasons |= CANDIDATE_DEDUPE_REJECT_SEMANTIC_MISMATCH;
    }
    if (reject_reasons) *reject_reasons = reasons;
    return reasons ? -1 : 1;
  }
  if (!r->event_id[0] && !slot->source_event_id[0] &&
      generation_known && slot->generation_known) {
    if (!signal || !signal[0] ||
        strncmp(slot->signal, signal, sizeof(slot->signal)) != 0) {
      reasons |= CANDIDATE_DEDUPE_REJECT_SEMANTIC_MISMATCH;
    }
    if (reject_reasons) *reject_reasons = reasons;
    return reasons ? -1 : 1;
  }
  /* Distinct source events bridge only the observed provider-enrichment
   * shape: exactly one source record carries the raw generation tuple, the
   * atomic semantics are identical, and delivery skew is tightly bounded.
   * Snapshot resolution may prove PID lifetime equality, but must not rewrite
   * this source-shape fact. */
  if (slot->source_generation_shapes ==
          (CANDIDATE_SOURCE_GENERATION_MISSING |
           CANDIDATE_SOURCE_GENERATION_BOUND) ||
      (slot->source_generation_shapes &
       (source_generation_shape == CANDIDATE_SOURCE_GENERATION_BOUND
            ? CANDIDATE_SOURCE_GENERATION_MISSING
            : CANDIDATE_SOURCE_GENERATION_BOUND)) == 0u) {
    reasons |= CANDIDATE_DEDUPE_REJECT_SOURCE_SHAPE;
  }
  if (!semantic_signal || !semantic_signal[0] ||
      strncmp(slot->semantic_signal, semantic_signal,
              sizeof(slot->semantic_signal)) != 0) {
    reasons |= CANDIDATE_DEDUPE_REJECT_SEMANTIC_MISMATCH;
  }
  if (llabs(ts - slot->last_ns) > EDR_EVIDENCE_CANDIDATE_ENRICHMENT_SKEW_NS) {
    reasons |= CANDIDATE_DEDUPE_REJECT_SKEW;
  }
  if (reject_reasons) *reject_reasons = reasons;
  return reasons ? -1 : 1;
}

static void candidate_dedupe_observe_reject_reasons(uint32_t reasons) {
  if (reasons & CANDIDATE_DEDUPE_REJECT_GENERATION_CONFLICT) {
    s_status.candidate_dedup_generation_conflict_rejects++;
  }
  if (reasons & CANDIDATE_DEDUPE_REJECT_SOURCE_SHAPE) {
    s_status.candidate_dedup_source_shape_rejects++;
  }
  if (reasons & CANDIDATE_DEDUPE_REJECT_SEMANTIC_MISMATCH) {
    s_status.candidate_dedup_semantic_mismatch_rejects++;
  }
  if (reasons & CANDIDATE_DEDUPE_REJECT_SKEW) {
    s_status.candidate_dedup_skew_rejects++;
  }
}

static int candidate_dedupe_reuse(const EdrBehaviorRecord *r, int64_t ts,
                                  char *candidate_id, size_t candidate_id_cap) {
  EvidenceProcessGeneration generation;
  int generation_known;
  uint8_t source_generation_shape;
  if (!candidate_identity_bound(r)) {
    return 0;
  }
  uint32_t win_s = candidate_dedupe_window_s();
  if (win_s == 0u) {
    return 0;
  }
  char signal[65];
  char semantic_signal[65];
  generation_known = record_process_generation(r, &generation);
  source_generation_shape = record_source_generation_shape(r);
  candidate_signal_for(r, signal, sizeof(signal));
  candidate_semantic_signal_for(r, semantic_signal, sizeof(semantic_signal));
  int64_t cutoff = ts - (int64_t)win_s * 1000000000LL;
  for (size_t i = 0; i < EDR_EVIDENCE_CANDIDATE_DEDUP_SLOTS; i++) {
    CandidateDedupeSlot *s = &s_candidate_dedupe[i];
    uint32_t reject_reasons = 0u;
    int evaluation = s->last_ns >= cutoff
                         ? candidate_dedupe_slot_evaluate(
                               s, r, ts, &generation, generation_known,
                               source_generation_shape, signal, semantic_signal,
                               &reject_reasons)
                         : 0;
    if (evaluation > 0) {
      s->last_ns = ts;
      if (generation_known && !s->generation_known) {
        s->generation = generation;
        s->generation_known = 1u;
      }
      s->source_generation_shapes |= source_generation_shape;
      if (r->event_id[0] && s->source_event_id[0] &&
          strncmp(s->source_event_id, r->event_id,
                  sizeof(s->source_event_id)) != 0 &&
          !s->bridged_source_event_id[0]) {
        copy_s(s->bridged_source_event_id,
               sizeof(s->bridged_source_event_id), r->event_id);
        copy_s(s->bridged_signal, sizeof(s->bridged_signal), signal);
      }
      if (candidate_id && candidate_id_cap > 0u && s->candidate_id[0]) {
        copy_s(candidate_id, candidate_id_cap, s->candidate_id);
      }
      s_status.candidate_deduped++;
      s_status.candidate_reused++;
      return 1;
    }
    if (evaluation < 0) {
      candidate_dedupe_observe_reject_reasons(reject_reasons);
    }
  }
  return 0;
}

static void candidate_dedupe_admit(const EdrBehaviorRecord *r, int64_t ts,
                                   const char *candidate_id) {
  EvidenceProcessGeneration generation;
  int generation_known;
  uint8_t source_generation_shape;
  if (!candidate_identity_bound(r) || candidate_dedupe_window_s() == 0u) {
    return;
  }
  char signal[65];
  char semantic_signal[65];
  generation_known = record_process_generation(r, &generation);
  source_generation_shape = record_source_generation_shape(r);
  candidate_signal_for(r, signal, sizeof(signal));
  candidate_semantic_signal_for(r, semantic_signal, sizeof(semantic_signal));
  size_t replace_i = 0u;
  int64_t oldest = INT64_MAX;
  for (size_t i = 0; i < EDR_EVIDENCE_CANDIDATE_DEDUP_SLOTS; i++) {
    CandidateDedupeSlot *s = &s_candidate_dedupe[i];
    if (candidate_dedupe_slot_evaluate(
            s, r, ts, &generation, generation_known, source_generation_shape,
            signal, semantic_signal, NULL) > 0) {
      s->last_ns = ts;
      if (generation_known && !s->generation_known) {
        s->generation = generation;
        s->generation_known = 1u;
      }
      s->source_generation_shapes |= source_generation_shape;
      if (r->event_id[0] && s->source_event_id[0] &&
          strncmp(s->source_event_id, r->event_id,
                  sizeof(s->source_event_id)) != 0 &&
          !s->bridged_source_event_id[0]) {
        copy_s(s->bridged_source_event_id,
               sizeof(s->bridged_source_event_id), r->event_id);
        copy_s(s->bridged_signal, sizeof(s->bridged_signal), signal);
      }
      if (candidate_id && candidate_id[0]) {
        copy_s(s->candidate_id, sizeof(s->candidate_id), candidate_id);
      }
      return;
    }
    if (!s->used) {
      replace_i = i;
      oldest = INT64_MIN;
      break;
    }
    if (s->last_ns < oldest) {
      oldest = s->last_ns;
      replace_i = i;
    }
  }
  CandidateDedupeSlot *slot = &s_candidate_dedupe[replace_i];
  if (slot->used) {
    s_status.candidate_dedup_evictions++;
  }
  memset(slot, 0, sizeof(*slot));
  slot->used = 1u;
  slot->last_ns = ts;
  slot->pid = r->pid;
  slot->type = (uint32_t)r->type;
  slot->source_generation_shapes = source_generation_shape;
  slot->generation_known = generation_known ? 1u : 0u;
  if (generation_known) {
    slot->generation = generation;
  }
  copy_s(slot->endpoint_id, sizeof(slot->endpoint_id), r->endpoint_id);
  copy_s(slot->candidate_id, sizeof(slot->candidate_id), candidate_id);
  copy_s(slot->signal, sizeof(slot->signal), signal);
  copy_s(slot->semantic_signal, sizeof(slot->semantic_signal), semantic_signal);
  copy_s(slot->source_event_id, sizeof(slot->source_event_id), r->event_id);
}

#if defined(EDR_HAVE_SQLITE)
/* Bounded reclamation intent survives a poll, never a SQLite statement or
 * uncommitted deletion. Admission/startup can take over at any time. */
static unsigned s_maintenance_reclaim_pages;
/* Once pressure starts, finish recovering the WAL working target even if one
 * partial slice brings the file just below the hard admission limit. */
static int s_maintenance_pressure_pending;
/* Two bounded keyset cursors prevent protected old groups from starving newer
 * eligible groups. Losing a cursor on restart only repeats safe validation. */
static struct { int value_class; sqlite3_int64 time; char id[160]; } s_retirement_cursor[2];
static struct { sqlite3_int64 time; char id[80]; } s_command_retirement_cursor;
static int sqlite_maintenance(int defer_reclaim);
typedef struct { uint64_t deadline_ns, bytes_left; unsigned rows_left; } EvidenceMaintenanceSlice;
static unsigned s_maintenance_stage;
static int sqlite_retire_command_facts(sqlite3_int64 cutoff, EvidenceMaintenanceSlice *slice);
static int sqlite_maintenance_yield(const EvidenceMaintenanceSlice *slice);
static int sqlite_maintenance_charge(EvidenceMaintenanceSlice *slice,unsigned rows,uint64_t bytes);

static int exec_sql(const char *sql) {
  char *err = NULL;
  if (!s_db) {
    return -1;
  }
  int rc = sqlite3_exec(s_db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) {
    set_error(err ? err : "sqlite exec failed");
    sqlite3_free(err);
    return -1;
  }
  return 0;
}

#define RETENTION_ACTIVE_CLOCK_KEY "local_retention_v1_active_ms"
#define RETENTION_ACTIVE_CLOCK_ROW \
  "minute_unix=0 AND endpoint_id='' AND metric_name='" RETENTION_ACTIVE_CLOCK_KEY "'"
#define RETENTION_FLOOR_ELAPSED \
  "EXISTS(SELECT 1 FROM metrics WHERE " RETENTION_ACTIVE_CLOCK_ROW \
  " AND typeof(value)='integer' AND value>=OLD.alert_context_protect_until_active_ms)"

/* This clock has one durable INTEGER row, not one timer per event. Only
 * successfully committed owner transactions advance its base. Reopening does
 * not credit offline time, and a crash can only extend the minimum residence. */
static struct {
  uint64_t base_ms, anchor_ms, pending_ms, pending_mono_ms;
  int valid, pending;
} s_retention_clock;

static uint64_t retention_monotonic_ms(void) {
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  if (s_test_retention_monotonic_ms >= 0)
    return (uint64_t)s_test_retention_monotonic_ms;
#endif
  return evidence_cache_clock_ns() / 1000000u;
}

static int retention_clock_error(unsigned cause, const char *message) {
  s_retention_clock.valid = s_retention_clock.pending = 0;
  s_status.retention_clock_valid = 0u;
  s_status.retention_clock_cause_code = cause;
  ++s_status.retention_clock_failures;
  set_error(message);
  return -1;
}

static void sqlite_retention_clock_committed(void) {
  if (!s_retention_clock.pending) return;
  uint64_t now = retention_monotonic_ms();
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  if (s_test_retention_after_commit_ms >= 0) {
    now = (uint64_t)s_test_retention_after_commit_ms;
    s_test_retention_after_commit_ms = -1;
  }
#endif
  s_retention_clock.base_ms = s_retention_clock.pending_ms;
  s_status.retention_active_ms = s_retention_clock.base_ms;
  s_retention_clock.pending = 0;
  /* Exclude the commit interval itself, so a slow fsync cannot shorten a
   * protection interval measured from the successful admission boundary. */
  if (!now || now < s_retention_clock.pending_mono_ms) {
    (void)retention_clock_error(3u, "retention monotonic clock unavailable after committed owner transaction");
    return;
  }
  s_retention_clock.anchor_ms = now;
}

static int sqlite_retention_clock_stage(void) {
  sqlite3_stmt *st = NULL;
  uint64_t now = retention_monotonic_ms();
  if (!s_retention_clock.valid) {
    set_error("retention clock remains unavailable; original clock cause preserved");
    return -1;
  }
  if (sqlite3_get_autocommit(s_db))
    return retention_clock_error(5u, "retention clock requires a valid owner transaction");
  if (!now || now < s_retention_clock.anchor_ms)
    return retention_clock_error(3u, "retention monotonic clock unavailable or regressed; parent evidence preserved");
  uint64_t elapsed = now - s_retention_clock.anchor_ms;
  if (elapsed > (uint64_t)INT64_MAX || s_retention_clock.base_ms > (uint64_t)INT64_MAX - elapsed)
    return retention_clock_error(4u, "retention active clock overflow; parent evidence preserved");
  uint64_t tick = s_retention_clock.base_ms + elapsed;
  int cause = 5;
  if (sqlite3_prepare_v2(s_db, "SELECT value FROM metrics WHERE " RETENTION_ACTIVE_CLOCK_ROW ";",
      -1, &st, NULL) != SQLITE_OK) goto failed;
  int step = sqlite3_step(st);
  if (step == SQLITE_DONE) { cause = 1; goto failed; }
  if (step != SQLITE_ROW) goto failed;
  if (sqlite3_column_type(st, 0) != SQLITE_INTEGER || sqlite3_column_int64(st, 0) < 0 ||
      (uint64_t)sqlite3_column_int64(st, 0) != s_retention_clock.base_ms) { cause = 2; goto failed; }
  sqlite3_finalize(st); st = NULL;
  if (sqlite3_prepare_v2(s_db, "UPDATE metrics SET value=?1 WHERE " RETENTION_ACTIVE_CLOCK_ROW ";",
      -1, &st, NULL) != SQLITE_OK || sqlite3_bind_int64(st, 1, (sqlite3_int64)tick) != SQLITE_OK ||
      sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(s_db) != 1) goto failed;
  sqlite3_finalize(st);
  s_retention_clock.pending_ms = tick;
  s_retention_clock.pending_mono_ms = now;
  s_retention_clock.pending = 1;
  return 0;
failed:
  sqlite3_finalize(st);
  return retention_clock_error((unsigned)cause, "retention active clock missing, invalid or unavailable; parent evidence preserved");
}

/* Stable names are intentional: supported older owners replace their own v1
 * policy triggers at open, but cannot discard these minimum-residence guards.
 * Old maintenance may fail explicitly; it must not delete newer protected
 * evidence or reset the seventh permanent metrics row. */
static int sqlite_parent_floor_guards(void) {
  static const char *const guards[] = {
    "CREATE TRIGGER IF NOT EXISTS retention_active_clock_v1_insert BEFORE INSERT ON metrics "
      "WHEN NEW.minute_unix=0 AND NEW.endpoint_id='' AND NEW.metric_name='" RETENTION_ACTIVE_CLOCK_KEY "' "
      "AND (typeof(NEW.value)!='integer' OR NEW.value<0) "
      "BEGIN SELECT RAISE(ABORT,'invalid retention active clock'); END;",
    "CREATE TRIGGER IF NOT EXISTS retention_active_clock_v1_update BEFORE UPDATE ON metrics "
      "WHEN OLD.minute_unix=0 AND OLD.endpoint_id='' AND OLD.metric_name='" RETENTION_ACTIVE_CLOCK_KEY "' "
      "AND (NEW.minute_unix IS NOT OLD.minute_unix OR NEW.endpoint_id IS NOT OLD.endpoint_id "
      "OR NEW.metric_name IS NOT OLD.metric_name OR typeof(OLD.value)!='integer' OR OLD.value<0 "
      "OR typeof(NEW.value)!='integer' OR NEW.value<OLD.value) "
      "BEGIN SELECT RAISE(ABORT,'retention active clock cannot move backwards'); END;",
    "CREATE TRIGGER IF NOT EXISTS retention_active_clock_v1_delete BEFORE DELETE ON metrics "
      "WHEN OLD.minute_unix=0 AND OLD.endpoint_id='' AND OLD.metric_name='" RETENTION_ACTIVE_CLOCK_KEY "' "
      "BEGIN SELECT RAISE(ABORT,'retention active clock owner required'); END;",
    "CREATE TRIGGER IF NOT EXISTS alert_context_floor_v1_insert BEFORE INSERT ON p0_candidates "
      "WHEN typeof(NEW.alert_context_protect_until_active_ms)!='integer' OR NEW.alert_context_protect_until_active_ms!=0 "
      "BEGIN SELECT RAISE(ABORT,'parent floor requires a newly frozen context reference'); END;",
    "CREATE TRIGGER IF NOT EXISTS alert_context_floor_v1_update BEFORE UPDATE ON p0_candidates "
      "WHEN typeof(OLD.alert_context_protect_until_active_ms)!='integer' OR OLD.alert_context_protect_until_active_ms<0 "
      "OR typeof(NEW.alert_context_protect_until_active_ms)!='integer' OR NEW.alert_context_protect_until_active_ms<0 "
      "OR (OLD.alert_context_protect_until_active_ms!=0 AND ("
      "NEW.alert_context_protect_until_active_ms IS NOT OLD.alert_context_protect_until_active_ms "
      "OR NEW.candidate_id IS NOT OLD.candidate_id OR NEW.endpoint_id IS NOT OLD.endpoint_id "
      "OR NEW.tenant_id IS NOT OLD.tenant_id OR NEW.pid IS NOT OLD.pid OR NEW.ppid IS NOT OLD.ppid "
      "OR NEW.event_time_ns IS NOT OLD.event_time_ns OR NEW.process_start_key IS NOT OLD.process_start_key "
      "OR NEW.process_creation_filetime_100ns IS NOT OLD.process_creation_filetime_100ns "
      "OR NEW.subject_command_fact_id IS NOT OLD.subject_command_fact_id "
      "OR NEW.parent_command_fact_id IS NOT OLD.parent_command_fact_id)) "
      "OR (OLD.alert_context_protect_until_active_ms=0 AND NEW.alert_context_protect_until_active_ms>0 "
      "AND NOT EXISTS(SELECT 1 FROM metrics WHERE " RETENTION_ACTIVE_CLOCK_ROW " AND typeof(value)='integer' "
      "AND value>=0 AND value<NEW.alert_context_protect_until_active_ms)) "
      "BEGIN SELECT RAISE(ABORT,'frozen parent floor or query identity changed'); END;",
    "CREATE TRIGGER IF NOT EXISTS alert_context_floor_v1_eligible BEFORE UPDATE OF local_retention_state ON p0_candidates "
      "WHEN NEW.local_retention_state='retirement_eligible' AND ("
      "typeof(OLD.alert_context_protect_until_active_ms)!='integer' OR OLD.alert_context_protect_until_active_ms<0 "
      "OR (OLD.alert_context_protect_until_active_ms>0 AND NOT " RETENTION_FLOOR_ELAPSED ")) "
      "BEGIN SELECT RAISE(ABORT,'parent context minimum residence protects this group'); END;",
    "CREATE TRIGGER IF NOT EXISTS alert_context_floor_v1_delete BEFORE DELETE ON p0_candidates "
      "WHEN typeof(OLD.alert_context_protect_until_active_ms)!='integer' OR OLD.alert_context_protect_until_active_ms<0 "
      "OR (OLD.alert_context_protect_until_active_ms>0 AND NOT " RETENTION_FLOOR_ELAPSED ") "
      "BEGIN SELECT RAISE(ABORT,'parent context minimum residence protects this group'); END;"
  };
  for (unsigned i = 0; i < sizeof(guards) / sizeof(guards[0]); ++i)
    if (exec_sql(guards[i]) != 0) return -1;
  return 0;
}

static int sqlite_retention_clock_open(void) {
  sqlite3_stmt *st = NULL;
  uint64_t now = retention_monotonic_ms();
  int cause = 5;
  if (!now) return retention_clock_error(3u, "retention monotonic clock unavailable at cache open");
  if (sqlite3_prepare_v2(s_db, "SELECT value FROM metrics WHERE " RETENTION_ACTIVE_CLOCK_ROW ";",
      -1, &st, NULL) != SQLITE_OK) goto failed;
  int step = sqlite3_step(st);
  uint64_t base = 0u;
  if (step == SQLITE_ROW) {
    if (sqlite3_column_type(st, 0) != SQLITE_INTEGER || sqlite3_column_int64(st, 0) < 0) { cause = 2; goto failed; }
    base = (uint64_t)sqlite3_column_int64(st, 0);
  } else if (step == SQLITE_DONE) {
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(s_db, "SELECT 1 FROM p0_candidates WHERE "
        "typeof(alert_context_protect_until_active_ms)!='integer' OR alert_context_protect_until_active_ms!=0 LIMIT 1;",
        -1, &st, NULL) != SQLITE_OK) goto failed;
    step = sqlite3_step(st);
    if (step == SQLITE_ROW) { cause = 1; goto failed; }
    if (step != SQLITE_DONE) goto failed;
    sqlite3_finalize(st); st = NULL;
    if (exec_sql("INSERT INTO metrics(minute_unix,endpoint_id,metric_name,value) VALUES(0,'','" RETENTION_ACTIVE_CLOCK_KEY "',0);") != 0)
      goto failed;
  } else goto failed;
  sqlite3_finalize(st); st = NULL;
  if (sqlite_parent_floor_guards() != 0) goto failed;
  s_retention_clock.base_ms = base;
  s_retention_clock.anchor_ms = now;
  s_retention_clock.pending_ms = base;
  s_retention_clock.pending_mono_ms = now;
  s_retention_clock.pending = s_retention_clock.valid = 1;
  s_status.retention_clock_valid = 1u;
  s_status.retention_clock_cause_code = 0u;
  return 0;
failed:
  sqlite3_finalize(st);
  return retention_clock_error((unsigned)cause, "retention active clock missing or invalid at cache open; existing evidence preserved");
}

static int sqlite_live_size_over_limit(uint64_t limit);

/* Old on-disk caches predate durable process-generation proof and explicit
 * source omission provenance. Use PRAGMA discovery before each deterministic
 * ALTER so reopening an existing cache is restart-safe and never drops
 * candidate evidence. */
static int sqlite_p0_candidates_has_column(const char *column) {
  sqlite3_stmt *st = NULL;
  int found = 0;
  if (!s_db || !column ||
      sqlite3_prepare_v2(s_db, "PRAGMA table_info(p0_candidates);", -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  while (sqlite3_step(st) == SQLITE_ROW) {
    const char *name = (const char *)sqlite3_column_text(st, 1);
    if (name && strcmp(name, column) == 0) {
      found = 1;
      break;
    }
  }
  sqlite3_finalize(st);
  return found;
}

static int sqlite_ensure_p0_candidate_columns(void) {
  static const struct {
    const char *name;
    const char *alter;
  } columns[] = {
      {"process_start_key", "ALTER TABLE p0_candidates ADD COLUMN process_start_key TEXT;"},
      {"process_creation_filetime_100ns",
       "ALTER TABLE p0_candidates ADD COLUMN process_creation_filetime_100ns TEXT;"},
      {"process_generation_source",
       "ALTER TABLE p0_candidates ADD COLUMN process_generation_source TEXT;"},
      {"source_completeness",
       "ALTER TABLE p0_candidates ADD COLUMN source_completeness TEXT;"},
      {"source_truncated_fields",
       "ALTER TABLE p0_candidates ADD COLUMN source_truncated_fields TEXT;"},
      {"normalized_command",
       "ALTER TABLE p0_candidates ADD COLUMN normalized_command TEXT;"},
      {"normalized_command_truncated",
       "ALTER TABLE p0_candidates ADD COLUMN normalized_command_truncated INTEGER NOT NULL DEFAULT 0;"},
      {"script_path", "ALTER TABLE p0_candidates ADD COLUMN script_path TEXT;"},
      {"exe_hash", "ALTER TABLE p0_candidates ADD COLUMN exe_hash TEXT;"},
      {"username", "ALTER TABLE p0_candidates ADD COLUMN username TEXT;"},
      {"user_sid", "ALTER TABLE p0_candidates ADD COLUMN user_sid TEXT;"},
      {"identity_source",
       "ALTER TABLE p0_candidates ADD COLUMN identity_source TEXT;"},
      {"identity_quality",
       "ALTER TABLE p0_candidates ADD COLUMN identity_quality TEXT;"},
      {"retention_policy_version",
       "ALTER TABLE p0_candidates ADD COLUMN retention_policy_version INTEGER NOT NULL DEFAULT 0;"},
      {"local_retention_state",
       "ALTER TABLE p0_candidates ADD COLUMN local_retention_state TEXT NOT NULL DEFAULT 'retained';"},
      {"retention_value_class",
       "ALTER TABLE p0_candidates ADD COLUMN retention_value_class INTEGER NOT NULL DEFAULT 0;"},
      {"retention_value_reason",
       "ALTER TABLE p0_candidates ADD COLUMN retention_value_reason TEXT NOT NULL DEFAULT 'unclassified';"},
      {"subject_command_fact_id",
       "ALTER TABLE p0_candidates ADD COLUMN subject_command_fact_id TEXT NOT NULL DEFAULT '';"},
      {"parent_command_fact_id",
       "ALTER TABLE p0_candidates ADD COLUMN parent_command_fact_id TEXT NOT NULL DEFAULT '';"},
      {"alert_context_protect_until_active_ms",
       "ALTER TABLE p0_candidates ADD COLUMN alert_context_protect_until_active_ms INTEGER NOT NULL DEFAULT 0;"},
  };
  for (size_t i = 0u; i < sizeof(columns) / sizeof(columns[0]); ++i) {
    int has_column = sqlite_p0_candidates_has_column(columns[i].name);
    if (has_column < 0 || (has_column == 0 && exec_sql(columns[i].alter) != 0)) {
      return -1;
    }
  }
  return 0;
}

static int sqlite_ensure_command_fact_ownership(void) {
  static const struct { const char *name, *sql; } fields[] = {
    {"command_retention_policy", "ALTER TABLE artifacts ADD COLUMN command_retention_policy INTEGER NOT NULL DEFAULT 0;"},
    {"command_owner_pid", "ALTER TABLE artifacts ADD COLUMN command_owner_pid INTEGER NOT NULL DEFAULT 0;"},
    {"command_owner_start_key", "ALTER TABLE artifacts ADD COLUMN command_owner_start_key TEXT NOT NULL DEFAULT '';"},
    {"command_owner_creation", "ALTER TABLE artifacts ADD COLUMN command_owner_creation TEXT NOT NULL DEFAULT '';"}
  };
  for (unsigned i = 0; i < sizeof(fields)/sizeof(fields[0]); ++i) {
    sqlite3_stmt *st = NULL; int found = 0, rc;
    if (sqlite3_prepare_v2(s_db, "PRAGMA table_info(artifacts);", -1, &st, NULL) != SQLITE_OK) return -1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
      const char *name = (const char *)sqlite3_column_text(st, 1);
      if (name && !strcmp(name, fields[i].name)) found = 1;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || (!found && exec_sql(fields[i].sql))) return -1;
  }
  return exec_sql("CREATE INDEX IF NOT EXISTS idx_command_fact_retirement ON artifacts(created_ns,artifact_id) WHERE artifact_type='process_command_line' AND command_retention_policy=1;");
}

/* Additive ownership only. A replay/enrichment of an old candidate does not
 * promote it to a policy whose dependencies were never registered. */
static int sqlite_retention_metadata_open(void) {
  sqlite3_stmt *st = NULL;
  if (sqlite_ensure_command_fact_ownership() != 0) return -1;
  if (exec_sql("BEGIN IMMEDIATE;") != 0) return -1;
  if (sqlite3_prepare_v2(s_db,
      "SELECT COUNT(*) FROM p0_candidates WHERE typeof(retention_policy_version)!='integer' "
      "OR retention_policy_version NOT IN (0,1) OR local_retention_state IS NULL "
      "OR local_retention_state!='retained';", -1, &st, NULL) != SQLITE_OK ||
      sqlite3_step(st) != SQLITE_ROW || sqlite3_column_int64(st, 0) != 0) goto failed;
  sqlite3_finalize(st); st = NULL;
  if (exec_sql(
      "CREATE INDEX IF NOT EXISTS idx_candidates_retention ON p0_candidates(retention_policy_version,event_time_ns,candidate_id);"
      "CREATE INDEX IF NOT EXISTS idx_candidates_query_scope_time ON p0_candidates(endpoint_id,tenant_id,event_time_ns);"
      "CREATE INDEX IF NOT EXISTS idx_candidates_retention_value ON p0_candidates(retention_policy_version,retention_value_class,event_time_ns,candidate_id);"
      "CREATE INDEX IF NOT EXISTS idx_candidates_subject_command ON p0_candidates(subject_command_fact_id);"
      "CREATE INDEX IF NOT EXISTS idx_candidates_parent_command ON p0_candidates(parent_command_fact_id);"
      "CREATE INDEX IF NOT EXISTS idx_candidates_retention_generation ON p0_candidates(endpoint_id,tenant_id,pid,process_start_key,process_creation_filetime_100ns,candidate_id);"
      "CREATE INDEX IF NOT EXISTS idx_artifacts_candidate_owner ON artifacts(candidate_id,artifact_type,upload_status);"
      "CREATE INDEX IF NOT EXISTS idx_candidates_retention_unknown_generation ON p0_candidates(endpoint_id,tenant_id,pid) "
      "WHERE process_start_key IS NULL OR process_start_key IN ('','0') "
      "OR process_creation_filetime_100ns IS NULL OR process_creation_filetime_100ns IN ('','0');"
      "CREATE INDEX IF NOT EXISTS idx_artifacts_pmfe_retention ON artifacts(upload_status,created_ns,artifact_id) "
      "WHERE artifact_type='pmfe_followup_local_v1' AND "
      "(upload_status IS NULL OR upload_status NOT IN ('completed','expired','conflict'));"
      "DROP TRIGGER IF EXISTS candidate_retention_v1_insert;"
      "CREATE TRIGGER candidate_retention_v1_insert BEFORE INSERT ON p0_candidates "
      "WHEN typeof(NEW.retention_policy_version)!='integer' OR NEW.retention_policy_version NOT IN(0,1) "
      "OR NEW.local_retention_state IS NOT 'retained' BEGIN SELECT RAISE(ABORT,'unsupported candidate retention policy'); END;"
      "DROP TRIGGER IF EXISTS candidate_retention_v1_update;"
      "CREATE TRIGGER candidate_retention_v1_update BEFORE UPDATE OF retention_policy_version,local_retention_state ON p0_candidates "
      "WHEN NEW.retention_policy_version IS NOT OLD.retention_policy_version OR "
      "NEW.local_retention_state IS NULL OR NEW.local_retention_state NOT IN('retained','retirement_eligible') "
      "OR (NEW.local_retention_state='retirement_eligible' AND NEW.retention_policy_version!=1) "
      "BEGIN SELECT RAISE(ABORT,'unsupported candidate retention transition'); END;") != 0) goto failed;
  if (sqlite3_prepare_v2(s_db, "SELECT COUNT(*) FROM p0_candidates WHERE retention_policy_version=0 OR retention_value_class=0;",
      -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW) goto failed;
  uint64_t legacy = (uint64_t)sqlite3_column_int64(st, 0);
  sqlite3_finalize(st); st = NULL;
  if (edr_context_store_install_retention_guards(&s_context_store)!=0) { set_error(s_context_store.error); goto failed; }
  if (sqlite_retention_clock_open() != 0) goto failed;
  if (exec_sql("COMMIT;") != 0) goto failed;
  sqlite_retention_clock_committed();
  s_status.retention_legacy_candidates = legacy;
  return 0;
failed:
  sqlite3_finalize(st);
  (void)exec_sql("ROLLBACK;");
  s_retention_clock.pending = 0;
  set_error("candidate retention metadata unavailable or unsupported; evidence preserved");
  return -1;
}

/* `process_cache` keeps only the most recent known generation for a PID, but
 * it must never silently reinterpret that row as a PID-only identity after a
 * restart.  These append-only ALTERs are safe for every previously shipped
 * schema and leave historical rows explicitly generation-unknown. */
static int sqlite_process_cache_has_column(const char *column) {
  sqlite3_stmt *st = NULL;
  int found = 0;
  if (!s_db || !column ||
      sqlite3_prepare_v2(s_db, "PRAGMA table_info(process_cache);", -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  while (sqlite3_step(st) == SQLITE_ROW) {
    const char *name = (const char *)sqlite3_column_text(st, 1);
    if (name && strcmp(name, column) == 0) {
      found = 1;
      break;
    }
  }
  sqlite3_finalize(st);
  return found;
}

static int sqlite_ensure_process_cache_generation_columns(void) {
  static const struct {
    const char *name;
    const char *alter;
  } columns[] = {
      {"parent_pid_state", "ALTER TABLE process_cache ADD COLUMN parent_pid_state INTEGER NOT NULL DEFAULT 0;"},
      {"process_start_key", "ALTER TABLE process_cache ADD COLUMN process_start_key TEXT;"},
      {"process_creation_filetime_100ns",
       "ALTER TABLE process_cache ADD COLUMN process_creation_filetime_100ns TEXT;"},
      {"process_generation_source",
       "ALTER TABLE process_cache ADD COLUMN process_generation_source TEXT;"},
      {"parent_process_start_key",
       "ALTER TABLE process_cache ADD COLUMN parent_process_start_key TEXT;"},
      {"parent_process_creation_filetime_100ns",
       "ALTER TABLE process_cache ADD COLUMN parent_process_creation_filetime_100ns TEXT;"},
      {"parent_process_generation_source",
       "ALTER TABLE process_cache ADD COLUMN parent_process_generation_source TEXT;"},
      {"username", "ALTER TABLE process_cache ADD COLUMN username TEXT;"},
      {"domain", "ALTER TABLE process_cache ADD COLUMN domain TEXT;"},
      {"user_sid", "ALTER TABLE process_cache ADD COLUMN user_sid TEXT;"},
      {"logon_id", "ALTER TABLE process_cache ADD COLUMN logon_id TEXT;"},
      {"identity_source",
       "ALTER TABLE process_cache ADD COLUMN identity_source TEXT;"},
      {"identity_quality",
       "ALTER TABLE process_cache ADD COLUMN identity_quality TEXT;"},
      {"exe_hash", "ALTER TABLE process_cache ADD COLUMN exe_hash TEXT;"},
      {"cmdline_truncated_fields",
       "ALTER TABLE process_cache ADD COLUMN cmdline_truncated_fields TEXT;"},
  };
  for (size_t i = 0u; i < sizeof(columns) / sizeof(columns[0]); ++i) {
    int has_column = sqlite_process_cache_has_column(columns[i].name);
    if (has_column < 0 || (has_column == 0 && exec_sql(columns[i].alter) != 0)) {
      return -1;
    }
  }
  return 0;
}

static void sqlite_u64_decimal(uint64_t value, char out[32]) {
  if (out) (void)snprintf(out, 32u, "%llu", (unsigned long long)value);
}

static int sqlite_decimal_u64(const char *text, uint64_t *out) {
  uint64_t value = 0u;
  if (!text || !text[0] || !out) return 0;
  for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
    if (*p < (unsigned char)'0' || *p > (unsigned char)'9' ||
        value > (UINT64_MAX - (uint64_t)(*p - (unsigned char)'0')) / 10u) {
      return 0;
    }
    value = value * 10u + (uint64_t)(*p - (unsigned char)'0');
  }
  *out = value;
  return value != 0u;
}

/* All process-cache readers use this one projection.  A pre-migration row
 * with NULL/empty tuple is intentionally invisible to authoritative tree
 * joins instead of being treated as a PID-only parent. */
static int sqlite_read_process_cache_row(sqlite3_stmt *st, ProcSlot *out) {
  const char *start_key;
  const char *creation;
  const char *parent_start_key;
  const char *parent_creation;
  if (!st || !out) return 0;
  memset(out, 0, sizeof(*out));
  copy_s(out->endpoint_id, sizeof(out->endpoint_id),
         (const char *)sqlite3_column_text(st, 0));
  copy_s(out->tenant_id, sizeof(out->tenant_id),
         (const char *)sqlite3_column_text(st, 1));
  out->pid = (uint32_t)sqlite3_column_int64(st, 2);
  out->ppid = (uint32_t)sqlite3_column_int64(st, 3);
  out->parent_pid_state = edr_parent_pid_effective_state(out->ppid, (uint8_t)sqlite3_column_int(st, 24));
  copy_s(out->name, sizeof(out->name), (const char *)sqlite3_column_text(st, 4));
  copy_s(out->path, sizeof(out->path), (const char *)sqlite3_column_text(st, 5));
  {
    const char *fields = (const char *)sqlite3_column_text(st, 23);
    const int exact = copy_s(out->cmdline, sizeof(out->cmdline),
                             (const char *)sqlite3_column_text(st, 6));
    copy_s(out->cmdline_truncated_fields, sizeof(out->cmdline_truncated_fields),
           fields ? fields : "source.cmdline_quality_unknown");
    if (!exact) source_field_list_append(out->cmdline_truncated_fields,
        sizeof(out->cmdline_truncated_fields), "source.cmdline");
  }
  copy_s(out->parent_name, sizeof(out->parent_name),
         (const char *)sqlite3_column_text(st, 7));
  copy_s(out->parent_path, sizeof(out->parent_path),
         (const char *)sqlite3_column_text(st, 8));
  out->last_seen_ns = sqlite3_column_int64(st, 9);
  start_key = (const char *)sqlite3_column_text(st, 10);
  creation = (const char *)sqlite3_column_text(st, 11);
  if (!sqlite_decimal_u64(start_key, &out->generation.process_start_key) ||
      !sqlite_decimal_u64(creation, &out->generation.creation_filetime_100ns) ||
      !generation_bound(&out->generation)) {
    return 0;
  }
  copy_s(out->process_generation_source, sizeof(out->process_generation_source),
         (const char *)sqlite3_column_text(st, 12));
  parent_start_key = (const char *)sqlite3_column_text(st, 13);
  parent_creation = (const char *)sqlite3_column_text(st, 14);
  if (out->parent_pid_state == EDR_PARENT_PID_KNOWN &&
      sqlite_decimal_u64(parent_start_key, &out->parent_generation.process_start_key) &&
      sqlite_decimal_u64(parent_creation,
                         &out->parent_generation.creation_filetime_100ns) &&
      generation_bound(&out->parent_generation)) {
    copy_s(out->parent_process_generation_source,
           sizeof(out->parent_process_generation_source),
           (const char *)sqlite3_column_text(st, 15));
  } else {
    memset(&out->parent_generation, 0, sizeof(out->parent_generation));
  }
  copy_s(out->username, sizeof(out->username),
         (const char *)sqlite3_column_text(st, 16));
  copy_s(out->domain, sizeof(out->domain),
         (const char *)sqlite3_column_text(st, 17));
  copy_s(out->user_sid, sizeof(out->user_sid),
         (const char *)sqlite3_column_text(st, 18));
  copy_s(out->logon_id, sizeof(out->logon_id),
         (const char *)sqlite3_column_text(st, 19));
  copy_s(out->identity_source, sizeof(out->identity_source),
         (const char *)sqlite3_column_text(st, 20));
  copy_s(out->identity_quality, sizeof(out->identity_quality),
         (const char *)sqlite3_column_text(st, 21));
  copy_s(out->exe_hash, sizeof(out->exe_hash),
         (const char *)sqlite3_column_text(st, 22));
  return 1;
}

static uint64_t path_size_bytes(const char *path) {
  if (!path || !path[0]) {
    return 0u;
  }
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0u;
  }
  return st.st_size > 0 ? (uint64_t)st.st_size : 0u;
}

static void refresh_db_size_status(void) {
  s_status.db_bytes = path_size_bytes(s_status.path);
  if (!s_status.path[0]) {
    s_status.wal_bytes = 0u;
    s_status.shm_bytes = 0u;
    s_status.physical_bytes = s_status.db_bytes;
    return;
  }
  char wal_path[640];
  snprintf(wal_path, sizeof(wal_path), "%s-wal", s_status.path);
  s_status.wal_bytes = path_size_bytes(wal_path);
  snprintf(wal_path, sizeof(wal_path), "%s-shm", s_status.path);
  s_status.shm_bytes = path_size_bytes(wal_path);
  s_status.physical_bytes = s_status.db_bytes + s_status.wal_bytes + s_status.shm_bytes;
}

static void refresh_candidate_inventory_status(EdrEvidenceCacheStatus *st) {
  sqlite3_stmt *stmt = NULL;
  if (!st || !s_db ||
      sqlite3_prepare_v2(s_db,
                         "SELECT COUNT(*),COALESCE(MIN(event_time_ns),0) FROM p0_candidates;",
                         -1, &stmt, NULL) != SQLITE_OK) {
    return;
  }
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    sqlite3_int64 rows = sqlite3_column_int64(stmt, 0);
    sqlite3_int64 oldest = sqlite3_column_int64(stmt, 1);
    st->p0_candidate_rows = rows > 0 ? (uint64_t)rows : 0u;
    st->oldest_p0_candidate_event_time_ns = oldest > 0 ? (int64_t)oldest : 0;
  }
  sqlite3_finalize(stmt);
}

static int db_size_over_limit(void) {
  if (!s_status.path[0] || s_status.max_db_mb == 0u) {
    return 0;
  }
  refresh_db_size_status();
  uint64_t limit = (uint64_t)s_status.max_db_mb * 1024ULL * 1024ULL;
  uint64_t total = s_status.db_bytes + s_status.wal_bytes;
  return limit > 0u && total > limit;
}

static uint64_t sqlite_capacity_live_target(void) {
  uint64_t limit = (uint64_t)s_status.max_db_mb * 1024ULL * 1024ULL;
  uint64_t headroom = limit / 16u;
  if (headroom > 8u * 1024u * 1024u) headroom = 8u * 1024u * 1024u;
  return limit - headroom;
}

static int sqlite_physical_write_allow(uint64_t payload_bytes) {
  EdrStoragePhysicalSnapshot snapshot={0};
  int overflow=payload_bytes>(UINT64_MAX-8u*1024u*1024u)/3u;
  int rc=overflow ? -2 : edr_storage_physical_admit(s_status.path,payload_bytes*3u+8u*1024u*1024u,0,&snapshot);
  if(rc) {
    set_error(overflow ? "physical_size_overflow" : snapshot.cause);
    ++s_status.db_budget_dropped;
    if(rc==-1) ++s_status.physical_refusals; else ++s_status.physical_guard_failures;
    s_status.physical_cause_code=overflow ? 3u : rc==-1 ? 1u : 2u;
    return 0;
  }
  return 1;
}


/* SQLite page accounting includes logical pages still present only in WAL.
 * A delete can dirty any existing index/overflow page, and a checkpoint can
 * extend the DB while its WAL must remain. Use a whole existing-page copy
 * plus the bounded slice envelope, then the common WAL/temp multiplier.
 * This deliberately may hold maintenance near the physical floor. */
static int sqlite_database_page_bytes(uint64_t *bytes, uint64_t *page_size) {
  sqlite3_stmt *st=NULL;
  int ok=sqlite3_prepare_v2(s_db,"SELECT page_count,page_size FROM pragma_page_count,pragma_page_size;",-1,&st,NULL)==SQLITE_OK &&
      sqlite3_step(st)==SQLITE_ROW;
  sqlite3_int64 pages=ok ? sqlite3_column_int64(st,0) : -1;
  sqlite3_int64 size=ok ? sqlite3_column_int64(st,1) : -1;
  sqlite3_finalize(st);
  if(pages<0 || size<=0 || (uint64_t)pages>UINT64_MAX/(uint64_t)size) {
    set_error("physical maintenance page accounting unavailable");
    ++s_status.physical_guard_failures; s_status.physical_cause_code=2u;
    return 0;
  }
  *bytes=(uint64_t)pages*(uint64_t)size;
  if(page_size) *page_size=(uint64_t)size;
  return 1;
}

static int sqlite_database_write_allow(uint64_t work_bytes) {
  uint64_t current=0;
  if(!sqlite_database_page_bytes(&current,NULL)) return 0;
  return sqlite_physical_write_allow(current>UINT64_MAX-work_bytes ? UINT64_MAX : current+work_bytes);
}

static uint64_t s_evidence_wal_page_size;
/* Preserve the normal 1000-page passive checkpoint cadence, but guard the
 * actual accumulated WAL. A long reader can leave far more than 1000 pages;
 * a fixed per-event allowance cannot authorize copying that entire backlog.
 * This callback runs after commit: refusal must never report a false failed
 * commit, and the already committed WAL remains the durable owner. */
static int sqlite_guarded_autocheckpoint(void *unused, sqlite3 *db, const char *name, int pages) {
  (void)unused;
  if (pages < 1000) return SQLITE_OK;
  uint64_t frame=s_evidence_wal_page_size+24u;
  if (!frame || (uint64_t)pages>(UINT64_MAX-32u)/frame ||
      !sqlite_physical_write_allow((uint64_t)pages*frame+32u)) return SQLITE_OK;
  int rc=sqlite3_wal_checkpoint_v2(db,name,SQLITE_CHECKPOINT_PASSIVE,NULL,NULL);
  if(rc!=SQLITE_OK) set_error("automatic evidence checkpoint deferred; committed WAL retained");
  return SQLITE_OK;
}

/* Cost manifest for the actual CREATE INDEX declarations in this owner and
 * evidence_context_store.c. The source contract test compares both sets.
 * Kind 0 always applies, 1 is the legacy context layout, 2 is compact. */
static const struct { const char *name, *table; unsigned layout; } startup_index_cost_manifest[] = {
    {"idx_command_fact_retirement", "artifacts", 0},
    {"idx_candidates_retention", "p0_candidates", 0},
    {"idx_candidates_query_scope_time", "p0_candidates", 0},
    {"idx_candidates_retention_value", "p0_candidates", 0},
    {"idx_candidates_subject_command", "p0_candidates", 0},
    {"idx_candidates_parent_command", "p0_candidates", 0},
    {"idx_candidates_retention_generation", "p0_candidates", 0},
    {"idx_artifacts_candidate_owner", "artifacts", 0},
    {"idx_candidates_retention_unknown_generation", "p0_candidates", 0},
    {"idx_artifacts_pmfe_retention", "artifacts", 0},
    {"idx_process_cache_parent", "process_cache", 0},
    {"idx_event_cache_ep_time", "event_cache", 0},
    {"idx_event_cache_pid_time", "event_cache", 0},
    {"idx_p0_candidates_ep_time", "p0_candidates", 0},
    {"idx_p0_candidates_pid_time", "p0_candidates", 0},
    {"idx_artifacts_ep_time", "artifacts", 0},
    {"idx_artifacts_pmfe_state_created", "artifacts", 0},
    {"idx_file_evidence_sha", "file_evidence", 0},
    {"idx_process_cache_retention", "process_cache", 0},
    {"idx_file_evidence_retention", "file_evidence", 0},
    {"idx_network_ioc_retention", "network_ioc", 0},
    {"idx_registry_evidence_retention", "registry_evidence", 0},
    {"idx_command_results_retention", "command_results", 0},
    {"idx_artifacts_pmfe_terminal_retention", "artifacts", 0},
    {"idx_context_facts_ep_time", "context_facts", 1},
    {"idx_candidate_context_refs_candidate", "candidate_context_refs", 1},
    {"idx_candidate_context_refs_fact", "candidate_context_refs", 1},
    {"idx_compact_context_candidate_time", "compact_context_refs", 2},
    {"idx_compact_context_fact", "compact_context_refs", 2},
    {"idx_compact_context_time", "compact_context_refs", 2},
};

static int sqlite_startup_probe_cancel(void *deadline) {
  return evidence_cache_clock_ns() >= *(const uint64_t *)deadline;
}

static int sqlite_table_index_inventory(const char *table, uint64_t *bytes) {
  sqlite3_stmt *st=NULL; char *query=NULL, *next=NULL; unsigned columns=0;
  char *pragma=sqlite3_mprintf("PRAGMA table_info(\"%w\");",table);
  if(!pragma || sqlite3_prepare_v2(s_db,pragma,-1,&st,NULL)!=SQLITE_OK) {sqlite3_free(pragma);return 0;}
  sqlite3_free(pragma);
  query=sqlite3_mprintf("SELECT COALESCE(SUM(128");
  if(!query) goto failed;
  int rc;
  while((rc=sqlite3_step(st))==SQLITE_ROW) {
    const char *column=(const char *)sqlite3_column_text(st,1);
    if(!column) goto failed;
    next=sqlite3_mprintf("%s+16+COALESCE(length(CAST(\"%w\" AS BLOB)),0)",query,column);
    sqlite3_free(query);query=next;next=NULL;
    if(!query) goto failed;
    ++columns;
  }
  sqlite3_finalize(st);st=NULL;
  if(rc!=SQLITE_DONE) goto failed;
  if(!columns) {*bytes=0;sqlite3_free(query);return 1;}
  next=sqlite3_mprintf("%s),0) FROM \"%w\";",query,table);
  sqlite3_free(query);query=next;next=NULL;
  if(!query || sqlite3_prepare_v2(s_db,query,-1,&st,NULL)!=SQLITE_OK || sqlite3_step(st)!=SQLITE_ROW ||
      sqlite3_column_type(st,0)!=SQLITE_INTEGER || sqlite3_column_int64(st,0)<0) goto failed;
  *bytes=(uint64_t)sqlite3_column_int64(st,0);
  sqlite3_finalize(st);sqlite3_free(query);return 1;
failed:
  sqlite3_finalize(st);sqlite3_free(query);return 0;
}

static int sqlite_startup_schema_write_allow(void) {
  sqlite3_stmt *st=NULL; uint64_t current=0,growth=0;
  uint64_t inventory[sizeof(startup_index_cost_manifest)/sizeof(startup_index_cost_manifest[0])]={0};
  unsigned char measured[sizeof(startup_index_cost_manifest)/sizeof(startup_index_cost_manifest[0])]={0};
  if(!sqlite_database_page_bytes(&current,NULL)) return 0;
  growth=current;
  uint64_t deadline=evidence_cache_clock_ns()+10000000000ULL;
  sqlite3_progress_handler(s_db,10000,sqlite_startup_probe_cancel,&deadline);
  for(unsigned i=0;i<sizeof(startup_index_cost_manifest)/sizeof(startup_index_cost_manifest[0]);++i) {
    unsigned layout=startup_index_cost_manifest[i].layout;
    if((layout==1u && s_context_store.format) || (layout==2u && !s_context_store.format)) continue;
    if(sqlite3_prepare_v2(s_db,"SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1;",-1,&st,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(st,1,startup_index_cost_manifest[i].name,-1,SQLITE_STATIC)!=SQLITE_OK) goto failed;
    int rc=sqlite3_step(st);
    sqlite3_finalize(st);st=NULL;
    if(rc==SQLITE_ROW) continue;
    if(rc!=SQLITE_DONE) goto failed;
    unsigned owner=i;
    for(unsigned j=0;j<i;++j) if(measured[j] && !strcmp(startup_index_cost_manifest[j].table,startup_index_cost_manifest[i].table)) {owner=j;break;}
    if(!measured[owner]) {
      if(!sqlite_table_index_inventory(startup_index_cost_manifest[i].table,&inventory[owner])) goto failed;
      measured[owner]=1;
    }
    /* Twice the entire source row inventory, including 128 bytes/row and
     * 16/column serialization allowance, covers a sparse B-tree index whose
     * keys are a subset of those rows. Do not charge unrelated blob tables. */
    if(inventory[owner]>(UINT64_MAX-growth)/2u) goto overflow;
    growth+=inventory[owner]*2u;
  }
  sqlite3_progress_handler(s_db,0,NULL,NULL);
  if(growth>UINT64_MAX-EDR_EVIDENCE_MANIFEST_MAX_BYTES) return sqlite_physical_write_allow(UINT64_MAX);
  return sqlite_physical_write_allow(growth+EDR_EVIDENCE_MANIFEST_MAX_BYTES);
overflow:
  sqlite3_progress_handler(s_db,0,NULL,NULL);
  return sqlite_physical_write_allow(UINT64_MAX);
failed:
  sqlite3_finalize(st);sqlite3_progress_handler(s_db,0,NULL,NULL);
  set_error("physical startup index accounting failed or exceeded 10s; existing cache preserved");
  ++s_status.physical_guard_failures; s_status.physical_cause_code=2u; return 0;
}

static int sqlite_maintenance_checkpoint(int mode);

static int sqlite_size_budget_allow_mode(int allow_retirement) {
  if (!sqlite_physical_write_allow(EDR_EVIDENCE_MANIFEST_MAX_BYTES)) return 0;
  if (!db_size_over_limit()) {
    s_last_capacity_failure_ns = 0u;
    return 1;
  }
  /* Automatic checkpoint can leave a large, reusable WAL allocation behind.
   * The cleanup target is not an admission cap: normal database growth past
   * that target must still allow WAL reset while the database fits the hard
   * cap. An active reader can prevent reset; physical admission still wins. */
  uint64_t limit = (uint64_t)s_status.max_db_mb * 1024ULL * 1024ULL;
  if (s_status.db_bytes < limit) {
    if (!sqlite_database_write_allow(EDR_EVIDENCE_MANIFEST_MAX_BYTES)) return 0;
    int rc = sqlite3_wal_checkpoint_v2(s_db, NULL, SQLITE_CHECKPOINT_TRUNCATE,
                                      NULL, NULL);
    if (rc != SQLITE_OK) {
      char error[128];
      snprintf(error, sizeof(error), "evidence cache WAL reset blocked or failed: sqlite rc=%d", rc);
      set_error(error);
      s_status.db_budget_dropped++;
      return 0;
    }
    if (!db_size_over_limit()) {
      s_last_capacity_failure_ns = 0u;
      return 1;
    }
  }
  uint64_t now = edr_monotonic_ns();
  /* Damp repeated failures, not successful reclamation. A fast writer can
   * refill the recovered space within ten seconds; rejecting it merely because
   * the previous cleanup succeeded recently turns throughput gains into loss. */
  /* An existing candidate update must not retire its own owner or dependencies
   * to make room, then recreate them through the upsert. It can reset a reusable
   * WAL above, but otherwise refuses until normal maintenance frees space. */
  if (allow_retirement && (s_last_capacity_failure_ns == 0u ||
      now - s_last_capacity_failure_ns >= 10000000000ULL)) {
    s_last_maintenance_ns = now;
    int maintenance_result = sqlite_maintenance(0);
    if (!db_size_over_limit()) {
      s_maintenance_reclaim_pages = 0u;
      s_last_capacity_failure_ns = 0u;
      return 1;
    }
    s_last_capacity_failure_ns = edr_monotonic_ns();
    if (maintenance_result != 0) {
      /* Keep the actionable maintenance cause instead of replacing it with
       * a generic full-cache message. Physical admission remains binding. */
      s_status.db_budget_dropped++;
      return 0;
    }
  }
  s_status.db_budget_dropped++;
  set_error("evidence cache size budget exceeded");
  return 0;
}

static int sqlite_size_budget_allow(void) {
  return sqlite_size_budget_allow_mode(1);
}

typedef struct {
  uint32_t base;
  uint32_t ordinary_context;
} EvidenceWriteBudgetLimits;

static EvidenceWriteBudgetLimits sqlite_write_budget_limits(void) {
  EvidenceWriteBudgetLimits limits;
  memset(&limits, 0, sizeof(limits));
  limits.base = env_u32_clamped("EDR_EVIDENCE_CACHE_WRITE_BUDGET_PER_MIN",
                                80u, 0u, 100000u);
  if (limits.base == 0u) {
    return limits;
  }
  /* Count changed source transactions, not their candidate fanout or physical
   * SQLite statements. Generic FILE_READ context remains best effort and gets
   * half the compatible base budget. Action/ancestry context is not rejected
   * solely by a fixed per-minute count; it remains bounded by context windows,
   * database capacity/retention, and atomic SQLite transaction outcomes. */
  limits.ordinary_context = env_u32_clamped(
      "EDR_EVIDENCE_CACHE_ORDINARY_CONTEXT_WRITE_BUDGET_PER_MIN",
      limits.base / 2u ? limits.base / 2u : 1u, 1u, 100000u);
  return limits;
}

static int sqlite_write_budget_allow(uint32_t units, int64_t ts,
                                     EvidenceWriteClass write_class) {
  /* This budget protects work performed now.  Event time is attacker- and
   * transport-influenced and may arrive late or out of order; using it here
   * allowed an older event to reset the live write budget backwards. */
  (void)ts;
  int64_t minute = (now_unix_ns() / 1000000000LL) / 60LL;
  if (minute != s_write_budget_minute) {
    s_write_budget_minute = minute;
    s_write_budget_count = 0u;
    s_write_budget_ordinary_context_count = 0u;
  }
  if (write_class == EVIDENCE_WRITE_CRITICAL_CONTEXT) {
    return 1;
  }
  EvidenceWriteBudgetLimits limits = sqlite_write_budget_limits();
  if (limits.base == 0u) {
    return 1;
  }
  if (units == 0u) {
    units = 1u;
  }
  if (write_class != EVIDENCE_WRITE_ORDINARY_CONTEXT ||
      s_write_budget_ordinary_context_count >= limits.ordinary_context ||
      units > limits.ordinary_context - s_write_budget_ordinary_context_count) {
    s_status.write_budget_dropped++;
    s_status.write_budget_context_dropped++;
    if (write_class == EVIDENCE_WRITE_ORDINARY_CONTEXT) {
      s_status.write_budget_ordinary_context_dropped++;
      set_error("evidence cache ordinary context write budget exceeded");
    } else {
      set_error("evidence cache invalid context write class");
    }
    return 0;
  }
  s_write_budget_count += units;
  s_write_budget_ordinary_context_count += units;
  return 1;
}

/* A context reservation becomes consumption only when its artifact transaction
 * commits. An injected/disk failure therefore cannot exhaust the pool for a
 * later context record. */
static void sqlite_write_budget_release(uint32_t units, int64_t ts,
                                        EvidenceWriteClass write_class) {
  if (write_class == EVIDENCE_WRITE_CRITICAL_CONTEXT) {
    return;
  }
  EvidenceWriteBudgetLimits limits = sqlite_write_budget_limits();
  if (limits.base == 0u) {
    return;
  }
  if (units == 0u) {
    units = 1u;
  }
  (void)ts;
  int64_t minute = (now_unix_ns() / 1000000000LL) / 60LL;
  if (minute == s_write_budget_minute && s_write_budget_count >= units) {
    s_write_budget_count -= units;
    if (write_class == EVIDENCE_WRITE_ORDINARY_CONTEXT &&
        s_write_budget_ordinary_context_count >= units) {
      s_write_budget_ordinary_context_count -= units;
    }
  }
}

static void bind_text(sqlite3_stmt *st, int idx, const char *s) {
  sqlite3_bind_text(st, idx, s ? s : "", -1, SQLITE_TRANSIENT);
}

static void hydrate_process_command(ProcSlot *p) {
  sqlite3_stmt *st = NULL;
  char start[32], birth[32];
  if (!s_db || !p || !generation_bound(&p->generation)) return;
  sqlite_u64_decimal(p->generation.process_start_key, start);
  sqlite_u64_decimal(p->generation.creation_filetime_100ns, birth);
  if (sqlite3_prepare_v2(s_db,
      "SELECT cmdline,cmdline_truncated_fields FROM process_cache WHERE "
      "endpoint_id=? AND tenant_id=? AND pid=? AND process_start_key=? "
      "AND process_creation_filetime_100ns=?;", -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare durable command hydration failed");
    return;
  }
  bind_text(st, 1, p->endpoint_id); bind_text(st, 2, p->tenant_id);
  sqlite3_bind_int64(st, 3, p->pid);
  bind_text(st, 4, start); bind_text(st, 5, birth);
  int rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    const char *fields = (const char *)sqlite3_column_text(st, 1);
    const int exact = copy_s(p->cmdline, sizeof(p->cmdline),
                             (const char *)sqlite3_column_text(st, 0));
    copy_s(p->cmdline_truncated_fields, sizeof(p->cmdline_truncated_fields),
           fields ? fields : "source.cmdline_quality_unknown");
    if (!exact) source_field_list_append(p->cmdline_truncated_fields,
        sizeof(p->cmdline_truncated_fields), "source.cmdline");
  } else if (rc != SQLITE_DONE) {
    set_error("read durable command hydration failed");
  }
  sqlite3_finalize(st);
}

/* Persist the same conservative late-parent repair used by the hot cache.
 * Every child row is revalidated against the process-tree interval at that
 * child's immutable creation time; PPID alone is never authority.  Parent
 * tuple and display fields are updated by one statement in one observation
 * transaction, so a restart cannot expose a mixed old/new edge. */
static int repair_child_parent_edges_sqlite(
    const EdrBehaviorRecord *parent,
    const EvidenceProcessGeneration *parent_generation) {
  static const char *select_sql =
      "SELECT pid,process_start_key,process_creation_filetime_100ns,"
      "parent_process_start_key,parent_process_creation_filetime_100ns "
      "FROM process_cache WHERE endpoint_id=? AND ppid=? AND pid<>? AND parent_pid_state IN (0,1) "
      "AND COALESCE(parent_process_generation_source,'')<>'parent_generation_conflict';";
  static const char *update_sql =
      "UPDATE process_cache SET parent_process_start_key=?,"
      "parent_process_creation_filetime_100ns=?,"
      "parent_process_generation_source=?,parent_name=?,parent_path=? "
      "WHERE endpoint_id=? AND pid=? AND ppid=? AND process_start_key=? "
      "AND process_creation_filetime_100ns=? AND parent_pid_state IN (0,1);";
  sqlite3_stmt *select_st = NULL;
  sqlite3_stmt *update_st = NULL;
  char parent_start_key[32];
  char parent_creation[32];
  int step_rc;
  int result = -1;
  int transaction_started = 0;

  if (!s_db || !parent || !generation_bound(parent_generation) ||
      parent->pid == 0u || parent->type != EDR_EVENT_PROCESS_CREATE ||
      !edr_process_create_is_lifecycle_authoritative(parent)) {
    return 0;
  }
  /* Identity observations need not be detection candidates. Repair existing
   * durable child rows on the observation path without persisting every
   * ordinary parent as a new candidate or fabricating high-priority context. */
  if (exec_sql("BEGIN IMMEDIATE;") != 0) return -1;
  transaction_started = 1;
  if (sqlite3_prepare_v2(s_db, select_sql, -1, &select_st, NULL) !=
      SQLITE_OK) {
    set_error("prepare durable child parent repair scan failed");
    goto done;
  }
  if (sqlite3_prepare_v2(s_db, update_sql, -1, &update_st, NULL) !=
      SQLITE_OK) {
    set_error("prepare durable child parent repair update failed");
    goto done;
  }
  bind_text(select_st, 1, parent->endpoint_id);
  sqlite3_bind_int64(select_st, 2, (sqlite3_int64)parent->pid);
  sqlite3_bind_int64(select_st, 3, (sqlite3_int64)parent->pid);
  sqlite_u64_decimal(parent_generation->process_start_key, parent_start_key);
  sqlite_u64_decimal(parent_generation->creation_filetime_100ns,
                     parent_creation);

  while ((step_rc = sqlite3_step(select_st)) == SQLITE_ROW) {
    const uint32_t child_pid = (uint32_t)sqlite3_column_int64(select_st, 0);
    const char *child_start_text =
        (const char *)sqlite3_column_text(select_st, 1);
    const char *child_creation_text =
        (const char *)sqlite3_column_text(select_st, 2);
    const char *old_parent_start_text =
        (const char *)sqlite3_column_text(select_st, 3);
    const char *old_parent_creation_text =
        (const char *)sqlite3_column_text(select_st, 4);
    uint64_t child_start_key = 0u;
    uint64_t child_creation = 0u;
    uint64_t old_parent_start_key = 0u;
    uint64_t old_parent_creation = 0u;
    uint64_t child_birth_ns = 0u;
    ProcessTreeEntry selected;
    const int old_parent_bound =
        sqlite_decimal_u64(old_parent_start_text, &old_parent_start_key) &&
        sqlite_decimal_u64(old_parent_creation_text, &old_parent_creation);

    if (!sqlite_decimal_u64(child_start_text, &child_start_key) ||
        !sqlite_decimal_u64(child_creation_text, &child_creation) ||
        parent_generation->creation_filetime_100ns > child_creation ||
        !generation_birth_unix_ns(child_creation, &child_birth_ns) ||
        edr_pt_cache_snapshot_parent_at(parent->pid, child_birth_ns, &selected) != 0 ||
        selected.process_start_key != parent_generation->process_start_key ||
        selected.creation_filetime_100ns !=
            parent_generation->creation_filetime_100ns) {
      continue;
    }
    if (old_parent_bound &&
        (old_parent_start_key != parent_generation->process_start_key ||
         old_parent_creation !=
             parent_generation->creation_filetime_100ns) &&
        parent_generation->creation_filetime_100ns <= old_parent_creation) {
      continue;
    }

    sqlite3_reset(update_st);
    sqlite3_clear_bindings(update_st);
    bind_text(update_st, 1, parent_start_key);
    bind_text(update_st, 2, parent_creation);
    bind_text(update_st, 3, "verified_late_child_birth_parent_snapshot");
    bind_text(update_st, 4, selected.process_name);
    bind_text(update_st, 5, selected.exe_path);
    bind_text(update_st, 6, parent->endpoint_id);
    sqlite3_bind_int64(update_st, 7, (sqlite3_int64)child_pid);
    sqlite3_bind_int64(update_st, 8, (sqlite3_int64)parent->pid);
    bind_text(update_st, 9, child_start_text);
    bind_text(update_st, 10, child_creation_text);
    if (sqlite3_step(update_st) != SQLITE_DONE) {
      set_error("durable child parent repair update failed");
      goto done;
    }
  }
  if (step_rc != SQLITE_DONE) {
    set_error("durable child parent repair scan failed");
    goto done;
  }
  if (exec_sql("COMMIT;") != 0) goto done;
  transaction_started = 0;
  result = 0;

done:
  sqlite3_finalize(update_st);
  sqlite3_finalize(select_st);
  if (transaction_started) {
    char *error = NULL;
    (void)sqlite3_exec(s_db,"ROLLBACK;",NULL,NULL,&error);
    sqlite3_free(error);
  }
  return result;
}

static int upsert_process_sqlite(const EdrBehaviorRecord *r) {
  EvidenceProcessGeneration generation;
  EvidenceProcessGeneration parent_generation;
  ProcessTreeEntry parent_snapshot;
  char start_key[32], creation[32], parent_start_key[32], parent_creation[32];
  int parent_known;
  int preserve_stronger_identity = 0;
  int replace_command = 1;
  uint32_t durable_ppid = r->ppid;
  uint8_t durable_parent_state = edr_parent_pid_effective_state(r->ppid, r->parent_pid_state);
  char command_fields[64];
  if (!s_db || !should_update_process_cache(r) ||
      !record_process_generation(r, &generation)) {
    /* Unknown PID-only metadata is never durable authority. It may remain in
     * the bounded in-memory display cache, but must not overwrite a known
     * restarted lifetime in SQLite. */
    return 0;
  }
  if (!sqlite_physical_write_allow(sizeof(*r))) return -1;
  parent_known = record_parent_snapshot(r, &parent_snapshot);
  command_record_provenance(r, command_fields);
  memset(&parent_generation, 0, sizeof(parent_generation));
  if (parent_known) {
    parent_generation.process_start_key = parent_snapshot.process_start_key;
    parent_generation.creation_filetime_100ns =
        parent_snapshot.creation_filetime_100ns;
    parent_generation.start_time_ns = parent_snapshot.start_time_ns;
  }
  sqlite_u64_decimal(generation.process_start_key, start_key);
  sqlite_u64_decimal(generation.creation_filetime_100ns, creation);
  if (parent_known) {
    sqlite_u64_decimal(parent_generation.process_start_key, parent_start_key);
    sqlite_u64_decimal(parent_generation.creation_filetime_100ns, parent_creation);
  } else {
    parent_start_key[0] = '\0';
    parent_creation[0] = '\0';
  }
  {
    sqlite3_stmt *identity_st = NULL;
    const char *identity_sql =
        "SELECT identity_quality,cmdline,cmdline_truncated_fields,ppid,parent_pid_state FROM process_cache WHERE endpoint_id=? AND pid=? "
        "AND process_start_key=? AND process_creation_filetime_100ns=? AND tenant_id=? LIMIT 1;";
    if (sqlite3_prepare_v2(s_db, identity_sql, -1, &identity_st, NULL) !=
        SQLITE_OK) {
      set_error("prepare process_cache identity quality failed");
      return -1;
    }
    bind_text(identity_st, 1, r->endpoint_id);
    sqlite3_bind_int64(identity_st, 2, (sqlite3_int64)r->pid);
    bind_text(identity_st, 3, start_key);
    bind_text(identity_st, 4, creation);
    bind_text(identity_st, 5, r->tenant_id);
    int read_rc = sqlite3_step(identity_st);
    if (read_rc == SQLITE_ROW) {
      uint32_t previous_ppid = (uint32_t)sqlite3_column_int64(identity_st, 3);
      uint8_t previous_state = (uint8_t)sqlite3_column_int(identity_st, 4);
      edr_parent_pid_merge(&previous_ppid, &previous_state, durable_ppid, durable_parent_state);
      durable_ppid = previous_ppid;
      durable_parent_state = previous_state;
      const char *current_quality =
          (const char *)sqlite3_column_text(identity_st, 0);
      preserve_stronger_identity =
          identity_quality_rank(current_quality) >
          identity_quality_rank(r->identity_quality);
      replace_command = command_fact_should_replace(
          (const char *)sqlite3_column_text(identity_st, 1),
          (const char *)sqlite3_column_text(identity_st, 2), r->cmdline, command_fields);
    } else if (read_rc != SQLITE_DONE) {
      set_error("read process_cache field quality failed");
      sqlite3_finalize(identity_st);
      return -1;
    }
    sqlite3_finalize(identity_st);
  }
  const char *sql =
      "INSERT INTO process_cache(endpoint_id,tenant_id,pid,ppid,name,path,cmdline,parent_name,parent_path,"
      "first_seen_ns,last_seen_ns,process_start_key,process_creation_filetime_100ns,"
      "process_generation_source,parent_process_start_key,parent_process_creation_filetime_100ns,"
      "parent_process_generation_source,username,domain,user_sid,logon_id,identity_source,"
      "identity_quality,exe_hash,cmdline_truncated_fields,parent_pid_state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?27) "
      "ON CONFLICT(endpoint_id,pid) DO UPDATE SET parent_pid_state=excluded.parent_pid_state,"
      "tenant_id=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns "
      "THEN excluded.tenant_id WHEN excluded.tenant_id<>'' THEN excluded.tenant_id ELSE process_cache.tenant_id END,"
      "ppid=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns "
      "THEN excluded.ppid WHEN excluded.ppid<>0 THEN excluded.ppid ELSE process_cache.ppid END,"
      "name=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns "
      "THEN excluded.name WHEN excluded.name<>'' THEN excluded.name ELSE process_cache.name END,"
      "path=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns "
      "THEN excluded.path WHEN excluded.path<>'' THEN excluded.path ELSE process_cache.path END,"
      "cmdline=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns "
      "THEN excluded.cmdline WHEN ?26 THEN excluded.cmdline ELSE process_cache.cmdline END,"
      "cmdline_truncated_fields=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns "
      "THEN excluded.cmdline_truncated_fields WHEN ?26 THEN excluded.cmdline_truncated_fields "
      "ELSE process_cache.cmdline_truncated_fields END,"
      "parent_name=CASE WHEN excluded.parent_pid_state IN (3,4) OR excluded.parent_process_generation_source='parent_generation_conflict' THEN '' WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns OR "
      "(excluded.ppid<>0 AND process_cache.ppid IS NOT excluded.ppid) OR "
      "(excluded.parent_process_start_key<>'' AND (process_cache.ppid IS NOT excluded.ppid OR "
      "process_cache.parent_process_start_key IS NOT excluded.parent_process_start_key OR "
      "process_cache.parent_process_creation_filetime_100ns IS NOT excluded.parent_process_creation_filetime_100ns)) "
      "THEN excluded.parent_name WHEN excluded.parent_name<>'' THEN excluded.parent_name ELSE process_cache.parent_name END,"
      "parent_path=CASE WHEN excluded.parent_pid_state IN (3,4) OR excluded.parent_process_generation_source='parent_generation_conflict' THEN '' WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns OR "
      "(excluded.ppid<>0 AND process_cache.ppid IS NOT excluded.ppid) OR "
      "(excluded.parent_process_start_key<>'' AND (process_cache.ppid IS NOT excluded.ppid OR "
      "process_cache.parent_process_start_key IS NOT excluded.parent_process_start_key OR "
      "process_cache.parent_process_creation_filetime_100ns IS NOT excluded.parent_process_creation_filetime_100ns)) "
      "THEN excluded.parent_path WHEN excluded.parent_path<>'' THEN excluded.parent_path ELSE process_cache.parent_path END,"
      "first_seen_ns=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns "
      "THEN excluded.first_seen_ns ELSE MIN(process_cache.first_seen_ns,excluded.first_seen_ns) END,"
      "last_seen_ns=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns "
      "THEN excluded.last_seen_ns ELSE MAX(process_cache.last_seen_ns,excluded.last_seen_ns) END,"
      "process_start_key=excluded.process_start_key,"
      "process_creation_filetime_100ns=excluded.process_creation_filetime_100ns,"
      "process_generation_source=CASE WHEN excluded.process_generation_source<>'' THEN "
      "excluded.process_generation_source ELSE process_cache.process_generation_source END,"
      "parent_process_start_key=CASE WHEN excluded.parent_pid_state IN (3,4) THEN '' WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns OR "
      "(excluded.ppid<>0 AND process_cache.ppid IS NOT excluded.ppid) OR "
      "excluded.parent_process_start_key<>'' THEN excluded.parent_process_start_key ELSE process_cache.parent_process_start_key END,"
      "parent_process_creation_filetime_100ns=CASE WHEN excluded.parent_pid_state IN (3,4) THEN '' WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns OR "
      "(excluded.ppid<>0 AND process_cache.ppid IS NOT excluded.ppid) OR "
      "excluded.parent_process_start_key<>'' THEN excluded.parent_process_creation_filetime_100ns ELSE process_cache.parent_process_creation_filetime_100ns END,"
      "parent_process_generation_source=CASE WHEN excluded.parent_pid_state IN (3,4) THEN '' WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns OR "
      "(excluded.ppid<>0 AND process_cache.ppid IS NOT excluded.ppid) OR "
      "excluded.parent_process_start_key<>'' OR excluded.parent_process_generation_source='parent_generation_conflict' THEN excluded.parent_process_generation_source ELSE process_cache.parent_process_generation_source END,"
      "username=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns THEN excluded.username WHEN excluded.username<>'' THEN excluded.username ELSE process_cache.username END,"
      "domain=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns THEN excluded.domain WHEN excluded.domain<>'' THEN excluded.domain ELSE process_cache.domain END,"
      "user_sid=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns THEN excluded.user_sid WHEN excluded.user_sid<>'' THEN excluded.user_sid ELSE process_cache.user_sid END,"
      "logon_id=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns THEN excluded.logon_id WHEN excluded.logon_id<>'' THEN excluded.logon_id ELSE process_cache.logon_id END,"
      "identity_source=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns THEN excluded.identity_source WHEN excluded.identity_source<>'' THEN excluded.identity_source ELSE process_cache.identity_source END,"
      "identity_quality=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns THEN excluded.identity_quality WHEN excluded.identity_quality<>'' THEN excluded.identity_quality ELSE process_cache.identity_quality END,"
      "exe_hash=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns THEN excluded.exe_hash WHEN excluded.exe_hash<>'' THEN excluded.exe_hash ELSE process_cache.exe_hash END "
      "WHERE process_cache.process_start_key IS NULL OR process_cache.process_start_key='' OR "
      "process_cache.process_creation_filetime_100ns IS NULL OR "
      "process_cache.process_creation_filetime_100ns='' OR "
      "(process_cache.process_start_key=excluded.process_start_key AND "
      "process_cache.process_creation_filetime_100ns=excluded.process_creation_filetime_100ns) OR "
      "excluded.last_seen_ns>process_cache.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare process_cache failed");
    return -1;
  }
  int64_t ts = record_time_ns(r);
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->tenant_id);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)durable_ppid);
  bind_text(st, 5, r->process_name);
  bind_text(st, 6, r->exe_path);
  bind_text(st, 7, r->cmdline);
  if (durable_parent_state == EDR_PARENT_PID_CONFLICT || durable_parent_state == EDR_PARENT_PID_INVALID) {
    parent_known = 0;
    parent_start_key[0] = parent_creation[0] = '\0';
  }
  /* Parent display and generation must come from one child-birth snapshot.
   * Never persist a newly recomputed tuple beside stale fields carried by an
   * earlier record revision. */
  bind_text(st, 8, durable_parent_state != EDR_PARENT_PID_CONFLICT && durable_parent_state != EDR_PARENT_PID_INVALID ? (parent_known ? parent_snapshot.process_name : r->parent_name) : "");
  bind_text(st, 9, durable_parent_state != EDR_PARENT_PID_CONFLICT && durable_parent_state != EDR_PARENT_PID_INVALID ? (parent_known ? parent_snapshot.exe_path : r->parent_path) : "");
  sqlite3_bind_int64(st, 10, (sqlite3_int64)ts);
  sqlite3_bind_int64(st, 11, (sqlite3_int64)ts);
  bind_text(st, 12, start_key);
  bind_text(st, 13, creation);
  bind_text(st, 14, record_process_generation_source(r));
  bind_text(st, 15, parent_start_key);
  bind_text(st, 16, parent_creation);
  bind_text(st, 17, strcmp(r->parent_resolution_source, "parent_generation_conflict") == 0
                        ? "parent_generation_conflict"
                        : parent_known ? record_parent_generation_source(r) : "");
  bind_text(st, 18, preserve_stronger_identity ? "" : r->username);
  bind_text(st, 19, preserve_stronger_identity ? "" : r->domain);
  bind_text(st, 20, preserve_stronger_identity ? "" : r->user_sid);
  bind_text(st, 21, preserve_stronger_identity ? "" : r->logon_id);
  bind_text(st, 22, preserve_stronger_identity ? "" : r->identity_source);
  bind_text(st, 23, preserve_stronger_identity ? "" : r->identity_quality);
  bind_text(st, 24, r->exe_hash);
  bind_text(st, 25, command_fields);
  sqlite3_bind_int(st, 26, replace_command);
  sqlite3_bind_int(st, 27, durable_parent_state);
  int rc = sqlite3_step(st);
  if (rc != SQLITE_DONE) {
    set_error("upsert process_cache failed");
  }
  sqlite3_finalize(st);
  return rc == SQLITE_DONE ? 0 : -1;
}

static int upsert_file_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r || (!r->file_path[0] && !r->exe_path[0])) {
    return 0;
  }
  const char *sql =
      "INSERT INTO file_evidence(endpoint_id,path,sha256,pid,last_seen_ns) VALUES(?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,path) DO UPDATE SET sha256=excluded.sha256,pid=excluded.pid,"
      "last_seen_ns=excluded.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare file_evidence failed");
    return -1;
  }
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->file_path[0] ? r->file_path : r->exe_path);
  bind_text(st, 3, r->exe_hash);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)record_time_ns(r));
  int rc = sqlite3_step(st);
  if (rc != SQLITE_DONE) {
    set_error("upsert file_evidence failed");
  }
  sqlite3_finalize(st);
  return rc == SQLITE_DONE ? 0 : -1;
}

static int upsert_network_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r || (!r->net_dst[0] && !r->dns_query[0])) {
    return 0;
  }
  const char *sql =
      "INSERT INTO network_ioc(endpoint_id,remote_ip,remote_url,dst_port,pid,last_seen_ns) "
      "VALUES(?,?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,remote_ip,remote_url,dst_port,pid) DO UPDATE SET "
      "last_seen_ns=excluded.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare network_ioc failed");
    return -1;
  }
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->net_dst);
  bind_text(st, 3, r->dns_query);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)r->net_dport);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 6, (sqlite3_int64)record_time_ns(r));
  int rc = sqlite3_step(st);
  if (rc != SQLITE_DONE) {
    set_error("upsert network_ioc failed");
  }
  sqlite3_finalize(st);
  return rc == SQLITE_DONE ? 0 : -1;
}

static int upsert_registry_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r || !r->reg_key_path[0]) {
    return 0;
  }
  const char *sql =
      "INSERT INTO registry_evidence(endpoint_id,key_path,value_name,op,pid,last_seen_ns) "
      "VALUES(?,?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,key_path,value_name,op,pid) DO UPDATE SET last_seen_ns=excluded.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare registry_evidence failed");
    return -1;
  }
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->reg_key_path);
  bind_text(st, 3, r->reg_value_name);
  bind_text(st, 4, r->reg_op);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 6, (sqlite3_int64)record_time_ns(r));
  int rc = sqlite3_step(st);
  if (rc != SQLITE_DONE) {
    set_error("upsert registry_evidence failed");
  }
  sqlite3_finalize(st);
  return rc == SQLITE_DONE ? 0 : -1;
}

static int manifest_utf8_bytes_valid(const char *text, size_t length) {
  const unsigned char *p = (const unsigned char *)text;
  const unsigned char *end;
  if (!text && length != 0u) return 0;
  end = p + length;
  while (p < end) {
    unsigned char c = *p++;
    if (c == 0u) return 0;
    if (c <= 0x7fu) continue;
    if (c >= 0xc2u && c <= 0xdfu) {
      if ((size_t)(end - p) < 1u || (p[0] & 0xc0u) != 0x80u) return 0;
      p += 1;
    } else if (c >= 0xe0u && c <= 0xefu) {
      if ((size_t)(end - p) < 2u || (p[0] & 0xc0u) != 0x80u ||
          (p[1] & 0xc0u) != 0x80u ||
          (c == 0xe0u && p[0] < 0xa0u) || (c == 0xedu && p[0] > 0x9fu)) return 0;
      p += 2;
    } else if (c >= 0xf0u && c <= 0xf4u) {
      if ((size_t)(end - p) < 3u || (p[0] & 0xc0u) != 0x80u ||
          (p[1] & 0xc0u) != 0x80u ||
          (p[2] & 0xc0u) != 0x80u || (c == 0xf0u && p[0] < 0x90u) ||
          (c == 0xf4u && p[0] > 0x8fu)) return 0;
      p += 3;
    } else {
      return 0;
    }
  }
  return 1;
}

static int manifest_utf8_valid(const char *text) {
  const char *value = text ? text : "";
  return manifest_utf8_bytes_valid(value, strlen(value));
}

static cJSON *manifest_create_object(void) {
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  if (s_test_manifest_allocation_failures) {
    s_test_manifest_allocation_failures--;
    return NULL;
  }
#endif
  return cJSON_CreateObject();
}

static void manifest_rejected(const char *reason) {
  s_status.manifest_rejections++;
  set_error(reason ? reason : "context manifest rejected");
}

static int manifest_add_text(cJSON *object, const char *name, const char *value) {
  if (!object || !name || !manifest_utf8_valid(value)) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_INVALID;
    return 0;
  }
  if (!cJSON_AddStringToObject(object, name, value ? value : "")) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE;
    return 0;
  }
  return 1;
}

/* cJSON's number representation is a double.  Preserve source event times
 * and FILETIME-derived values exactly by attaching trusted decimal digits as
 * a cJSON raw number, while cJSON still owns all JSON structure/escaping. */
static int manifest_add_i64(cJSON *object, const char *name, int64_t value) {
  char decimal[32];
  int written;
  cJSON *number;
  if (!object || !name) return 0;
  written = snprintf(decimal, sizeof(decimal), "%lld", (long long)value);
  if (written < 0 || (size_t)written >= sizeof(decimal)) return 0;
  number = cJSON_CreateRaw(decimal);
  if (!number || !cJSON_AddItemToObject(object, name, number)) {
    cJSON_Delete(number);
    s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE;
    return 0;
  }
  return 1;
}

static int manifest_add_u64(cJSON *object, const char *name, uint64_t value) {
  char decimal[32];
  int written;
  cJSON *number;
  if (!object || !name) return 0;
  written = snprintf(decimal, sizeof(decimal), "%llu", (unsigned long long)value);
  if (written < 0 || (size_t)written >= sizeof(decimal)) return 0;
  number = cJSON_CreateRaw(decimal);
  if (!number || !cJSON_AddItemToObject(object, name, number)) {
    cJSON_Delete(number);
    s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE;
    return 0;
  }
  return 1;
}

/* Process generation is an exact identifier, not a JavaScript number.  Emit
 * it as canonical decimal text so every consumer preserves all 64 bits. */
static int manifest_add_u64_text(cJSON *object, const char *name, uint64_t value) {
  char decimal[32];
  int written = snprintf(decimal, sizeof(decimal), "%llu", (unsigned long long)value);
  return written >= 0 && (size_t)written < sizeof(decimal) &&
         manifest_add_text(object, name, decimal);
}

static int manifest_finish(cJSON *root, char **out) {
  char *printed;
  if (!root || !out) {
    manifest_rejected("context manifest missing output");
    return -1;
  }
  *out = NULL;
  printed = cJSON_PrintUnformatted(root);
  if (!printed || strlen(printed) > EDR_EVIDENCE_MANIFEST_MAX_BYTES) {
    s_persistence_failure = printed ? EDR_EVIDENCE_FAILURE_INVALID : EDR_EVIDENCE_FAILURE_RESOURCE;
    if (printed) cJSON_free(printed);
    manifest_rejected("context manifest allocation or bounded-size failure");
    return -1;
  }
  *out = printed;
  return 0;
}

static int manifest_add_candidate_evidence(cJSON *root,
                                           const EdrBehaviorRecord *r) {
  cJSON *command = NULL;
  cJSON *identity = NULL;
  cJSON *artifact = NULL;
  cJSON *context = NULL;
  cJSON *evidence = NULL;
  cJSON *file = NULL;
  cJSON *signature = NULL;
  cJSON *signature_copy = NULL;
  char normalized[EDR_BR_STR_LONG];
  char script_path[EDR_BR_STR_LONG];
  int normalized_truncated;
  int ok;
  if (!root || !r) return 0;
  normalized_truncated = edr_p0_normalize_command_for_evidence(
      r->cmdline, normalized, sizeof(normalized));
  (void)edr_p0_extract_script_path(r->cmdline, script_path,
                                   sizeof(script_path));
  command = cJSON_CreateObject();
  identity = cJSON_CreateObject();
  artifact = cJSON_CreateObject();
  if (!command || !identity || !artifact) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE;
    goto fail;
  }
  ok = manifest_add_text(command, "raw", r->cmdline) &&
       manifest_add_text(command, "normalized", normalized) &&
       cJSON_AddBoolToObject(command, "normalized_truncated",
                             normalized_truncated) != NULL &&
       manifest_add_text(command, "script_path", script_path) &&
       manifest_add_text(identity, "username", r->username) &&
       manifest_add_text(identity, "domain", r->domain) &&
       manifest_add_text(identity, "user_sid", r->user_sid) &&
       manifest_add_text(identity, "logon_id", r->logon_id) &&
       manifest_add_text(identity, "source", r->identity_source) &&
       manifest_add_text(identity, "quality", r->identity_quality) &&
       manifest_add_text(artifact, "path", r->exe_path) &&
       manifest_add_text(artifact, "sha256", r->exe_hash);
  if (!ok) goto fail;
  if (r->detection_context[0]) {
    context = cJSON_Parse(r->detection_context);
    evidence = context ? cJSON_GetObjectItemCaseSensitive(context, "evidence") : NULL;
    signature = cJSON_IsObject(evidence)
                    ? cJSON_GetObjectItemCaseSensitive(evidence, "signature")
                    : NULL;
    if (!cJSON_IsObject(signature)) {
      file = context ? cJSON_GetObjectItemCaseSensitive(context, "file") : NULL;
      signature = cJSON_IsObject(file)
                      ? cJSON_GetObjectItemCaseSensitive(file,
                                                         "signature_trust")
                      : NULL;
    }
    if (!cJSON_IsObject(signature)) {
      signature = context ? cJSON_GetObjectItemCaseSensitive(
                                context, "signature_trust")
                          : NULL;
    }
  }
  if (cJSON_IsObject(signature)) {
    signature_copy = cJSON_Duplicate(signature, 1);
    if (!signature_copy ||
        !cJSON_AddItemToObject(artifact, "signature", signature_copy)) {
      cJSON_Delete(signature_copy);
      goto fail;
    }
    signature_copy = NULL;
  } else if (!cJSON_AddNullToObject(artifact, "signature")) {
    goto fail;
  }
  if (!cJSON_AddItemToObject(root, "command", command)) goto fail;
  command = NULL;
  if (!cJSON_AddItemToObject(root, "identity", identity)) goto fail;
  identity = NULL;
  if (!cJSON_AddItemToObject(root, "artifact", artifact)) goto fail;
  artifact = NULL;
  cJSON_Delete(context);
  return 1;

fail:
  cJSON_Delete(command);
  cJSON_Delete(identity);
  cJSON_Delete(artifact);
  cJSON_Delete(context);
  return 0;
}

#if defined(EDR_HAVE_SQLITE)
#define EDR_EVIDENCE_SOURCE_EVENT_ALIASES_MAX 16u

static int manifest_array_add_unique_source(cJSON *array, const char *value,
                                            uint32_t *count) {
  cJSON *item;
  if (!array || !count || !value || !value[0]) return 1;
  if (!manifest_utf8_valid(value)) { s_persistence_failure = EDR_EVIDENCE_FAILURE_INVALID; return 0; }
  cJSON_ArrayForEach(item, array) {
    if (cJSON_IsString(item) && item->valuestring &&
        strcmp(item->valuestring, value) == 0) {
      return 1;
    }
  }
  if (*count >= EDR_EVIDENCE_SOURCE_EVENT_ALIASES_MAX) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_INVALID; return 0;
  }
  item = cJSON_CreateString(value);
  if (!item || !cJSON_AddItemToArray(array, item)) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE;
    cJSON_Delete(item);
    return 0;
  }
  (*count)++;
  return 1;
}

/* The candidate bundle is mutable, so retain every bounded provider source
 * id before replacing its latest enrichment view. This reuses the existing
 * artifact row and transaction rather than creating another persistence
 * path or charging extra cache writes. */
static int manifest_add_source_event_aliases(cJSON *root, const char *candidate_id,
                                             const char *current_event_id) {
  cJSON *aliases = NULL;
  sqlite3_stmt *st = NULL;
  uint32_t count = 0u;
  int ok = 1;
  aliases = cJSON_CreateArray();
  if (!root || !aliases || !candidate_id || !candidate_id[0]) {
    if (!aliases) s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE;
    cJSON_Delete(aliases);
    return 0;
  }
  if (s_db && sqlite3_prepare_v2(
                  s_db,
                  "SELECT manifest_json FROM artifacts WHERE candidate_id=? "
                  "AND artifact_type='p0_context_bundle' LIMIT 1;",
                  -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_text(st, 1, candidate_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
      const char *raw = (const char *)sqlite3_column_text(st, 0);
      cJSON *previous = cJSON_Parse(raw ? raw : "");
      if (!previous) {
        ok = 0;
      } else {
        cJSON *previous_aliases =
            cJSON_GetObjectItemCaseSensitive(previous, "source_event_ids");
        if (cJSON_IsArray(previous_aliases)) {
          cJSON *item;
          cJSON_ArrayForEach(item, previous_aliases) {
            if (!cJSON_IsString(item) || !item->valuestring ||
                !manifest_array_add_unique_source(aliases, item->valuestring,
                                                  &count)) {
              ok = 0;
              break;
            }
          }
        } else {
          cJSON *previous_source =
              cJSON_GetObjectItemCaseSensitive(previous, "source_event_id");
          if (cJSON_IsString(previous_source) && previous_source->valuestring) {
            ok = manifest_array_add_unique_source(
                aliases, previous_source->valuestring, &count);
          }
        }
        cJSON_Delete(previous);
      }
    }
    sqlite3_finalize(st);
  } else if (s_db) {
    s_persistence_failure = sqlite3_errcode(s_db) == SQLITE_NOMEM ?
        EDR_EVIDENCE_FAILURE_RESOURCE : EDR_EVIDENCE_FAILURE_STORAGE;
    cJSON_Delete(aliases);
    return 0;
  }
  if (ok) {
    ok = manifest_array_add_unique_source(aliases, current_event_id, &count);
  }
  if (!ok || !cJSON_AddItemToObject(root, "source_event_ids", aliases)) {
    cJSON_Delete(aliases);
    return 0;
  }
  return 1;
}
#endif

static int build_context_manifest_json(const EdrBehaviorRecord *r, const char *candidate_id,
                                       uint32_t pre_count, int64_t post_until_ns,
                                       char **out) {
  cJSON *root = NULL;
  cJSON *context = NULL;
  EvidenceProcessGeneration generation;
  ProcessTreeEntry parent_snapshot;
  int generation_known, parent_known;
  const char *generation_source;
  int ok;
  int rc = -1;
  if (!r || !out) {
    manifest_rejected("context manifest missing source record");
    return -1;
  }
  generation_known = record_process_generation(r, &generation);
  generation_source = generation_known ? record_process_generation_source(r) : "";
  parent_known = record_parent_snapshot(r, &parent_snapshot);
  s_persistence_failure = EDR_EVIDENCE_FAILURE_UNCLASSIFIED;
  root = manifest_create_object();
  if (!root) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE;
    manifest_rejected("context manifest allocation failed");
    return -1;
  }
  context = root ? cJSON_AddArrayToObject(root, "context") : NULL;
  ok = root && context &&
#if defined(EDR_HAVE_SQLITE)
       manifest_add_source_event_aliases(root, candidate_id, r->event_id) &&
#endif
       manifest_add_text(root, "schema", "p0_context_bundle.v1") &&
       manifest_add_text(root, "candidate_id", candidate_id) &&
       manifest_add_text(root, "source_event_id", r->event_id) &&
       manifest_add_candidate_evidence(root, r) &&
       manifest_add_text(root, "endpoint_id", r->endpoint_id) &&
       manifest_add_i64(root, "event_time_ns", record_time_ns(r)) &&
       manifest_add_u64(root, "pid", r->pid) &&
       manifest_add_u64(root, "ppid", r->ppid) &&
       manifest_add_u64(root, "parent_pid_state", edr_parent_pid_effective_state(r->ppid, r->parent_pid_state)) &&
       manifest_add_u64_text(root, "parent_process_start_key", parent_known ? parent_snapshot.process_start_key : 0u) &&
       manifest_add_u64_text(root, "parent_creation_filetime_100ns", parent_known ? parent_snapshot.creation_filetime_100ns : 0u) &&
       manifest_add_text(root, "parent_process_generation_source", parent_known ? record_parent_generation_source(r) : "") &&
       manifest_add_text(root, "parent_process_name", parent_known ? parent_snapshot.process_name : "") &&
       manifest_add_text(root, "parent_exe_path", parent_known ? parent_snapshot.exe_path : "") &&
       manifest_add_u64_text(root, "process_start_key",
                             generation_known ? generation.process_start_key : 0u) &&
       manifest_add_u64_text(root, "process_creation_filetime_100ns",
                             generation_known ? generation.creation_filetime_100ns : 0u) &&
       manifest_add_text(root, "process_generation_source", generation_source) &&
       manifest_add_text(root, "source_completeness", r->source_completeness) &&
       manifest_add_text(root, "source_truncated_fields", r->source_truncated_fields) &&
       manifest_add_u64(root, "type", (uint32_t)r->type) &&
       manifest_add_text(root, "process_name", r->process_name) &&
       manifest_add_text(root, "path", r->file_path[0] ? r->file_path : r->exe_path) &&
       manifest_add_text(root, "remote_ip", r->net_dst) &&
       manifest_add_u64(root, "remote_port", r->net_dport) &&
       manifest_add_u64(root, "pre_window_s", evidence_context_window_s()) &&
       manifest_add_u64(root, "post_window_s", evidence_context_window_s()) &&
       manifest_add_u64(root, "pre_context_count", pre_count) &&
       manifest_add_i64(root, "post_until_ns", post_until_ns);
  int64_t cutoff = record_time_ns(r) - (int64_t)evidence_context_window_s() * 1000000000LL;
  uint32_t pos = s_context_ring_pos;
  uint32_t added = 0u;
  for (uint32_t i = 0u; ok && i < EDR_EVIDENCE_CONTEXT_RING_SLOTS && added < 32u; ++i) {
    const RingSlot *s = &s_context_ring[(pos + EDR_EVIDENCE_CONTEXT_RING_SLOTS - 1u - i) %
                                        EDR_EVIDENCE_CONTEXT_RING_SLOTS];
    cJSON *item;
    if (!s->used || s->event_time_ns < cutoff ||
        s->event_time_ns > record_time_ns(r) || !ring_related_to_record(s, r)) {
      continue;
    }
    item = cJSON_CreateObject();
    ok = item &&
         manifest_add_i64(item, "event_time_ns", s->event_time_ns) &&
         manifest_add_u64(item, "type", s->type) &&
         manifest_add_u64(item, "pid", s->pid) &&
         manifest_add_u64(item, "ppid", s->ppid) &&
         manifest_add_u64(item, "parent_pid_state", s->parent_pid_state) &&
         manifest_add_u64_text(item, "process_start_key", s->generation.process_start_key) &&
         manifest_add_u64_text(item, "process_creation_filetime_100ns",
                               s->generation.creation_filetime_100ns) &&
         manifest_add_text(item, "process_generation_source",
                           s->process_generation_source) &&
         manifest_add_text(item, "source_completeness", s->source_completeness) &&
         manifest_add_text(item, "source_truncated_fields", s->source_truncated_fields) &&
         manifest_add_u64_text(item, "parent_process_start_key",
                               s->parent_generation.process_start_key) &&
         manifest_add_u64_text(item, "parent_creation_filetime_100ns",
                               s->parent_generation.creation_filetime_100ns) &&
         manifest_add_text(item, "parent_process_generation_source",
                           s->parent_process_generation_source) &&
         manifest_add_text(item, "endpoint_id", s->endpoint_id) &&
         manifest_add_text(item, "process_name", s->process_name) &&
         manifest_add_text(item, "file_path", s->file_path) &&
         manifest_add_text(item, "remote_ip", s->net_dst) &&
         manifest_add_u64(item, "remote_port", s->net_dport) &&
         cJSON_AddItemToArray(context, item);
    if (!ok) {
      cJSON_Delete(item);
      break;
    }
    added++;
  }
  if (ok) {
    uint32_t omitted = pre_count > added ? pre_count - added : 0u;
    ok = manifest_add_u64(root, "serialized_context_count", added) &&
         manifest_add_u64(root, "omitted_context_count", omitted) &&
         cJSON_AddBoolToObject(root, "context_truncated", omitted != 0u);
  }
  if (!ok) {
    manifest_rejected("context manifest allocation or UTF-8 validation failed");
  } else {
    rc = manifest_finish(root, out);
  }
  cJSON_Delete(root);
  return rc;
}

static int build_post_context_manifest_template_json(const EdrBehaviorRecord *r,
                                                     char **out) {
  cJSON *root = NULL;
  EvidenceProcessGeneration generation;
  ProcessTreeEntry parent_snapshot;
  int generation_known;
  int parent_generation_known;
  const char *generation_source;
  int ok;
  int rc = -1;
  if (!r || !out) {
    manifest_rejected("post-context manifest missing source record");
    return -1;
  }
  generation_known = record_process_generation(r, &generation);
  parent_generation_known = record_parent_snapshot(r, &parent_snapshot);
  generation_source = generation_known ? record_process_generation_source(r) : "";
  s_persistence_failure = EDR_EVIDENCE_FAILURE_UNCLASSIFIED;
  root = manifest_create_object();
  if (!root) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE;
    manifest_rejected("context manifest allocation failed");
    return -1;
  }
  ok = root &&
       manifest_add_text(root, "schema", "p0_post_context_event.v1") &&
       cJSON_AddNullToObject(root, "candidate_id") &&
       manifest_add_text(root, "source_event_id", r->event_id) &&
       manifest_add_i64(root, "event_time_ns", record_time_ns(r)) &&
       manifest_add_u64(root, "type", (uint32_t)r->type) &&
       manifest_add_u64(root, "pid", r->pid) &&
       manifest_add_u64(root, "ppid", r->ppid) &&
       manifest_add_u64(root, "parent_pid_state", edr_parent_pid_effective_state(r->ppid,r->parent_pid_state)) &&
       manifest_add_u64_text(root, "process_start_key",
                             generation_known ? generation.process_start_key : 0u) &&
       manifest_add_u64_text(root, "process_creation_filetime_100ns",
                             generation_known ? generation.creation_filetime_100ns : 0u) &&
       manifest_add_text(root, "process_generation_source", generation_source) &&
       manifest_add_u64_text(root, "parent_process_start_key",
                             parent_generation_known ? parent_snapshot.process_start_key : 0u) &&
       manifest_add_u64_text(root, "parent_creation_filetime_100ns",
                             parent_generation_known ? parent_snapshot.creation_filetime_100ns : 0u) &&
       manifest_add_text(root, "parent_process_generation_source",
                          parent_generation_known ? record_parent_generation_source(r) : "") &&
       manifest_add_text(root, "parent_process_name", parent_generation_known ? parent_snapshot.process_name : "") &&
       manifest_add_text(root, "parent_exe_path", parent_generation_known ? parent_snapshot.exe_path : "") &&
       manifest_add_text(root, "source_completeness", r->source_completeness) &&
       manifest_add_text(root, "source_truncated_fields", r->source_truncated_fields) &&
       manifest_add_text(root, "process_name", r->process_name) &&
       manifest_add_text(root, "path", r->file_path[0] ? r->file_path : r->exe_path) &&
       manifest_add_text(root, "dns_query", r->dns_query) &&
       manifest_add_text(root, "remote_ip", r->net_dst) &&
       manifest_add_u64(root, "remote_port", r->net_dport) &&
       manifest_add_text(root, "registry_key", r->reg_key_path) &&
       manifest_add_text(root, "registry_value", r->reg_value_name) &&
       manifest_add_text(root, "registry_op", r->reg_op);
  if (!ok) {
    manifest_rejected("post-context manifest allocation or UTF-8 validation failed");
  } else {
    rc = manifest_finish(root, out);
  }
  cJSON_Delete(root);
  return rc;
}

static void artifact_source_identity_for(const EdrBehaviorRecord *r, char *out, size_t cap) {
  EdrSha256Ctx ctx;
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  static const char hex[] = "0123456789abcdef";
  if (!out || cap == 0u) return;
  out[0] = '\0';
  if (!r || cap < 65u) return;
  if (!r->event_id[0]) {
    /* candidate_signal_for is already the module's length-delimited semantic
     * commitment.  Reuse it rather than adding a second normalizer. */
    candidate_signal_for(r, out, cap);
    return;
  }
  edr_sha256_init(&ctx);
  candidate_digest_text(&ctx, "edr-local-evidence-artifact-source-id-v1");
  candidate_digest_text(&ctx, r->event_id);
  edr_sha256_final(&ctx, digest);
  for (size_t i = 0u; i < sizeof(digest); ++i) {
    out[i * 2u] = hex[digest[i] >> 4u];
    out[i * 2u + 1u] = hex[digest[i] & 0x0fu];
  }
  out[64] = '\0';
}

static int context_fact_id_for_identity(const char *endpoint_id,
                                        const char *tenant_id,
                                        const char *source_identity,
                                        const char *manifest_template,
                                        char out[65]) {
  EdrSha256Ctx ctx;
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  static const char hex[] = "0123456789abcdef";
  if (!source_identity || !source_identity[0] || !manifest_template || !out) return -1;
  edr_sha256_init(&ctx);
  candidate_digest_text(&ctx, "edr-local-evidence-context-fact-v1");
  candidate_digest_text(&ctx, endpoint_id ? endpoint_id : "");
  candidate_digest_text(&ctx, tenant_id ? tenant_id : "");
  candidate_digest_text(&ctx, source_identity);
  candidate_digest_text(&ctx, manifest_template);
  edr_sha256_final(&ctx, digest);
  for (size_t i = 0u; i < sizeof(digest); ++i) {
    out[i * 2u] = hex[digest[i] >> 4u];
    out[i * 2u + 1u] = hex[digest[i] & 0x0fu];
  }
  out[64] = '\0';
  return 0;
}

static int context_fact_id_for(const EdrBehaviorRecord *r,
                               const char *manifest_template, char out[65]) {
  char source_identity[65];
  if (!r || !out) return -1;
  artifact_source_identity_for(r, source_identity, sizeof(source_identity));
  return context_fact_id_for_identity(r->endpoint_id, r->tenant_id, source_identity,
                                      manifest_template, out);
}

static char *context_candidate_id_json(const char *candidate_id) {
  cJSON *value;
  char *json;
  if (!candidate_id || !candidate_id[0] || !manifest_utf8_valid(candidate_id)) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_INVALID;
    return NULL;
  }
  value = cJSON_CreateString(candidate_id);
  if (!value) { s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE; return NULL; }
  json = cJSON_PrintUnformatted(value);
  if (!json) s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE;
  cJSON_Delete(value);
  return json;
}

static int artifact_id_for(const EdrBehaviorRecord *r, const char *candidate_id,
                           const char *artifact_type, char *out, size_t out_cap) {
  char source_identity[65];
  const char *type_name = artifact_type && artifact_type[0] ? artifact_type : "artifact";
  int written;
  if (!candidate_id || !candidate_id[0] || !out || out_cap == 0u) {
    return -1;
  }
  /* The candidate bundle is a mutable representation of one candidate, not
   * another source event.  Give its UPSERT a candidate-stable artifact id so
   * enrichment replaces the manifest instead of accumulating sibling bundles. */
  if (strcmp(type_name, "p0_context_bundle") == 0) {
    copy_s(source_identity, sizeof(source_identity), "candidate");
  } else {
    artifact_source_identity_for(r, source_identity, sizeof(source_identity));
  }
  written = snprintf(out, out_cap, "%s:%s:%s", candidate_id, type_name, source_identity);
  if (!source_identity[0] || written < 0 || (size_t)written >= out_cap) {
    set_error("artifact source identity unavailable");
    return -1;
  }
  return 0;
}

static int insert_artifact_sqlite(const EdrBehaviorRecord *r, const char *candidate_id,
                                  const char *artifact_type, const char *path,
                                  const char *sha256, const char *manifest_json,
                                  const char *upload_status) {
  if (!s_db || !candidate_id || !candidate_id[0]) {
    return -1;
  }
  s_persistence_failure = EDR_EVIDENCE_FAILURE_STORAGE;
  if (!sqlite_physical_write_allow(manifest_json ? strlen(manifest_json) : 0u)) return -1;
  const char *sql =
      "INSERT INTO artifacts(artifact_id,endpoint_id,tenant_id,candidate_id,artifact_type,path,"
      "sha256,manifest_json,created_ns,upload_status,minio_key) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
      "ON CONFLICT(artifact_id) DO UPDATE SET upload_status=excluded.upload_status,"
      "manifest_json=excluded.manifest_json,created_ns=excluded.created_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare artifacts failed");
    return -1;
  }
  char artifact_id[384];
  if (artifact_id_for(r, candidate_id, artifact_type, artifact_id,
                      sizeof(artifact_id)) != 0) {
    sqlite3_finalize(st);
    return -1;
  }
  bind_text(st, 1, artifact_id);
  bind_text(st, 2, r ? r->endpoint_id : "");
  bind_text(st, 3, r ? r->tenant_id : "");
  bind_text(st, 4, candidate_id);
  bind_text(st, 5, artifact_type);
  bind_text(st, 6, path);
  bind_text(st, 7, sha256);
  bind_text(st, 8, manifest_json);
  sqlite3_bind_int64(st, 9, (sqlite3_int64)now_unix_ns());
  bind_text(st, 10, upload_status ? upload_status : "local");
  bind_text(st, 11, "");
  int rc = sqlite3_step(st);
  if (rc != SQLITE_DONE) {
    set_error("insert artifacts failed");
  }
  sqlite3_finalize(st);
  return rc == SQLITE_DONE ? 0 : -1;
}

typedef struct {
  uint32_t candidate_index;
  char artifact_id[384];
  char *candidate_id_json;
} PreparedContextRef;

typedef struct {
  char fact_id[65];
  char *manifest_template;
  PreparedContextRef *refs;
  uint32_t ref_count;
  uint32_t fact_insert;
} PreparedContextArtifacts;

static void sqlite_free_prepared_context_artifacts(PreparedContextArtifacts *prepared) {
  if (!prepared) return;
  for (uint32_t i = 0u; i < prepared->ref_count; ++i) {
    cJSON_free(prepared->refs[i].candidate_id_json);
  }
  cJSON_free(prepared->manifest_template);
  free(prepared->refs);
  memset(prepared, 0, sizeof(*prepared));
}

static int sqlite_prepare_context_fact(const EdrBehaviorRecord *r,
                                       PreparedContextArtifacts *prepared) {
  static const char sql[] =
      "SELECT manifest_template_json FROM context_facts WHERE fact_id=?;";
  sqlite3_stmt *st = NULL;
  int step;
  if (!s_db || !r || !prepared ||
      build_post_context_manifest_template_json(r,
                                                &prepared->manifest_template) != 0 ||
      context_fact_id_for(r, prepared->manifest_template,
                          prepared->fact_id) != 0) {
    return -1;
  }
  s_persistence_failure = EDR_EVIDENCE_FAILURE_STORAGE;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare context fact replay lookup failed");
    return -1;
  }
  bind_text(st, 1, prepared->fact_id);
  step = sqlite3_step(st);
  if (step == SQLITE_ROW) {
    const char *existing = (const char *)sqlite3_column_text(st, 0);
    if (!existing || strcmp(existing, prepared->manifest_template) != 0) {
      s_persistence_failure = EDR_EVIDENCE_FAILURE_INVALID;
      set_error("context fact hash collision");
      sqlite3_finalize(st);
      return -1;
    }
  } else if (step == SQLITE_DONE) {
    prepared->fact_insert = 1u;
  } else {
    set_error("read context fact replay manifest failed");
    sqlite3_finalize(st);
    return -1;
  }
  sqlite3_finalize(st);
  return 0;
}

static int sqlite_prepare_context_artifacts(const EdrBehaviorRecord *r,
                                            char candidate_ids[][160],
                                            uint32_t candidate_count,
                                            PreparedContextArtifacts *prepared) {
  sqlite3_stmt *st = NULL;
  if (!s_db || !r || !candidate_ids || candidate_count == 0u || !prepared) {
    return -1;
  }
  memset(prepared, 0, sizeof(*prepared));
  if (sqlite_prepare_context_fact(r, prepared) != 0) goto fail;
  prepared->refs = (PreparedContextRef *)calloc(
      candidate_count, sizeof(PreparedContextRef));
  if (!prepared->refs) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_RESOURCE;
    set_error("allocate post-context replay plan failed");
    goto fail;
  }
  st = edr_context_store_prepare_lookup(&s_context_store);
  if (!st) {
    set_error("prepare context reference replay lookup failed");
    goto fail;
  }
  for (uint32_t i = 0u; i < candidate_count; ++i) {
    PreparedContextRef *ref = &prepared->refs[prepared->ref_count];
    int step;
    if (!candidate_ids[i][0] ||
        artifact_id_for(r, candidate_ids[i], "post_context", ref->artifact_id,
                        sizeof(ref->artifact_id)) != 0) goto fail;
    if (edr_context_store_bind_lookup(&s_context_store, st, ref->artifact_id) != 0) goto fail;
    step = sqlite3_step(st);
    if (step == SQLITE_ROW) {
      const char *existing_candidate = (const char *)sqlite3_column_text(st, 0);
      const char *existing_fact = (const char *)sqlite3_column_text(st, 1);
      int candidate_matches = existing_candidate &&
                              strcmp(existing_candidate, candidate_ids[i]) == 0;
      int exact = candidate_matches && existing_fact &&
                  strcmp(existing_fact, prepared->fact_id) == 0;
      if (sqlite3_step(st) != SQLITE_DONE) {
        set_error("ambiguous context reference replay identity");
        goto fail;
      }
      (void)sqlite3_reset(st);
      (void)sqlite3_clear_bindings(st);
      if (exact) continue;
      if (!candidate_matches) {
        s_persistence_failure = EDR_EVIDENCE_FAILURE_INVALID;
        set_error("context reference candidate conflict");
        goto fail;
      }
    } else if (step == SQLITE_DONE) {
      (void)sqlite3_reset(st);
      (void)sqlite3_clear_bindings(st);
    } else {
      set_error("read context reference replay state failed");
      goto fail;
    }
    ref->candidate_id_json = context_candidate_id_json(candidate_ids[i]);
    if (!ref->candidate_id_json) {
      set_error("encode context reference candidate id failed");
      goto fail;
    }
    ref->candidate_index = i;
    prepared->ref_count++;
  }
  sqlite3_finalize(st);
  return 0;
fail:
  sqlite3_finalize(st);
  sqlite_free_prepared_context_artifacts(prepared);
  return -1;
}

/* Preserve all-or-none post-context attribution when one event belongs to
 * multiple live candidate windows.  A failed row cannot leave an arbitrary
 * prefix of candidates looking complete. */
static void sqlite_rollback_silent(void);
static int sqlite_commit_candidate_transaction(void);

static int sqlite_record_context_artifacts(const EdrBehaviorRecord *r,
                                           char candidate_ids[][160],
                                           const PreparedContextArtifacts *prepared) {
  sqlite3_int64 written_ns;
  if (!r || !candidate_ids || !prepared ||
      (!prepared->fact_insert && prepared->ref_count == 0u) ||
      exec_sql("BEGIN IMMEDIATE;") != 0) {
    return -1;
  }
  /* Admission can run maintenance after the fanout was prepared. A retired
   * candidate may therefore still be named by this call's saved RAM IDs even
   * though maintenance cleared its window. Recheck every changed target in
   * the write transaction before inserting either a shared fact or any ref.
   * An old retained candidate is still a valid owner; this does not promote
   * its retention policy. Reject the complete fanout if any owner is missing. */
  sqlite3_stmt *owner = NULL;
  if (sqlite3_prepare_v2(s_db,
      "SELECT 1 FROM p0_candidates WHERE candidate_id=?1 "
      "AND local_retention_state='retained' AND endpoint_id=?2 AND tenant_id=?3;",
      -1, &owner, NULL) != SQLITE_OK) {
    set_error("prepare context retained-owner validation failed");
    sqlite_rollback_silent();
    return -1;
  }
  for (uint32_t i = 0u; i < prepared->ref_count; ++i) {
    const PreparedContextRef *ref = &prepared->refs[i];
    if (ref->candidate_index >= EDR_EVIDENCE_CONTEXT_WINDOWS ||
        !candidate_ids[ref->candidate_index][0]) {
      s_persistence_failure = EDR_EVIDENCE_FAILURE_INVALID;
      set_error("context retained-owner identity unavailable; fanout rejected");
      sqlite3_finalize(owner);
      sqlite_rollback_silent();
      return -1;
    }
    int rc = sqlite3_bind_text(owner, 1, candidate_ids[ref->candidate_index], -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(owner, 2, r->endpoint_id, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(owner, 3, r->tenant_id, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_step(owner);
    if (rc != SQLITE_ROW) {
      if (rc == SQLITE_DONE) {
        s_persistence_failure = EDR_EVIDENCE_FAILURE_INVALID;
        set_error("context candidate retired or scope changed; fanout rejected");
      } else set_error("read context retained-owner validation failed");
      sqlite3_finalize(owner);
      sqlite_rollback_silent();
      return -1;
    }
    if (sqlite3_reset(owner) != SQLITE_OK || sqlite3_clear_bindings(owner) != SQLITE_OK) {
      set_error("reset context retained-owner validation failed");
      sqlite3_finalize(owner);
      sqlite_rollback_silent();
      return -1;
    }
  }
  sqlite3_finalize(owner);
  written_ns = (sqlite3_int64)now_unix_ns();
  if (prepared->fact_insert) {
    static const char fact_sql[] =
        "INSERT INTO context_facts(fact_id,endpoint_id,tenant_id,manifest_template_json,"
        "created_ns,updated_ns) VALUES(?,?,?,?,?,?);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s_db, fact_sql, -1, &st, NULL) != SQLITE_OK) {
      set_error("prepare context fact upsert failed");
      sqlite_rollback_silent();
      return -1;
    }
    bind_text(st, 1, prepared->fact_id);
    bind_text(st, 2, r->endpoint_id);
    bind_text(st, 3, r->tenant_id);
    bind_text(st, 4, prepared->manifest_template);
    sqlite3_bind_int64(st, 5, written_ns);
    sqlite3_bind_int64(st, 6, written_ns);
    if (sqlite3_step(st) != SQLITE_DONE) {
      set_error("upsert context fact failed");
      sqlite3_finalize(st);
      sqlite_rollback_silent();
      return -1;
    }
    sqlite3_finalize(st);
  }
  EdrContextWriter writer;
  if (edr_context_writer_open(&s_context_store, &writer) != 0) {
    set_error(s_context_store.error);
    sqlite_rollback_silent();
    return -1;
  }
  for (uint32_t i = 0u; i < prepared->ref_count; ++i) {
    const PreparedContextRef *ref = &prepared->refs[i];
    if (edr_context_writer_put(&writer, ref->artifact_id,
          candidate_ids[ref->candidate_index], prepared->fact_id,
          ref->candidate_id_json, written_ns, 0, "local_manifest", "") != 0) {
      set_error(s_context_store.error);
      edr_context_writer_close(&writer);
      sqlite_rollback_silent();
      return -1;
    }
  }
  edr_context_writer_close(&writer);
  if (sqlite_commit_candidate_transaction() != 0) {
    sqlite_rollback_silent();
    return -1;
  }
  return 0;
}

static int sqlite_record_budgeted_context_artifacts(const EdrBehaviorRecord *r,
                                                    char candidate_ids[][160],
                                                    uint32_t candidate_count,
                                                    int64_t ts,
                                                    EvidenceWriteClass write_class,
                                                    uint32_t *written) {
  s_persistence_failure = EDR_EVIDENCE_FAILURE_STORAGE;
  PreparedContextArtifacts prepared;
  uint32_t budget_units;
  uint32_t materialized_changes;
  uint64_t maintenance_runs;
  if (written) *written = 0u;
  if (sqlite_prepare_context_artifacts(r, candidate_ids, candidate_count,
                                       &prepared) != 0) {
    return -1;
  }
  budget_units = (prepared.fact_insert || prepared.ref_count) ? 1u : 0u;
  materialized_changes = prepared.ref_count;
  if (budget_units == 0u) {
    sqlite_free_prepared_context_artifacts(&prepared);
    return 0;
  }
  maintenance_runs = s_status.maintenance_runs;
  if (!sqlite_size_budget_allow()) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_CAPACITY;
    sqlite_free_prepared_context_artifacts(&prepared);
    return -1;
  }
  if (s_status.maintenance_runs != maintenance_runs) {
    /* Capacity maintenance may remove the last old ref and its fact after
     * preparation. Recheck before writing a ref to that fact. */
    sqlite_free_prepared_context_artifacts(&prepared);
    if (sqlite_prepare_context_artifacts(r, candidate_ids, candidate_count,
                                         &prepared) != 0) return -1;
    budget_units = (prepared.fact_insert || prepared.ref_count) ? 1u : 0u;
    materialized_changes = prepared.ref_count;
    if (budget_units == 0u) {
      sqlite_free_prepared_context_artifacts(&prepared);
      return 0;
    }
  }
  if (!sqlite_write_budget_allow(budget_units, ts, write_class)) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_WRITE_BUDGET;
    sqlite_free_prepared_context_artifacts(&prepared);
    return -1;
  }
  s_persistence_failure = EDR_EVIDENCE_FAILURE_STORAGE;
  if (sqlite_record_context_artifacts(r, candidate_ids, &prepared) != 0) {
    sqlite_write_budget_release(budget_units, ts, write_class);
    sqlite_free_prepared_context_artifacts(&prepared);
    return -1;
  }
  s_status.context_facts_written += prepared.fact_insert;
  s_status.context_refs_written += prepared.ref_count;
  if ((unsigned)r->type < EDR_LOCAL_EVIDENCE_EVENT_TYPE_BUCKETS) {
    s_status.context_ref_writes_by_event_type[(unsigned)r->type] +=
        prepared.ref_count;
  }
  if (written) *written = materialized_changes;
  sqlite_free_prepared_context_artifacts(&prepared);
  return 0;
}

static void sqlite_rollback_silent(void) {
  char *err = NULL;
  if (s_db) {
    (void)sqlite3_exec(s_db, "ROLLBACK;", NULL, NULL, &err);
  }
  sqlite3_free(err);
  s_retention_clock.pending = 0;
}

static int sqlite_commit_candidate_transaction(void) {
  int rc;
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  s_test_commit_active = 1;
#endif
  rc = exec_sql("COMMIT;");
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  s_test_commit_active = 0;
#endif
  if (rc != 0) {
    sqlite_rollback_silent();
    return -1;
  }
  sqlite_retention_clock_committed();
  return 0;
}

static const char *legacy_context_source_identity(const char *artifact_id) {
  static const char marker[] = ":post_context:";
  const char *found = NULL;
  const char *cursor = artifact_id;
  if (!artifact_id) return NULL;
  while ((cursor = strstr(cursor, marker)) != NULL) {
    found = cursor + sizeof(marker) - 1u;
    cursor = found;
  }
  if (!found || strlen(found) != 64u) return NULL;
  for (const unsigned char *p = (const unsigned char *)found; *p; ++p) {
    if (!isxdigit(*p)) return NULL;
  }
  return found;
}

/* Previously shipped databases stored one complete post-context JSON payload
 * per candidate. Normalize those rows only after every fact and edge has been
 * rebuilt in the same transaction. Reopening is therefore idempotent after a
 * success and retries the untouched legacy rows after any failure. */
static int sqlite_migrate_legacy_context_artifacts(void) {
  static const char select_sql[] =
      "SELECT a.artifact_id,a.endpoint_id,a.tenant_id,a.candidate_id,a.manifest_json,"
      "a.created_ns,a.upload_status,a.minio_key FROM artifacts a "
      "LEFT JOIN context_reference_projection r ON r.artifact_id=a.artifact_id "
      "WHERE a.artifact_type='post_context' AND "
      "(r.artifact_id IS NULL OR a.created_ns>r.created_ns) "
      "ORDER BY a.created_ns,a.artifact_id;";
  static const char fact_sql[] =
      "INSERT INTO context_facts(fact_id,endpoint_id,tenant_id,manifest_template_json,"
      "created_ns,updated_ns) VALUES(?,?,?,?,?,?) "
      "ON CONFLICT(fact_id) DO NOTHING;";
  static const char normalize_sql[] =
      "SELECT "
      "CASE WHEN json_valid(?1) THEN json_type(?1,'$') END,"
      "CASE WHEN json_valid(?1) THEN json_type(?1,'$.candidate_id') END,"
      "CASE WHEN json_valid(?1) THEN json_extract(?1,'$.candidate_id') END,"
      "CASE WHEN json_valid(?1) THEN "
      "json_set(?1,'$.candidate_id',json('null')) END;";
  static const char fact_lookup_sql[] =
      "SELECT endpoint_id,tenant_id,manifest_template_json "
      "FROM context_facts WHERE fact_id=?;";
  sqlite3_stmt *select_st = NULL;
  sqlite3_stmt *normalize_st = NULL;
  sqlite3_stmt *fact_st = NULL;
  sqlite3_stmt *fact_lookup_st = NULL;
  EdrContextWriter writer;
  memset(&writer, 0, sizeof(writer));
  int result = -1;
  if (!s_db || exec_sql("BEGIN IMMEDIATE;") != 0) return -1;
  if (sqlite3_prepare_v2(s_db, select_sql, -1, &select_st, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(s_db, normalize_sql, -1, &normalize_st, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(s_db, fact_sql, -1, &fact_st, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(s_db, fact_lookup_sql, -1, &fact_lookup_st, NULL) != SQLITE_OK ||
      edr_context_writer_open(&s_context_store, &writer) != 0) {
    set_error("prepare legacy context normalization failed");
    goto done;
  }
  for (;;) {
    int step = sqlite3_step(select_st);
    if (step == SQLITE_DONE) break;
    if (step != SQLITE_ROW) {
      set_error("read legacy context artifact failed");
      goto done;
    }
    const char *artifact_id = (const char *)sqlite3_column_text(select_st, 0);
    const char *endpoint_id = (const char *)sqlite3_column_text(select_st, 1);
    const char *tenant_id = (const char *)sqlite3_column_text(select_st, 2);
    const char *candidate_id = (const char *)sqlite3_column_text(select_st, 3);
    const char *manifest_json = (const char *)sqlite3_column_text(select_st, 4);
    int manifest_bytes = sqlite3_column_bytes(select_st, 4);
    sqlite3_int64 created_ns = sqlite3_column_int64(select_st, 5);
    const char *upload_status = (const char *)sqlite3_column_text(select_st, 6);
    const char *minio_key = (const char *)sqlite3_column_text(select_st, 7);
    const char *source_identity = legacy_context_source_identity(artifact_id);
    const char *manifest_template = NULL;
    char fact_id[65];
    char *candidate_json = NULL;
    if (!artifact_id || !candidate_id || !candidate_id[0] || !source_identity) {
      set_error("legacy context artifact identity invalid");
      goto row_done;
    }
    if (sqlite3_column_type(select_st, 4) != SQLITE_TEXT || !manifest_json ||
        manifest_bytes <= 0 ||
        (size_t)manifest_bytes > EDR_EVIDENCE_MANIFEST_MAX_BYTES ||
        !manifest_utf8_bytes_valid(manifest_json, (size_t)manifest_bytes)) {
      set_error("legacy context manifest invalid");
      goto row_done;
    }
    sqlite3_reset(normalize_st);
    sqlite3_clear_bindings(normalize_st);
    if (sqlite3_bind_text(normalize_st, 1, manifest_json, manifest_bytes,
                          SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(normalize_st) != SQLITE_ROW) {
      set_error("normalize legacy context manifest failed");
      goto row_done;
    }
    {
      const char *root_type = (const char *)sqlite3_column_text(normalize_st, 0);
      const char *candidate_type = (const char *)sqlite3_column_text(normalize_st, 1);
      const char *manifest_candidate =
          (const char *)sqlite3_column_text(normalize_st, 2);
      manifest_template = (const char *)sqlite3_column_text(normalize_st, 3);
      if (!root_type || strcmp(root_type, "object") != 0 || !candidate_type ||
          strcmp(candidate_type, "text") != 0 || !manifest_candidate ||
          strcmp(manifest_candidate, candidate_id) != 0 || !manifest_template ||
          sqlite3_column_bytes(normalize_st, 3) <= 0 ||
          (size_t)sqlite3_column_bytes(normalize_st, 3) >
              EDR_EVIDENCE_MANIFEST_MAX_BYTES ||
          strstr(manifest_template, "\"candidate_id\":null") == NULL) {
        set_error("legacy context manifest invalid");
        goto row_done;
      }
    }
    candidate_json = context_candidate_id_json(candidate_id);
    if (!candidate_json ||
        context_fact_id_for_identity(endpoint_id, tenant_id, source_identity,
                                     manifest_template, fact_id) != 0) {
      set_error("normalize legacy context manifest failed");
      goto row_done;
    }
    sqlite3_reset(fact_st);
    sqlite3_clear_bindings(fact_st);
    bind_text(fact_st, 1, fact_id);
    bind_text(fact_st, 2, endpoint_id ? endpoint_id : "");
    bind_text(fact_st, 3, tenant_id ? tenant_id : "");
    bind_text(fact_st, 4, manifest_template);
    sqlite3_bind_int64(fact_st, 5, created_ns);
    sqlite3_bind_int64(fact_st, 6, created_ns);
    if (sqlite3_step(fact_st) != SQLITE_DONE) {
      set_error("migrate legacy context fact failed");
      goto row_done;
    }
    sqlite3_reset(fact_lookup_st);
    sqlite3_clear_bindings(fact_lookup_st);
    bind_text(fact_lookup_st, 1, fact_id);
    if (sqlite3_step(fact_lookup_st) != SQLITE_ROW) {
      set_error("verify migrated legacy context fact failed");
      goto row_done;
    }
    {
      const char *stored_endpoint =
          (const char *)sqlite3_column_text(fact_lookup_st, 0);
      const char *stored_tenant =
          (const char *)sqlite3_column_text(fact_lookup_st, 1);
      const char *stored_manifest =
          (const char *)sqlite3_column_text(fact_lookup_st, 2);
      if (!stored_endpoint || strcmp(stored_endpoint, endpoint_id ? endpoint_id : "") != 0 ||
          !stored_tenant || strcmp(stored_tenant, tenant_id ? tenant_id : "") != 0 ||
          !stored_manifest || strcmp(stored_manifest, manifest_template) != 0) {
        set_error("legacy context fact hash collision");
        goto row_done;
      }
    }
    if (edr_context_writer_put(&writer, artifact_id, candidate_id, fact_id,
          candidate_json, created_ns, 0, upload_status ? upload_status : "local_manifest",
          minio_key ? minio_key : "") != 0) {
      set_error(s_context_store.error);
      goto row_done;
    }
    cJSON_free(candidate_json);
    continue;

row_done:
    cJSON_free(candidate_json);
    goto done;
  }
  if (exec_sql("COMMIT;") != 0) {
    goto done;
  }
  result = 0;

done:
  edr_context_writer_close(&writer);
  sqlite3_finalize(fact_lookup_st);
  sqlite3_finalize(fact_st);
  sqlite3_finalize(normalize_st);
  sqlite3_finalize(select_st);
  if (result != 0) sqlite_rollback_silent();
  return result;
}

/* A durable candidate is updated even after the small in-memory reuse window
 * expires (or after a restart).  This avoids treating an enrichment replay as
 * a fresh admission and charging it against the bounded new-candidate budget. */
static int sqlite_candidate_exists(const char *candidate_id) {
  sqlite3_stmt *st = NULL;
  int exists = -1;
  if (!s_db || !candidate_id || !candidate_id[0]) {
    return 0;
  }
  if (sqlite3_prepare_v2(s_db, "SELECT 1 FROM p0_candidates WHERE candidate_id=? LIMIT 1;",
                         -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare p0_candidates lookup failed");
    return -1;
  }
  if (sqlite3_bind_text(st, 1, candidate_id, -1, SQLITE_TRANSIENT) == SQLITE_OK) {
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) exists = 1;
    else if (rc == SQLITE_DONE) exists = 0;
  }
  if (exists < 0) set_error("p0_candidates lookup failed; existing owner state unknown");
  sqlite3_finalize(st);
  return exists;
}

static int command_fact_key(const EdrBehaviorRecord *r, char key[80]);

typedef struct {
  ProcessTreeEntry parent;
  int parent_known, parent_generation_conflict;
  int subject_command_unavailable, parent_command_unavailable;
  int command_dependency_missing;
} RetainedAlertParentContext;

/* This is a local fact, referenced by the existing candidate retirement group.
 * The command body is shared through the existing generation-bound artifact;
 * it is never copied into a pending upload or a per-alert manifest. */
static int sqlite_record_alert_parent_context(const EdrBehaviorRecord *r,
    const char *candidate_id, const RetainedAlertParentContext *context,
    const char *parent_command_ref, unsigned *facts_written,
    unsigned *refs_written) {
  cJSON *root = manifest_create_object(), *child = NULL, *parent = NULL;
  char *json = NULL, *candidate_json = NULL;
  char fact_id[65], artifact_id[256];
  sqlite3_stmt *st = NULL;
  int result = -1, reference_exists = 0;
  *facts_written = *refs_written = 0u;
  if (!root) goto done;
  uint8_t parent_state = edr_parent_pid_effective_state(r->ppid, r->parent_pid_state);
  if (parent_state > EDR_PARENT_PID_CONFLICT ||
      (parent_state == EDR_PARENT_PID_KNOWN && (!r->ppid || r->ppid == r->pid)) ||
      (parent_state == EDR_PARENT_PID_EXPLICIT_ZERO && r->ppid)) parent_state = EDR_PARENT_PID_INVALID;
  child = cJSON_AddObjectToObject(root, "child");
  int ok = child &&
      manifest_add_text(root, "schema", "edr.local-alert-parent-context.v1") &&
      cJSON_AddNullToObject(root, "candidate_id") &&
      manifest_add_text(root, "source_event_id", r->event_id) &&
      manifest_add_u64_text(root, "event_time_ns", (uint64_t)record_time_ns(r)) &&
      manifest_add_u64(child, "pid", r->pid) &&
      manifest_add_u64_text(child, "process_start_key", r->process_start_key) &&
      manifest_add_u64_text(child, "process_creation_filetime_100ns", r->process_creation_filetime_100ns) &&
      manifest_add_u64(root, "parent_pid", r->ppid) &&
      manifest_add_u64(root, "parent_pid_state", parent_state) &&
      cJSON_AddBoolToObject(root, "parent_generation_conflict", context->parent_generation_conflict);
  if (ok && context->parent_known) {
    const ProcessTreeEntry *p = &context->parent;
    parent = cJSON_AddObjectToObject(root, "parent");
    const char *path_quality = !p->exe_path[0] ? "missing" :
        (p->source_truncation_mask & EDR_PTC_SOURCE_TRUNC_EXE_PATH) ? "truncated" : "complete";
    const char *command_quality = parent_command_ref[0] ? "complete" :
        (p->source_truncation_mask & EDR_PTC_SOURCE_TRUNC_CMDLINE) ? "truncated" :
        p->cmdline[0] ? "unknown" : "missing";
    ok = parent && manifest_add_u64(parent, "pid", p->pid) &&
        manifest_add_u64(parent, "parent_pid_state", EDR_PARENT_PID_KNOWN) &&
        manifest_add_u64_text(parent, "process_start_key", p->process_start_key) &&
        manifest_add_u64_text(parent, "process_creation_filetime_100ns", p->creation_filetime_100ns) &&
        manifest_add_text(parent, "name", p->process_name) &&
        manifest_add_text(parent, "path", p->exe_path) &&
        manifest_add_text(parent, "path_quality", path_quality) &&
        manifest_add_text(parent, "command_fact_ref", parent_command_ref) &&
        manifest_add_text(parent, "cmdline_quality", command_quality);
  } else if (ok) ok = cJSON_AddNullToObject(root, "parent") != NULL;
  if (!ok || manifest_finish(root, &json) != 0 ||
      context_fact_id_for(r, json, fact_id) != 0) goto done;
  int n = snprintf(artifact_id, sizeof(artifact_id), "%s:alert_parent_context", candidate_id);
  if (n <= 0 || (size_t)n >= sizeof(artifact_id)) goto done;
  st = edr_context_store_prepare_lookup(&s_context_store);
  if (!st || edr_context_store_bind_lookup(&s_context_store, st, artifact_id) != 0) goto done;
  int step = sqlite3_step(st);
  if (step == SQLITE_ROW) {
    const char *owner = (const char *)sqlite3_column_text(st, 0);
    const char *prior = (const char *)sqlite3_column_text(st, 1);
    int same = owner && prior && !strcmp(owner, candidate_id) && !strcmp(prior, fact_id);
    if (!same || sqlite3_step(st) != SQLITE_DONE) {
      s_persistence_failure = EDR_EVIDENCE_FAILURE_INVALID;
      set_error("alert parent context differs from its frozen source snapshot");
      goto done;
    }
    reference_exists = 1;
  }
  else if (step != SQLITE_DONE) goto done;
  sqlite3_finalize(st); st = NULL;
  if (sqlite3_prepare_v2(s_db,
      "SELECT manifest_template_json FROM context_facts WHERE fact_id=?;", -1, &st, NULL) != SQLITE_OK) goto done;
  bind_text(st, 1, fact_id);
  step = sqlite3_step(st);
  if (step == SQLITE_ROW) {
    const char *prior = (const char *)sqlite3_column_text(st, 0);
    if (!prior || strcmp(prior, json)) {
      s_persistence_failure = EDR_EVIDENCE_FAILURE_INVALID;
      set_error("alert parent context fact hash collision"); goto done;
    }
  } else if (step == SQLITE_DONE && !reference_exists) *facts_written = 1u;
  else goto done;
  sqlite3_finalize(st); st = NULL;
  if (reference_exists) { result = 0; goto done; }
  sqlite3_int64 written = (sqlite3_int64)now_unix_ns();
  if (*facts_written) {
    if (sqlite3_prepare_v2(s_db,
        "INSERT INTO context_facts(fact_id,endpoint_id,tenant_id,manifest_template_json,created_ns,updated_ns) VALUES(?,?,?,?,?,?);",
        -1, &st, NULL) != SQLITE_OK) goto done;
    bind_text(st, 1, fact_id); bind_text(st, 2, r->endpoint_id); bind_text(st, 3, r->tenant_id); bind_text(st, 4, json);
    sqlite3_bind_int64(st, 5, written); sqlite3_bind_int64(st, 6, written);
    if (sqlite3_step(st) != SQLITE_DONE) goto done;
    sqlite3_finalize(st); st = NULL;
  }
  candidate_json = context_candidate_id_json(candidate_id);
  EdrContextWriter writer;
  if (!candidate_json || edr_context_writer_open(&s_context_store, &writer) != 0) goto done;
  result = edr_context_writer_put(&writer, artifact_id, candidate_id, fact_id,
      candidate_json, written, 0, "local_manifest", "");
  edr_context_writer_close(&writer);
  if (result == 0) *refs_written = 1u;
done:
  sqlite3_finalize(st);
  cJSON_Delete(root); cJSON_free(json); cJSON_free(candidate_json);
  if (result != 0 && s_persistence_failure != EDR_EVIDENCE_FAILURE_INVALID)
    set_error("local alert parent context transaction unavailable");
  return result;
}

/* This is a bounded investigation preference, never an irreversible pin.
 * Ordinary low-severity ancestors/context remain in the selected group. */
static int candidate_value_class(const EdrBehaviorRecord *r, uint32_t pre_count,
                                 int generation_known, const char **reason) {
  if (r->type == EDR_EVENT_PROTOCOL_SHELLCODE || r->type == EDR_EVENT_WEBSHELL_DETECTED ||
      r->type == EDR_EVENT_PMFE_SCAN_RESULT || r->type == EDR_EVENT_BEHAVIOR_ONNX_ALERT) {
    *reason = "detector_evidence"; return 2;
  }
  if (generation_known && pre_count) { *reason = "causal_context"; return 2; }
  *reason = "recent_detail"; return 1;
}

static int candidate_command_reference(const EdrBehaviorRecord *r, char key[80]) {
  sqlite3_stmt *st = NULL;
  key[0] = 0;
  if (!command_fact_key(r, key)) return 0;
  if (sqlite3_prepare_v2(s_db, "SELECT 1 FROM artifacts WHERE artifact_id=? AND "
      "endpoint_id=? AND tenant_id=? AND artifact_type='process_command_line' "
      "AND upload_status='embedded';", -1, &st, NULL) != SQLITE_OK) return -1;
  bind_text(st, 1, key); bind_text(st, 2, r->endpoint_id); bind_text(st, 3, r->tenant_id);
  int step = sqlite3_step(st);
  sqlite3_finalize(st);
  if (step == SQLITE_DONE) key[0] = 0;
  return step == SQLITE_ROW || step == SQLITE_DONE ? 0 : -1;
}

static int sqlite_record_candidate(const EdrBehaviorRecord *r, const char *candidate_id,
                                   uint32_t pre_count, int64_t post_until_ns,
                                   RetainedAlertParentContext *alert_parent) {
  EvidenceProcessGeneration generation;
  int generation_known;
  const char *generation_source, *value_reason;
  char subject_command[80] = "", parent_command[80] = "";
  char normalized_command[EDR_BR_STR_LONG];
  char script_path[EDR_BR_STR_LONG];
  int normalized_command_truncated;
  if (!s_db || !r) {
    set_error("evidence cache database unavailable");
    return -1;
  }
  generation_known = record_process_generation(r, &generation);
  generation_source = generation_known ? record_process_generation_source(r) : "";
  int value_class = candidate_value_class(r, pre_count, generation_known, &value_reason);
  normalized_command_truncated = edr_p0_normalize_command_for_evidence(
      r->cmdline, normalized_command, sizeof(normalized_command));
  (void)edr_p0_extract_script_path(r->cmdline, script_path,
                                   sizeof(script_path));
  char computed_candidate_id[160];
  if (!candidate_id || !candidate_id[0]) {
    candidate_id_for(r, computed_candidate_id, sizeof(computed_candidate_id));
    candidate_id = computed_candidate_id;
  }
  if (exec_sql("BEGIN IMMEDIATE;") != 0) {
    return -1;
  }
  if (sqlite_retention_clock_stage() != 0) {
    sqlite_rollback_silent();
    return -1;
  }
  if (upsert_process_sqlite(r) != 0) {
    sqlite_rollback_silent();
    return -1;
  }
  EdrBehaviorRecord *parent_identity = (EdrBehaviorRecord *)calloc(1, sizeof(*parent_identity));
  if (!parent_identity) { sqlite_rollback_silent(); set_error("command dependency allocation failed"); return -1; }
  copy_s(parent_identity->tenant_id, sizeof(parent_identity->tenant_id), r->tenant_id);
  copy_s(parent_identity->endpoint_id, sizeof(parent_identity->endpoint_id), r->endpoint_id);
  parent_identity->pid = r->ppid;
  parent_identity->process_start_key = r->parent_process_start_key;
  parent_identity->process_creation_filetime_100ns = r->parent_process_creation_filetime_100ns;
  int dependency_rc = alert_parent && alert_parent->subject_command_unavailable ? 0 :
      candidate_command_reference(r, subject_command);
  if (!dependency_rc && record_parent_context_proven(r) &&
      (!alert_parent || (alert_parent->parent_known && !alert_parent->parent_command_unavailable)))
    dependency_rc = candidate_command_reference(parent_identity, parent_command);
  if (alert_parent && ((!alert_parent->subject_command_unavailable && !subject_command[0]) ||
      (alert_parent->parent_known && !alert_parent->parent_command_unavailable && !parent_command[0])))
    alert_parent->command_dependency_missing = 1;
  free(parent_identity);
  if (dependency_rc) { sqlite_rollback_silent(); set_error("command dependency lookup failed"); return -1; }
  const char *sql =
      "INSERT INTO p0_candidates(candidate_id,endpoint_id,tenant_id,event_time_ns,type,pid,ppid,"
      "process_name,exe_path,cmdline,file_path,dns_query,net_dst,net_dport,reg_key_path,"
      "reg_value_name,reg_op,detection_context,context_pre_count,context_post_until_ns,created_ns,"
      "process_start_key,process_creation_filetime_100ns,process_generation_source,"
      "source_completeness,source_truncated_fields,normalized_command,normalized_command_truncated,script_path,exe_hash,"
      "username,user_sid,identity_source,identity_quality,retention_policy_version,retention_value_class,retention_value_reason,subject_command_fact_id,parent_command_fact_id) "
      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?) "
      "ON CONFLICT(candidate_id) DO UPDATE SET "
      "tenant_id=CASE WHEN excluded.tenant_id<>'' THEN excluded.tenant_id ELSE p0_candidates.tenant_id END,"
      "event_time_ns=CASE WHEN p0_candidates.event_time_ns=0 THEN excluded.event_time_ns "
      "WHEN excluded.event_time_ns=0 THEN p0_candidates.event_time_ns "
      "ELSE MIN(p0_candidates.event_time_ns,excluded.event_time_ns) END,"
      "type=CASE WHEN excluded.type<>0 THEN excluded.type ELSE p0_candidates.type END,"
      "pid=CASE WHEN excluded.pid<>0 THEN excluded.pid ELSE p0_candidates.pid END,"
      "ppid=CASE WHEN excluded.ppid<>0 THEN excluded.ppid ELSE p0_candidates.ppid END,"
      "process_name=CASE WHEN excluded.process_name<>'' THEN excluded.process_name ELSE p0_candidates.process_name END,"
      "exe_path=CASE WHEN excluded.exe_path<>'' THEN excluded.exe_path ELSE p0_candidates.exe_path END,"
      "cmdline=CASE WHEN excluded.cmdline<>'' THEN excluded.cmdline ELSE p0_candidates.cmdline END,"
      "file_path=CASE WHEN excluded.file_path<>'' THEN excluded.file_path ELSE p0_candidates.file_path END,"
      "dns_query=CASE WHEN excluded.dns_query<>'' THEN excluded.dns_query ELSE p0_candidates.dns_query END,"
      "net_dst=CASE WHEN excluded.net_dst<>'' THEN excluded.net_dst ELSE p0_candidates.net_dst END,"
      "net_dport=CASE WHEN excluded.net_dport<>0 THEN excluded.net_dport ELSE p0_candidates.net_dport END,"
      "reg_key_path=CASE WHEN excluded.reg_key_path<>'' THEN excluded.reg_key_path ELSE p0_candidates.reg_key_path END,"
      "reg_value_name=CASE WHEN excluded.reg_value_name<>'' THEN excluded.reg_value_name ELSE p0_candidates.reg_value_name END,"
      "reg_op=CASE WHEN excluded.reg_op<>'' THEN excluded.reg_op ELSE p0_candidates.reg_op END,"
      "detection_context=CASE WHEN excluded.detection_context<>'' THEN excluded.detection_context ELSE p0_candidates.detection_context END,"
      "context_pre_count=MAX(p0_candidates.context_pre_count,excluded.context_pre_count),"
      "context_post_until_ns=MAX(p0_candidates.context_post_until_ns,excluded.context_post_until_ns),"
      "created_ns=excluded.created_ns,"
      "process_start_key=CASE WHEN excluded.process_start_key<>'' AND excluded.process_start_key<>'0' THEN excluded.process_start_key ELSE p0_candidates.process_start_key END,"
      "process_creation_filetime_100ns=CASE WHEN excluded.process_creation_filetime_100ns<>'' AND excluded.process_creation_filetime_100ns<>'0' THEN excluded.process_creation_filetime_100ns ELSE p0_candidates.process_creation_filetime_100ns END,"
      "process_generation_source=CASE WHEN excluded.process_generation_source<>'' THEN excluded.process_generation_source ELSE p0_candidates.process_generation_source END,"
      "source_completeness=CASE WHEN p0_candidates.source_completeness='' THEN excluded.source_completeness "
      "WHEN (CASE excluded.source_completeness WHEN 'COMPLETE' THEN 7 WHEN 'COALESCED' THEN 6 "
      "WHEN 'CORRELATION_MISSING' THEN 5 WHEN 'ENRICHMENT_ONLY' THEN 4 WHEN 'TRUNCATED' THEN 3 "
      "WHEN 'NOT_EVALUABLE' THEN 2 WHEN 'COALESCE_BACKPRESSURE' THEN 1 ELSE 0 END) > "
      "(CASE p0_candidates.source_completeness WHEN 'COMPLETE' THEN 7 WHEN 'COALESCED' THEN 6 "
      "WHEN 'CORRELATION_MISSING' THEN 5 WHEN 'ENRICHMENT_ONLY' THEN 4 WHEN 'TRUNCATED' THEN 3 "
      "WHEN 'NOT_EVALUABLE' THEN 2 WHEN 'COALESCE_BACKPRESSURE' THEN 1 ELSE 0 END) "
      "THEN excluded.source_completeness ELSE p0_candidates.source_completeness END,"
      "source_truncated_fields=CASE WHEN p0_candidates.source_completeness='' THEN excluded.source_truncated_fields "
      "WHEN (CASE excluded.source_completeness WHEN 'COMPLETE' THEN 7 WHEN 'COALESCED' THEN 6 "
      "WHEN 'CORRELATION_MISSING' THEN 5 WHEN 'ENRICHMENT_ONLY' THEN 4 WHEN 'TRUNCATED' THEN 3 "
      "WHEN 'NOT_EVALUABLE' THEN 2 WHEN 'COALESCE_BACKPRESSURE' THEN 1 ELSE 0 END) > "
      "(CASE p0_candidates.source_completeness WHEN 'COMPLETE' THEN 7 WHEN 'COALESCED' THEN 6 "
      "WHEN 'CORRELATION_MISSING' THEN 5 WHEN 'ENRICHMENT_ONLY' THEN 4 WHEN 'TRUNCATED' THEN 3 "
      "WHEN 'NOT_EVALUABLE' THEN 2 WHEN 'COALESCE_BACKPRESSURE' THEN 1 ELSE 0 END) "
      "THEN excluded.source_truncated_fields ELSE p0_candidates.source_truncated_fields END,"
      "normalized_command=CASE WHEN excluded.normalized_command<>'' THEN excluded.normalized_command ELSE p0_candidates.normalized_command END,"
      "normalized_command_truncated=CASE WHEN excluded.normalized_command<>'' THEN excluded.normalized_command_truncated ELSE p0_candidates.normalized_command_truncated END,"
      "script_path=CASE WHEN excluded.script_path<>'' THEN excluded.script_path ELSE p0_candidates.script_path END,"
      "exe_hash=CASE WHEN excluded.exe_hash<>'' THEN excluded.exe_hash ELSE p0_candidates.exe_hash END,"
      "username=CASE WHEN excluded.username<>'' THEN excluded.username ELSE p0_candidates.username END,"
      "user_sid=CASE WHEN excluded.user_sid<>'' THEN excluded.user_sid ELSE p0_candidates.user_sid END,"
      "identity_source=CASE WHEN excluded.identity_source<>'' THEN excluded.identity_source ELSE p0_candidates.identity_source END,"
      "identity_quality=CASE WHEN excluded.identity_quality<>'' THEN excluded.identity_quality ELSE p0_candidates.identity_quality END,"
      "retention_value_reason=CASE WHEN p0_candidates.retention_policy_version=1 AND p0_candidates.retention_value_class=1 AND excluded.retention_value_class=2 THEN excluded.retention_value_reason ELSE p0_candidates.retention_value_reason END,"
      "retention_value_class=CASE WHEN p0_candidates.retention_policy_version=1 AND p0_candidates.retention_value_class=1 THEN MAX(p0_candidates.retention_value_class,excluded.retention_value_class) ELSE p0_candidates.retention_value_class END,"
      "subject_command_fact_id=CASE WHEN excluded.subject_command_fact_id<>'' THEN excluded.subject_command_fact_id ELSE p0_candidates.subject_command_fact_id END,"
      "parent_command_fact_id=CASE WHEN excluded.parent_command_fact_id<>'' THEN excluded.parent_command_fact_id ELSE p0_candidates.parent_command_fact_id END;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare p0_candidates failed");
    sqlite_rollback_silent();
    return -1;
  }
  bind_text(st, 1, candidate_id);
  bind_text(st, 2, r ? r->endpoint_id : "");
  bind_text(st, 3, r ? r->tenant_id : "");
  sqlite3_bind_int64(st, 4, (sqlite3_int64)record_time_ns(r));
  sqlite3_bind_int64(st, 5, (sqlite3_int64)(r ? r->type : 0));
  sqlite3_bind_int64(st, 6, (sqlite3_int64)(r ? r->pid : 0u));
  sqlite3_bind_int64(st, 7, (sqlite3_int64)(r ? r->ppid : 0u));
  bind_text(st, 8, r ? r->process_name : "");
  bind_text(st, 9, r ? r->exe_path : "");
  bind_text(st, 10, r ? r->cmdline : "");
  bind_text(st, 11, r ? r->file_path : "");
  bind_text(st, 12, r ? r->dns_query : "");
  bind_text(st, 13, r ? r->net_dst : "");
  sqlite3_bind_int64(st, 14, (sqlite3_int64)(r ? r->net_dport : 0u));
  bind_text(st, 15, r ? r->reg_key_path : "");
  bind_text(st, 16, r ? r->reg_value_name : "");
  bind_text(st, 17, r ? r->reg_op : "");
  bind_text(st, 18, r ? r->detection_context : "");
  sqlite3_bind_int64(st, 19, (sqlite3_int64)pre_count);
  sqlite3_bind_int64(st, 20, (sqlite3_int64)post_until_ns);
  sqlite3_bind_int64(st, 21, (sqlite3_int64)now_unix_ns());
  char start_key_text[32];
  char creation_text[32];
  sqlite_u64_decimal(generation_known ? generation.process_start_key : 0u, start_key_text);
  sqlite_u64_decimal(generation_known ? generation.creation_filetime_100ns : 0u,
                     creation_text);
  bind_text(st, 22, start_key_text);
  bind_text(st, 23, creation_text);
  bind_text(st, 24, generation_source);
  bind_text(st, 25, r->source_completeness);
  bind_text(st, 26, r->source_truncated_fields);
  bind_text(st, 27, normalized_command);
  sqlite3_bind_int(st, 28, normalized_command_truncated);
  bind_text(st, 29, script_path);
  bind_text(st, 30, r->exe_hash);
  bind_text(st, 31, r->username);
  bind_text(st, 32, r->user_sid);
  bind_text(st, 33, r->identity_source);
  bind_text(st, 34, r->identity_quality);
  sqlite3_bind_int(st, 35, value_class);
  bind_text(st, 36, value_reason);
  bind_text(st, 37, subject_command);
  bind_text(st, 38, parent_command);
  if (sqlite3_step(st) != SQLITE_DONE) {
    set_error("insert p0_candidates failed");
    sqlite3_finalize(st);
    sqlite_rollback_silent();
    return -1;
  }
  sqlite3_finalize(st);
  if (upsert_file_sqlite(r) != 0 || upsert_network_sqlite(r) != 0 ||
      upsert_registry_sqlite(r) != 0) {
    sqlite_rollback_silent();
    return -1;
  }
  char *manifest = NULL;
  if (build_context_manifest_json(r, candidate_id, pre_count, post_until_ns, &manifest) != 0) {
    sqlite_rollback_silent();
    return -1;
  }
  int artifact_rc = insert_artifact_sqlite(r, candidate_id, "p0_context_bundle", "", "", manifest,
                                           "local_manifest");
  cJSON_free(manifest);
  unsigned parent_facts = 0u, parent_refs = 0u;
  if (artifact_rc != 0 || (alert_parent && sqlite_record_alert_parent_context(r,
          candidate_id, alert_parent, parent_command, &parent_facts, &parent_refs) != 0)) {
    sqlite_rollback_silent();
    return -1;
  }
  /* Grant a minimum residence only when this transaction first freezes the
   * exact source's parent ref. Replays, ordinary upserts and queries never
   * renew a protection, and historical zero rows are not backfilled. */
  if (parent_refs) {
    uint64_t duration = (uint64_t)s_status.selected_retention_hours * 3600000u;
    if (!duration || s_retention_clock.pending_ms > (uint64_t)INT64_MAX - duration) {
      (void)retention_clock_error(4u, "parent context minimum residence overflow");
      sqlite_rollback_silent(); return -1;
    }
    if (sqlite3_prepare_v2(s_db, "UPDATE p0_candidates SET alert_context_protect_until_active_ms=?1 "
        "WHERE candidate_id=?2 AND alert_context_protect_until_active_ms=0;", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(st, 1, (sqlite3_int64)(s_retention_clock.pending_ms + duration)) != SQLITE_OK ||
        sqlite3_bind_text(st, 2, candidate_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(s_db) != 1) {
      sqlite3_finalize(st); sqlite_rollback_silent();
      set_error("parent context minimum residence could not be committed"); return -1;
    }
    sqlite3_finalize(st); st = NULL;
  }
  int live_size_over = sqlite_live_size_over_limit(
      (uint64_t)s_status.max_db_mb * 1024u * 1024u);
  if (live_size_over < 0) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_STORAGE;
    sqlite_rollback_silent(); return -1;
  }
  if (live_size_over > 0) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_CAPACITY;
    ++s_status.db_budget_dropped;
    set_error("candidate context page budget exceeded; protected evidence preserved");
    sqlite_rollback_silent(); return -1;
  }
  if (sqlite_commit_candidate_transaction() != 0) {
    sqlite_rollback_silent(); return -1;
  }
  /* These counters describe durable candidate commits, never a statement
   * that was later rolled back. */
  s_status.records_written++;
  s_status.p0_candidates_written++;
  s_status.artifacts_written++;
  s_status.artifacts_written += parent_refs;
  s_status.context_facts_written += parent_facts;
  s_status.context_refs_written += parent_refs;
  s_status.retention_parent_protections += parent_refs;
  if ((unsigned)r->type < EDR_LOCAL_EVIDENCE_EVENT_TYPE_BUCKETS)
    s_status.context_ref_writes_by_event_type[(unsigned)r->type] += parent_refs;
  return 0;
}

/* The cache mutex serializes producers with this bounded batch. Watermarks
 * describe only successfully committed counts from this process, so reopening
 * in the same minute adds new observations without replacing earlier totals. */
static int sqlite_flush_metrics_slice(int final_attempt, EvidenceMaintenanceSlice *slice) {
  unsigned char written[EDR_EVIDENCE_METRIC_SLOTS][METRIC_COUNT]={{0}};
  unsigned written_rows=0;
  int pending = 0, began = 0, rc;
  sqlite3_stmt *st = NULL;
  uint64_t now = edr_monotonic_ns();
  int64_t cutoff = (now_unix_ns() / 1000000000LL -
                    (int64_t)s_status.retention_hours * 3600LL) / 60LL;
  for (size_t i = 0; i < EDR_EVIDENCE_METRIC_SLOTS; ++i) {
    MetricSlot *m = &s_metrics[i];
    if (m->minute_unix != 0 && m->minute_unix < cutoff) {
      /* Retirement follows the same minute boundary as DELETE in maintenance.
       * It must also apply during slot replacement and final close. */
      memset(m, 0, sizeof(*m));
    }
    if (metric_slot_pending(m)) pending = 1;
  }
  if (!pending) return 0;
  if (!sqlite_physical_write_allow(sizeof(s_metrics))) goto failed;
  if (!final_attempt && now < s_metric_retry_after_ns) return -1;
  if (!s_db) { set_error("metrics flush has no database"); goto failed; }
  if (!sqlite3_get_autocommit(s_db)) {
    set_error("metrics flush refused inside an existing transaction");
    goto failed;
  }
  const char *sql =
      "INSERT INTO metrics(minute_unix,endpoint_id,metric_name,value) VALUES(?,?,?,?) "
      "ON CONFLICT(minute_unix,endpoint_id,metric_name) DO UPDATE "
      "SET value=metrics.value+excluded.value "
      "WHERE metrics.value>=0 AND metrics.value<=9223372036854775807-excluded.value;";
  rc = sqlite3_exec(s_db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
  if (rc != SQLITE_OK) { set_error("metrics transaction begin failed"); goto failed; }
  began = 1;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("metrics statement prepare failed"); goto failed;
  }
  for (size_t i = 0; i < EDR_EVIDENCE_METRIC_SLOTS; ++i) {
    MetricSlot *m = &s_metrics[i];
    for (size_t j = 0; m->minute_unix != 0 && j < METRIC_COUNT; ++j) {
      uint64_t delta = metric_slot_value(m, j) - m->committed[j];
      if (!delta) continue;
      if (slice && (written_rows>=128u || !sqlite_maintenance_charge(slice,1,
              strlen(m->endpoint_id)+strlen(metric_names[j])+32u))) goto commit_metrics;
      if (delta > (uint64_t)INT64_MAX ||
          sqlite3_bind_int64(st, 1, m->minute_unix) != SQLITE_OK ||
          sqlite3_bind_text(st, 2, m->endpoint_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
          sqlite3_bind_text(st, 3, metric_names[j], -1, SQLITE_STATIC) != SQLITE_OK ||
          sqlite3_bind_int64(st, 4, (sqlite3_int64)delta) != SQLITE_OK) {
        set_error("metrics delta overflow or bind failed"); goto failed;
      }
      if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(s_db) != 1) {
        set_error("metrics write failed or cumulative value overflowed"); goto failed;
      }
      if (sqlite3_reset(st) != SQLITE_OK || sqlite3_clear_bindings(st) != SQLITE_OK) {
        set_error("metrics statement reset failed"); goto failed;
      }
      written[i][j]=1; ++written_rows;
    }
  }
commit_metrics:
  sqlite3_finalize(st);
  st = NULL;
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  s_test_commit_active = 1;
#endif
  rc = sqlite3_exec(s_db, "COMMIT;", NULL, NULL, NULL);
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  s_test_commit_active = 0;
#endif
  if (rc != SQLITE_OK) {
    set_error("metrics transaction commit failed"); goto failed;
  }
  for (size_t i = 0; i < EDR_EVIDENCE_METRIC_SLOTS; ++i) {
    MetricSlot *m = &s_metrics[i];
    for (size_t j = 0; j < METRIC_COUNT; ++j) if(written[i][j]) m->committed[j] = metric_slot_value(m, j);
  }
  s_metric_retry_after_ns = 0u;
  return 0;
failed:
  if (st) sqlite3_finalize(st);
  if (began && sqlite3_exec(s_db, "ROLLBACK;", NULL, NULL, NULL) != SQLITE_OK &&
      !sqlite3_get_autocommit(s_db))
    set_error("metrics rollback failed; database transaction remains active");
  s_status.metric_write_failures++;
  /* A full metrics ring must not turn a storage error into per-event SQL I/O.
   * Retry on the existing maintenance cadence; close gets one final attempt. */
  s_metric_retry_after_ns = now > UINT64_MAX - 60000000000ULL
                               ? UINT64_MAX : now + 60000000000ULL;
  return -1;
}

static int sqlite_flush_metrics(int final_attempt) {
  EvidenceMaintenanceSlice slice={evidence_cache_clock_ns()+20000000ULL,
      4u*EDR_EVIDENCE_MANIFEST_MAX_BYTES,4096u};
  return sqlite_flush_metrics_slice(final_attempt,final_attempt ? NULL : &slice);
}

/* DELETE changes live pages, not the allocated file length. Use live pages
 * only to decide whether more evidence must be evicted; admission still uses
 * the physical database + WAL budget after reclamation. On inspection failure
 * do not delete evidence speculatively. */
static int sqlite_live_size_over_limit(uint64_t limit) {
  sqlite3_stmt *st = NULL;
  int over = -1;
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  int deny_query = s_test_live_size_query_failures > 0u;
  if (deny_query) {
    --s_test_live_size_query_failures;
    (void)sqlite3_set_authorizer(s_db, evidence_cache_test_deny_query, NULL);
  }
#endif
  if (sqlite3_prepare_v2(s_db,
      "SELECT (page_count-freelist_count)*page_size "
      "FROM pragma_page_count,pragma_freelist_count,pragma_page_size;",
      -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
    sqlite3_int64 bytes = sqlite3_column_int64(st, 0);
    if (bytes >= 0) {
      over = (uint64_t)bytes > limit;
    }
  }
  sqlite3_finalize(st);
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  if (deny_query) (void)sqlite3_set_authorizer(s_db, NULL, NULL);
#endif
  if (over < 0) set_error("evidence cache live-page size query failed");
  return over;
}

static int sqlite_maintenance_error(const char *stage, int rc) {
  char error[sizeof(s_status.last_error)];
  snprintf(error, sizeof(error), "maintenance %s: sqlite=%d/%d %s", stage,
           rc, sqlite3_extended_errcode(s_db), sqlite3_errmsg(s_db));
  set_error(error);
  return -1;
}

/* One maintenance turn shares time, row and literal-byte work budgets across
 * all tables. These are cooperative work bounds, not a hard SQLite I/O limit. */
static int sqlite_maintenance_yield(const EvidenceMaintenanceSlice *slice) {
  return !slice->rows_left || !slice->bytes_left || evidence_cache_clock_ns() >= slice->deadline_ns;
}
static int sqlite_maintenance_charge(EvidenceMaintenanceSlice *slice, unsigned rows, uint64_t bytes) {
  if (sqlite_maintenance_yield(slice) || rows > slice->rows_left || bytes > slice->bytes_left) {
    slice->rows_left = 0; slice->bytes_left = 0; return 0;
  }
  slice->rows_left -= rows; slice->bytes_left -= bytes; return 1;
}

/* Reconstructible indexes and optional query copies have no delivery owner.
 * Only fixed internal identifiers enter this SQL; values remain bound. Read
 * lengths, not large payloads, then delete a bounded transaction of rowids. */
static int sqlite_maintenance_delete(const char *table, const char *clock_column,
    const char *condition, const char *byte_expression, sqlite3_int64 cutoff,
    EvidenceMaintenanceSlice *slice) {
  sqlite3_stmt *st=NULL, *del=NULL;
  sqlite3_int64 ids[128]; unsigned count=0, removed=0;
  char sql[2048]; int step=SQLITE_DONE, began=0;
  if (sqlite_maintenance_yield(slice)) return 0;
  if (!sqlite_database_write_allow(slice->bytes_left)) return -1;
  if (exec_sql("BEGIN IMMEDIATE;") != 0) goto failed;
  began=1;
  int length=snprintf(sql,sizeof(sql),"SELECT rowid,64+(%s) FROM %s WHERE %s<?1 AND (%s) ORDER BY %s,rowid LIMIT 128;",
      byte_expression,table,clock_column,condition,clock_column);
  if(length<0 || (size_t)length>=sizeof(sql)) { set_error("maintenance statement exceeds fixed buffer"); goto failed; }
  if (sqlite3_prepare_v2(s_db,sql,-1,&st,NULL)!=SQLITE_OK || sqlite3_bind_int64(st,1,cutoff)!=SQLITE_OK) goto failed;
  while (!sqlite_maintenance_yield(slice) && (step=sqlite3_step(st))==SQLITE_ROW) {
    sqlite3_int64 bytes=sqlite3_column_int64(st,1);
    if (bytes<0) goto failed;
    /* Account selection plus deletion before accepting a row. An oversized
     * legacy copy stays present and exhausts this slice, never half-deletes. */
    if (!sqlite_maintenance_charge(slice,2,(uint64_t)bytes)) break;
    ids[count++]=sqlite3_column_int64(st,0);
  }
  if (step!=SQLITE_DONE && step!=SQLITE_ROW) goto failed;
  sqlite3_finalize(st); st=NULL;
  snprintf(sql,sizeof(sql),"DELETE FROM %s WHERE rowid=?1 AND %s<?2 AND (%s);",table,clock_column,condition);
  if (sqlite3_prepare_v2(s_db,sql,-1,&del,NULL)!=SQLITE_OK) goto failed;
  for (unsigned i=0;i<count && evidence_cache_clock_ns()<slice->deadline_ns;++i) {
    if (sqlite3_bind_int64(del,1,ids[i])!=SQLITE_OK || sqlite3_bind_int64(del,2,cutoff)!=SQLITE_OK ||
        sqlite3_step(del)!=SQLITE_DONE) goto failed;
    removed+=(unsigned)sqlite3_changes(s_db);
    if (sqlite3_reset(del)!=SQLITE_OK) goto failed;
  }
  sqlite3_finalize(del); del=NULL;
  if (exec_sql("COMMIT;")!=0) goto failed;
  s_status.db_retention_evicted+=removed;
  return 0;
failed:
  sqlite_maintenance_error(table,sqlite3_errcode(s_db));
  sqlite3_finalize(st); sqlite3_finalize(del);
  if(began) sqlite_rollback_silent();
  return -1;
}

static int sqlite_maintenance_checkpoint(int mode) {
  if (!sqlite_database_write_allow(EDR_EVIDENCE_MANIFEST_MAX_BYTES)) return -1;
  int rc = sqlite3_wal_checkpoint_v2(s_db, NULL, mode, NULL, NULL);
  return rc == SQLITE_OK ? 0 : sqlite_maintenance_error("checkpoint", rc);
}

static int sqlite_maintenance_reclaim(unsigned pages) {
  char sql[64];
  uint64_t bytes=0, page_size=0;
  if (!sqlite_database_page_bytes(&bytes,&page_size) ||
      !sqlite_database_write_allow((uint64_t)pages*page_size)) return -1;
  snprintf(sql, sizeof(sql), "PRAGMA incremental_vacuum(%u);", pages);
  if (exec_sql(sql) != 0)
    return sqlite_maintenance_error("incremental vacuum", sqlite3_errcode(s_db));
  return sqlite_maintenance_checkpoint(SQLITE_CHECKPOINT_TRUNCATE);
}

static int sqlite_retention_protect_pmfe_locked(EvidenceMaintenanceSlice *slice);
static int context_window_nominally_ended(const ContextWindowSlot *w,
                                         int64_t event_time_ns, uint64_t mono_ns);

/* These six fixed aggregate rows are disposition evidence, not ACK receipts
 * or per-record tombstones. Their size is bounded independently of traffic and
 * they share the existing metrics table's physical budget. */
static int sqlite_retention_record_locked(int pressure, uint64_t groups,
                                          uint64_t rows, uint64_t bytes) {
  static const char *const names[2][3] = {
    {"local_retention_v1_expired_groups", "local_retention_v1_expired_rows", "local_retention_v1_expired_work_bytes"},
    {"local_retention_v1_capacity_groups", "local_retention_v1_capacity_rows", "local_retention_v1_capacity_work_bytes"}
  };
  uint64_t values[] = {groups, rows, bytes};
  sqlite3_stmt *st = NULL;
  if (!groups) return 0;
  if (sqlite3_prepare_v2(s_db,
      "INSERT INTO metrics(minute_unix,endpoint_id,metric_name,value) VALUES(0,'',?,?) "
      "ON CONFLICT(minute_unix,endpoint_id,metric_name) DO UPDATE SET value=metrics.value+excluded.value "
      "WHERE typeof(metrics.value)='integer' AND metrics.value>=0 "
      "AND metrics.value<=9223372036854775807-excluded.value;", -1, &st, NULL) != SQLITE_OK) goto failed;
  for (unsigned i = 0; i < 3u; ++i) {
    if (values[i] > INT64_MAX || sqlite3_bind_text(st, 1, names[pressure != 0][i], -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, (sqlite3_int64)values[i]) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(s_db) != 1 ||
        sqlite3_reset(st) != SQLITE_OK || sqlite3_clear_bindings(st) != SQLITE_OK) goto failed;
  }
  sqlite3_finalize(st); return 0;
failed:
  sqlite3_finalize(st);
  set_error("local retirement disposition write failed or counter overflowed; group preserved");
  return -1;
}

/* Cooperative wall-time bound. SQLite I/O and the current statement may
 * overrun; the next boundary yields, and helper rollback preserves the group. */
static int sqlite_retirement_yield(void *deadline) {
  return evidence_cache_clock_ns() >= *(const uint64_t *)deadline;
}

/* A whole candidate and its causal context are the unit of retirement. Legacy
 * rows, unknown owners and oversized groups stay present. A bounded number of
 * groups is examined; shared facts are charged conservatively to the work
 * budget even when another reference keeps them alive. */
static int sqlite_retire_candidate_groups(int pressure, sqlite3_int64 cutoff,
                                          unsigned *retired, EvidenceMaintenanceSlice *slice) {
  enum { MAX_CANDIDATES = 1000, MAX_WORK_ROWS = 4096 };
  char (*ids)[160] = NULL;
  sqlite3_int64 times[MAX_CANDIDATES];
  int classes[MAX_CANDIDATES];
  unsigned char held_ids[MAX_CANDIDATES] = {0};
  unsigned char eligible[MAX_CANDIDATES] = {0};
  unsigned char floor_protected[MAX_CANDIDATES] = {0};
  sqlite3_stmt *st = NULL;
  sqlite3_stmt *select_st = NULL;
  unsigned count = 0u, processed = 0u, groups = 0u, held = 0u, floor_held = 0u, work_rows = 0u;
  uint64_t work_bytes = 0u, retired_work_bytes = 0u, removed_rows = 0u, byte_limit = 0u;
  int rc = -1, began = 0, step;
  int64_t now = now_unix_ns(); uint64_t mono = edr_monotonic_ns();
  uint64_t deadline = slice->deadline_ns;
  *retired = 0u;
  if (sqlite_maintenance_yield(slice)) return 0;
  if (!sqlite_database_write_allow(slice->bytes_left)) return -1;
  ids = calloc(MAX_CANDIDATES, sizeof(*ids));
  if (!ids) { set_error("local retirement selector allocation failed"); goto done; }
  if (exec_sql("BEGIN IMMEDIATE;") != 0) {
    sqlite_maintenance_error("candidate retirement begin", sqlite3_errcode(s_db));
    goto done;
  }
  began = 1;
  if (sqlite_retention_clock_stage() != 0) goto done;
  if (sqlite3_prepare_v2(s_db,
      "SELECT page_size FROM pragma_page_size;", -1, &st, NULL) != SQLITE_OK ||
      sqlite3_step(st) != SQLITE_ROW || sqlite3_column_int64(st, 0) <= 0) goto storage_failed;
  uint64_t page_size = (uint64_t)sqlite3_column_int64(st, 0);
  sqlite3_finalize(st); st = NULL;
  if (sqlite3_prepare_v2(s_db, "PRAGMA wal_autocheckpoint;", -1, &st, NULL) != SQLITE_OK ||
      sqlite3_step(st) != SQLITE_ROW) goto storage_failed;
  sqlite3_int64 pages = sqlite3_column_int64(st, 0);
  /* SQLite's default checkpoint is 1000 pages. A disabled checkpoint does not
   * grant an unbounded reclamation transaction. The existing 1 MiB manifest
   * envelope gives a second upper bound of four such envelopes per slice. */
  uint64_t checkpoint_pages = pages > 0 && pages < 1000 ? (uint64_t)pages : 1000u;
  byte_limit = page_size * checkpoint_pages;
  if (byte_limit > 4u * EDR_EVIDENCE_MANIFEST_MAX_BYTES) byte_limit = 4u * EDR_EVIDENCE_MANIFEST_MAX_BYTES;
  if (byte_limit > slice->bytes_left) byte_limit = slice->bytes_left;
  sqlite3_finalize(st); st = NULL;
  if (exec_sql("CREATE TEMP TABLE IF NOT EXISTS evidence_retention_protected(candidate_id TEXT PRIMARY KEY);"
               "DELETE FROM evidence_retention_protected;") != 0) goto done;
  if (sqlite3_prepare_v2(s_db,
      "INSERT OR IGNORE INTO evidence_retention_protected(candidate_id) VALUES(?);", -1, &st, NULL) != SQLITE_OK) goto storage_failed;
  for (unsigned i = 0; i < EDR_EVIDENCE_CONTEXT_WINDOWS; ++i) {
    const ContextWindowSlot *w = &s_context_windows[i];
    if (!w->pid || context_window_nominally_ended(w, now, mono)) continue;
    if (!sqlite_maintenance_charge(slice,1,strlen(w->candidate_id)+32u)) { rc=0; goto done; }
    if (sqlite3_bind_text(st, 1, w->candidate_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE || sqlite3_reset(st) != SQLITE_OK) goto storage_failed;
  }
  sqlite3_finalize(st); st = NULL;
  int protection = sqlite_retention_protect_pmfe_locked(slice);
  if (protection != 0) { if (protection > 0) rc=0; goto done; }
  if (sqlite_maintenance_yield(slice)) { rc=0; goto done; }
  if (byte_limit > slice->bytes_left) byte_limit=slice->bytes_left;
  if (sqlite3_prepare_v2(s_db,
      "SELECT candidate_id,event_time_ns,local_retention_state='retained' AND created_ns>0 "
      "AND context_post_until_ns>0 AND context_post_until_ns<?1 "
      "AND (?2=1 OR (event_time_ns<CASE WHEN retention_value_class=2 THEN ?7 ELSE ?3 END "
      "AND created_ns<CASE WHEN retention_value_class=2 THEN ?7 ELSE ?3 END)) "
      "AND typeof(alert_context_protect_until_active_ms)='integer' "
      "AND alert_context_protect_until_active_ms>=0 AND alert_context_protect_until_active_ms<=?8 "
      "AND retention_value_class IN(1,2) "
      "AND NOT EXISTS(SELECT 1 FROM evidence_retention_protected x WHERE x.candidate_id=p.candidate_id),retention_value_class,"
      "typeof(alert_context_protect_until_active_ms)!='integer' OR alert_context_protect_until_active_ms<0 "
      "OR alert_context_protect_until_active_ms>?8 "
      "FROM p0_candidates p WHERE retention_policy_version=1 AND event_time_ns>0 "
      "AND (retention_value_class,event_time_ns,candidate_id)>(?6,?4,?5) "
      "ORDER BY retention_value_class,event_time_ns,candidate_id LIMIT 1;", -1, &select_st, NULL) != SQLITE_OK ||
      sqlite3_bind_int64(select_st, 1, now) != SQLITE_OK || sqlite3_bind_int(select_st, 2, pressure != 0) != SQLITE_OK ||
      sqlite3_bind_int64(select_st, 3, cutoff) != SQLITE_OK ||
      sqlite3_bind_int64(select_st, 4, s_retirement_cursor[pressure != 0].time) != SQLITE_OK ||
      sqlite3_bind_text(select_st, 5, s_retirement_cursor[pressure != 0].id, -1, SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_bind_int(select_st, 6, s_retirement_cursor[pressure != 0].value_class) != SQLITE_OK ||
      sqlite3_bind_int64(select_st, 7, now - (sqlite3_int64)s_status.selected_retention_hours * 3600LL * 1000000000LL) != SQLITE_OK ||
      sqlite3_bind_int64(select_st, 8, (sqlite3_int64)s_retention_clock.pending_ms) != SQLITE_OK) goto storage_failed;
  /* An empty indexed seek may wrap once without increasing the 1000-row
   * inspection budget. Late imports and a refilled cache can sort before the
   * previous cursor; they must not require a minute-long poll to be visible.
   * Process each selected group before selecting another: eager collection
   * can consume the whole cooperative deadline without advancing any owner.
   * Reset the SELECT before mutations, rather than changing its active scan. */
  unsigned wrapped = 0u;
  while (count < MAX_CANDIDATES && work_rows < MAX_WORK_ROWS && work_bytes < byte_limit) {
    if (sqlite_maintenance_yield(slice)) break;
    step = sqlite3_step(select_st);
    if (step == SQLITE_DONE) {
      if (count || wrapped || !s_retirement_cursor[pressure != 0].time ||
          sqlite_maintenance_yield(slice)) break;
      if (sqlite3_reset(select_st) != SQLITE_OK || sqlite3_bind_int64(select_st, 4, 0) != SQLITE_OK ||
          sqlite3_bind_text(select_st, 5, "", -1, SQLITE_STATIC) != SQLITE_OK ||
          sqlite3_bind_int(select_st, 6, 0) != SQLITE_OK) goto storage_failed;
      wrapped = 1u;
      continue;
    }
    if (step != SQLITE_ROW) goto storage_failed;
    const char *id = (const char *)sqlite3_column_text(select_st, 0);
    int n = sqlite3_column_bytes(select_st, 0);
    if (!id || n <= 0 || n >= (int)sizeof(ids[0]) || strlen(id) != (size_t)n) {
      set_error("local retirement candidate identity unavailable; group preserved"); goto done;
    }
    unsigned i = count;
    times[i] = sqlite3_column_int64(select_st, 1);
    eligible[i] = sqlite3_column_int(select_st, 2) == 1;
    classes[i] = sqlite3_column_int(select_st, 3);
    floor_protected[i] = sqlite3_column_int(select_st, 4) != 0;
    memcpy(ids[i], id, (size_t)n + 1u);
    if (sqlite3_reset(select_st) != SQLITE_OK) goto storage_failed;
    if (!sqlite_maintenance_charge(slice,1,(uint64_t)n+32u)) break;
    ++count;
    if (sqlite_maintenance_yield(slice)) break;
    EdrContextRetirement disposition;
    processed = i + 1u;
    if (!eligible[i] || work_rows == MAX_WORK_ROWS) {
      held_ids[i] = 1; ++held;
      if (floor_protected[i]) ++floor_held;
      goto next_candidate;
    }
    if (sqlite3_prepare_v2(s_db,
        "UPDATE p0_candidates SET local_retention_state='retirement_eligible' "
        "WHERE candidate_id=? AND retention_policy_version=1 AND local_retention_state='retained';",
        -1, &st, NULL) != SQLITE_OK || sqlite3_bind_text(st, 1, ids[i], -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(s_db) != 1) goto storage_failed;
    sqlite3_finalize(st); st = NULL;
    int decision = edr_context_store_retire_candidate(&s_context_store, ids[i],
        slice->rows_left < MAX_WORK_ROWS-work_rows ? slice->rows_left : MAX_WORK_ROWS-work_rows,
        slice->bytes_left < byte_limit-work_bytes ? slice->bytes_left : byte_limit-work_bytes,
        sqlite_retirement_yield, &deadline, &disposition);
    if (decision < 0) { set_error(s_context_store.error); goto done; }
    work_rows += disposition.work_rows;
    work_bytes += disposition.payload_bytes;
    slice->rows_left -= disposition.work_rows;
    slice->bytes_left -= disposition.payload_bytes;
    if (decision > 0) {
      ++held;
      if (sqlite3_prepare_v2(s_db, "UPDATE p0_candidates SET local_retention_state='retained' WHERE candidate_id=?;",
          -1, &st, NULL) != SQLITE_OK || sqlite3_bind_text(st, 1, ids[i], -1, SQLITE_TRANSIENT) != SQLITE_OK ||
          sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(s_db) != 1) goto storage_failed;
      sqlite3_finalize(st); st = NULL;
      held_ids[i] = 1;
      goto next_candidate;
    }
    retired_work_bytes += disposition.payload_bytes;
    removed_rows += disposition.candidates + disposition.references + disposition.artifacts + disposition.facts;
    ++groups;
next_candidate:
    if (sqlite3_bind_int64(select_st, 4, times[i]) != SQLITE_OK ||
        sqlite3_bind_text(select_st, 5, ids[i], -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(select_st, 6, classes[i]) != SQLITE_OK) goto storage_failed;
  }
  sqlite3_finalize(select_st); select_st = NULL;
  if (sqlite_retention_record_locked(pressure, groups, removed_rows, retired_work_bytes) != 0 ||
      sqlite_commit_candidate_transaction() != 0) goto done;
  began = 0;
  if (processed) {
    s_retirement_cursor[pressure != 0].value_class = classes[processed - 1u];
    s_retirement_cursor[pressure != 0].time = times[processed - 1u];
    snprintf(s_retirement_cursor[pressure != 0].id, sizeof(s_retirement_cursor[0].id), "%s", ids[processed - 1u]);
  } else if (!count) {
    memset(&s_retirement_cursor[pressure != 0], 0, sizeof(s_retirement_cursor[0]));
  }
  /* Retired groups must not be resurrected by late events in a nominally ended
   * RAM window. Clear only committed IDs, never an attempted/rolled-back group. */
  for (unsigned i = 0; i < processed; ++i) {
    if (held_ids[i]) continue;
    for (unsigned j = 0; j < EDR_EVIDENCE_CONTEXT_WINDOWS; ++j)
      if (!strcmp(s_context_windows[j].candidate_id, ids[i])) memset(&s_context_windows[j], 0, sizeof(s_context_windows[j]));
    for (unsigned j = 0; j < EDR_EVIDENCE_CANDIDATE_DEDUP_SLOTS; ++j)
      if (!strcmp(s_candidate_dedupe[j].candidate_id, ids[i])) memset(&s_candidate_dedupe[j], 0, sizeof(s_candidate_dedupe[j]));
  }
  s_status.retention_groups_retired += groups;
  s_status.retention_groups_held += held;
  s_status.retention_floor_held += floor_held;
  if (pressure) s_status.db_capacity_evicted += removed_rows;
  else s_status.db_retention_evicted += removed_rows;
  *retired = groups;
  rc = 0;
  goto done;
storage_failed:
  sqlite_maintenance_error("candidate group retirement", sqlite3_errcode(s_db));
done:
  sqlite3_finalize(st);
  sqlite3_finalize(select_st);
  if (began) sqlite_rollback_silent();
  if (rc != 0) s_status.retention_failures++;
  free(ids);
  return rc;
}

/* Called under the owner lock, once per preprocess turn. The caller releases
 * the lock and returns to event processing before any subsequent slice. */
static int sqlite_maintenance_reclaim_poll(void) {
  sqlite3_stmt *st = NULL;
  int result = 0, trim_memory;
  unsigned pages = s_maintenance_reclaim_pages < 256u
                       ? s_maintenance_reclaim_pages : 256u;
  int rc = sqlite3_prepare_v2(s_db, "PRAGMA freelist_count;", -1, &st, NULL);
  if (rc == SQLITE_OK) rc = sqlite3_step(st);
  if (rc != SQLITE_ROW) {
    sqlite_maintenance_error("freelist query", rc);
    sqlite3_finalize(st);
    goto failed;
  }
  sqlite3_int64 free_pages = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  if (free_pages < 0) {
    set_error("maintenance freelist query returned negative pages");
    goto failed;
  }
  if ((sqlite3_uint64)free_pages < pages) pages = (unsigned)free_pages;
  if (pages == 0u) {
    s_maintenance_reclaim_pages = 0u;
  } else {
    if (sqlite_maintenance_reclaim(pages) != 0) goto failed;
    s_maintenance_reclaim_pages -= pages;
    if (free_pages == pages) s_maintenance_reclaim_pages = 0u;
  }
  goto finish;
failed:
  result = -1;
  /* Restart from a fresh maintenance cycle after the existing minute backoff.
   * A delayed slice must not turn failure into a per-event retry loop. */
  s_maintenance_reclaim_pages = 0u;
  s_last_maintenance_ns = edr_monotonic_ns();
finish:
  if (!s_maintenance_reclaim_pages) s_last_maintenance_ns=edr_monotonic_ns();
  /* An empty reclaim turn must not discard the working set needed by the
   * unfinished pressure slice. Actual reclamation, errors and resource
   * pressure retain the existing memory release boundary. */
  trim_memory = result != 0 || pages != 0u ||
      !s_maintenance_pressure_pending || evidence_cache_pressure_active();
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  if (s_test_force_original_memory_trim) trim_memory = 1;
#endif
  if (trim_memory) {
    (void)sqlite3_db_release_memory(s_db);
    (void)sqlite3_release_memory(0);
  }
  refresh_db_size_status();
  return result;
}

static int sqlite_maintenance(int defer_reclaim) {
  unsigned pending_reclaim_pages = s_maintenance_reclaim_pages;
  s_maintenance_reclaim_pages = 0u;
  if (!s_db) { set_error("maintenance database unavailable"); return -1; }
  EvidenceMaintenanceSlice slice={evidence_cache_clock_ns()+20000000ULL,
      4u*EDR_EVIDENCE_MANIFEST_MAX_BYTES,4096u};
  s_status.maintenance_runs++;
  if (!sqlite_database_write_allow(slice.bytes_left)) return -1;
  int result = 0, trim_memory;
  /* Admission may take over an already scheduled reclaim slice. Consume at
   * most that one existing 256-page operation before optional TTL/clock writes
   * and their checkpoint can exhaust this turn's cooperative deadline. The
   * reclaim helper performs its own guarded checkpoint; never start a second
   * slice here. Free-page reclamation does not retire an evidence owner. */
  if (!defer_reclaim && pending_reclaim_pages != 0u) {
    s_maintenance_reclaim_pages = pending_reclaim_pages;
    if (sqlite_maintenance_yield(&slice)) goto finish;
    return sqlite_maintenance_reclaim_poll();
  }
  result = sqlite_flush_metrics_slice(0,&slice);
  if (result != 0) goto failed;
  sqlite3_int64 cutoff = now_unix_ns() - (int64_t)s_status.retention_hours * 3600LL * 1000000000LL;
  sqlite3_int64 cutoff_minute = (cutoff / 1000000000LL) / 60LL;
  unsigned retired = 0u;
  /* Rotate the starting stage after every slice so a large candidate backlog
   * cannot starve reconstructible copies or shared-command reclamation. */
  static const struct { const char *table,*clock,*condition,*bytes; } ttl[] = {
    {"process_cache","last_seen_ns","1","COALESCE(length(CAST(endpoint_id AS BLOB)),0)+COALESCE(length(CAST(tenant_id AS BLOB)),0)+COALESCE(length(CAST(name AS BLOB)),0)+COALESCE(length(CAST(path AS BLOB)),0)+COALESCE(length(CAST(cmdline AS BLOB)),0)+COALESCE(length(CAST(parent_name AS BLOB)),0)+COALESCE(length(CAST(parent_path AS BLOB)),0)+COALESCE(length(CAST(username AS BLOB)),0)+COALESCE(length(CAST(domain AS BLOB)),0)+COALESCE(length(CAST(user_sid AS BLOB)),0)+COALESCE(length(CAST(logon_id AS BLOB)),0)+COALESCE(length(CAST(identity_source AS BLOB)),0)+COALESCE(length(CAST(identity_quality AS BLOB)),0)+COALESCE(length(CAST(exe_hash AS BLOB)),0)+COALESCE(length(CAST(cmdline_truncated_fields AS BLOB)),0)+COALESCE(length(CAST(process_start_key AS BLOB)),0)+COALESCE(length(CAST(process_creation_filetime_100ns AS BLOB)),0)+COALESCE(length(CAST(process_generation_source AS BLOB)),0)+COALESCE(length(CAST(parent_process_start_key AS BLOB)),0)+COALESCE(length(CAST(parent_process_creation_filetime_100ns AS BLOB)),0)+COALESCE(length(CAST(parent_process_generation_source AS BLOB)),0)+64"},
    {"file_evidence","last_seen_ns","1","COALESCE(length(CAST(endpoint_id AS BLOB)),0)+COALESCE(length(CAST(path AS BLOB)),0)+COALESCE(length(CAST(sha256 AS BLOB)),0)"},
    {"network_ioc","last_seen_ns","1","COALESCE(length(CAST(endpoint_id AS BLOB)),0)+COALESCE(length(CAST(remote_ip AS BLOB)),0)+COALESCE(length(CAST(remote_url AS BLOB)),0)"},
    {"registry_evidence","last_seen_ns","1","COALESCE(length(CAST(endpoint_id AS BLOB)),0)+COALESCE(length(CAST(key_path AS BLOB)),0)+COALESCE(length(CAST(value_name AS BLOB)),0)+COALESCE(length(CAST(op AS BLOB)),0)"},
    {"command_results","updated_ns","1","COALESCE(length(CAST(command_id AS BLOB)),0)+COALESCE(length(CAST(command_type AS BLOB)),0)+COALESCE(length(CAST(status AS BLOB)),0)+COALESCE(length(CAST(detail AS BLOB)),0)+COALESCE(length(CAST(artifacts AS BLOB)),0)"},
    {"artifacts","created_ns","artifact_type='pmfe_followup_local_v1' AND upload_status IN('completed','expired','conflict')","COALESCE(length(CAST(artifact_id AS BLOB)),0)+COALESCE(length(CAST(endpoint_id AS BLOB)),0)+COALESCE(length(CAST(tenant_id AS BLOB)),0)+COALESCE(length(CAST(candidate_id AS BLOB)),0)+COALESCE(length(CAST(path AS BLOB)),0)+COALESCE(length(CAST(sha256 AS BLOB)),0)+COALESCE(length(CAST(manifest_json AS BLOB)),0)+COALESCE(length(CAST(minio_key AS BLOB)),0)+64"},
    {"metrics","minute_unix","NOT(minute_unix=0 AND endpoint_id='' AND metric_name IN('local_retention_v1_expired_groups','local_retention_v1_expired_rows','local_retention_v1_expired_work_bytes','local_retention_v1_capacity_groups','local_retention_v1_capacity_rows','local_retention_v1_capacity_work_bytes','" RETENTION_ACTIVE_CLOCK_KEY "'))","COALESCE(length(CAST(endpoint_id AS BLOB)),0)+COALESCE(length(CAST(metric_name AS BLOB)),0)"}
  };
  if (db_size_over_limit()) s_maintenance_pressure_pending=1;
  for (unsigned pass=0;pass<9u && !sqlite_maintenance_yield(&slice);++pass) {
    unsigned stage=s_maintenance_stage;
    s_maintenance_stage=(stage+1u)%9u;
    if (stage==0) {
      int pressure = 0;
      /* Share the existing candidate turn with live pressure. A dense set of
       * unexpired rows can otherwise spend every turn's deadline in normal
       * inspection before the later pressure loop gets a chance to run. */
      if (s_maintenance_pressure_pending) {
        pressure = sqlite_live_size_over_limit(sqlite_capacity_live_target());
        if (pressure < 0) goto failed;
        if (!pressure) s_maintenance_pressure_pending=0;
      }
      if (sqlite_retire_candidate_groups(pressure,cutoff,&retired,&slice)!=0) goto failed;
    } else if(stage==6) {
      if (sqlite_retire_command_facts(cutoff,&slice)!=0) goto failed;
    } else {
      unsigned i=stage<6 ? stage-1 : stage-2;
      if(sqlite_maintenance_delete(ttl[i].table,ttl[i].clock,ttl[i].condition,ttl[i].bytes,
           i==6 ? cutoff_minute : cutoff,&slice)!=0) goto failed;
    }
  }
  if (db_size_over_limit()) s_maintenance_pressure_pending=1;
  if (s_maintenance_pressure_pending) {
    uint64_t target = sqlite_capacity_live_target();
    /* Decide from live pages before checkpointing. A slow checkpoint can use
     * the entire cooperative time slice on every turn and otherwise starve
     * pressure retirement forever. Free pages do not justify eviction; the
     * live-page check below still protects that case. Checkpoint after work. */
    for (unsigned pass=0;pass<4u && !sqlite_maintenance_yield(&slice);++pass) {
      int over=sqlite_live_size_over_limit(target);
      if(over<0) goto failed;
      if(!over) { s_maintenance_pressure_pending=0; break; }
      if(sqlite_retire_candidate_groups(1,cutoff,&retired,&slice)!=0) goto failed;
      if(!retired && !s_retirement_cursor[1].time) break;
    }
    if (!sqlite_maintenance_yield(&slice) && sqlite_maintenance_checkpoint(SQLITE_CHECKPOINT_TRUNCATE)!=0) goto failed;
    refresh_db_size_status();
    if (s_status.db_bytes+s_status.wal_bytes>target) {
      s_maintenance_reclaim_pages=4096u;
      /* One current 256-page reclamation statement, then later owner polls.
       * Startup/admission obey the same bound and may reject until it drains. */
      if(!defer_reclaim && !sqlite_maintenance_yield(&slice) &&
          sqlite_maintenance_reclaim_poll()!=0) goto failed;
    }
  } else if(!sqlite_maintenance_yield(&slice) && sqlite_maintenance_checkpoint(SQLITE_CHECKPOINT_PASSIVE)!=0) goto failed;
  goto finish;
failed:
  s_maintenance_reclaim_pages=0u; result=-1;
finish:
  /* Preserve the bounded pager between unfinished pressure turns; repeatedly
   * starting a cold preflight can spend every cooperative slice before a
   * group commits. Completed work and resource/error paths still trim. */
  trim_memory = result != 0 || !s_maintenance_pressure_pending ||
      !sqlite_maintenance_yield(&slice) || evidence_cache_pressure_active();
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  if (s_test_force_original_memory_trim) trim_memory = 1;
#endif
  if (trim_memory) {
    (void)sqlite3_db_release_memory(s_db);
    (void)sqlite3_release_memory(0);
  }
  refresh_db_size_status();
  return result;
}

#endif

/* Admission reads SQLite's own page accounting rather than scanning payload
 * tables. The transaction includes the old-row lookup, growth check, write and
 * final page check; both in-process writers and other SQLite writers serialize.
 * No pressure cleanup is performed for this optional detailed copy. */
#if defined(EDR_HAVE_SQLITE)
static int sqlite_command_result_budget(uint64_t incoming, const char *command_id) {
  sqlite3_stmt *st = NULL;
  uint64_t live = 0u, prior = 0u;
  if (sqlite3_prepare_v2(s_db,
      "SELECT (page_count-freelist_count)*page_size "
      "FROM pragma_page_count,pragma_freelist_count,pragma_page_size;",
      -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW ||
      sqlite3_column_int64(st, 0) < 0) {
    sqlite3_finalize(st);
    set_error("command result page accounting failed");
    return -1;
  }
  live = (uint64_t)sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  st = NULL;
  if (sqlite3_prepare_v2(s_db,
      "SELECT length(CAST(command_id AS BLOB))+"
      "COALESCE(length(CAST(command_type AS BLOB)),0)+"
      "COALESCE(length(CAST(status AS BLOB)),0)+"
      "COALESCE(length(CAST(detail AS BLOB)),0)+"
      "COALESCE(length(CAST(artifacts AS BLOB)),0) "
      "FROM command_results WHERE command_id=?;", -1, &st, NULL) != SQLITE_OK) {
    sqlite3_finalize(st);
    set_error("command result prior size lookup failed");
    return -1;
  }
  if (sqlite3_bind_text(st, 1, command_id, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize(st);
    set_error("command result prior identity binding failed");
    return -1;
  }
  int rc = sqlite3_step(st);
  if (rc == SQLITE_ROW && sqlite3_column_int64(st, 0) >= 0)
    prior = (uint64_t)sqlite3_column_int64(st, 0);
  else if (rc != SQLITE_DONE) {
    sqlite3_finalize(st);
    set_error("command result prior size lookup failed");
    return -1;
  }
  sqlite3_finalize(st);
  uint64_t limit = (uint64_t)s_status.max_db_mb * 1024ULL * 1024ULL;
  uint64_t growth = incoming > prior ? incoming - prior : 0u;
  /* Reject a huge first write/update before SQLite can spill it to WAL.
   * The post-write live-page check also charges record/index/page overhead. */
  return live <= limit && growth <= limit - live;
}
#endif

int edr_local_evidence_cache_record_command_result(
    const char *command_id, const char *command_type, const char *status,
    int execution_status, int exit_code, const char *detail, const char *artifacts) {
  int outcome = EDR_EVIDENCE_COMMAND_RESULT_UNAVAILABLE;
  evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  sqlite3_stmt *st = NULL;
  int began = 0;
  if (!command_id || !command_id[0]) {
    outcome = EDR_EVIDENCE_COMMAND_RESULT_INVALID;
    set_error("command result identity missing");
    goto finish;
  }
  if (!s_db) {
    set_error("command result database unavailable");
    goto finish;
  }
  /* This is the existing DB+WAL admission scope, not an Agent-directory or
   * SHM/log hard cap. Reclamation remains on the existing maintenance path. */
  const char *fields[] = {command_id, command_type, status, detail, artifacts};
  uint64_t incoming = 0u;
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    size_t bytes = fields[i] ? strlen(fields[i]) : 0u;
    if (bytes > UINT64_MAX - incoming) goto capacity;
    incoming += bytes;
  }
  outcome = EDR_EVIDENCE_COMMAND_RESULT_STORAGE;
  if (!sqlite_physical_write_allow(incoming)) { outcome = EDR_EVIDENCE_COMMAND_RESULT_CAPACITY; ++s_status.command_results_capacity_rejected; goto finish; }
  if (exec_sql("BEGIN IMMEDIATE;") != 0) goto finish;
  began = 1;
  if (db_size_over_limit()) goto capacity;
  int admitted = sqlite_command_result_budget(incoming, command_id);
  if (admitted < 0) goto finish;
  if (!admitted) goto capacity;
  const char *sql =
      "INSERT INTO command_results(command_id,command_type,status,execution_status,exit_code,"
      "detail,artifacts,updated_ns) VALUES(?,?,?,?,?,?,?,?) "
      "ON CONFLICT(command_id) DO UPDATE SET command_type=excluded.command_type,"
      "status=excluded.status,execution_status=excluded.execution_status,"
      "exit_code=excluded.exit_code,detail=excluded.detail,artifacts=excluded.artifacts,"
      "updated_ns=excluded.updated_ns;";
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare command_results failed");
    goto finish;
  }
  const int parameters[] = {1, 2, 3, 6, 7};
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    if (sqlite3_bind_text(st, parameters[i], fields[i] ? fields[i] : "", -1,
                         SQLITE_TRANSIENT) != SQLITE_OK) {
      set_error("command result text binding failed");
      goto finish;
    }
  }
  if (sqlite3_bind_int64(st, 4, (sqlite3_int64)execution_status) != SQLITE_OK ||
      sqlite3_bind_int64(st, 5, (sqlite3_int64)exit_code) != SQLITE_OK ||
      sqlite3_bind_int64(st, 8, (sqlite3_int64)now_unix_ns()) != SQLITE_OK) {
    set_error("command result metadata binding failed");
    goto finish;
  }
  int rc = sqlite3_step(st);
  sqlite3_finalize(st);
  st = NULL;
  if (rc != SQLITE_DONE) {
    set_error("upsert command_results failed");
    goto finish;
  }
  int over = sqlite_live_size_over_limit((uint64_t)s_status.max_db_mb * 1024ULL * 1024ULL);
  if (over < 0) goto finish;
  if (over) goto capacity;
  if (exec_sql("COMMIT;") != 0) goto finish;
  began = 0;
  outcome = EDR_EVIDENCE_COMMAND_RESULT_STORED;
  s_status.command_results_written++;
  goto finish;
capacity:
  outcome = EDR_EVIDENCE_COMMAND_RESULT_CAPACITY;
  s_status.command_results_capacity_rejected++;
  s_status.db_budget_dropped++;
  set_error("command result copy size budget exceeded");
finish:
  sqlite3_finalize(st);
  if (began && sqlite3_exec(s_db, "ROLLBACK;", NULL, NULL, NULL) != SQLITE_OK &&
      !sqlite3_get_autocommit(s_db)) {
    set_error("command result rollback failed; database transaction remains active");
    outcome = EDR_EVIDENCE_COMMAND_RESULT_STORAGE;
  }
#else
  (void)command_id;
  (void)command_type;
  (void)status;
  (void)execution_status;
  (void)exit_code;
  (void)detail;
  (void)artifacts;
#endif
  if (outcome != EDR_EVIDENCE_COMMAND_RESULT_STORED &&
      outcome != EDR_EVIDENCE_COMMAND_RESULT_CAPACITY)
    s_status.command_results_failed++;
  evidence_cache_unlock();
  return outcome;
}

/* A command fact is immutable for one exact process generation. The existing
 * artifact retention/capacity owner also governs these rows; they are embedded
 * in the event before queue admission, not a new file-upload work queue. */
#if defined(EDR_HAVE_SQLITE)
static int command_fact_key(const EdrBehaviorRecord *r, char key[80]) {
  EdrSha256Ctx ctx;
  uint8_t digest[32];
  if (!r || !r->tenant_id[0] || !r->endpoint_id[0] || !r->pid ||
      !r->process_start_key || !r->process_creation_filetime_100ns ||
      !memchr(r->tenant_id, 0, sizeof(r->tenant_id)) ||
      !memchr(r->endpoint_id, 0, sizeof(r->endpoint_id))) return 0;
  edr_sha256_init(&ctx);
  candidate_digest_text(&ctx, r->tenant_id);
  candidate_digest_text(&ctx, r->endpoint_id);
  candidate_digest_u64(&ctx, r->pid);
  candidate_digest_u64(&ctx, r->process_start_key);
  candidate_digest_u64(&ctx, r->process_creation_filetime_100ns);
  edr_sha256_final(&ctx, digest);
  memcpy(key, "command:", 8u);
  for (size_t i = 0; i < 32u; ++i) snprintf(key + 8u + 2u*i, 3u, "%02x", digest[i]);
  return 1;
}

/* Full commands are shared by exact generation. Candidate references and both
 * subject/parent process-cache tuples own them; frozen queue wire is inline.
 * Unknown older artifacts are deliberately outside this retirement authority. */
static int sqlite_retire_command_facts(sqlite3_int64 cutoff, EvidenceMaintenanceSlice *slice) {
  if (sqlite_maintenance_yield(slice)) return 0;
  if (!sqlite_database_write_allow(slice->bytes_left)) return -1;
  sqlite3_int64 cursor_time = s_command_retirement_cursor.time;
  const char *cursor_id = s_command_retirement_cursor.id;
  sqlite3_stmt *st = NULL, *del = NULL;
  char ids[128][80]; unsigned count = 0, inspected = 0;
  uint64_t work_bytes = 0;
  sqlite3_int64 last_time = cursor_time; char last_id[80];
  copy_s(last_id, sizeof(last_id), cursor_id);
  if (exec_sql("BEGIN IMMEDIATE;") != 0) return -1;
  if (sqlite3_prepare_v2(s_db,
      "SELECT artifact_id,created_ns,endpoint_id,tenant_id,command_owner_pid,command_owner_start_key,command_owner_creation,"
      "length(CAST(manifest_json AS BLOB)) FROM artifacts a WHERE artifact_type='process_command_line' "
      "AND command_retention_policy=1 AND created_ns>0 AND created_ns<?1 AND (created_ns,artifact_id)>(?2,?3) "
      "AND upload_status IN('embedded','conflict') AND candidate_id='' AND COALESCE(minio_key,'')='' "
      "ORDER BY created_ns,artifact_id LIMIT 128;", -1, &st, NULL) != SQLITE_OK ||
      sqlite3_bind_int64(st, 1, cutoff) != SQLITE_OK || sqlite3_bind_int64(st, 2, cursor_time) != SQLITE_OK ||
      sqlite3_bind_text(st, 3, cursor_id, -1, SQLITE_STATIC) != SQLITE_OK) goto failed;
  int step;
  while ((step = sqlite3_step(st)) == SQLITE_ROW) {
    if (sqlite_maintenance_yield(slice)) break;
    const char *id = (const char *)sqlite3_column_text(st, 0), *ep = (const char *)sqlite3_column_text(st, 2);
    const char *tenant = (const char *)sqlite3_column_text(st, 3);
    uint32_t pid = (uint32_t)sqlite3_column_int64(st, 4);
    uint64_t start = 0, creation = 0;
    const char *start_text = (const char *)sqlite3_column_text(st, 5), *creation_text = (const char *)sqlite3_column_text(st, 6);
    ++inspected;
    sqlite3_int64 bytes = sqlite3_column_int64(st, 7);
    if (bytes < 0 || !sqlite_maintenance_charge(slice,2,(uint64_t)bytes+128u)) break;
    if (id && sqlite3_column_bytes(st,0)==72 && strlen(id)==72u) {
      last_time=sqlite3_column_int64(st,1); copy_s(last_id,sizeof(last_id),id);
    }
    if (!id || strlen(id) != 72u || sqlite3_column_bytes(st, 0) != 72 || !ep || !ep[0] || !tenant || !tenant[0] || !pid ||
        !sqlite_decimal_u64(start_text, &start) || !sqlite_decimal_u64(creation_text, &creation) || !start || !creation) continue;
    last_time = sqlite3_column_int64(st, 1); copy_s(last_id, sizeof(last_id), id);
    if ((uint64_t)bytes > 4u * EDR_EVIDENCE_MANIFEST_MAX_BYTES - work_bytes) break;
    work_bytes += (uint64_t)bytes;
    int ram_owner = 0;
    for (unsigned i = 0; i < EDR_EVIDENCE_PROC_SLOTS && !ram_owner; ++i) {
      const ProcSlot *p = &s_proc[i];
      if (!strcmp(p->endpoint_id, ep) && !strcmp(p->tenant_id, tenant) &&
          ((p->pid == pid && p->generation.process_start_key == start && p->generation.creation_filetime_100ns == creation) ||
           (p->ppid == pid && p->parent_generation.process_start_key == start && p->parent_generation.creation_filetime_100ns == creation))) ram_owner = 1;
    }
    if (!ram_owner) copy_s(ids[count++], sizeof(ids[0]), id);
  }
  if (step != SQLITE_DONE && step != SQLITE_ROW) goto failed;
  sqlite3_finalize(st); st = NULL;
  if (sqlite3_prepare_v2(s_db,
      "DELETE FROM artifacts WHERE artifact_id=?1 AND artifact_type='process_command_line' AND command_retention_policy=1 "
      "AND NOT EXISTS(SELECT 1 FROM p0_candidates WHERE subject_command_fact_id=?1 OR parent_command_fact_id=?1) "
      "AND NOT EXISTS(SELECT 1 FROM process_cache p WHERE p.endpoint_id=artifacts.endpoint_id AND p.tenant_id=artifacts.tenant_id "
      "AND ((p.pid=artifacts.command_owner_pid AND p.process_start_key=artifacts.command_owner_start_key AND p.process_creation_filetime_100ns=artifacts.command_owner_creation) "
      "OR (p.ppid=artifacts.command_owner_pid AND p.parent_process_start_key=artifacts.command_owner_start_key AND p.parent_process_creation_filetime_100ns=artifacts.command_owner_creation)));",
      -1, &del, NULL) != SQLITE_OK) goto failed;
  uint64_t removed = 0;
  for (unsigned i = 0; i < count; ++i) {
    if (evidence_cache_clock_ns() >= slice->deadline_ns) break;
    if (sqlite3_bind_text(del, 1, ids[i], -1, SQLITE_TRANSIENT) != SQLITE_OK || sqlite3_step(del) != SQLITE_DONE) goto failed;
    removed += (unsigned)sqlite3_changes(s_db);
    if (sqlite3_reset(del) != SQLITE_OK) goto failed;
  }
  sqlite3_finalize(del); del = NULL;
  if (exec_sql("COMMIT;") != 0) goto failed;
  if (inspected) { s_command_retirement_cursor.time = last_time; copy_s(s_command_retirement_cursor.id, sizeof(s_command_retirement_cursor.id), last_id); }
  else memset(&s_command_retirement_cursor, 0, sizeof(s_command_retirement_cursor));
  s_status.db_retention_evicted += removed;
  return 0;
failed:
  sqlite3_finalize(st); sqlite3_finalize(del); sqlite_rollback_silent();
  set_error("command fact retirement failed; uncommitted facts preserved"); return -1;
}

static char *read_command_fact_locked(const EdrBehaviorRecord *r) {
  char key[80], hash[65];
  char *result = NULL;
  sqlite3_stmt *st = NULL;
  if (!s_db || !command_fact_key(r, key)) return NULL;
  if (sqlite3_prepare_v2(s_db,
        "SELECT manifest_json,sha256 FROM artifacts WHERE artifact_id=? AND tenant_id=? "
        "AND endpoint_id=? AND artifact_type='process_command_line' AND upload_status='embedded'", -1, &st, NULL) != SQLITE_OK)
    return NULL;
  bind_text(st, 1, key); bind_text(st, 2, r->tenant_id); bind_text(st, 3, r->endpoint_id);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const char *json = (const char *)sqlite3_column_text(st, 0);
    const char *expected = (const char *)sqlite3_column_text(st, 1);
    int bytes = sqlite3_column_bytes(st, 0);
    cJSON *root = json && bytes > 0 && (size_t)bytes < EDR_PROCESS_COMMAND_FACT_CAP * 6u + 200u
        ? cJSON_Parse(json) : NULL;
    const cJSON *command = cJSON_GetObjectItemCaseSensitive(root, "command_line");
    const cJSON *reference = cJSON_GetObjectItemCaseSensitive(root, "reference");
    if (cJSON_IsString(command) && command->valuestring[0]) {
      size_t n = strlen(command->valuestring);
      if (n < EDR_PROCESS_COMMAND_FACT_CAP && manifest_utf8_valid(command->valuestring) &&
          edr_sha256_hex((const uint8_t *)command->valuestring, n, hash) == 0 &&
          expected && strcmp(expected, hash) == 0 && cJSON_IsString(reference) &&
          strcmp(reference->valuestring, key) == 0) {
        result = (char *)malloc(n + 1u);
        if (result) memcpy(result, command->valuestring, n + 1u);
      } else set_error("command fact hash/encoding/size invalid");
    }
    cJSON_Delete(root);
  }
  sqlite3_finalize(st);
  return result;
}
#endif

int edr_local_evidence_cache_save_command_fact(const EdrBehaviorRecord *r, const char *command) {
  int rc = -1;
  evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  char key[80], hash[65];
  sqlite3_stmt *st = NULL;
  cJSON *root = NULL;
  char *json = NULL;
  int began = 0;
  size_t n = command ? strlen(command) : 0u;
  set_error("complete command fact unavailable: invalid identity, encoding, or storage");
  if (!s_db || !command_fact_key(r, key) || !n || n >= EDR_PROCESS_COMMAND_FACT_CAP ||
      !manifest_utf8_valid(command) || edr_sha256_hex((const uint8_t *)command, n, hash)) goto done;
  /* Pressure work precedes the owner transaction. All subsequent reads and
   * admission serialize with other SQLite writers, including process writes. */
  if (!sqlite_size_budget_allow() || exec_sql("BEGIN IMMEDIATE;")) goto done;
  began = 1;
  char *prior = read_command_fact_locked(r);
  if (prior) {
    int equal = !strcmp(prior, command);
    free(prior);
    if (!equal) {
      if (sqlite3_prepare_v2(s_db, "UPDATE artifacts SET upload_status='conflict' WHERE artifact_id=?",
          -1, &st, NULL) != SQLITE_OK || sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
          sqlite3_step(st) != SQLITE_DONE) { set_error("command fact conflict could not be persisted"); goto done; }
      sqlite3_finalize(st); st = NULL;
    }
    if (exec_sql("COMMIT;")) goto done;
    began = 0; rc = equal ? 0 : -1;
    if (!equal) set_error("same-generation command fact conflict; reference invalidated");
    goto done;
  }
  root = cJSON_CreateObject();
  if (!manifest_add_text(root, "command_line", command) || !manifest_add_text(root, "reference", key) ||
      !(json = cJSON_PrintUnformatted(root))) { set_error("command fact serialization failed"); goto done; }
  if (sqlite3_prepare_v2(s_db, "SELECT (page_count-freelist_count)*page_size FROM pragma_page_count,pragma_freelist_count,pragma_page_size;",
      -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW || sqlite3_column_int64(st, 0) < 0) {
    set_error("command fact page accounting failed"); goto done;
  }
  uint64_t live = (uint64_t)sqlite3_column_int64(st, 0), limit = (uint64_t)s_status.max_db_mb * 1024u * 1024u;
  sqlite3_finalize(st); st = NULL;
  if (live > limit || strlen(json) + strlen(key) + strlen(r->tenant_id) + strlen(r->endpoint_id) + sizeof(hash) > limit - live) {
    set_error("command fact capacity exhausted"); ++s_status.db_budget_dropped; goto done;
  }
  if (sqlite3_prepare_v2(s_db,
      "INSERT INTO artifacts(artifact_id,endpoint_id,tenant_id,candidate_id,artifact_type,sha256,manifest_json,created_ns,upload_status,minio_key,"
      "command_retention_policy,command_owner_pid,command_owner_start_key,command_owner_creation) "
      "VALUES(?,?,?,'','process_command_line',?,?,?,'embedded','',1,?,?,?) ON CONFLICT(artifact_id) DO NOTHING;", -1, &st, NULL) != SQLITE_OK) goto done;
  bind_text(st, 1, key); bind_text(st, 2, r->endpoint_id); bind_text(st, 3, r->tenant_id);
  bind_text(st, 4, hash); bind_text(st, 5, json);
  sqlite3_bind_int64(st, 6, (sqlite3_int64)now_unix_ns()); sqlite3_bind_int64(st, 7, r->pid);
  char start[32], creation[32];
  sqlite_u64_decimal(r->process_start_key, start); sqlite_u64_decimal(r->process_creation_filetime_100ns, creation);
  bind_text(st, 8, start); bind_text(st, 9, creation);
  if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(s_db) != 1) {
    set_error("command fact commit failed or existing fact invalid"); goto done;
  }
  sqlite3_finalize(st); st = NULL;
  if (sqlite_live_size_over_limit(limit) != 0) { set_error("command fact page budget exceeded"); ++s_status.db_budget_dropped; goto done; }
  if (exec_sql("COMMIT;")) goto done;
  began = 0; ++s_status.artifacts_written; rc = 0;
done:
  sqlite3_finalize(st);
  if (began) sqlite_rollback_silent();
  cJSON_free(json); cJSON_Delete(root);
#else
  (void)r; (void)command;
#endif
  if (!rc) set_error("");
  evidence_cache_unlock();
  return rc;
}

/* PMFE follow-ups use the existing artifacts owner. The original frame is
 * immutable, generation-bound and hash-verified; a result is authorized only
 * after its exact final wire is committed, independently of delivery ACK. */
#define PMFE_ASSOC_TYPE "pmfe_followup_local_v1"
#define PMFE_ASSOC_CAP 64u
#define PMFE_ASSOC_TTL_NS (3600LL * 1000000000LL)
#define PMFE_ASSOC_LEASE_NS (300LL * 1000000000LL)

#if defined(EDR_HAVE_SQLITE)
static void pmfe_error(unsigned cause,const char *detail) {
  if (s_status.pmfe_failures!=UINT64_MAX) ++s_status.pmfe_failures;
  s_status.pmfe_cause_code=cause;
  set_error(detail);
}
static void pmfe_refresh_inventory(EdrEvidenceCacheStatus *status) {
  sqlite3_stmt *st=NULL;
  if (!s_db || sqlite3_prepare_v2(s_db,
      "SELECT upload_status,COUNT(*) FROM artifacts WHERE artifact_type='" PMFE_ASSOC_TYPE "' GROUP BY upload_status",
      -1,&st,NULL)!=SQLITE_OK) return;
  while (sqlite3_step(st)==SQLITE_ROW) {
    const char *state=(const char *)sqlite3_column_text(st,0);
    unsigned n=(unsigned)sqlite3_column_int(st,1);
    if (!state) continue;
    if (!strcmp(state,"scheduled")) status->pmfe_scheduled=n;
    else if (!strcmp(state,"running")) status->pmfe_running=n;
    else if (!strcmp(state,"result_bound")) status->pmfe_result_bound=n;
    else if (!strcmp(state,"result_acked")) status->pmfe_result_acked=n;
    else if (!strcmp(state,"expired")) status->pmfe_expired=n;
    if (strcmp(state,"completed") && strcmp(state,"expired") && strcmp(state,"conflict")) status->pmfe_active+=n;
  }
  sqlite3_finalize(st);
}
static const char *pmfe_text(const cJSON *root, const char *name) {
  const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
  return cJSON_IsString(v) && v->valuestring ? v->valuestring : "";
}
static uint64_t pmfe_u64(const cJSON *root, const char *name) {
  const char *s = pmfe_text(root, name); char *end = NULL;
  if (!s[0]) return 0u;
  for (const char *p = s; *p; ++p) if (*p < '0' || *p > '9') return 0u;
  errno = 0; unsigned long long value = strtoull(s, &end, 10);
  return errno || !end || *end ? 0u : (uint64_t)value;
}
static int pmfe_put_u64(cJSON *root, const char *name, uint64_t value) {
  char s[32]; snprintf(s, sizeof(s), "%llu", (unsigned long long)value);
  cJSON_DeleteItemFromObjectCaseSensitive(root, name);
  return manifest_add_text(root, name, s);
}
static char *pmfe_hex(const uint8_t *frame, size_t len) {
  if (!frame || !len || len > EDR_EGRESS_FRAME_MAX) return NULL;
  char *s = malloc(2u * len + 1u);
  if (s) for (size_t i = 0; i < len; ++i) snprintf(s + 2u*i, 3u, "%02x", frame[i]);
  return s;
}
static uint8_t *pmfe_unhex(const char *s, size_t *len) {
  size_t n = strlen(s); *len = 0u;
  if (!n || n % 2u || n / 2u > EDR_EGRESS_FRAME_MAX) return NULL;
  uint8_t *out = malloc(n / 2u); if (!out) return NULL;
  for (size_t i = 0; i < n; i += 2u) {
    unsigned byte = 0u;
    for (size_t j = 0; j < 2u; ++j) {
      char c = s[i+j]; unsigned v;
      if (c >= '0' && c <= '9') v = (unsigned)(c-'0');
      else if (c >= 'a' && c <= 'f') v = (unsigned)(c-'a')+10u;
      else { free(out); return NULL; }
      byte = byte * 16u + v;
    }
    out[i/2u] = (uint8_t)byte;
  }
  *len = n / 2u; return out;
}
static int pmfe_key(const char *alert, const char *endpoint, const char *tenant, char key[80]) {
  if (!alert || !alert[0] || strlen(alert) >= 64u || !endpoint || !endpoint[0] ||
      strlen(endpoint) >= 48u || !tenant || !tenant[0] || strlen(tenant) >= 64u) return 0;
  EdrSha256Ctx ctx; uint8_t digest[32]; edr_sha256_init(&ctx);
  candidate_digest_text(&ctx, tenant); candidate_digest_text(&ctx, endpoint);
  candidate_digest_text(&ctx, alert); edr_sha256_final(&ctx, digest);
  memcpy(key, "pmfe:", 5u);
  for (size_t i = 0; i < 32u; ++i) snprintf(key+5u+2u*i, 3u, "%02x", digest[i]);
  return 1;
}
static int pmfe_original_scope_verified(const cJSON *root,const uint8_t *wire,size_t len) {
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event)); if (!event) return 0;
  const cJSON *pid=cJSON_GetObjectItemCaseSensitive(root,"pid");
  pb_istream_t stream=pb_istream_from_buffer(wire,len);
  int valid=pb_decode(&stream,edr_v1_BehaviorEvent_fields,event) &&
      event->type==EDR_EVENT_PROTOCOL_SHELLCODE && cJSON_IsNumber(pid) && pid->valuedouble==event->pid &&
      event->process_start_key==pmfe_u64(root,"process_start_key") &&
      event->process_creation_filetime_100ns==pmfe_u64(root,"process_creation_filetime_100ns") &&
      event->event_time_ns>0 && (uint64_t)event->event_time_ns==pmfe_u64(root,"source_event_time_ns") &&
      !strcmp(event->endpoint_id,pmfe_text(root,"endpoint_id")) &&
      !strcmp(event->tenant_id,pmfe_text(root,"tenant_id")) &&
      !strcmp(event->event_id,pmfe_text(root,"original_event_id"));
  cJSON *ctx=valid ? cJSON_ParseWithOpts(event->ave_result_json,NULL,1) : NULL;
  const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence");
  valid=valid && !strcmp(pmfe_text(engine,"alert_id"),pmfe_text(root,"source_alert_id"));
  cJSON_Delete(ctx); free(event); return valid;
}
static int pmfe_result_scope_verified(const cJSON *root,const uint8_t *wire,size_t len) {
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event)); if (!event) return 0;
  const cJSON *pid=cJSON_GetObjectItemCaseSensitive(root,"pid");
  pb_istream_t stream=pb_istream_from_buffer(wire,len);
  int valid=pb_decode(&stream,edr_v1_BehaviorEvent_fields,event) &&
      event->type==EDR_EVENT_PMFE_SCAN_RESULT && cJSON_IsNumber(pid) && pid->valuedouble==event->pid &&
      event->process_start_key==pmfe_u64(root,"process_start_key") &&
      event->process_creation_filetime_100ns==pmfe_u64(root,"process_creation_filetime_100ns") &&
      event->event_time_ns>0 && (uint64_t)event->event_time_ns==pmfe_u64(root,"result_event_time_ns") &&
      !strcmp(event->endpoint_id,pmfe_text(root,"endpoint_id")) &&
      !strcmp(event->tenant_id,pmfe_text(root,"tenant_id")) &&
      !strcmp(event->event_id,pmfe_text(root,"result_event_id"));
  cJSON *ctx=valid ? cJSON_ParseWithOpts(event->ave_result_json,NULL,1) : NULL;
  const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence");
  valid=valid && !strcmp(pmfe_text(engine,"schema"),"pmfe_result_v1") &&
      !strcmp(pmfe_text(engine,"detector"),"pmfe") &&
      cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(engine,"followup_only")) &&
      !strcmp(pmfe_text(engine,"source_alert_id"),pmfe_text(root,"source_alert_id")) &&
      !strcmp(pmfe_text(engine,"status"),pmfe_text(root,"result_status")) &&
      !strcmp(pmfe_text(engine,"verdict"),pmfe_text(root,"result_verdict"));
  cJSON_Delete(ctx); free(event); return valid;
}
static cJSON *pmfe_read_locked(const char *key, char state[32]) {
  sqlite3_stmt *st = NULL; cJSON *root = NULL; state[0] = 0;
  if (s_db && sqlite3_prepare_v2(s_db,
      "SELECT manifest_json,sha256,upload_status FROM artifacts WHERE artifact_id=? AND artifact_type='" PMFE_ASSOC_TYPE "'",
      -1, &st, NULL) == SQLITE_OK) {
    bind_text(st, 1, key);
    if (sqlite3_step(st) == SQLITE_ROW) {
      const char *json = (const char *)sqlite3_column_text(st, 0);
      int n = sqlite3_column_bytes(st, 0);
      root = json && n > 0 && (unsigned)n <= EDR_EVIDENCE_MANIFEST_MAX_BYTES
          ? cJSON_ParseWithOpts(json, NULL, 1) : NULL;
      const char *column_hash = (const char *)sqlite3_column_text(st, 1);
      size_t bytes = 0; char hash[65];
      uint8_t *wire = pmfe_unhex(pmfe_text(root, "original_wire_hex"), &bytes);
      if (!cJSON_IsObject(root) || strcmp(pmfe_text(root,"schema"),PMFE_ASSOC_TYPE) ||
          !wire || edr_sha256_hex(wire, bytes, hash) || !column_hash ||
          strcmp(hash,column_hash) || strcmp(hash,pmfe_text(root,"original_sha256")) ||
          !pmfe_original_scope_verified(root,wire,bytes)) {
        cJSON_Delete(root); root = NULL; pmfe_error(2u,"pmfe association original hash invalid");
      } else {
        copy_s(state,32u,(const char *)sqlite3_column_text(st,2));
        if (!strcmp(state,"result_bound") || !strcmp(state,"result_acked") || !strcmp(state,"completed")) {
          size_t result_len=0; uint8_t *result=pmfe_unhex(pmfe_text(root,"result_wire_hex"),&result_len);
          if (!result || edr_sha256_hex(result,result_len,hash) ||
              strcmp(hash,pmfe_text(root,"result_sha256")) || !pmfe_result_scope_verified(root,result,result_len)) {
            cJSON_Delete(root); root=NULL; pmfe_error(2u,"pmfe association result hash or binding invalid");
          }
          free(result);
        }
      }
      free(wire);
    }
  }
  sqlite3_finalize(st); return root;
}
static int pmfe_write_locked(const char *key, cJSON *root, const char *state) {
  char *json = cJSON_PrintUnformatted(root); sqlite3_stmt *st = NULL; int rc = -1;
  if (!json || strlen(json) > EDR_EVIDENCE_MANIFEST_MAX_BYTES || !sqlite_physical_write_allow(json ? strlen(json) : 0u) ||
      exec_sql("PRAGMA synchronous=FULL;") || exec_sql("BEGIN IMMEDIATE;")) goto done;
  if (sqlite3_prepare_v2(s_db,
      "INSERT INTO artifacts(artifact_id,endpoint_id,tenant_id,candidate_id,artifact_type,sha256,manifest_json,created_ns,upload_status)"
      " VALUES(?,?,?,?,'" PMFE_ASSOC_TYPE "',?,?,?,?) ON CONFLICT(artifact_id) DO UPDATE SET manifest_json=excluded.manifest_json,upload_status=excluded.upload_status",
      -1,&st,NULL) == SQLITE_OK) {
    bind_text(st,1,key); bind_text(st,2,pmfe_text(root,"endpoint_id"));
    bind_text(st,3,pmfe_text(root,"tenant_id")); bind_text(st,4,pmfe_text(root,"original_event_id"));
    bind_text(st,5,pmfe_text(root,"original_sha256")); bind_text(st,6,json);
    sqlite3_bind_int64(st,7,(sqlite3_int64)pmfe_u64(root,"created_ns")); bind_text(st,8,state);
    if (sqlite3_step(st)==SQLITE_DONE && sqlite_commit_candidate_transaction()==0) rc=0;
    else sqlite_rollback_silent();
  } else sqlite_rollback_silent();
done:
  sqlite3_finalize(st); cJSON_free(json);
  (void)exec_sql("PRAGMA synchronous=NORMAL;");
  if (rc) pmfe_error(1u,"pmfe association FULL commit failed");
  return rc;
}
static int pmfe_task_from_root(const cJSON *root, EdrPmfeFollowupTask *t) {
  memset(t,0,sizeof(*t));
  const cJSON *pid=cJSON_GetObjectItemCaseSensitive(root,"pid");
  const cJSON *band=cJSON_GetObjectItemCaseSensitive(root,"band");
  if (!cJSON_IsNumber(pid) || pid->valuedouble<1 || pid->valuedouble>UINT32_MAX ||
      (double)(uint32_t)pid->valuedouble!=pid->valuedouble || !cJSON_IsNumber(band) ||
      band->valuedouble<0 || band->valuedouble>2 ||
      band->valuedouble!=(double)(uint32_t)band->valuedouble) return 0;
  t->pid=(uint32_t)pid->valuedouble; t->band=(uint32_t)band->valuedouble;
  t->process_start_key=pmfe_u64(root,"process_start_key");
  t->process_creation_filetime_100ns=pmfe_u64(root,"process_creation_filetime_100ns");
  t->source_event_time_ns=(int64_t)pmfe_u64(root,"source_event_time_ns");
  t->vad_hint_va=pmfe_u64(root,"vad_hint_va");
  copy_s(t->source_alert_id,sizeof(t->source_alert_id),pmfe_text(root,"source_alert_id"));
  copy_s(t->endpoint_id,sizeof(t->endpoint_id),pmfe_text(root,"endpoint_id"));
  copy_s(t->tenant_id,sizeof(t->tenant_id),pmfe_text(root,"tenant_id"));
  return t->process_start_key && t->process_creation_filetime_100ns &&
      t->source_event_time_ns>0 && pmfe_key(t->source_alert_id,t->endpoint_id,t->tenant_id,t->association_id);
}
/* The caller owns the cache mutex and an IMMEDIATE transaction, and has
 * cleared temp.evidence_retention_protected. PMFE's immutable wire proves the
 * owner scope; its artifacts.candidate_id is a source event id, not a P0 id.
 * Provider enrichment may reuse another source's candidate id. Protect the
 * whole proven process generation as well as the canonical source id rather
 * than scan every bundle's bounded source_event_ids array. An unbound older
 * candidate in that PID scope cannot safely be classified as a non-alias.
 * The existing 4096-reference maintenance batch bound also bounds this
 * temporary selector. Exhaustion stops reclamation, never weakens the pin. */
static int sqlite_retention_protect_pmfe_locked(EvidenceMaintenanceSlice *slice) {
  enum { PROTECTED_LIMIT = 4096 };
  sqlite3_stmt *owners = NULL, *insert = NULL, *generation = NULL, *unknown = NULL;
  sqlite3_stmt *count_stmt = NULL;
  EdrBehaviorRecord *identity = NULL;
  cJSON *root = NULL;
  const char *failure = "retention PMFE protection storage failure";
  unsigned owner_count = 0u, protected_count = 0u, generation_rows = 0u;
  int rc = -1, step;
  if (!s_db || sqlite3_get_autocommit(s_db)) {
    set_error("retention PMFE protection requires a transaction");
    return -1;
  }
  if (sqlite3_prepare_v2(s_db,
      "SELECT COUNT(*) FROM temp.evidence_retention_protected;",
      -1, &count_stmt, NULL) != SQLITE_OK ||
      sqlite3_step(count_stmt) != SQLITE_ROW ||
      sqlite3_column_type(count_stmt, 0) != SQLITE_INTEGER ||
      sqlite3_column_int64(count_stmt, 0) < 0 ||
      sqlite3_column_int64(count_stmt, 0) > PROTECTED_LIMIT) goto done;
  protected_count = (unsigned)sqlite3_column_int64(count_stmt, 0);
  sqlite3_finalize(count_stmt); count_stmt = NULL;
  if (sqlite3_prepare_v2(s_db,
      "SELECT artifact_id,upload_status,endpoint_id,tenant_id,candidate_id,length(CAST(manifest_json AS BLOB)) FROM artifacts "
      "WHERE artifact_type='" PMFE_ASSOC_TYPE "' "
      "AND (upload_status IS NULL OR upload_status NOT IN ('completed','expired','conflict')) "
      "ORDER BY upload_status,created_ns,artifact_id LIMIT 65;",
      -1, &owners, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(s_db,
      "INSERT OR IGNORE INTO temp.evidence_retention_protected(candidate_id) VALUES(?);",
      -1, &insert, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(s_db,
      "SELECT candidate_id FROM p0_candidates WHERE endpoint_id=? AND tenant_id=? AND pid=? "
      "AND process_start_key=? AND process_creation_filetime_100ns=? "
      "ORDER BY candidate_id LIMIT 4097;",
      -1, &generation, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(s_db,
      "SELECT 1 FROM p0_candidates INDEXED BY idx_candidates_retention_unknown_generation "
      "WHERE endpoint_id=? AND tenant_id=? AND pid=? "
      "AND (process_start_key IS NULL OR process_start_key IN ('','0') "
      "OR process_creation_filetime_100ns IS NULL OR process_creation_filetime_100ns IN ('','0')) LIMIT 1;",
      -1, &unknown, NULL) != SQLITE_OK) goto done;
  while ((step = sqlite3_step(owners)) == SQLITE_ROW) {
    sqlite3_int64 bytes=sqlite3_column_int64(owners,5);
    if (bytes<0) goto done;
    if (!sqlite_maintenance_charge(slice,1,(uint64_t)bytes+128u)) { rc=1; goto done; }
    if (++owner_count > PMFE_ASSOC_CAP) {
      failure = "retention PMFE protection owner limit exceeded";
      goto done;
    }
    const char *key = (const char *)sqlite3_column_text(owners, 0);
    const char *state = (const char *)sqlite3_column_text(owners, 1);
    if (!key || strlen(key) != 69u || sqlite3_column_bytes(owners, 0) != 69 ||
        !state || sqlite3_column_bytes(owners, 1) != (int)strlen(state) ||
        (strcmp(state, "scheduled") && strcmp(state, "running") &&
         strcmp(state, "result_bound") && strcmp(state, "result_acked"))) {
      failure = "retention PMFE protection owner state invalid";
      goto done;
    }
    char verified_state[32]; EdrPmfeFollowupTask task;
    root = pmfe_read_locked(key, verified_state);
    if (!root || strcmp(state, verified_state) || !pmfe_task_from_root(root, &task) ||
        strcmp(key, task.association_id)) {
      failure = "retention PMFE protection owner validation failed";
      goto done;
    }
    const char *source = pmfe_text(root, "original_event_id");
    const char *scope[] = {task.endpoint_id, task.tenant_id, source};
    for (unsigned column = 2u; column <= 4u; ++column) {
      const char *stored = (const char *)sqlite3_column_text(owners, (int)column);
      if (!stored || sqlite3_column_bytes(owners, (int)column) != (int)strlen(stored) ||
          strcmp(stored, scope[column - 2u])) {
        failure = "retention PMFE protection owner scope invalid";
        goto done;
      }
    }
    if (!source[0] || strlen(source) >= sizeof(identity->event_id)) {
      failure = "retention PMFE protection source identity invalid";
      goto done;
    }
    if (!identity && !(identity = calloc(1u, sizeof(*identity)))) {
      failure = "retention PMFE protection allocation failed";
      goto done;
    }
    copy_s(identity->event_id, sizeof(identity->event_id), source);
    copy_s(identity->endpoint_id, sizeof(identity->endpoint_id), task.endpoint_id);
    copy_s(identity->tenant_id, sizeof(identity->tenant_id), task.tenant_id);
    char canonical[160], start[32], creation[32];
    candidate_id_for(identity, canonical, sizeof(canonical));
    sqlite_u64_decimal(task.process_start_key, start);
    sqlite_u64_decimal(task.process_creation_filetime_100ns, creation);
    sqlite3_reset(insert);
    if (!canonical[0] || sqlite3_bind_text(insert, 1, canonical, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(insert) != SQLITE_DONE) goto done;
    protected_count += (unsigned)sqlite3_changes(s_db);
    if (protected_count > PROTECTED_LIMIT) {
      failure = "retention PMFE protection candidate limit exceeded";
      goto done;
    }
    sqlite3_reset(unknown);
    if (sqlite3_bind_text(unknown, 1, task.endpoint_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(unknown, 2, task.tenant_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(unknown, 3, task.pid) != SQLITE_OK) goto done;
    step = sqlite3_step(unknown);
    if (step != SQLITE_DONE) {
      if (step == SQLITE_ROW) failure = "retention PMFE protection candidate generation unavailable";
      goto done;
    }
    sqlite3_reset(generation);
    if (sqlite3_bind_text(generation, 1, task.endpoint_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(generation, 2, task.tenant_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(generation, 3, task.pid) != SQLITE_OK ||
        sqlite3_bind_text(generation, 4, start, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(generation, 5, creation, -1, SQLITE_TRANSIENT) != SQLITE_OK) goto done;
    while ((step = sqlite3_step(generation)) == SQLITE_ROW) {
      if (!sqlite_maintenance_charge(slice,1,160u)) { rc=1; goto done; }
      if (++generation_rows > PROTECTED_LIMIT) {
        failure = "retention PMFE protection generation scan limit exceeded";
        goto done;
      }
      const char *candidate = (const char *)sqlite3_column_text(generation, 0);
      if (!candidate || !candidate[0] || strlen(candidate) >= sizeof(canonical) ||
          sqlite3_column_bytes(generation, 0) != (int)strlen(candidate)) {
        failure = "retention PMFE protection candidate identity invalid";
        goto done;
      }
      sqlite3_reset(insert);
      if (sqlite3_bind_text(insert, 1, candidate, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
          sqlite3_step(insert) != SQLITE_DONE) goto done;
      protected_count += (unsigned)sqlite3_changes(s_db);
      if (protected_count > PROTECTED_LIMIT) {
        failure = "retention PMFE protection candidate limit exceeded";
        goto done;
      }
    }
    if (step != SQLITE_DONE) goto done;
    cJSON_Delete(root); root = NULL;
  }
  if (step != SQLITE_DONE) goto done;
  rc = 0;
done:
  sqlite3_finalize(count_stmt); sqlite3_finalize(owners); sqlite3_finalize(insert);
  sqlite3_finalize(generation); sqlite3_finalize(unknown);
  cJSON_Delete(root); free(identity);
  if (rc<0) set_error(failure);
  return rc;
}
static cJSON *pmfe_result_root_locked(const EdrBehaviorRecord *r, char key[80], char state[32]) {
  if (!r || r->type!=EDR_EVENT_PMFE_SCAN_RESULT || !r->process_start_key ||
      !r->process_creation_filetime_100ns || r->event_time_ns<=0) return NULL;
  cJSON *ctx=cJSON_ParseWithOpts(r->detection_context,NULL,1);
  const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence");
  const char *status=pmfe_text(engine,"status"), *verdict=pmfe_text(engine,"verdict");
  int valid=!strcmp(pmfe_text(engine,"schema"),"pmfe_result_v1") &&
      !strcmp(pmfe_text(engine,"detector"),"pmfe") &&
      cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(engine,"followup_only")) &&
      ((!strcmp(status,"completed_clean") && !strcmp(verdict,"clean")) ||
       ((!strcmp(status,"failed") || !strcmp(status,"partial")) && !strcmp(verdict,"inconclusive")) ||
       ((!strcmp(status,"completed_suspicious") || !strcmp(status,"partial")) && !strcmp(verdict,"suspicious")));
  cJSON *root=valid && pmfe_key(pmfe_text(engine,"source_alert_id"),r->endpoint_id,r->tenant_id,key)
      ? pmfe_read_locked(key,state) : NULL;
  cJSON_Delete(ctx); EdrPmfeFollowupTask task;
  if (root && (!pmfe_task_from_root(root,&task) || task.pid!=r->pid ||
      task.process_start_key!=r->process_start_key || task.process_creation_filetime_100ns!=r->process_creation_filetime_100ns ||
      r->event_time_ns<task.source_event_time_ns ||
      (uint64_t)r->event_time_ns>pmfe_u64(root,"expires_ns"))) {
    cJSON_Delete(root); root=NULL; pmfe_error(4u,"pmfe followup scope/generation/time mismatch");
  }
  return root;
}
static int pmfe_association_validate(const char *alert, const char *endpoint, const char *tenant,
    const char *event_id, uint32_t pid, uint64_t start, uint64_t birth, int64_t time_ns,
    const char *status, const char *verdict, const uint8_t *frame, size_t len, void *user) {
  (void)user; char key[80],state[32],hash[65]; int valid=0; cJSON *root=NULL;
  uint8_t *original=NULL; size_t original_len=0;
  if (!pmfe_key(alert,endpoint,tenant,key) || edr_sha256_hex(frame,len,hash)) return 0;
  evidence_cache_lock(); root=pmfe_read_locked(key,state); EdrPmfeFollowupTask task;
  if (root && pmfe_task_from_root(root,&task) && pid==task.pid && start==task.process_start_key &&
      birth==task.process_creation_filetime_100ns && time_ns>0 &&
      (uint64_t)time_ns==pmfe_u64(root,"result_event_time_ns") &&
      !strcmp(event_id,pmfe_text(root,"result_event_id")) &&
      !strcmp(status,pmfe_text(root,"result_status")) && !strcmp(verdict,pmfe_text(root,"result_verdict")) &&
      !strcmp(hash,pmfe_text(root,"result_sha256")) &&
      (!strcmp(state,"result_bound") || !strcmp(state,"result_acked") || !strcmp(state,"completed"))) {
    original=pmfe_unhex(pmfe_text(root,"original_wire_hex"),&original_len);
    valid=original!=NULL;
  }
  cJSON_Delete(root); evidence_cache_unlock();
  /* Never recurse into egress while holding the evidence owner mutex. The
   * original is a positive shellcode detector frame, not another follow-up. */
  if (valid) valid=edr_egress_frame_validate(original,original_len,NULL,0u);
  free(original); return valid;
}
static int pmfe_frame_matches(const EdrBehaviorRecord *r,const char *alert,const uint8_t *frame,size_t len,int original) {
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event)); if (!event) return 0;
  pb_istream_t stream=pb_istream_from_buffer(frame,len);
  int valid=pb_decode(&stream,edr_v1_BehaviorEvent_fields,event) &&
      event->type==(int32_t)r->type && event->pid==r->pid &&
      event->process_start_key==r->process_start_key &&
      event->process_creation_filetime_100ns==r->process_creation_filetime_100ns &&
      event->event_time_ns==r->event_time_ns && !strcmp(event->event_id,r->event_id) &&
      !strcmp(event->endpoint_id,r->endpoint_id) && !strcmp(event->tenant_id,r->tenant_id);
  cJSON *ctx=valid ? cJSON_ParseWithOpts(event->ave_result_json,NULL,1) : NULL;
  const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence");
  valid=valid && alert && !strcmp(pmfe_text(engine,original ? "alert_id" : "source_alert_id"),alert);
  if (!original && valid) {
    cJSON *record_context=cJSON_ParseWithOpts(r->detection_context,NULL,1);
    const cJSON *record_engine=cJSON_GetObjectItemCaseSensitive(record_context,"engine_evidence");
    valid=!strcmp(pmfe_text(engine,"schema"),"pmfe_result_v1") &&
        !strcmp(pmfe_text(engine,"detector"),"pmfe") &&
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(engine,"followup_only")) &&
        !strcmp(pmfe_text(engine,"status"),pmfe_text(record_engine,"status")) &&
        !strcmp(pmfe_text(engine,"verdict"),pmfe_text(record_engine,"verdict"));
    cJSON_Delete(record_context);
  }
  cJSON_Delete(ctx); free(event); return valid;
}
#endif

int edr_local_evidence_cache_pmfe_prepare(const EdrBehaviorRecord *r,
    const char *alert, const uint8_t *frame, size_t len, uint32_t band, uint64_t hint,
    EdrPmfeFollowupTask *out) {
  if (!r || !out || r->type!=EDR_EVENT_PROTOCOL_SHELLCODE || !r->event_id[0] ||
      !r->pid || !r->process_start_key || !r->process_creation_filetime_100ns ||
      r->event_time_ns<=0 || band>2u || !frame || !len || len>EDR_EGRESS_FRAME_MAX ||
      !edr_egress_frame_validate(frame,len,NULL,0u)) return -1;
  int rc=-1; evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  char key[80],state[32],hash[65]; cJSON *root=NULL; char *hex=NULL;
  cJSON *ctx=cJSON_ParseWithOpts(r->detection_context,NULL,1);
  const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence");
  if (!s_db || !pmfe_frame_matches(r,alert,frame,len,1) || strcmp(pmfe_text(engine,"alert_id"),alert ? alert : "") ||
      !pmfe_key(alert,r->endpoint_id,r->tenant_id,key) || edr_sha256_hex(frame,len,hash)) goto prepare_done;
  root=pmfe_read_locked(key,state);
  if (root) {
    EdrPmfeFollowupTask existing;
    if (pmfe_task_from_root(root,&existing) && existing.pid==r->pid &&
        existing.process_start_key==r->process_start_key && existing.process_creation_filetime_100ns==r->process_creation_filetime_100ns &&
        !strcmp(hash,pmfe_text(root,"original_sha256")) &&
        (!strcmp(state,"scheduled") || !strcmp(state,"running") || !strcmp(state,"result_bound") ||
         !strcmp(state,"result_acked") || !strcmp(state,"completed"))) {
      *out=existing; rc=(!strcmp(state,"scheduled") || !strcmp(state,"running")) ? 0 : 1;
    }
    else { (void)pmfe_write_locked(key,root,"conflict"); pmfe_error(6u,"pmfe original association conflict"); }
    goto prepare_done;
  }
  sqlite3_stmt *st=NULL; unsigned count=PMFE_ASSOC_CAP;
  /* A corrupt or wrong-type row is still existing evidence. Never replace its
   * immutable bytes by treating a failed verification as a cache miss. */
  if (sqlite3_prepare_v2(s_db,"SELECT 1 FROM artifacts WHERE artifact_id=?",-1,&st,NULL)!=SQLITE_OK) {
    pmfe_error(1u,"pmfe association existence query failed"); goto prepare_done;
  }
  bind_text(st,1,key); int exists=sqlite3_step(st);
  sqlite3_finalize(st); st=NULL;
  if (exists!=SQLITE_DONE) {
    pmfe_error(exists==SQLITE_ROW ? 2u : 1u,
        exists==SQLITE_ROW ? "pmfe existing association is corrupt or has wrong owner" : "pmfe association existence read failed");
    goto prepare_done;
  }
  if (sqlite3_prepare_v2(s_db,"SELECT COUNT(*) FROM artifacts WHERE artifact_type='" PMFE_ASSOC_TYPE "' AND COALESCE(upload_status,'') NOT IN ('completed','expired','conflict')",-1,&st,NULL)==SQLITE_OK && sqlite3_step(st)==SQLITE_ROW)
    count=(unsigned)sqlite3_column_int(st,0);
  sqlite3_finalize(st);
  if (count>=PMFE_ASSOC_CAP || !sqlite_size_budget_allow()) { pmfe_error(3u,"pmfe association capacity exhausted"); goto prepare_done; }
  root=cJSON_CreateObject(); hex=pmfe_hex(frame,len); uint64_t now=(uint64_t)now_unix_ns();
  if (!root || !hex || !manifest_add_text(root,"schema",PMFE_ASSOC_TYPE) ||
      !manifest_add_text(root,"source_alert_id",alert) || !manifest_add_text(root,"original_event_id",r->event_id) ||
      !manifest_add_text(root,"endpoint_id",r->endpoint_id) || !manifest_add_text(root,"tenant_id",r->tenant_id) ||
      !manifest_add_text(root,"original_sha256",hash) || !manifest_add_text(root,"original_wire_hex",hex) ||
      !cJSON_AddNumberToObject(root,"pid",r->pid) || !cJSON_AddNumberToObject(root,"band",band) ||
      !pmfe_put_u64(root,"process_start_key",r->process_start_key) ||
      !pmfe_put_u64(root,"process_creation_filetime_100ns",r->process_creation_filetime_100ns) ||
      !pmfe_put_u64(root,"source_event_time_ns",(uint64_t)r->event_time_ns) ||
      !pmfe_put_u64(root,"vad_hint_va",hint) || !pmfe_put_u64(root,"created_ns",now) ||
      !pmfe_put_u64(root,"expires_ns",now+PMFE_ASSOC_TTL_NS) || !pmfe_put_u64(root,"attempts",0u) ||
      !pmfe_put_u64(root,"retry_after_ns",0u)) goto prepare_done;
  if (pmfe_write_locked(key,root,"scheduled")==0 && pmfe_task_from_root(root,out)) rc=0;
prepare_done:
  cJSON_Delete(root); cJSON_Delete(ctx); free(hex);
#else
  (void)alert; (void)hint;
#endif
  evidence_cache_unlock(); return rc;
}

int edr_local_evidence_cache_pmfe_apply_scope(EdrBehaviorRecord *r) {
  if (!r || r->type!=EDR_EVENT_PMFE_SCAN_RESULT) return 0;
  int rc=0; evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  /* association_id is only a lookup hint from the worker's typed task. It
   * supplies no egress authority; final-wire binding remains mandatory. */
  const char *p=strstr(r->script_snippet,"pmfe_association_id=");
  char key[80],state[32]; size_t n=0;
  if (p) {
    p+=strlen("pmfe_association_id=");
    while (p[n] && p[n]!=' ' && p[n]!='\n' && n+1u<sizeof(key)) { key[n]=p[n]; ++n; }
    key[n]=0;
    cJSON *root=pmfe_read_locked(key,state); EdrPmfeFollowupTask task;
    if (root && pmfe_task_from_root(root,&task) && !strcmp(task.association_id,key) &&
        task.pid==r->pid && task.process_start_key==r->process_start_key &&
        task.process_creation_filetime_100ns==r->process_creation_filetime_100ns) {
      copy_s(r->endpoint_id,sizeof(r->endpoint_id),task.endpoint_id);
      copy_s(r->tenant_id,sizeof(r->tenant_id),task.tenant_id); rc=1;
    }
    cJSON_Delete(root);
  }
#endif
  evidence_cache_unlock(); return rc;
}

int edr_local_evidence_cache_pmfe_result_pending(const EdrBehaviorRecord *r) {
  int rc=0; evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  char key[80],state[32]; cJSON *root=pmfe_result_root_locked(r,key,state);
  rc=root && (!strcmp(state,"scheduled") || !strcmp(state,"running") || !strcmp(state,"result_bound"));
  cJSON_Delete(root);
#else
  (void)r;
#endif
  evidence_cache_unlock(); return rc;
}

int edr_local_evidence_cache_pmfe_bind_result(const EdrBehaviorRecord *r, const uint8_t *frame, size_t len) {
  if (!frame || !len || len>EDR_EGRESS_FRAME_MAX) return -1;
  int rc=-1; evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  char key[80],state[32],hash[65]; cJSON *root=pmfe_result_root_locked(r,key,state); char *hex=NULL;
  if (root && pmfe_frame_matches(r,pmfe_text(root,"source_alert_id"),frame,len,0) && !edr_sha256_hex(frame,len,hash)) {
    if (!strcmp(state,"result_bound") || !strcmp(state,"result_acked") || !strcmp(state,"completed")) {
      rc=!strcmp(hash,pmfe_text(root,"result_sha256")) ? 0 : -1;
      if (rc) pmfe_error(6u,"pmfe conflicting result rejected; original immutable result retained");
    } else if ((!strcmp(state,"scheduled") || !strcmp(state,"running")) &&
               (uint64_t)now_unix_ns()<=pmfe_u64(root,"expires_ns") && sqlite_size_budget_allow()) {
      cJSON *ctx=cJSON_Parse(r->detection_context);
      const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence"); hex=pmfe_hex(frame,len);
      if (hex && manifest_add_text(root,"result_event_id",r->event_id) &&
          manifest_add_text(root,"result_sha256",hash) && manifest_add_text(root,"result_wire_hex",hex) &&
          manifest_add_text(root,"result_status",pmfe_text(engine,"status")) &&
          manifest_add_text(root,"result_verdict",pmfe_text(engine,"verdict")) &&
          pmfe_put_u64(root,"result_event_time_ns",(uint64_t)r->event_time_ns) &&
          pmfe_put_u64(root,"retry_after_ns",0u)) rc=pmfe_write_locked(key,root,"result_bound");
      cJSON_Delete(ctx);
    }
  }
  free(hex); cJSON_Delete(root);
#else
  (void)r;
#endif
  evidence_cache_unlock(); return rc;
}

#if defined(EDR_HAVE_SQLITE) && defined(EDR_LOCAL_EVIDENCE_CACHE_TESTING)
static void pmfe_capture_query_cost_locked(sqlite3_stmt *statement, unsigned index) {
  if (!statement) return;
  EdrEvidenceCacheQueryCost *cost = &s_test_pmfe_query_cost[index];
  cost->queries++;
  cost->vm_steps += (uint64_t)sqlite3_stmt_status(statement, SQLITE_STMTSTATUS_VM_STEP, 0);
  cost->fullscan_steps += (uint64_t)sqlite3_stmt_status(statement, SQLITE_STMTSTATUS_FULLSCAN_STEP, 0);
}
#endif

int edr_local_evidence_cache_pmfe_take_task(EdrPmfeFollowupTask *out) {
  if (!out) return 0; int rc=0; evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  sqlite3_stmt *st=NULL; char key[80]="";
  if (s_db && sqlite3_prepare_v2(s_db,"SELECT artifact_id FROM artifacts WHERE artifact_type='" PMFE_ASSOC_TYPE "' AND upload_status IN ('scheduled','running') ORDER BY created_ns LIMIT 64",-1,&st,NULL)==SQLITE_OK) {
    while (sqlite3_step(st)==SQLITE_ROW) {
      char state[32]; copy_s(key,sizeof(key),(const char *)sqlite3_column_text(st,0));
      cJSON *root=pmfe_read_locked(key,state); uint64_t now=(uint64_t)now_unix_ns();
      if (root && (now>pmfe_u64(root,"expires_ns") ||
          (pmfe_u64(root,"attempts")>=3u && (!strcmp(state,"scheduled") || now>=pmfe_u64(root,"retry_after_ns"))))) {
        if (pmfe_write_locked(key,root,"expired")==0) pmfe_error(5u,"pmfe followup scan expired or retry budget exhausted");
      } else if (root && pmfe_u64(root,"attempts")<3u && (!strcmp(state,"scheduled") || now>=pmfe_u64(root,"retry_after_ns")) && pmfe_task_from_root(root,out) &&
          pmfe_put_u64(root,"attempts",pmfe_u64(root,"attempts")+1u) &&
          pmfe_put_u64(root,"retry_after_ns",now+PMFE_ASSOC_LEASE_NS) && pmfe_write_locked(key,root,"running")==0) rc=1;
      cJSON_Delete(root); if (rc) break;
    }
  }
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  pmfe_capture_query_cost_locked(st, 0u);
#endif
  sqlite3_finalize(st);
#endif
  evidence_cache_unlock(); return rc;
}

int edr_local_evidence_cache_pmfe_replay_result(uint8_t **frame,size_t *length) {
  if (!frame || !length) return 0; *frame=NULL; *length=0; int rc=0; evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  sqlite3_stmt *st=NULL;
  if (s_db && sqlite3_prepare_v2(s_db,"SELECT artifact_id FROM artifacts WHERE artifact_type='" PMFE_ASSOC_TYPE "' AND upload_status IN ('result_bound','result_acked') ORDER BY created_ns LIMIT 64",-1,&st,NULL)==SQLITE_OK) {
    while (sqlite3_step(st)==SQLITE_ROW) {
      char key[80],state[32],hash[65]; copy_s(key,sizeof(key),(const char *)sqlite3_column_text(st,0));
      cJSON *root=pmfe_read_locked(key,state); uint64_t now=(uint64_t)now_unix_ns();
      if (root && now>=pmfe_u64(root,"retry_after_ns")) {
        *frame=pmfe_unhex(pmfe_text(root,"result_wire_hex"),length);
        if (*frame && !edr_sha256_hex(*frame,*length,hash) && !strcmp(hash,pmfe_text(root,"result_sha256")) &&
            pmfe_put_u64(root,"retry_after_ns",now+30000000000ULL) && pmfe_write_locked(key,root,state)==0) rc=!strcmp(state,"result_acked") ? 2 : 1;
        if (!rc) { free(*frame); *frame=NULL; *length=0; }
      }
      cJSON_Delete(root); if (rc) break;
    }
  }
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  pmfe_capture_query_cost_locked(st, 1u);
#endif
  sqlite3_finalize(st);
#endif
  evidence_cache_unlock(); return rc;
}

void edr_local_evidence_cache_pmfe_note_submit_failure(const EdrPmfeFollowupTask *task) {
  if (!task) return;
  evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  char state[32]; cJSON *root=pmfe_read_locked(task->association_id,state);
  EdrPmfeFollowupTask retained;
  if (root && !strcmp(state,"running") && pmfe_task_from_root(root,&retained) &&
      retained.pid==task->pid && retained.process_start_key==task->process_start_key &&
      retained.process_creation_filetime_100ns==task->process_creation_filetime_100ns)
    pmfe_error(7u,"pmfe worker admission unavailable; bounded scan lease retained");
  cJSON_Delete(root);
#endif
  evidence_cache_unlock();
}

int edr_local_evidence_cache_pmfe_ack_frame(const uint8_t *frame,size_t len) {
  if (!frame || !len || len>EDR_EGRESS_FRAME_MAX) return -1;
  int rc=0; evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  char hash[65]; sqlite3_stmt *st=NULL;
  if (edr_sha256_hex(frame,len,hash)) rc=-1;
  else if (s_db && sqlite3_prepare_v2(s_db,"SELECT artifact_id FROM artifacts WHERE artifact_type='" PMFE_ASSOC_TYPE "' AND upload_status IN ('result_bound','result_acked','completed')",-1,&st,NULL)==SQLITE_OK) {
    while (sqlite3_step(st)==SQLITE_ROW) {
      char key[80],state[32]; copy_s(key,sizeof(key),(const char *)sqlite3_column_text(st,0));
      cJSON *root=pmfe_read_locked(key,state);
      if (root && !strcmp(hash,pmfe_text(root,"result_sha256"))) {
        rc=(!strcmp(state,"result_acked") || !strcmp(state,"completed")) ? 1 :
            (pmfe_write_locked(key,root,"result_acked")==0 ? 1 : -1);
        cJSON_Delete(root); break;
      }
      cJSON_Delete(root);
    }
  } else if (s_db) rc=-1;
  sqlite3_finalize(st);
#endif
  evidence_cache_unlock(); return rc;
}

int edr_local_evidence_cache_pmfe_queue_removed(const uint8_t *frame,size_t len) {
  int rc=0; evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  char hash[65]; sqlite3_stmt *st=NULL;
  if (!frame || !len || len>EDR_EGRESS_FRAME_MAX || edr_sha256_hex(frame,len,hash)) rc=-1;
  else if (s_db && sqlite3_prepare_v2(s_db,"SELECT artifact_id FROM artifacts WHERE artifact_type='" PMFE_ASSOC_TYPE "' AND upload_status IN ('result_bound','result_acked','completed')",-1,&st,NULL)==SQLITE_OK) {
    while (sqlite3_step(st)==SQLITE_ROW) {
      char key[80],state[32]; copy_s(key,sizeof(key),(const char *)sqlite3_column_text(st,0));
      cJSON *root=pmfe_read_locked(key,state);
      if (root && !strcmp(hash,pmfe_text(root,"result_sha256"))) {
        rc=!strcmp(state,"completed") ? 1 : !strcmp(state,"result_acked")
            ? (pmfe_write_locked(key,root,"completed")==0 ? 1 : -1) : -1;
        cJSON_Delete(root); break;
      }
      cJSON_Delete(root);
    }
  } else if (s_db) rc=-1;
  sqlite3_finalize(st);
#else
  (void)frame; (void)len;
#endif
  evidence_cache_unlock(); return rc;
}

#if defined(EDR_HAVE_SQLITE)
static int pmfe_receipt_handler(const char *alert,const char *endpoint,const char *tenant,
    const char *event_id,uint32_t pid,uint64_t start,uint64_t birth,int64_t event_ns,
    const char *status,const char *verdict,const uint8_t *frame,size_t len,void *user) {
  (void)alert; (void)endpoint; (void)tenant; (void)event_id; (void)pid; (void)start;
  (void)birth; (void)event_ns; (void)status; (void)verdict; (void)user;
  return edr_local_evidence_cache_pmfe_ack_frame(frame,len);
}
static int pmfe_queue_removed_handler(const char *alert,const char *endpoint,const char *tenant,
    const char *event_id,uint32_t pid,uint64_t start,uint64_t birth,int64_t event_ns,
    const char *status,const char *verdict,const uint8_t *frame,size_t len,void *user) {
  (void)alert; (void)endpoint; (void)tenant; (void)event_id; (void)pid; (void)start;
  (void)birth; (void)event_ns; (void)status; (void)verdict; (void)user;
  return edr_local_evidence_cache_pmfe_queue_removed(frame,len);
}
#endif

char *edr_local_evidence_cache_read_command_fact(const EdrBehaviorRecord *r) {
  char *result = NULL;
  evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  result = read_command_fact_locked(r);
#else
  (void)r;
#endif
  evidence_cache_unlock();
  return result;
}

void edr_local_evidence_cache_resolve_commands(const EdrBehaviorRecord *r,
                                               char **subject, char **parent) {
  if (!subject || !parent) return;
  *subject = NULL; *parent = NULL;
  if (!r || !memchr(r->cmdline, 0, sizeof(r->cmdline)) ||
      !memchr(r->parent_cmdline, 0, sizeof(r->parent_cmdline))) return;
  if ((!r->cmdline[0] || edr_behavior_source_field_truncated(r, "source.cmdline") ||
       edr_behavior_source_field_truncated(r, "source.cmdline_quality_unknown")) &&
      strcmp(r->command_line_origin, "live_command_fact_store_failed") != 0)
    *subject = edr_local_evidence_cache_read_command_fact(r);
  if ((!r->parent_cmdline[0] || edr_behavior_source_field_truncated(r, "source.parent_cmdline")) &&
      !edr_behavior_source_field_truncated(r, "source.parent_command_fact") &&
      record_parent_context_proven(r)) {
    EdrBehaviorRecord *identity = (EdrBehaviorRecord *)calloc(1u, sizeof(*identity));
    if (identity) {
      copy_s(identity->tenant_id, sizeof(identity->tenant_id), r->tenant_id);
      copy_s(identity->endpoint_id, sizeof(identity->endpoint_id), r->endpoint_id);
      identity->pid = r->ppid;
      identity->process_start_key = r->parent_process_start_key;
      identity->process_creation_filetime_100ns = r->parent_process_creation_filetime_100ns;
      *parent = edr_local_evidence_cache_read_command_fact(identity);
      free(identity);
    }
  }
  /* An explicit source value may conflict; a reference is not permission to
   * overwrite it with another observation, even within the same lifetime. */
  if (*subject && r->cmdline[0] && strncmp(*subject, r->cmdline, strlen(r->cmdline)) != 0) {
    free(*subject); *subject = NULL;
  }
  if (*parent && r->parent_cmdline[0] && strncmp(*parent, r->parent_cmdline, strlen(r->parent_cmdline)) != 0) {
    free(*parent); *parent = NULL;
  }
}

static void evidence_cache_close_locked(void) {
#if defined(EDR_HAVE_SQLITE)
  /* Completed slices are SQLite commits; remaining free pages are discovered
   * by normal startup maintenance, with no durable scheduler state to replay. */
  s_maintenance_reclaim_pages = 0u;
  s_maintenance_pressure_pending=0;
  s_maintenance_stage=0;
  memset(s_retirement_cursor, 0, sizeof(s_retirement_cursor));
  memset(&s_command_retirement_cursor, 0, sizeof(s_command_retirement_cursor));
  if (s_db) {
    if (sqlite_flush_metrics(1) != 0) {
      uint64_t lost = 0u;
      for (size_t i = 0; i < EDR_EVIDENCE_METRIC_SLOTS; ++i) {
        MetricSlot *m = &s_metrics[i];
        for (size_t j = 0; j < METRIC_COUNT; ++j) {
          /* Ordinary type and reason label the same observation. Count once. */
          if (j >= METRIC_ORDINARY_BASE && j < METRIC_CANDIDATE_BASE) continue;
          evidence_cache_add_saturating(&lost, metric_slot_value(m, j) - m->committed[j]);
        }
      }
      evidence_cache_add_saturating(&s_status.metric_unrecorded, lost);
      /* A closed volatile metrics ring cannot retry after reopen. Keep this
       * terminal loss visible even when startup resets the health counters. */
      fprintf(stderr, "[evidence-cache] closing with %llu uncommitted diagnostic counts: %s\n",
              (unsigned long long)lost, s_status.last_error);
    }
    (void)sqlite_maintenance_checkpoint(SQLITE_CHECKPOINT_TRUNCATE);
    sqlite3_close(s_db);
    s_db = NULL;
  }
#endif
  s_status.db_open = 0;
}

#if defined(EDR_HAVE_SQLITE)
static int sqlite_auto_vacuum_mode(void) {
  sqlite3_stmt *st = NULL;
  int mode = -1;
  if (sqlite3_prepare_v2(s_db, "PRAGMA auto_vacuum;", -1, &st, NULL) == SQLITE_OK &&
      sqlite3_step(st) == SQLITE_ROW) mode = sqlite3_column_int(st, 0);
  sqlite3_finalize(st);
  return mode;
}

/* Existing caches need one SQLite-atomic rebuild to add the pointer map.
 * Do this before exposing the cache to collectors. A failed migration leaves
 * opening failed and can be retried; never accept a silent no-op pragma. */
static int sqlite_ensure_incremental_vacuum(void) {
  int mode = sqlite_auto_vacuum_mode();
  if (mode == 2) return 0;
  if (!sqlite_database_write_allow(EDR_EVIDENCE_MANIFEST_MAX_BYTES)) return -1;
  if (mode < 0 || exec_sql("PRAGMA auto_vacuum=INCREMENTAL;") != 0) {
    set_error("evidence cache incremental vacuum setup failed");
    return -1;
  }
  if (sqlite_auto_vacuum_mode() != 2) {
    if (!sqlite_database_write_allow(EDR_EVIDENCE_MANIFEST_MAX_BYTES)) return -1;
    if (exec_sql("VACUUM;") != 0) {
      set_error("evidence cache incremental vacuum migration failed");
      return -1;
    }
  }
  if (sqlite_auto_vacuum_mode() != 2) {
    set_error("evidence cache incremental vacuum unavailable");
    return -1;
  }
  if (sqlite_maintenance_checkpoint(SQLITE_CHECKPOINT_TRUNCATE) != 0) return -1;
  return 0;
}
#endif

int edr_local_evidence_cache_open(const char *path, uint32_t max_db_mb,
                                  uint32_t retention_hours) {
  return edr_local_evidence_cache_open_with_policy(path, max_db_mb,
                                                   retention_hours, retention_hours);
}

int edr_local_evidence_cache_open_with_policy(const char *path, uint32_t max_db_mb,
                                              uint32_t retention_hours,
                                              uint32_t selected_hours) {
  if (retention_hours > (uint32_t)(INT64_MAX/3600000000000LL) ||
      selected_hours > (uint32_t)(INT64_MAX/3600000000000LL)) return -1;
  evidence_cache_lock();
  evidence_cache_close_locked();
  memset(&s_status, 0, sizeof(s_status));
#if defined(EDR_HAVE_SQLITE)
  memset(&s_retention_clock, 0, sizeof(s_retention_clock));
#endif
  memset(s_proc, 0, sizeof(s_proc));
  memset(s_ring, 0, sizeof(s_ring));
  memset(s_context_ring, 0, sizeof(s_context_ring));
  memset(s_context_windows, 0, sizeof(s_context_windows));
  memset(s_metrics, 0, sizeof(s_metrics));
  s_metric_retry_after_ns = 0u;
  memset(s_candidate_dedupe, 0, sizeof(s_candidate_dedupe));
  memset(s_ordinary_agg, 0, sizeof(s_ordinary_agg));
  s_ring_pos = 0;
  s_context_ring_pos = 0;
  s_context_window_next = 0;
  s_last_maintenance_ns = 0u;
  s_last_capacity_failure_ns = 0u;
  s_write_budget_minute = 0;
  s_write_budget_count = 0u;
  s_write_budget_ordinary_context_count = 0u;
  s_status.max_db_mb = max_db_mb ? max_db_mb : 128u;
  s_status.retention_hours = retention_hours ? retention_hours : 24u;
  s_status.selected_retention_hours = selected_hours >= s_status.retention_hours
      ? selected_hours : s_status.retention_hours;
  copy_s(s_status.path, sizeof(s_status.path), (path && path[0]) ? path : "local_evidence_cache.db");

#if defined(EDR_HAVE_SQLITE)
  char startup_wal[sizeof(s_status.path)+5u];
  snprintf(startup_wal,sizeof(startup_wal),"%s-wal",s_status.path);
  uint64_t startup_bytes=path_size_bytes(s_status.path), startup_wal_bytes=path_size_bytes(startup_wal);
  uint64_t startup_work = startup_wal_bytes>UINT64_MAX-EDR_EVIDENCE_MANIFEST_MAX_BYTES ||
      startup_bytes>UINT64_MAX-startup_wal_bytes-EDR_EVIDENCE_MANIFEST_MAX_BYTES
      ? UINT64_MAX : startup_bytes+startup_wal_bytes+EDR_EVIDENCE_MANIFEST_MAX_BYTES;
  if (!sqlite_physical_write_allow(startup_work)) {
    evidence_cache_unlock(); return -1;
  }
  if (sqlite3_open(s_status.path, &s_db) != SQLITE_OK || !s_db) {
    char err[160];
    snprintf(err, sizeof(err), "sqlite open failed: %s",
             s_db ? sqlite3_errmsg(s_db) : "no sqlite handle");
    if (s_db) {
      sqlite3_close(s_db);
    }
    s_db = NULL;
    set_error(err);
    evidence_cache_unlock();
    return -1;
  }
  /* Never let last-close perform an unchecked checkpoint. The explicit
   * guarded checkpoint above may defer, leaving committed WAL bytes intact. */
  if (sqlite3_db_config(s_db,SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,1,NULL)!=SQLITE_OK) {
    set_error("cannot disable unguarded evidence close checkpoint");
    sqlite3_close(s_db); s_db=NULL; evidence_cache_unlock(); return -1;
  }
  s_status.db_open = 1;
  if (edr_context_store_check_format(&s_context_store, s_db) != 0) {
    set_error(s_context_store.error);
    evidence_cache_close_locked();
    evidence_cache_unlock();
    return -1;
  }
  s_status.storage_format = (uint32_t)s_context_store.format;
  if (!sqlite_startup_schema_write_allow()) {
    sqlite3_close(s_db); s_db=NULL; s_status.db_open=0;
    evidence_cache_unlock(); return -1;
  }
  uint64_t startup_logical=0,startup_page_size=0;
  if (!sqlite_database_page_bytes(&startup_logical,&startup_page_size)) {
    sqlite3_close(s_db); s_db=NULL; s_status.db_open=0;
    evidence_cache_unlock(); return -1;
  }
  s_evidence_wal_page_size=startup_page_size;
  (void)sqlite3_wal_hook(s_db,sqlite_guarded_autocheckpoint,NULL);
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  s_test_commit_failures = 0u;
  s_test_live_size_query_failures = 0u;
  s_test_manifest_allocation_failures = 0u;
  s_test_commit_active = 0;
  (void)sqlite3_commit_hook(s_db, evidence_cache_test_commit_hook, NULL);
#endif
  (void)exec_sql("PRAGMA journal_mode=WAL;");
  (void)exec_sql("PRAGMA synchronous=NORMAL;");
  (void)exec_sql("PRAGMA cache_size=-1024;");
  (void)exec_sql("PRAGMA mmap_size=0;");
  if (sqlite_ensure_incremental_vacuum() != 0) {
    evidence_cache_close_locked();
    evidence_cache_unlock();
    return -1;
  }
  const char *schema =
      "CREATE TABLE IF NOT EXISTS process_cache ("
      "endpoint_id TEXT NOT NULL,tenant_id TEXT,pid INTEGER NOT NULL,ppid INTEGER,"
      "name TEXT,path TEXT,cmdline TEXT,parent_name TEXT,parent_path TEXT,"
      "first_seen_ns INTEGER,last_seen_ns INTEGER,process_start_key TEXT,"
      "process_creation_filetime_100ns TEXT,process_generation_source TEXT,"
      "parent_process_start_key TEXT,parent_process_creation_filetime_100ns TEXT,"
      "parent_process_generation_source TEXT,username TEXT,domain TEXT,user_sid TEXT,"
      "logon_id TEXT,identity_source TEXT,identity_quality TEXT,exe_hash TEXT,cmdline_truncated_fields TEXT,"
      "parent_pid_state INTEGER NOT NULL DEFAULT 0,"
      "PRIMARY KEY(endpoint_id,pid));"
      "CREATE INDEX IF NOT EXISTS idx_process_cache_parent ON process_cache(endpoint_id,ppid);"
      "CREATE TABLE IF NOT EXISTS event_cache ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT,endpoint_id TEXT,tenant_id TEXT,"
      "event_time_ns INTEGER,type INTEGER,pid INTEGER,ppid INTEGER,process_name TEXT,exe_path TEXT,"
      "cmdline TEXT,file_path TEXT,dns_query TEXT,net_src TEXT,net_dst TEXT,net_sport INTEGER,"
      "net_dport INTEGER,reg_key_path TEXT,reg_value_name TEXT,reg_op TEXT,detection_context TEXT);"
      "CREATE INDEX IF NOT EXISTS idx_event_cache_ep_time ON event_cache(endpoint_id,event_time_ns);"
      "CREATE INDEX IF NOT EXISTS idx_event_cache_pid_time ON event_cache(endpoint_id,pid,event_time_ns);"
      "CREATE TABLE IF NOT EXISTS p0_candidates ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,candidate_id TEXT UNIQUE,endpoint_id TEXT,tenant_id TEXT,"
      "event_time_ns INTEGER,type INTEGER,pid INTEGER,ppid INTEGER,process_name TEXT,exe_path TEXT,"
      "cmdline TEXT,file_path TEXT,dns_query TEXT,net_dst TEXT,net_dport INTEGER,reg_key_path TEXT,"
      "reg_value_name TEXT,reg_op TEXT,detection_context TEXT,context_pre_count INTEGER,"
      "context_post_until_ns INTEGER,created_ns INTEGER,process_start_key TEXT,"
      "process_creation_filetime_100ns TEXT,process_generation_source TEXT,"
      "source_completeness TEXT,source_truncated_fields TEXT,normalized_command TEXT,"
      "normalized_command_truncated INTEGER NOT NULL DEFAULT 0,"
      "script_path TEXT,exe_hash TEXT,username TEXT,user_sid TEXT,identity_source TEXT,"
      "identity_quality TEXT);"
      "CREATE INDEX IF NOT EXISTS idx_p0_candidates_ep_time ON p0_candidates(endpoint_id,event_time_ns);"
      "CREATE INDEX IF NOT EXISTS idx_p0_candidates_pid_time ON p0_candidates(endpoint_id,pid,event_time_ns);"
      "CREATE TABLE IF NOT EXISTS artifacts ("
      "artifact_id TEXT PRIMARY KEY,endpoint_id TEXT,tenant_id TEXT,candidate_id TEXT,"
      "artifact_type TEXT,path TEXT,sha256 TEXT,manifest_json TEXT,created_ns INTEGER,"
      "upload_status TEXT,minio_key TEXT);"
      "CREATE INDEX IF NOT EXISTS idx_artifacts_ep_time ON artifacts(endpoint_id,created_ns);"
      "CREATE INDEX IF NOT EXISTS idx_artifacts_pmfe_state_created "
      "ON artifacts(upload_status,created_ns,artifact_id) "
      "WHERE artifact_type='" PMFE_ASSOC_TYPE "';"
      "CREATE TABLE IF NOT EXISTS command_results ("
      "command_id TEXT PRIMARY KEY,command_type TEXT,status TEXT,execution_status INTEGER,"
      "exit_code INTEGER,detail TEXT,artifacts TEXT,updated_ns INTEGER);"
      "CREATE TABLE IF NOT EXISTS metrics ("
      "minute_unix INTEGER,endpoint_id TEXT,metric_name TEXT,value INTEGER,"
      "PRIMARY KEY(minute_unix,endpoint_id,metric_name));"
      "CREATE TABLE IF NOT EXISTS file_evidence ("
      "endpoint_id TEXT NOT NULL,path TEXT NOT NULL,sha256 TEXT,pid INTEGER,last_seen_ns INTEGER,"
      "PRIMARY KEY(endpoint_id,path));"
      "CREATE INDEX IF NOT EXISTS idx_file_evidence_sha ON file_evidence(sha256 COLLATE NOCASE);"
      "CREATE TABLE IF NOT EXISTS network_ioc ("
      "endpoint_id TEXT NOT NULL,remote_ip TEXT NOT NULL,remote_url TEXT NOT NULL,dst_port INTEGER NOT NULL,"
      "pid INTEGER NOT NULL,last_seen_ns INTEGER,"
      "PRIMARY KEY(endpoint_id,remote_ip,remote_url,dst_port,pid));"
      "CREATE TABLE IF NOT EXISTS registry_evidence ("
      "endpoint_id TEXT NOT NULL,key_path TEXT NOT NULL,value_name TEXT NOT NULL,op TEXT NOT NULL,"
      "pid INTEGER NOT NULL,last_seen_ns INTEGER,"
      "PRIMARY KEY(endpoint_id,key_path,value_name,op,pid));"
      "CREATE INDEX IF NOT EXISTS idx_process_cache_retention ON process_cache(last_seen_ns);"
      "CREATE INDEX IF NOT EXISTS idx_file_evidence_retention ON file_evidence(last_seen_ns);"
      "CREATE INDEX IF NOT EXISTS idx_network_ioc_retention ON network_ioc(last_seen_ns);"
      "CREATE INDEX IF NOT EXISTS idx_registry_evidence_retention ON registry_evidence(last_seen_ns);"
      "CREATE INDEX IF NOT EXISTS idx_command_results_retention ON command_results(updated_ns);"
      "CREATE INDEX IF NOT EXISTS idx_artifacts_pmfe_terminal_retention ON artifacts(created_ns) "
      "WHERE artifact_type='pmfe_followup_local_v1' AND upload_status IN('completed','expired','conflict');"
      "CREATE TABLE IF NOT EXISTS forensic_jobs ("
      "task_id TEXT PRIMARY KEY,status TEXT,evidence_refs TEXT,upload_refs TEXT,error TEXT,"
      "retryable INTEGER,updated_ns INTEGER);";
  if (exec_sql(schema) != 0) {
    evidence_cache_close_locked();
    evidence_cache_unlock();
    return -1;
  }
  if (edr_context_store_open(&s_context_store, s_db) != 0) {
    set_error(s_context_store.error);
    evidence_cache_close_locked();
    evidence_cache_unlock();
    return -1;
  }
  if (sqlite_ensure_process_cache_generation_columns() != 0 ||
      sqlite_ensure_p0_candidate_columns() != 0 ||
      sqlite_retention_metadata_open() != 0 ||
      sqlite_migrate_legacy_context_artifacts() != 0) {
    evidence_cache_close_locked();
    evidence_cache_unlock();
    return -1;
  }
  sqlite_maintenance(0);
  if (!sqlite_database_write_allow(EDR_EVIDENCE_MANIFEST_MAX_BYTES) ||
      exec_sql("UPDATE artifacts SET upload_status='scheduled' WHERE artifact_type='pmfe_followup_local_v1' AND upload_status='running';") != 0) {
    evidence_cache_close_locked(); evidence_cache_unlock(); return -1;
  }
  evidence_cache_unlock();
  edr_egress_set_pmfe_association_validator(pmfe_association_validate,NULL);
  edr_egress_set_pmfe_receipt_handler(pmfe_receipt_handler,NULL);
  edr_egress_set_pmfe_queue_removed_handler(pmfe_queue_removed_handler,NULL);
  return 0;
#else
  (void)path;
  set_error("sqlite disabled");
  evidence_cache_unlock();
  return -1;
#endif
}

void edr_local_evidence_cache_close(void) {
  edr_egress_set_pmfe_association_validator(NULL,NULL);
  edr_egress_set_pmfe_receipt_handler(NULL,NULL);
  edr_egress_set_pmfe_queue_removed_handler(NULL,NULL);
  evidence_cache_lock();
  evidence_cache_close_locked();
  evidence_cache_unlock();
}

#if defined(EDR_HAVE_SQLITE) && defined(EDR_LOCAL_EVIDENCE_CACHE_TESTING)
void edr_local_evidence_cache_test_pmfe_query_cost(int result_query,
                                                  EdrEvidenceCacheQueryCost *out,
                                                  int reset) {
  evidence_cache_lock();
  unsigned index = result_query ? 1u : 0u;
  if (out) *out = s_test_pmfe_query_cost[index];
  if (reset) memset(&s_test_pmfe_query_cost[index], 0, sizeof(s_test_pmfe_query_cost[index]));
  evidence_cache_unlock();
}

void edr_local_evidence_cache_test_fail_next_manifest_allocations(unsigned count) {
  evidence_cache_lock();
  s_test_manifest_allocation_failures = count;
  evidence_cache_unlock();
}

void edr_local_evidence_cache_test_fail_next_commits(unsigned count) {
  evidence_cache_lock();
  s_test_commit_failures = count;
  evidence_cache_unlock();
}

void edr_local_evidence_cache_test_fail_next_live_size_queries(unsigned count) {
  evidence_cache_lock();
  s_test_live_size_query_failures = count;
  evidence_cache_unlock();
}

void edr_local_evidence_cache_test_force_original_memory_trim(int enabled) {
  evidence_cache_lock();
  s_test_force_original_memory_trim = enabled != 0;
  evidence_cache_unlock();
}
#endif

#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
void edr_local_evidence_cache_test_reset_mutex_timing(void) {
  evidence_cache_lock();
  memset(&s_evidence_cache_lock_timing, 0, sizeof(s_evidence_cache_lock_timing));
  /* Reset must leave a true zero-sample snapshot for the next status call. */
  s_evidence_cache_lock_tls.suppress_sample = 1u;
  evidence_cache_unlock();
}

void edr_local_evidence_cache_test_record_mutex_timing(uint64_t wait_ns,
                                                        uint64_t hold_ns) {
  evidence_cache_lock();
  evidence_cache_record_lock_timing_locked(wait_ns, hold_ns);
  /* Do not add this helper's implementation overhead as a second sample. */
  s_evidence_cache_lock_tls.suppress_sample = 1u;
  evidence_cache_unlock();
}

void edr_local_evidence_cache_test_hold_mutex(uint32_t hold_ms) {
  evidence_cache_lock();
#if defined(_WIN32)
  Sleep((DWORD)hold_ms);
#else
  struct timespec delay;
  delay.tv_sec = (time_t)(hold_ms / 1000u);
  delay.tv_nsec = (long)(hold_ms % 1000u) * 1000000L;
  (void)nanosleep(&delay, NULL);
#endif
  evidence_cache_unlock();
}
#endif

static uint32_t evidence_context_window_s(void) {
  const char *v = getenv("EDR_EVIDENCE_CONTEXT_WINDOW_S");
  char *end = NULL;
  unsigned long n = v && v[0] ? strtoul(v, &end, 10) : 60UL;
  if (end == v || n == 0UL) {
    n = 60UL;
  }
  if (n < 30UL) {
    n = 30UL;
  }
  if (n > 120UL) {
    n = 120UL;
  }
  return (uint32_t)n;
}

static int evidence_contains_ci(const char *haystack, const char *needle) {
  if (!needle || !needle[0]) {
    return 1;
  }
  if (!haystack || !haystack[0]) {
    return 0;
  }
  size_t nn = strlen(needle);
  for (const char *h = haystack; *h; h++) {
    size_t i = 0;
    while (i < nn && h[i] &&
           tolower((unsigned char)h[i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == nn) {
      return 1;
    }
  }
  return 0;
}

static int evidence_text_has_high_signal(const EdrBehaviorRecord *r);
static int evidence_string_has_high_signal(const char *text);
static int evidence_has_priority_or_high_confidence_context(const EdrBehaviorRecord *r);

/* This runtime-generated cache adds no command or target evidence. Limit the
 * exclusion to the observed ordinary writer, exact system-profile object and
 * non-destructive operations; never turn the surrounding directory into an
 * evidence allowlist. P0 evaluation and upload policy are independent. */
static int evidence_is_powershell_startup_cache_noise(const EdrBehaviorRecord *r) {
  static const char object[] =
      "\\windows\\system32\\config\\systemprofile\\appdata\\local\\microsoft"
      "\\windows\\powershell\\startupprofiledata-noninteractive";
  if (!r || (r->type != EDR_EVENT_FILE_WRITE && r->type != EDR_EVENT_FILE_CREATE) ||
      r->priority == 0u || evidence_has_priority_or_high_confidence_context(r) ||
      r->pmfe_snapshot[0] || r->cert_revoked_ancestor ||
      r->collector_evidence_gate[0] || r->source_truncated_fields[0] ||
      evidence_string_has_high_signal(r->cmdline) ||
      evidence_string_has_high_signal(r->script_snippet) ||
      strlen(r->process_name) != strlen("powershell.exe") ||
      !evidence_contains_ci(r->process_name, "powershell.exe")) {
    return 0;
  }
  const char *path = r->file_path;
  if (!isalpha((unsigned char)path[0]) || path[1] != ':' ||
      strlen(path + 2) != sizeof(object) - 1u) return 0;
  for (size_t i = 0; i < sizeof(object) - 1u; ++i) {
    char c = (char)tolower((unsigned char)path[i + 2]);
    if (c == '/') c = '\\';
    if (c != object[i]) return 0;
  }
  if (r->detection_context[0]) {
    /* Decision metadata contains negative keys such as pmfe_scan:false.
     * Consume their values through the baseline contract, not text tokens.
     * Unknown contexts and any requested investigation keep the fact. */
    cJSON *root = cJSON_Parse(r->detection_context);
    const cJSON *quality = cJSON_GetObjectItemCaseSensitive(root, "event_quality");
    const cJSON *score = cJSON_GetObjectItemCaseSensitive(quality, "score");
    const cJSON *action = cJSON_GetObjectItemCaseSensitive(quality, "selection_action");
    const cJSON *trigger = cJSON_GetObjectItemCaseSensitive(root, "detection_trigger");
    int baseline = baseline_context_has_no_server_signal(root, 1, 0) &&
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "suppressed")) &&
        cJSON_IsNumber(score) && score->valuedouble == 32.0 &&
        cJSON_IsString(action) &&
        (strcmp(action->valuestring, "emit_context") == 0 ||
         strcmp(action->valuestring, "local_only") == 0) &&
        cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(trigger, "pmfe_scan")) &&
        cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(trigger, "single_process_minidump")) &&
        cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(trigger, "targeted_files")) &&
        cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(trigger, "ioc_lookup"));
    cJSON_Delete(root);
    if (!baseline) return 0;
  }
  return 1;
}

static int evidence_is_low_value_file_noise(const EdrBehaviorRecord *r) {
  if (!r || !is_file_event_type((uint32_t)r->type)) {
    return 0;
  }
  const char *path = r->file_path[0] ? r->file_path : r->exe_path;
  if (!path || !path[0]) {
    return 0;
  }
  if (evidence_is_powershell_startup_cache_noise(r)) {
    return 1;
  }
  if (evidence_contains_ci(path, ":WofCompressedData")) {
    return 1;
  }
  if (evidence_contains_ci(path, "__PSScriptPolicyTest_")) {
    return 1;
  }
  if (evidence_contains_ci(path,
                           "\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\Caches\\")) {
    return 1;
  }
  if (evidence_contains_ci(path,
                           "\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\InstallService\\") &&
      evidence_contains_ci(path, ".catalogItem")) {
    return 1;
  }
  if (evidence_contains_ci(path,
                           "\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData\\") ||
      evidence_contains_ci(path,
                           "\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\Content\\")) {
    return 1;
  }
  if (evidence_contains_ci(path,
                           "\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\WindowsApps")) {
    return 1;
  }
  if (evidence_contains_ci(r->process_name, "svchost.exe") &&
      evidence_contains_ci(path, "\\Program Files\\WindowsApps\\MicrosoftWindows.Client.WebExperience_") &&
      evidence_contains_ci(path, "\\Dashboard\\WebContent\\wwwroot\\")) {
    return 1;
  }
  if (evidence_contains_ci(r->process_name, "MicrosoftEdgeUpdate.exe") &&
      (evidence_contains_ci(path, "\\Program Files (x86)\\Microsoft\\Temp\\EUF") ||
       evidence_contains_ci(r->exe_path, "\\Program Files (x86)\\Microsoft\\Temp\\EUF") ||
       evidence_contains_ci(r->cmdline, "\\Program Files (x86)\\Microsoft\\Temp\\EUF"))) {
    return 1;
  }
  if (evidence_contains_ci(r->process_name, "MoUsoCoreWorker.exe") &&
      evidence_contains_ci(path, "\\Windows\\System32\\drivers\\UMDF\\") &&
      evidence_contains_ci(path, ".dll.mui")) {
    return 1;
  }
  if (evidence_contains_ci(r->process_name, "backgroundTaskHost.exe") &&
      evidence_contains_ci(path, "\\Windows\\System32\\Tasks\\Microsoft\\Windows\\InstallService\\SmartRetry")) {
    return 1;
  }
  if (evidence_contains_ci(path, "\\Program Files\\WindowsApps\\") ||
      evidence_contains_ci(path, "/Program Files/WindowsApps/")) {
    if (evidence_contains_ci(path, "LanguageExperiencePack") ||
        evidence_contains_ci(path, ".js.map")) {
      return 1;
    }
  }
  if ((evidence_contains_ci(path, "\\Windows\\System32\\drivers\\") ||
       evidence_contains_ci(path, "/Windows/System32/drivers/")) &&
      (evidence_contains_ci(path, ".sys.mui") || evidence_contains_ci(path, ".sys"))) {
    return 1;
  }
  return 0;
}

static int evidence_string_has_high_signal(const char *text) {
  static const char *const tokens[] = {
      "encodedcommand", "-enc", "frombase64string", "invoke-expression", "iex ",
      "downloadstring", "downloadfile", "sekurlsa", "mimikatz", "ntdsutil",
      "vssadmin delete", "wbadmin delete", "bcdedit /set", "wevtutil cl",
      "sc create", "binpath=", "psexec", "admin$", "wmic process call create",
      "regsvr32", "mshta", "certutil -urlcache", "bitsadmin /transfer",
      "add-mppreference", "set-mppreference", "disableantispyware",
      "ransom_counter=1", "webshell_candidate", "shellcode",
  };
  if (!text || !text[0]) {
    return 0;
  }
  for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
    if (evidence_contains_ci(text, tokens[i])) {
      return 1;
    }
  }
  return 0;
}

static int evidence_json_string_is(const cJSON *object, const char *name,
                                   const char *expected) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, name);
  return cJSON_IsString(value) && strcmp(value->valuestring, expected) == 0;
}

static int evidence_context_has_positive_signal(const char *context) {
  cJSON *root = cJSON_ParseWithOpts(context, NULL, 1);
  int positive = 0;
  if (!evidence_json_string_is(root, "schema", "agent_decision_v1")) goto done;
  const cJSON *engine = cJSON_GetObjectItemCaseSensitive(root, "engine_evidence");
  const cJSON *signals = cJSON_GetObjectItemCaseSensitive(engine, "signals");
  if (evidence_json_string_is(engine, "schema", "pmfe_result_v1") &&
      evidence_json_string_is(engine, "verdict", "suspicious")) {
    /* A recommendation, field name, snapshot text or empty scan is not a
     * positive finding. Retention uses typed observed findings; outbound alert
     * identity is checked separately against its authoritative producer. */
    static const char *const counts[] = {
        "stomp_suspicious", "private_exec_image_hits", "private_exec_thread_starts",
        "memfd_exec", "deleted_exec", "thread_start_matches"};
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i) {
      const cJSON *value = cJSON_GetObjectItemCaseSensitive(signals, counts[i]);
      if (cJSON_IsNumber(value) && value->valuedouble > 0.0 &&
          value->valuedouble <= UINT32_MAX &&
          value->valuedouble == (double)(uint32_t)value->valuedouble) positive = 1;
    }
    if (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(signals, "injection_observed")))
      positive = 1;
  } else if (evidence_json_string_is(engine, "schema", "shellcode_result_v1") ||
             evidence_json_string_is(engine, "schema", "webshell_result_v1")) {
    const cJSON *detection = cJSON_GetObjectItemCaseSensitive(engine, "detection");
    const cJSON *detector = cJSON_GetObjectItemCaseSensitive(detection, "detector");
    const cJSON *rule = cJSON_GetObjectItemCaseSensitive(detection, "rule");
    const cJSON *score = cJSON_GetObjectItemCaseSensitive(detection, "score");
    positive = cJSON_IsString(detector) && detector->valuestring[0] &&
        cJSON_IsString(rule) && rule->valuestring[0] &&
        cJSON_IsNumber(score) && score->valuedouble >= 0.7 && score->valuedouble <= 1.0;
  }
done:
  cJSON_Delete(root);
  return positive;
}

static int evidence_text_has_high_signal(const EdrBehaviorRecord *r) {
  return r && (evidence_string_has_high_signal(r->cmdline) ||
               evidence_string_has_high_signal(r->script_snippet) ||
               evidence_context_has_positive_signal(r->detection_context));
}

static int evidence_is_high_risk_port(uint32_t port) {
  static const uint16_t ports[] = {
      22, 88, 135, 139, 389, 445, 464, 593, 636, 1080, 1433, 3128, 3306,
      3389, 5432, 5938, 5985, 5986, 6379, 7070, 8080, 8118, 8443, 9001,
      9050, 9200, 9300, 11211, 27017, 47001,
  };
  if (port == 0u) {
    return 0;
  }
  if (edr_p0_rule_ir_is_interesting_remote_port(port)) {
    return 1;
  }
  for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
    if (port == ports[i]) {
      return 1;
    }
  }
  return 0;
}

static int evidence_has_priority_or_high_confidence_context(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  /* This is only a local-cache reservation. Severity and confidence do not
   * establish an alert or authorize transmission. Read exact typed fields so
   * quoted/unrelated JSON text cannot change the retention class. */
  cJSON *root = cJSON_ParseWithOpts(r->detection_context, NULL, 1);
  const cJSON *confidence = cJSON_GetObjectItemCaseSensitive(root, "confidence");
  int retain = evidence_json_string_is(root, "severity", "P0") ||
      evidence_json_string_is(root, "severity", "P1") ||
      evidence_json_string_is(root, "priority", "P0") ||
      evidence_json_string_is(root, "priority", "P1") ||
      (cJSON_IsNumber(confidence) && confidence->valuedouble >= 0.8 &&
       confidence->valuedouble <= 1.0);
  cJSON_Delete(root);
  return retain;
}

/* Generic reads can dominate a live context window without adding process
 * ancestry or action evidence.  They retain a bounded best-effort pool while
 * process, registry, network, file mutation, and explicitly high-confidence
 * records consume a separate alert-context reservation. */
static EvidenceWriteClass evidence_context_write_class(const EdrBehaviorRecord *r) {
  if (r && r->type == EDR_EVENT_FILE_READ &&
      !evidence_has_priority_or_high_confidence_context(r) &&
      !evidence_text_has_high_signal(r)) {
    return EVIDENCE_WRITE_ORDINARY_CONTEXT;
  }
  return EVIDENCE_WRITE_CRITICAL_CONTEXT;
}

static int evidence_is_file_event(EdrEventType t) {
  return t == EDR_EVENT_FILE_READ || t == EDR_EVENT_FILE_CREATE || t == EDR_EVENT_FILE_WRITE ||
         t == EDR_EVENT_FILE_DELETE || t == EDR_EVENT_FILE_RENAME ||
         t == EDR_EVENT_FILE_PERMISSION_CHANGE;
}

static int evidence_file_path_usable(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
  if ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) {
    if (path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
      return 1;
    }
  }
  if ((path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1]) ||
      evidence_contains_ci(path, "\\device\\") || evidence_contains_ci(path, "\\??\\") ||
      evidence_contains_ci(path, "\\global??\\")) {
    return 1;
  }
  return strchr(path, '\\') != NULL || strchr(path, '/') != NULL;
}

static int evidence_file_event_has_weak_fields(const EdrBehaviorRecord *r) {
  if (!r || !evidence_is_file_event(r->type)) {
    return 0;
  }
  int no_process_identity = !r->process_name[0] && !r->exe_path[0] && !r->cmdline[0];
  if (no_process_identity) {
    return 1;
  }
  if (r->pid == 0u && no_process_identity) {
    return 1;
  }
  if (!evidence_file_path_usable(r->file_path)) {
    return 1;
  }
  return 0;
}

static int evidence_process_or_path_contains(const EdrBehaviorRecord *r, const char *needle) {
  if (!r || !needle || !needle[0]) {
    return 0;
  }
  return evidence_contains_ci(r->process_name, needle) || evidence_contains_ci(r->exe_path, needle) ||
         evidence_contains_ci(r->cmdline, needle) || evidence_contains_ci(r->parent_name, needle) ||
         evidence_contains_ci(r->parent_path, needle) || evidence_contains_ci(r->detection_context, needle);
}

static int evidence_checknetisolation_standard_path(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  if (r->exe_path[0]) {
    return evidence_contains_ci(r->exe_path, "\\Windows\\System32\\CheckNetIsolation.exe") ||
           evidence_contains_ci(r->exe_path, "\\Windows\\SysWOW64\\CheckNetIsolation.exe") ||
           evidence_contains_ci(r->exe_path, "/Windows/System32/CheckNetIsolation.exe") ||
           evidence_contains_ci(r->exe_path, "/Windows/SysWOW64/CheckNetIsolation.exe");
  }
  return evidence_contains_ci(r->cmdline, "\\Windows\\System32\\CheckNetIsolation.exe") ||
         evidence_contains_ci(r->cmdline, "\\Windows\\SysWOW64\\CheckNetIsolation.exe") ||
         evidence_contains_ci(r->cmdline, "/Windows/System32/CheckNetIsolation.exe") ||
         evidence_contains_ci(r->cmdline, "/Windows/SysWOW64/CheckNetIsolation.exe");
}

static int evidence_is_checknetisolation_standard_noise(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  if (r->type != EDR_EVENT_NET_CONNECT && r->type != EDR_EVENT_NET_LISTEN &&
      r->type != EDR_EVENT_NET_DNS_QUERY && r->type != EDR_EVENT_PROCESS_CREATE) {
    return 0;
  }
  if (!evidence_process_or_path_contains(r, "CheckNetIsolation.exe")) {
    return 0;
  }
  if (!evidence_checknetisolation_standard_path(r)) {
    return 0;
  }
  if (evidence_text_has_high_signal(r) || evidence_is_high_risk_port(r->net_dport)) {
    return 0;
  }
  return 1;
}

static int evidence_should_store_record(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  if (evidence_has_priority_or_high_confidence_context(r)) {
    return 1;
  }
  if (evidence_is_low_value_file_noise(r)) {
    return 0;
  }
  if (evidence_is_checknetisolation_standard_noise(r)) {
    return 0;
  }
  if (evidence_file_event_has_weak_fields(r) && !evidence_text_has_high_signal(r)) {
    return 0;
  }
  switch (r->type) {
  case EDR_EVENT_FILE_READ:
  case EDR_EVENT_FILE_CREATE:
  case EDR_EVENT_FILE_WRITE:
  case EDR_EVENT_FILE_DELETE:
  case EDR_EVENT_FILE_RENAME:
  case EDR_EVENT_FILE_PERMISSION_CHANGE:
  case EDR_EVENT_REG_CREATE_KEY:
  case EDR_EVENT_REG_SET_VALUE:
  case EDR_EVENT_REG_DELETE_KEY:
    return edr_windows_event_policy_should_persist(r);
  case EDR_EVENT_NET_CONNECT:
  case EDR_EVENT_NET_LISTEN:
    return evidence_is_high_risk_port(r->net_dport) || evidence_text_has_high_signal(r);
  case EDR_EVENT_SCRIPT_POWERSHELL:
  case EDR_EVENT_SCRIPT_WMI:
    return 0;
  case EDR_EVENT_PROTOCOL_SHELLCODE:
  case EDR_EVENT_WEBSHELL_DETECTED:
  case EDR_EVENT_FIREWALL_RULE_CHANGE:
  case EDR_EVENT_PMFE_SCAN_RESULT:
  case EDR_EVENT_BEHAVIOR_ONNX_ALERT:
    return 1;
  case EDR_EVENT_PROCESS_CREATE:
    return evidence_text_has_high_signal(r);
  default:
    return 0;
  }
}

int edr_local_evidence_cache_is_candidate(const EdrBehaviorRecord *r) {
  return evidence_should_store_record(r);
}

static int same_context_scope(const ContextWindowSlot *w,
                              const EdrBehaviorRecord *r) {
  if (!w || !r) {
    return 0;
  }
  if (w->endpoint_id[0] && r->endpoint_id[0] && strcmp(w->endpoint_id, r->endpoint_id) != 0) {
    return 0;
  }
  return strcmp(w->tenant_id, r->tenant_id) == 0;
}

/* A nominally ended window is preferred only when capacity requires replacing
 * an entry. Event time owns matching; monotonic age prevents a future source
 * timestamp from immediately aging out a newly admitted candidate. Keeping
 * entries until replacement still allows late events to match them. This is
 * not a claim that all late events have arrived or that replacement is lossless. */
static int context_window_nominally_ended(const ContextWindowSlot *w,
                                         int64_t event_time_ns, uint64_t mono_ns) {
  return w->pid != 0u && w->until_ns < event_time_ns &&
         w->until_ns >= w->from_ns && mono_ns >= w->created_mono_ns &&
         mono_ns - w->created_mono_ns >=
             (uint64_t)w->until_ns - (uint64_t)w->from_ns;
}

static void mark_one_context_window(uint32_t pid,
                                    const EvidenceProcessGeneration *generation,
                                    const char *endpoint_id,
                                    const char *tenant_id,
                                    const char *candidate_id, int64_t from_ns,
                                    int64_t until_ns) {
  if (pid == 0u || !generation_bound(generation) || !candidate_id || !candidate_id[0]) {
    return;
  }
  uint64_t mono_ns = edr_monotonic_ns();
  size_t empty_i = EDR_EVIDENCE_CONTEXT_WINDOWS;
  size_t ended_i = EDR_EVIDENCE_CONTEXT_WINDOWS;
  for (size_t i = 0; i < EDR_EVIDENCE_CONTEXT_WINDOWS; i++) {
    const ContextWindowSlot *existing = &s_context_windows[i];
    if (existing->pid == 0u && empty_i == EDR_EVIDENCE_CONTEXT_WINDOWS) empty_i = i;
    if (context_window_nominally_ended(existing, from_ns, mono_ns) &&
        (ended_i == EDR_EVIDENCE_CONTEXT_WINDOWS ||
         existing->until_ns < s_context_windows[ended_i].until_ns)) {
      ended_i = i;
    }
    if (s_context_windows[i].pid == pid &&
        generation_equal(&s_context_windows[i].generation, generation) &&
        (!s_context_windows[i].endpoint_id[0] || !endpoint_id || !endpoint_id[0] ||
         strcmp(s_context_windows[i].endpoint_id, endpoint_id) == 0) &&
        strcmp(s_context_windows[i].tenant_id,
               tenant_id ? tenant_id : "") == 0 &&
        strncmp(s_context_windows[i].candidate_id, candidate_id,
                sizeof(s_context_windows[i].candidate_id)) == 0) {
      s_context_windows[i].until_ns = until_ns;
      s_context_windows[i].from_ns = from_ns;
      copy_s(s_context_windows[i].endpoint_id, sizeof(s_context_windows[i].endpoint_id), endpoint_id);
      copy_s(s_context_windows[i].tenant_id, sizeof(s_context_windows[i].tenant_id),
             tenant_id);
      return;
    }
  }
  size_t replace_i = empty_i != EDR_EVIDENCE_CONTEXT_WINDOWS ? empty_i
      : ended_i != EDR_EVIDENCE_CONTEXT_WINDOWS ? ended_i
      : s_context_window_next % EDR_EVIDENCE_CONTEXT_WINDOWS;
  s_context_window_next = (uint32_t)((replace_i + 1u) % EDR_EVIDENCE_CONTEXT_WINDOWS);
  ContextWindowSlot *w = &s_context_windows[replace_i];
  if (w->pid != 0u) {
    s_status.context_window_evictions++;
    if (context_window_nominally_ended(w, from_ns, mono_ns)) {
      s_status.context_window_nominal_ended_replacements++;
    } else {
      s_status.context_window_protected_replacements++;
    }
  }
  memset(w, 0, sizeof(*w));
  w->pid = pid;
  w->from_ns = from_ns;
  w->until_ns = until_ns;
  w->created_mono_ns = mono_ns;
  w->generation = *generation;
  copy_s(w->endpoint_id, sizeof(w->endpoint_id), endpoint_id);
  copy_s(w->tenant_id, sizeof(w->tenant_id), tenant_id);
  copy_s(w->candidate_id, sizeof(w->candidate_id), candidate_id);
}

static int64_t context_window_until(int64_t now_ns) {
  uint32_t win_s = evidence_context_window_s();
  return now_ns + (int64_t)win_s * 1000000000LL;
}

static void mark_context_window(const EdrBehaviorRecord *r, int64_t until_ns,
                                const char *candidate_id) {
  EvidenceProcessGeneration generation;
  int64_t from_ns = record_time_ns(r);
  if (record_process_generation(r, &generation)) {
    mark_one_context_window(r->pid, &generation, r->endpoint_id, r->tenant_id,
                            candidate_id, from_ns, until_ns);
  }
  if (record_parent_generation(r, &generation)) {
    mark_one_context_window(r->ppid, &generation, r->endpoint_id, r->tenant_id,
                            candidate_id, from_ns, until_ns);
  }
}

/* One post-context record can belong to several distinct committed candidates.
 * The fixed 256-slot table is intentionally multi-keyed by candidate+process
 * generation. Replacement counters distinguish nominally ended entries from
 * entries still protected by event time or monotonic age. Neither category
 * proves the number of missing events; late-event completeness is bounded. */
static uint32_t context_window_matches(const EdrBehaviorRecord *r, int64_t now_ns,
                                       char candidate_ids[][160], uint32_t cap) {
  EvidenceProcessGeneration generation;
  EvidenceProcessGeneration parent_generation;
  int have_generation = record_process_generation(r, &generation);
  int have_parent_generation = record_parent_generation(r, &parent_generation);
  uint32_t count = 0u;
  if (!r || !candidate_ids || cap == 0u || (!have_generation && !have_parent_generation)) {
    return 0u;
  }
  for (size_t i = 0; i < EDR_EVIDENCE_CONTEXT_WINDOWS; i++) {
    ContextWindowSlot *w = &s_context_windows[i];
    if (w->pid == 0u || w->from_ns > now_ns || w->until_ns < now_ns ||
        !same_context_scope(w, r)) {
      continue;
    }
    if (!((have_generation && w->pid == r->pid && generation_equal(&w->generation, &generation)) ||
          (have_parent_generation && w->pid == r->ppid &&
           generation_equal(&w->generation, &parent_generation)))) {
      continue;
    }
    if (!w->candidate_id[0]) {
      continue;
    }
    int duplicate = 0;
    for (uint32_t n = 0u; n < count; ++n) {
      if (strncmp(candidate_ids[n], w->candidate_id, sizeof(w->candidate_id)) == 0) {
        duplicate = 1;
        break;
      }
    }
    if (!duplicate && count < cap) {
      copy_s(candidate_ids[count], sizeof(candidate_ids[count]), w->candidate_id);
      count++;
    }
  }
  return count;
}

static int ring_related_to_record(const RingSlot *s, const EdrBehaviorRecord *r) {
  EvidenceProcessGeneration generation;
  EvidenceProcessGeneration parent_generation;
  int have_generation;
  int have_parent_generation;
  if (!s || !s->used || !r) {
    return 0;
  }
  if (s->endpoint_id[0] && r->endpoint_id[0] && strcmp(s->endpoint_id, r->endpoint_id) != 0) {
    return 0;
  }
  if (strcmp(s->tenant_id, r->tenant_id) != 0) {
    return 0;
  }
  have_generation = record_process_generation(r, &generation);
  have_parent_generation = record_parent_generation(r, &parent_generation);
  if (have_generation && s->pid == r->pid && generation_equal(&s->generation, &generation)) {
    return 1;
  }
  if (have_generation && s->ppid == r->pid &&
      generation_equal(&s->parent_generation, &generation)) {
    return 1;
  }
  if (have_parent_generation && s->pid == r->ppid &&
      generation_equal(&s->generation, &parent_generation)) {
    return 1;
  }
  if (have_parent_generation && s->ppid == r->ppid &&
      generation_equal(&s->parent_generation, &parent_generation)) {
    return 1;
  }
  return 0;
}

static uint32_t context_before_count(const EdrBehaviorRecord *r, int64_t now_ns) {
  uint32_t win_s = evidence_context_window_s();
  int64_t cutoff = now_ns - (int64_t)win_s * 1000000000LL;
  uint32_t pos = s_context_ring_pos;
  uint32_t count = 0;
  for (uint32_t i = 0; i < EDR_EVIDENCE_CONTEXT_RING_SLOTS; i++) {
    const RingSlot *s = &s_context_ring[(pos + EDR_EVIDENCE_CONTEXT_RING_SLOTS - 1u - i) %
                                        EDR_EVIDENCE_CONTEXT_RING_SLOTS];
    if (!s->used) {
      continue;
    }
    if (s->event_time_ns < cutoff || s->event_time_ns > now_ns) {
      continue;
    }
    if (ring_related_to_record(s, r)) {
      count++;
    }
  }
  return count;
}

static void promote_context_before_window(const EdrBehaviorRecord *r, int64_t now_ns) {
  uint32_t win_s = evidence_context_window_s();
  int64_t cutoff = now_ns - (int64_t)win_s * 1000000000LL;
  uint32_t pos = s_context_ring_pos;
  for (uint32_t i = 0; i < EDR_EVIDENCE_CONTEXT_RING_SLOTS; i++) {
    const RingSlot *s = &s_context_ring[(pos + EDR_EVIDENCE_CONTEXT_RING_SLOTS - 1u - i) %
                                        EDR_EVIDENCE_CONTEXT_RING_SLOTS];
    if (!s->used) {
      continue;
    }
    if (s->event_time_ns < cutoff || s->event_time_ns > now_ns) {
      continue;
    }
    if (ring_related_to_record(s, r) &&
        ring_copy_to(s_ring, EDR_EVIDENCE_RING_SLOTS, &s_ring_pos, s)) {
      s_status.ring_evictions++;
    }
  }
}

void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *r) {
  if (!r) {
    return;
  }
  evidence_cache_lock();
  int64_t ts = record_time_ns(r);
  int store_candidate = evidence_should_store_record(r);
  int low_value_file_noise = evidence_is_low_value_file_noise(r);
  char candidate_id[160] = "";
  int candidate_reused = 0;
  if (store_candidate) {
    s_status.candidate_requests++;
    candidate_id_for(r, candidate_id, sizeof(candidate_id));
    candidate_reused = candidate_dedupe_reuse(r, ts, candidate_id, sizeof(candidate_id));
  }
  char context_candidate_ids[EDR_EVIDENCE_CONTEXT_WINDOWS][160];
  memset(context_candidate_ids, 0, sizeof(context_candidate_ids));
  uint32_t context_candidate_count = low_value_file_noise
      ? 0u
      : context_window_matches(r, ts, context_candidate_ids,
                               EDR_EVIDENCE_CONTEXT_WINDOWS);
  int store_context = context_candidate_count != 0u;
  EvidenceWriteClass context_write_class = evidence_context_write_class(r);
  uint32_t pre_count = 0;
  int64_t post_until_ns = 0;
  if (store_candidate) {
    /* Both are pure at this point. The ring promotion and post window only
     * become visible after the candidate transaction commits. */
    pre_count = context_before_count(r, ts);
    post_until_ns = context_window_until(ts);
  }
  if (!store_candidate && !store_context && low_value_file_noise) {
    record_metric_drop(r, ts, EDR_EVIDENCE_POLICY_FILTERED);
    s_status.records_skipped++;
    goto done;
  }
  if (!store_candidate && !store_context && evidence_cache_pressure_active()) {
    record_metric_drop(r, ts, EDR_EVIDENCE_PRESSURE_SKIPPED);
    s_status.pressure_dropped++;
    s_status.records_skipped++;
    goto done;
  }
  if (!store_candidate && !store_context && ordinary_aggregate_should_coalesce(r, ts)) {
    record_metric_drop(r, ts, EDR_EVIDENCE_COALESCED);
    s_status.records_skipped++;
    goto done;
  }
  if (!store_candidate && !store_context) {
    context_ring_capture(r);
    s_status.hot_ring_ingested++;
    record_metric_drop(r, ts, EDR_EVIDENCE_HOT_RING_ONLY);
    s_status.records_skipped++;
    goto done;
  }
  const char *eng = engine_from_context(r->detection_context);
  if (eng[0]) {
    copy_s(s_status.last_engine, sizeof(s_status.last_engine), eng);
  }
  s_status.last_event_time_ns = ts;
#if defined(EDR_HAVE_SQLITE)
  if (store_candidate) {
    int candidate_existing = candidate_reused;
    if (!s_db) {
      record_persistence_failure(r, ts, 1, EDR_EVIDENCE_FAILURE_NO_DATABASE);
      s_status.candidate_rejected++;
      s_status.records_dropped++;
      context_ring_capture(r);
      s_status.hot_ring_ingested++;
      goto done;
    }
    if (!candidate_existing && r->event_id[0]) {
      s_persistence_failure = EDR_EVIDENCE_FAILURE_STORAGE;
      int exists = sqlite_candidate_exists(candidate_id);
      if (exists < 0) {
        record_persistence_failure(r, ts, 1, s_persistence_failure);
        s_status.candidate_rejected++;
        s_status.candidate_transaction_failures++;
        s_status.records_dropped++;
        context_ring_capture(r);
        s_status.hot_ring_ingested++;
        goto done;
      }
      candidate_existing = exists;
    }
    if (!candidate_existing) {
      s_status.candidate_admission_attempts++;
    }
    /* P0/P1 candidates are outside the telemetry-rate budget, but both new
     * admissions and existing-owner updates obey the same storage budget.
     * Repeated updates can otherwise grow a reader-pinned WAL indefinitely. */
    if (!sqlite_size_budget_allow_mode(!candidate_existing)) {
      record_persistence_failure(r, ts, 1, EDR_EVIDENCE_FAILURE_CAPACITY);
      s_status.candidate_rejected++;
      s_status.records_dropped++;
      context_ring_capture(r);
      s_status.hot_ring_ingested++;
      goto done;
    }
    s_persistence_failure = EDR_EVIDENCE_FAILURE_STORAGE;
    if (sqlite_record_candidate(r, candidate_id, pre_count, post_until_ns, NULL) != 0) {
      record_persistence_failure(r, ts, 1, s_persistence_failure);
      s_status.candidate_rejected++;
      s_status.candidate_transaction_failures++;
      s_status.records_dropped++;
      context_ring_capture(r);
      s_status.hot_ring_ingested++;
      goto done;
    }
    edr_validation_trace_event(r, "local_retention", "candidate_committed");
    if (!candidate_existing) {
      s_status.candidate_admitted++;
      promote_context_before_window(r, ts);
      mark_context_window(r, post_until_ns, candidate_id);
    }
    if (!candidate_reused) {
      candidate_dedupe_admit(r, ts, candidate_id);
    }
    context_ring_capture(r);
    s_status.hot_ring_ingested++;
    ring_record(r);
    /* A high-priority event can itself be post-context evidence for every
     * earlier live candidate.  The candidate commit remains durable even if a
     * separately budgeted context bundle cannot be admitted. */
    if (context_candidate_count > 0u) {
      uint32_t context_artifacts_written = 0u;
      if (sqlite_record_budgeted_context_artifacts(
              r, context_candidate_ids, context_candidate_count, ts,
              context_write_class, &context_artifacts_written) != 0) {
        record_persistence_failure(r, ts, 0, s_persistence_failure);
        s_status.records_dropped++;
      } else {
        s_status.artifacts_written += context_artifacts_written;
        edr_validation_trace_event(r, "local_retention", "context_committed");
      }
    }
  } else if (s_db && store_context) {
    context_ring_capture(r);
    s_status.hot_ring_ingested++;
    ring_record(r);
    uint32_t context_artifacts_written = 0u;
    if (sqlite_record_budgeted_context_artifacts(
            r, context_candidate_ids, context_candidate_count, ts,
            context_write_class, &context_artifacts_written) != 0) {
      record_persistence_failure(r, ts, 0, s_persistence_failure);
      s_status.records_dropped++;
      goto done;
    }
    s_status.artifacts_written += context_artifacts_written;
    edr_validation_trace_event(r, "local_retention", "context_committed");
  } else if (store_context) {
    record_persistence_failure(r, ts, 0, EDR_EVIDENCE_FAILURE_NO_DATABASE);
    s_status.records_dropped++;
    /* SQLite being unavailable never pretends that a context artifact was
     * admitted; retain only the bounded in-memory view. */
    context_ring_capture(r);
    s_status.hot_ring_ingested++;
    ring_record(r);
  }
#else
  (void)candidate_id;
  (void)context_candidate_ids;
  (void)context_candidate_count;
  (void)context_write_class;
  (void)pre_count;
  (void)post_until_ns;
  if (store_candidate) {
    s_status.candidate_admission_attempts++;
    record_persistence_failure(r, ts, 1, EDR_EVIDENCE_FAILURE_NO_DATABASE);
    s_status.candidate_rejected++;
    s_status.records_dropped++;
    context_ring_capture(r);
    s_status.hot_ring_ingested++;
  } else if (store_context) {
    record_persistence_failure(r, ts, 0, EDR_EVIDENCE_FAILURE_NO_DATABASE);
    s_status.records_dropped++;
    context_ring_capture(r);
    s_status.hot_ring_ingested++;
    ring_record(r);
  }
#endif
done:
  evidence_cache_unlock();
}

int edr_local_evidence_cache_record_alert_context(const EdrBehaviorRecord *r,
                                                  const EdrCommandFacts *facts) {
  if (!r || !r->pid || !r->process_start_key || !r->process_creation_filetime_100ns ||
      !r->event_id[0] || !memchr(r->event_id, 0, sizeof(r->event_id)) ||
      !r->endpoint_id[0] || !memchr(r->endpoint_id, 0, sizeof(r->endpoint_id)) ||
      !r->tenant_id[0] || !memchr(r->tenant_id, 0, sizeof(r->tenant_id)) ||
      record_time_ns(r) <= 0) return -1;
  uint64_t child_birth_ns;
  if (!generation_birth_unix_ns(r->process_creation_filetime_100ns, &child_birth_ns)) return -1;
  EdrCommandFacts resolved = {0};
  edr_local_evidence_cache_resolve_commands(r, &resolved.subject, &resolved.parent);
  EdrCommandFacts complete_facts = {
      facts && facts->subject ? facts->subject : resolved.subject,
      facts && facts->parent ? facts->parent : resolved.parent};
  facts = &complete_facts;
  int command_failed = 0, result = -1;
#if defined(EDR_HAVE_SQLITE)
  RetainedAlertParentContext *context = calloc(1u, sizeof(*context));
  if (!context) { free(resolved.subject); free(resolved.parent); return -1; }
  context->parent_known = record_parent_context_proven(r) &&
      record_parent_snapshot(r, &context->parent);
  context->parent_generation_conflict = !strcmp(r->parent_resolution_source, "parent_generation_conflict") ||
      !strcmp(r->parent_resolution_status, "CONFLICT");
  if (context->parent_known) {
    ProcessTreeEntry complete;
    uint64_t birth_ns = 0u;
    ProcessTreeEntry *p = &context->parent;
    if (generation_birth_unix_ns(p->creation_filetime_100ns, &birth_ns) &&
        edr_pt_cache_snapshot_generation_at(p->pid, p->process_start_key, birth_ns, &complete) == 0 &&
        !complete.generation_conflict && complete.creation_filetime_100ns == p->creation_filetime_100ns) {
      if ((!p->exe_path[0] || (p->source_truncation_mask & EDR_PTC_SOURCE_TRUNC_EXE_PATH)) &&
          complete.exe_path[0] && !(complete.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_EXE_PATH) &&
          (!p->exe_path[0] || !strncmp(complete.exe_path, p->exe_path, strlen(p->exe_path)))) {
        copy_s(p->exe_path, sizeof(p->exe_path), complete.exe_path);
        p->source_truncation_mask &= (uint8_t)~EDR_PTC_SOURCE_TRUNC_EXE_PATH;
      }
      if ((!p->cmdline[0] || (p->source_truncation_mask & EDR_PTC_SOURCE_TRUNC_CMDLINE)) &&
          complete.cmdline[0] && !(complete.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_CMDLINE) &&
          (!p->cmdline[0] || !strncmp(complete.cmdline, p->cmdline, strlen(p->cmdline)))) {
        copy_s(p->cmdline, sizeof(p->cmdline), complete.cmdline);
        p->source_truncation_mask &= (uint8_t)~EDR_PTC_SOURCE_TRUNC_CMDLINE;
      }
    }
  }
  /* Even short commands are shared once by exact process generation. A
   * clipped preview never acquires the authority of a complete command. */
  const char *subject_command = facts->subject ? facts->subject :
      (!edr_behavior_source_field_truncated(r, "source.cmdline") &&
       !edr_behavior_source_field_truncated(r, "source.cmdline_quality_unknown") ? r->cmdline : NULL);
  context->subject_command_unavailable = !subject_command || !subject_command[0];
  if (subject_command && subject_command[0] &&
      (r->cmdline[0] && strncmp(subject_command, r->cmdline, strlen(r->cmdline)) != 0 ?
       1 : edr_local_evidence_cache_save_command_fact(r, subject_command) != 0)) {
    command_failed = 1; context->subject_command_unavailable = 1;
  }
  if (context->parent_known) {
    const char *parent_command = facts->parent ? facts->parent :
        !(context->parent.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_CMDLINE) ? context->parent.cmdline : NULL;
    context->parent_command_unavailable = !parent_command || !parent_command[0];
    if (parent_command && parent_command[0]) {
      EdrBehaviorRecord *identity = calloc(1u, sizeof(*identity));
      if (!identity) { command_failed = 1; context->parent_command_unavailable = 1; }
      else {
        copy_s(identity->tenant_id, sizeof(identity->tenant_id), r->tenant_id);
        copy_s(identity->endpoint_id, sizeof(identity->endpoint_id), r->endpoint_id);
        identity->pid = context->parent.pid;
        identity->process_start_key = context->parent.process_start_key;
        identity->process_creation_filetime_100ns = context->parent.creation_filetime_100ns;
        if ((r->parent_cmdline[0] && strncmp(parent_command, r->parent_cmdline, strlen(r->parent_cmdline))) ||
            edr_local_evidence_cache_save_command_fact(identity, parent_command) != 0) {
          command_failed = 1; context->parent_command_unavailable = 1;
        }
        free(identity);
      }
    }
  }
  evidence_cache_lock();
  if (parent_tuple_conflicted(r->ppid, r->parent_process_start_key,
        r->parent_process_creation_filetime_100ns)) {
    context->parent_known = 0;
    context->parent_generation_conflict = 1;
  }
  int64_t ts = record_time_ns(r);
  char candidate[160]; candidate_id_for(r, candidate, sizeof(candidate));
  s_status.candidate_requests++;
  int exists = s_db ? sqlite_candidate_exists(candidate) : -1;
  s_persistence_failure = !s_db ? EDR_EVIDENCE_FAILURE_NO_DATABASE : EDR_EVIDENCE_FAILURE_STORAGE;
  if (!s_db || exists < 0) goto rejected;
  if (!exists) s_status.candidate_admission_attempts++;
  if (!sqlite_size_budget_allow_mode(!exists)) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_CAPACITY; goto rejected;
  }
  if (!sqlite_write_budget_allow(1u, ts, EVIDENCE_WRITE_CRITICAL_CONTEXT)) {
    s_persistence_failure = EDR_EVIDENCE_FAILURE_WRITE_BUDGET; goto rejected;
  }
  if (sqlite_record_candidate(r, candidate, context_before_count(r, ts),
        context_window_until(ts), context) != 0) {
    s_status.candidate_transaction_failures++; goto rejected;
  }
  command_failed |= context->command_dependency_missing;
  if (!exists) s_status.candidate_admitted++;
  if (command_failed) {
    record_persistence_failure(r, ts, 0, EDR_EVIDENCE_FAILURE_STORAGE);
    set_error("alert snapshot retained but a complete command fact was refused");
  }
  edr_validation_trace_event(r, "local_retention", "alert_parent_context_committed");
  result = command_failed ? 1 : 0;
  goto finished;
rejected:
  record_persistence_failure(r, ts, 1, s_persistence_failure);
  s_status.candidate_rejected++;
  s_status.records_dropped++;
finished:
  evidence_cache_unlock();
  free(context);
#else
  evidence_cache_lock();
  s_status.candidate_requests++;
  s_status.candidate_rejected++;
  s_status.records_dropped++;
  record_persistence_failure(r, record_time_ns(r), 1, EDR_EVIDENCE_FAILURE_NO_DATABASE);
  evidence_cache_unlock();
  (void)facts; (void)command_failed;
#endif
  free(resolved.subject); free(resolved.parent);
  return result;
}

void edr_local_evidence_cache_poll_maintenance(void) {
  uint64_t now = edr_monotonic_ns();
  evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  if (s_db && s_maintenance_reclaim_pages != 0u) {
    (void)sqlite_maintenance_reclaim_poll();
    evidence_cache_unlock();
    return;
  }
#endif
  if (now - s_last_maintenance_ns < 60000000000ULL) {
    evidence_cache_unlock();
    return;
  }
  s_last_maintenance_ns = now;
#if defined(EDR_HAVE_SQLITE)
  sqlite_maintenance(1);
#endif
  evidence_cache_unlock();
}

static uint32_t utilization_bps(uint64_t used, uint64_t capacity) {
  if (capacity == 0u) {
    return 0u;
  }
  /* Avoid overflowing `used * 10000`, while retaining an observable value
   * for a legacy/on-disk cache that is already over its configured limit. */
  uint64_t whole = used / capacity;
  uint64_t remainder = used % capacity;
  uint64_t bps = whole >= UINT32_MAX / 10000u ? UINT32_MAX : whole * 10000u;
  uint64_t fractional = remainder >= UINT64_MAX / 10000u ? UINT32_MAX :
      (remainder * 10000u) / capacity;
  if (UINT32_MAX - bps < fractional) {
    return UINT32_MAX;
  }
  bps += fractional;
  return bps > UINT32_MAX ? UINT32_MAX : (uint32_t)bps;
}

void edr_local_evidence_cache_get_status(EdrEvidenceCacheStatus *out) {
  if (!out) {
    return;
  }
  evidence_cache_lock();
  EdrEvidenceCacheStatus st = s_status;
  st.query_pin_exhausted=atomic_load_explicit(&s_query_pin_exhausted,memory_order_relaxed);
  st.write_budget_used = s_write_budget_count;
#if defined(EDR_HAVE_SQLITE)
  EvidenceWriteBudgetLimits write_limits = sqlite_write_budget_limits();
  st.write_budget_base_limit = write_limits.base;
  st.write_budget_limit = write_limits.ordinary_context;
  st.write_budget_critical_context_used = 0u;
  st.write_budget_critical_context_limit = 0u;
  st.write_budget_ordinary_context_used = s_write_budget_ordinary_context_count;
  st.write_budget_ordinary_context_limit = write_limits.ordinary_context;
#else
  st.write_budget_base_limit = env_u32_clamped(
      "EDR_EVIDENCE_CACHE_WRITE_BUDGET_PER_MIN", 80u, 0u, 100000u);
#endif
  const EvidenceCacheLockTiming *lock_timing = &s_evidence_cache_lock_timing;
  st.mutex_lock_samples = lock_timing->samples;
  st.mutex_wait_total_ns = lock_timing->wait_total_ns;
  st.mutex_wait_max_ns = lock_timing->wait_max_ns;
  st.mutex_wait_p95_ns = evidence_cache_histogram_percentile(
      lock_timing->wait_histogram, lock_timing->samples, 95u);
  st.mutex_wait_p99_ns = evidence_cache_histogram_percentile(
      lock_timing->wait_histogram, lock_timing->samples, 99u);
  st.mutex_hold_total_ns = lock_timing->hold_total_ns;
  st.mutex_hold_max_ns = lock_timing->hold_max_ns;
  st.mutex_hold_p95_ns = evidence_cache_histogram_percentile(
      lock_timing->hold_histogram, lock_timing->samples, 95u);
  st.mutex_hold_p99_ns = evidence_cache_histogram_percentile(
      lock_timing->hold_histogram, lock_timing->samples, 99u);
  uint32_t proc_n = 0;
  uint32_t ring_n = 0;
  uint32_t hot_n = 0;
  uint32_t agg_n = 0;
  uint32_t window_n = 0;
  uint32_t dedupe_n = 0;
  int64_t oldest_proc = 0;
  int64_t oldest_ring = 0;
  int64_t oldest_hot = 0;
  int64_t oldest_dedupe = 0;
  int64_t now = now_unix_ns();
  int64_t dedupe_cutoff = now - (int64_t)candidate_dedupe_window_s() * 1000000000LL;
  for (size_t i = 0; i < EDR_EVIDENCE_PROC_SLOTS; i++) {
    if (s_proc[i].pid != 0u) {
      proc_n++;
      if (s_proc[i].last_seen_ns > 0 &&
          (oldest_proc == 0 || s_proc[i].last_seen_ns < oldest_proc)) {
        oldest_proc = s_proc[i].last_seen_ns;
      }
    }
  }
  for (size_t i = 0; i < EDR_EVIDENCE_RING_SLOTS; i++) {
    if (s_ring[i].used) {
      ring_n++;
      if (s_ring[i].event_time_ns > 0 &&
          (oldest_ring == 0 || s_ring[i].event_time_ns < oldest_ring)) {
        oldest_ring = s_ring[i].event_time_ns;
      }
    }
  }
  for (size_t i = 0; i < EDR_EVIDENCE_CONTEXT_RING_SLOTS; i++) {
    if (s_context_ring[i].used) {
      hot_n++;
      if (s_context_ring[i].event_time_ns > 0 &&
          (oldest_hot == 0 || s_context_ring[i].event_time_ns < oldest_hot)) {
        oldest_hot = s_context_ring[i].event_time_ns;
      }
    }
  }
  for (size_t i = 0; i < EDR_EVIDENCE_AGG_SLOTS; i++) {
    if (s_ordinary_agg[i].used) {
      agg_n++;
    }
  }
  for (size_t i = 0; i < EDR_EVIDENCE_CONTEXT_WINDOWS; i++) {
    if (s_context_windows[i].pid != 0u && s_context_windows[i].until_ns >= now) {
      window_n++;
    }
  }
  for (size_t i = 0; i < EDR_EVIDENCE_CANDIDATE_DEDUP_SLOTS; i++) {
    if (s_candidate_dedupe[i].used && s_candidate_dedupe[i].last_ns >= dedupe_cutoff) {
      dedupe_n++;
      if (s_candidate_dedupe[i].last_ns > 0 &&
          (oldest_dedupe == 0 || s_candidate_dedupe[i].last_ns < oldest_dedupe)) {
        oldest_dedupe = s_candidate_dedupe[i].last_ns;
      }
    }
  }
  st.process_slots_used = proc_n;
  st.process_slots_capacity = EDR_EVIDENCE_PROC_SLOTS;
  st.ring_events = ring_n;
  st.ring_capacity = EDR_EVIDENCE_RING_SLOTS;
  st.hot_ring_events = hot_n;
  st.hot_ring_capacity = EDR_EVIDENCE_CONTEXT_RING_SLOTS;
  st.metrics_minutes = metric_slots_used();
  st.metrics_capacity = EDR_EVIDENCE_METRIC_SLOTS;
  st.aggregate_slots_used = agg_n;
  st.aggregate_slots_capacity = EDR_EVIDENCE_AGG_SLOTS;
  st.context_windows_used = window_n;
  st.context_windows_capacity = EDR_EVIDENCE_CONTEXT_WINDOWS;
  st.candidate_dedup_slots_used = dedupe_n;
  st.candidate_dedup_capacity = EDR_EVIDENCE_CANDIDATE_DEDUP_SLOTS;
  st.process_slots_utilization_bps = utilization_bps(proc_n, EDR_EVIDENCE_PROC_SLOTS);
  st.ring_utilization_bps = utilization_bps(ring_n, EDR_EVIDENCE_RING_SLOTS);
  st.hot_ring_utilization_bps = utilization_bps(hot_n, EDR_EVIDENCE_CONTEXT_RING_SLOTS);
  st.metrics_utilization_bps = utilization_bps(st.metrics_minutes, EDR_EVIDENCE_METRIC_SLOTS);
  st.aggregate_utilization_bps = utilization_bps(agg_n, EDR_EVIDENCE_AGG_SLOTS);
  st.context_windows_utilization_bps = utilization_bps(window_n, EDR_EVIDENCE_CONTEXT_WINDOWS);
  st.candidate_dedup_utilization_bps =
      utilization_bps(dedupe_n, EDR_EVIDENCE_CANDIDATE_DEDUP_SLOTS);
  st.oldest_process_last_seen_ns = oldest_proc;
  st.oldest_ring_event_time_ns = oldest_ring;
  st.oldest_hot_ring_event_time_ns = oldest_hot;
  st.oldest_candidate_dedup_ns = oldest_dedupe;
  st.static_bytes = (uint64_t)sizeof(s_proc) + (uint64_t)sizeof(s_ring) +
                    (uint64_t)sizeof(s_context_ring) + (uint64_t)sizeof(s_context_windows) +
                    (uint64_t)sizeof(s_metrics) + (uint64_t)sizeof(s_candidate_dedupe) +
                    (uint64_t)sizeof(s_ordinary_agg);
  /* Health degradation must also describe an unavailable durable store. Keep
   * the ingestion throttle predicate independent of this snapshot field. */
  st.pressure_active = (!st.db_open || evidence_cache_pressure_active()) ? 1u : 0u;
#if defined(EDR_HAVE_SQLITE)
  refresh_db_size_status();
  st.db_bytes = s_status.db_bytes;
  st.wal_bytes = s_status.wal_bytes;
  st.shm_bytes = s_status.shm_bytes;
  st.physical_bytes = s_status.physical_bytes;
  st.db_utilization_bps = utilization_bps(st.db_bytes + st.wal_bytes,
                                          (uint64_t)st.max_db_mb * 1024ULL * 1024ULL);
  refresh_candidate_inventory_status(&st);
  pmfe_refresh_inventory(&st);
#endif
  *out = st;
  evidence_cache_unlock();
}

static void json_escape(char *dst, size_t cap, const char *s) {
  if (!dst || cap == 0u) {
    return;
  }
  size_t o = 0;
  dst[o++] = '"';
  if (!s) {
    s = "";
  }
  for (; *s && o + 2u < cap; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      dst[o++] = '\\';
      dst[o++] = (char)c;
    } else if (c < 0x20u) {
      dst[o++] = ' ';
    } else {
      dst[o++] = (char)c;
    }
  }
  if (o + 1u < cap) {
    dst[o++] = '"';
  }
  dst[o < cap ? o : cap - 1u] = '\0';
}

typedef struct {
  int has_type;
  uint32_t type;
  uint32_t pid;
  int has_process_start_key;
  uint64_t process_start_key;
  int has_process_creation_filetime_100ns;
  uint64_t process_creation_filetime_100ns;
  uint32_t limit;
  uint32_t time_window_s;
  int64_t from_ns, until_ns;
  char endpoint_id[48];
  char process_name_contains[513];
  char process_path_contains[4097];
  char cmdline_contains[4097];
  char file_path_contains[4097];
  char file_sha256[65];
  char file_ext[32];
  char remote_ip[129];
  uint32_t remote_port;
  char registry_key_contains[256];
} RtqFilter;

static int contains_ci(const char *haystack, const char *needle) {
  if (!needle || !needle[0]) {
    return 1;
  }
  if (!haystack || !haystack[0]) {
    return 0;
  }
  size_t nn = strlen(needle);
  for (const char *h = haystack; *h; h++) {
    size_t i = 0;
    while (i < nn && h[i] &&
           tolower((unsigned char)h[i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == nn) {
      return 1;
    }
  }
  return 0;
}

static int same_ci(const char *a, const char *b) {
  if (!a || !b) {
    return 0;
  }
  while (*a && *b) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
      return 0;
    }
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

static int path_ext_matches(const char *path, const char *ext) {
  if (!ext || !ext[0]) {
    return 1;
  }
  if (!path || !path[0]) {
    return 0;
  }
  const char *dot = strrchr(path, '.');
  if (!dot || !dot[0]) {
    return 0;
  }
  if (ext[0] == '.') {
    return same_ci(dot, ext);
  }
  return same_ci(dot + 1, ext);
}

static int json_get_string(const char *json, const char *key, char *out, size_t cap) {
  if (!json || !key || !out || cap == 0u) {
    return -1;
  }
  out[0] = '\0';
  char pat[80];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) {
    return -1;
  }
  const char *colon = strchr(p + strlen(pat), ':');
  if (!colon) {
    return -1;
  }
  const char *q = strchr(colon + 1, '"');
  if (!q) {
    return -1;
  }
  q++;
  size_t o = 0;
  while (*q && *q != '"' && o + 1u < cap) {
    if (*q == '\\' && q[1]) {
      q++;
      if (*q == 'n' || *q == 'r' || *q == 't') {
        out[o++] = ' ';
      } else {
        out[o++] = *q;
      }
      q++;
      continue;
    }
    out[o++] = *q++;
  }
  out[o] = '\0';
  return out[0] ? 0 : -1;
}

static int json_get_u64(const char *json, const char *key, uint64_t *out) {
  char text[64];
  char pattern[80];
  const char *p;
  char *end = NULL;
  unsigned long long value;
  if (!json || !key || !out) {
    return -1;
  }
  if (json_get_string(json, key, text, sizeof(text)) == 0) {
    if (text[0] < '0' || text[0] > '9') {
      return -1;
    }
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != ERANGE && end != text && *end == '\0') {
      *out = (uint64_t)value;
      return 0;
    }
    return -1;
  }
  snprintf(pattern, sizeof(pattern), "\"%s\"", key);
  p = strstr(json, pattern);
  if (!p) {
    return -1;
  }
  p = strchr(p + strlen(pattern), ':');
  if (!p) {
    return -1;
  }
  do {
    p++;
  } while (*p && isspace((unsigned char)*p));
  if (*p < '0' || *p > '9') {
    return -1;
  }
  errno = 0;
  value = strtoull(p, &end, 10);
  if (errno == ERANGE || end == p ||
      (*end != ',' && *end != '}' && !isspace((unsigned char)*end))) {
    return -1;
  }
  *out = (uint64_t)value;
  return 0;
}

static uint32_t event_type_from_name(const char *s, int *ok) {
  if (ok) {
    *ok = 1;
  }
  if (!s || !s[0]) {
    if (ok) {
      *ok = 0;
    }
    return 0u;
  }
  if (strcmp(s, "process") == 0 || strcmp(s, "process_create") == 0) {
    return (uint32_t)EDR_EVENT_PROCESS_CREATE;
  }
  if (strcmp(s, "network") == 0 || strcmp(s, "net") == 0 || strcmp(s, "connect") == 0) {
    return (uint32_t)EDR_EVENT_NET_CONNECT;
  }
  if (strcmp(s, "dns") == 0) {
    return (uint32_t)EDR_EVENT_NET_DNS_QUERY;
  }
  if (strcmp(s, "tls") == 0) {
    return (uint32_t)EDR_EVENT_NET_TLS_HANDSHAKE;
  }
  if (strcmp(s, "file") == 0 || strcmp(s, "file_write") == 0) {
    return (uint32_t)EDR_EVENT_FILE_WRITE;
  }
  if (strcmp(s, "registry") == 0 || strcmp(s, "reg") == 0) {
    return (uint32_t)EDR_EVENT_REG_SET_VALUE;
  }
  if (strcmp(s, "script") == 0 || strcmp(s, "powershell") == 0) {
    return (uint32_t)EDR_EVENT_SCRIPT_POWERSHELL;
  }
  if (strcmp(s, "webshell") == 0) {
    return (uint32_t)EDR_EVENT_WEBSHELL_DETECTED;
  }
  if (strcmp(s, "shellcode") == 0) {
    return (uint32_t)EDR_EVENT_PROTOCOL_SHELLCODE;
  }
  if (strcmp(s, "pmfe") == 0) {
    return (uint32_t)EDR_EVENT_PMFE_SCAN_RESULT;
  }
  char *end = NULL;
  unsigned long v = strtoul(s, &end, 10);
  if (end != s && *end == '\0' && v <= 0xffffffffUL) {
    return (uint32_t)v;
  }
  if (ok) {
    *ok = 0;
  }
  return 0u;
}

static int rtq_filter_text(const cJSON *root,const char *canonical,const char *alias,
                            char *out,size_t cap) {
  const cJSON *v=cJSON_GetObjectItemCaseSensitive(root,canonical);
  const cJSON *old=alias?cJSON_GetObjectItemCaseSensitive(root,alias):NULL;
  if(v && old && (!cJSON_IsString(v)||!cJSON_IsString(old)||strcmp(v->valuestring,old->valuestring)))return 0;
  if(!v)v=old;if(!v)return 1;
  if(!cJSON_IsString(v)||!v->valuestring||strlen(v->valuestring)>=cap)return 0;
  memcpy(out,v->valuestring,strlen(v->valuestring)+1);return 1;
}
static int rtq_filter_u32(const cJSON *root,const char *key,uint32_t *out,uint32_t min,uint32_t max) {
  const cJSON *v=cJSON_GetObjectItemCaseSensitive(root,key);if(!v)return 1;
  if(!cJSON_IsNumber(v)||v->valuedouble<min||v->valuedouble>max||v->valuedouble!=(double)(uint32_t)v->valuedouble)return 0;
  *out=(uint32_t)v->valuedouble;return 1;
}
static int parse_rtq_filter(const char *json, RtqFilter *f) {
  memset(f,0,sizeof(*f));f->limit=50u;f->time_window_s=600u;
  if(!json)return 0;
  cJSON *root=edr_egress_parse_purpose_object(json,strlen(json));if(!root)return -1;
  int ok=rtq_filter_text(root,"endpoint_id",NULL,f->endpoint_id,sizeof(f->endpoint_id)) &&
      rtq_filter_text(root,"process_name","process_name_contains",f->process_name_contains,sizeof(f->process_name_contains)) &&
      rtq_filter_text(root,"process_path",NULL,f->process_path_contains,sizeof(f->process_path_contains)) &&
      rtq_filter_text(root,"process_cmdline","cmdline_contains",f->cmdline_contains,sizeof(f->cmdline_contains)) &&
      rtq_filter_text(root,"file_path","file_path_contains",f->file_path_contains,sizeof(f->file_path_contains)) &&
      rtq_filter_text(root,"file_sha256","sha256",f->file_sha256,sizeof(f->file_sha256)) &&
      rtq_filter_text(root,"file_ext",NULL,f->file_ext,sizeof(f->file_ext)) &&
      rtq_filter_text(root,"remote_ip",NULL,f->remote_ip,sizeof(f->remote_ip)) &&
      rtq_filter_text(root,"registry_key_contains",NULL,f->registry_key_contains,sizeof(f->registry_key_contains)) &&
      rtq_filter_u32(root,"remote_port",&f->remote_port,1u,65535u) &&
      rtq_filter_u32(root,"pid",&f->pid,1u,UINT32_MAX) &&
      rtq_filter_u32(root,"limit",&f->limit,1u,1000u) &&
      rtq_filter_u32(root,"time_window_s",&f->time_window_s,1u,604800u);
  if(json_get_u64(json,"process_start_key",&f->process_start_key)==0)f->has_process_start_key=f->process_start_key!=0u;
  if(json_get_u64(json,"process_creation_filetime_100ns",&f->process_creation_filetime_100ns)==0)f->has_process_creation_filetime_100ns=f->process_creation_filetime_100ns!=0u;
  char et[65]={0};ok=ok&&rtq_filter_text(root,"event_type","type",et,sizeof(et));
  if(ok && et[0]){int known=0;f->type=event_type_from_name(et,&known);f->has_type=known;ok=known;}
  cJSON_Delete(root);return ok?0:-1;
}

static int rtq_match_common(const RtqFilter *f, uint32_t type, uint32_t pid,
                            int64_t event_time_ns, const char *endpoint_id,
                            const char *process_name, const char *cmdline, const char *process_path,
                            const char *file_path, const char *remote_ip, uint32_t remote_port,
                            const char *registry_key, uint64_t process_start_key,
                            uint64_t process_creation_filetime_100ns) {
  int64_t cutoff = f->from_ns ? f->from_ns : now_unix_ns() - (int64_t)f->time_window_s * 1000000000LL;
  if (f->until_ns && (event_time_ns <= 0 || event_time_ns > f->until_ns)) return 0;
  if (event_time_ns > 0 && event_time_ns < cutoff) {
    return 0;
  }
  if (f->has_type && f->type != type) {
    return 0;
  }
  if (f->pid != 0u && f->pid != pid) {
    return 0;
  }
  if (f->has_process_start_key && f->process_start_key != process_start_key) {
    return 0;
  }
  if (f->has_process_creation_filetime_100ns &&
      f->process_creation_filetime_100ns != process_creation_filetime_100ns) {
    return 0;
  }
  if (f->endpoint_id[0] && endpoint_id && endpoint_id[0] &&
      strcmp(f->endpoint_id, endpoint_id) != 0) {
    return 0;
  }
  if (!contains_ci(process_name, f->process_name_contains)) {
    return 0;
  }
  if (!contains_ci(process_path, f->process_path_contains) ||
      (f->remote_port && f->remote_port != remote_port)) return 0;
  if (!contains_ci(cmdline, f->cmdline_contains)) {
    return 0;
  }
  if (!contains_ci(file_path, f->file_path_contains)) {
    return 0;
  }
  if (f->remote_ip[0] && (!remote_ip || strcmp(f->remote_ip, remote_ip) != 0)) {
    return 0;
  }
  if (!contains_ci(registry_key, f->registry_key_contains)) {
    return 0;
  }
  return 1;
}

static void appendf(char *out, size_t cap, size_t *off, const char *fmt, ...) {
  if (!out || !off || *off >= cap) {
    return;
  }
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(out + *off, cap - *off, fmt, ap);
  va_end(ap);
  if (n < 0) {
    return;
  }
  size_t nn = (size_t)n;
  if (nn >= cap - *off) {
    *off = cap - 1u;
  } else {
    *off += nn;
  }
}

static void append_event_json(char *out, size_t cap, size_t *off, int *first,
                              const char *source, int64_t event_time_ns,
                              uint32_t type, uint32_t pid, uint32_t ppid,
                              const char *endpoint_id, const char *process_name,
                              const char *exe_path, const char *cmdline,
                              const char *file_path, const char *dns_query,
                              const char *remote_ip, uint32_t dst_port,
                              const char *registry_key, const char *registry_value,
                              const char *registry_op,
                              const char *process_start_key,
                              const char *process_creation_filetime_100ns,
                              const char *process_generation_source,
                              const char *source_completeness,
                              const char *source_truncated_fields) {
  char ep[120], pn[320], xp[1200], cl[1200], fp[1200], dns[640], rip[120], rk[1200], rv[640], ro[80];
  char start_key[48], creation[48], generation_source[160], source_state[80];
  char source_fields[EDR_BR_SOURCE_TRUNCATED_FIELDS_LEN * 2u + 3u];
  json_escape(ep, sizeof(ep), endpoint_id);
  json_escape(pn, sizeof(pn), process_name);
  json_escape(xp, sizeof(xp), exe_path);
  json_escape(cl, sizeof(cl), cmdline);
  json_escape(fp, sizeof(fp), file_path);
  json_escape(dns, sizeof(dns), dns_query);
  json_escape(rip, sizeof(rip), remote_ip);
  json_escape(rk, sizeof(rk), registry_key);
  json_escape(rv, sizeof(rv), registry_value);
  json_escape(ro, sizeof(ro), registry_op);
  json_escape(start_key, sizeof(start_key), process_start_key);
  json_escape(creation, sizeof(creation), process_creation_filetime_100ns);
  json_escape(generation_source, sizeof(generation_source), process_generation_source);
  json_escape(source_state, sizeof(source_state), source_completeness);
  json_escape(source_fields, sizeof(source_fields), source_truncated_fields);
  appendf(out, cap, off, "%s{\"source\":\"%s\",\"event_time_ns\":%lld,\"type\":%u,"
                          "\"pid\":%u,\"ppid\":%u,\"endpoint_id\":%s,\"process_name\":%s,"
                          "\"exe_path\":%s,\"cmdline\":%s,\"file_path\":%s,\"dns_query\":%s,"
                          "\"remote_ip\":%s,\"dst_port\":%u,\"registry_key\":%s,"
                          "\"registry_value\":%s,\"registry_op\":%s,\"process_start_key\":%s,"
                          "\"process_creation_filetime_100ns\":%s,\"process_generation_source\":%s,"
                          "\"source_completeness\":%s,\"source_truncated_fields\":%s}",
          *first ? "" : ",", source ? source : "", (long long)event_time_ns, type, pid, ppid,
          ep, pn, xp, cl, fp, dns, rip, dst_port, rk, rv, ro, start_key, creation,
          generation_source, source_state, source_fields);
  *first = 0;
}

static int evidence_cache_query_file_hash_json_locked(const char *file_sha256,
                                                       const char *file_path_contains,
                                                       const char *file_ext,
                                                       uint32_t limit,
                                                       char *out, size_t cap,
                                                       uint32_t *returned,
                                                       uint32_t *scanned,
                                                       int *truncated) {
  if (!out || cap == 0u) {
    return -1;
  }
  out[0] = '\0';
  uint32_t ret = 0;
  uint32_t scan = 0;
  int partial = 0;
  uint32_t lim = limit;
  if (lim == 0u || lim > 500u) {
    lim = 50u;
  }

  size_t off = 0;
  int first = 1;
  appendf(out, cap, &off, "[");
  if (file_sha256 && file_sha256[0]) {
#if defined(EDR_HAVE_SQLITE)
    if (s_db) {
      const char *sql =
          "SELECT endpoint_id,path,sha256,pid,last_seen_ns "
          "FROM file_evidence WHERE sha256 = ? COLLATE NOCASE "
          "ORDER BY last_seen_ns DESC LIMIT ?;";
      sqlite3_stmt *st = NULL;
      if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
        bind_text(st, 1, file_sha256);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)(lim * 20u + 100u));
        while (sqlite3_step(st) == SQLITE_ROW && ret < lim) {
          const char *ep = (const char *)sqlite3_column_text(st, 0);
          const char *path = (const char *)sqlite3_column_text(st, 1);
          const char *sha = (const char *)sqlite3_column_text(st, 2);
          uint32_t pid = (uint32_t)sqlite3_column_int64(st, 3);
          int64_t last_seen = sqlite3_column_int64(st, 4);
          scan++;
          if (!contains_ci(path, file_path_contains)) {
            continue;
          }
          if (!path_ext_matches(path, file_ext)) {
            continue;
          }
          char epj[120], pathj[1200], shaj[160];
          json_escape(epj, sizeof(epj), ep);
          json_escape(pathj, sizeof(pathj), path);
          json_escape(shaj, sizeof(shaj), sha);
          size_t row_start = off;
          appendf(out, cap, &off,
                  "%s{\"type\":\"file\",\"source\":\"file_evidence\",\"cache_hit\":true,"
                  "\"endpoint_id\":%s,\"path\":%s,\"sha256\":%s,\"pid\":%u,"
                  "\"last_seen_ns\":%lld}",
                  first ? "" : ",", epj, pathj, shaj, pid, (long long)last_seen);
          if (off >= cap - 1u) {
            off = row_start;
            out[off] = '\0';
            partial = 1;
            break;
          }
          first = 0;
          ret++;
        }
        sqlite3_finalize(st);
      }
    }
#endif
  }
  appendf(out, cap, &off, "]");
  out[cap - 1u] = '\0';
  if (returned) {
    *returned = ret;
  }
  if (scanned) {
    *scanned = scan;
  }
  if (truncated) {
    *truncated = partial;
  }
  return 0;
}

int edr_local_evidence_cache_query_file_hash_json(const char *file_sha256,
                                                  const char *file_path_contains,
                                                  const char *file_ext,
                                                  uint32_t limit,
                                                  char *out, size_t cap,
                                                  uint32_t *returned,
                                                  uint32_t *scanned,
                                                  int *truncated) {
  int rc;
  if (!out || cap == 0u) return -1;
  evidence_cache_lock();
  rc = evidence_cache_query_file_hash_json_locked(file_sha256, file_path_contains, file_ext,
                                                   limit, out, cap, returned, scanned, truncated);
  evidence_cache_unlock();
  return rc;
}

static void append_json_array_items(char *out, size_t cap, size_t *off, int *first,
                                    const char *array_json) {
  if (!out || !off || !first || !array_json) {
    return;
  }
  const char *b = strchr(array_json, '[');
  const char *e = strrchr(array_json, ']');
  if (!b || !e || e <= b + 1) {
    return;
  }
  b++;
  while (b < e && isspace((unsigned char)*b)) {
    b++;
  }
  while (e > b && isspace((unsigned char)e[-1])) {
    e--;
  }
  if (e <= b) {
    return;
  }
  if (!*first) {
    appendf(out, cap, off, ",");
  }
  size_t n = (size_t)(e - b);
  if (n > 0u) {
    if (n > (size_t)2147483647) {
      n = (size_t)2147483647;
    }
    appendf(out, cap, off, "%.*s", (int)n, b);
    *first = 0;
  }
}

/* A synchronous request owns at most one cache snapshot and the existing
 * signed result envelope (<=16383 bytes). Try-lock failure is a visible finite
 * pin-capacity refusal; no investigation can leave a permanent cache pin. */
static int evidence_cache_try_query_lock(void) {
#if defined(_WIN32)
  if (!TryAcquireSRWLockExclusive(&s_evidence_cache_lock)) return 0;
#else
  if (pthread_mutex_trylock(&s_evidence_cache_lock) != 0) return 0;
#endif
  s_evidence_cache_lock_tls.wait_ns = 0;
  s_evidence_cache_lock_tls.acquired_ns = evidence_cache_clock_ns();
  return 1;
}

static int authorized_query_number(const cJSON *root, const char *name,
                                  int64_t min, int64_t max, int64_t *out) {
  const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsNumber(v) || v->valuedouble < (double)min || v->valuedouble > (double)max ||
      v->valuedouble != (double)(int64_t)v->valuedouble) return 0;
  *out = (int64_t)v->valuedouble; return 1;
}

static cJSON *authorized_query_row(const RtqFilter *f, const char *source,
    int64_t ts, uint32_t type, uint32_t pid, uint32_t ppid, const char *const fields[16]) {
  static const char *const names[16] = {"endpoint_id", "process_name", "exe_path", "cmdline",
    "file_path", "dns_query", "remote_ip", "registry_key", "registry_value", "registry_op",
    "process_start_key", "process_creation_filetime_100ns", "process_generation_source",
    "source_completeness", "source_truncated_fields", "dst_port"};
  cJSON *row = cJSON_CreateObject();
  if (!row || !cJSON_AddStringToObject(row, "source", source) ||
      !cJSON_AddNumberToObject(row, "event_time_ns", (double)ts) ||
      !cJSON_AddNumberToObject(row, "type", type) || !cJSON_AddNumberToObject(row, "pid", pid) ||
      !cJSON_AddNumberToObject(row, "ppid", ppid)) goto failed;
  for (unsigned i = 0; i < 15; ++i) {
    if (i == 3 && !f->cmdline_contains[0]) continue;
    if (i == 4 && !f->file_path_contains[0] && (!f->has_type || f->type != EDR_EVENT_FILE_WRITE)) continue;
    if (i == 5 && (!f->has_type || f->type != EDR_EVENT_NET_DNS_QUERY)) continue;
    if (i == 6 && !f->remote_ip[0] && !f->remote_port && (!f->has_type || f->type != EDR_EVENT_NET_CONNECT)) continue;
    if (i >= 7 && i <= 9 && !f->registry_key_contains[0] && (!f->has_type || f->type != EDR_EVENT_REG_SET_VALUE)) continue;
    const char *value = fields[i] ? fields[i] : "";
    if (strlen(value) > 8192u || !manifest_utf8_valid(value) || !cJSON_AddStringToObject(row, names[i], value)) goto failed;
  }
  if (f->remote_ip[0] || f->remote_port || (f->has_type && f->type == EDR_EVENT_NET_CONNECT)) {
    if (!cJSON_AddNumberToObject(row, "dst_port", fields[15] ? strtoul(fields[15], NULL, 10) : 0)) goto failed;
  }
  return row;
failed:
  cJSON_Delete(row); return NULL;
}

#if defined(EDR_HAVE_SQLITE)
typedef struct { int64_t expires_ms; uint64_t until_mono_ns; } EvidenceQueryDeadline;
static int authorized_query_interrupted(void *arg) {
  const EvidenceQueryDeadline *deadline = (const EvidenceQueryDeadline *)arg;
  return now_unix_ns()/1000000LL >= deadline->expires_ms ||
         edr_monotonic_ns() >= deadline->until_mono_ns;
}

typedef struct {
  const RtqFilter *filter;
  EvidenceQueryDeadline *deadline;
  cJSON *rows;
  size_t envelope, *encoded_bytes;
  unsigned *returned;
  int *matched,*partial;
  const char *error;
} EvidenceQueueQuery;

static int authorized_queue_cancel(void *opaque) {
  EvidenceQueueQuery *q=opaque;
  return authorized_query_interrupted(q->deadline);
}
static uint32_t evidence_wire_u32(const uint8_t *p) {
  return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
/* The frozen terminal protocol contains a numeric uint64 birth timestamp.
 * Bind its decimal lexeme before cJSON can round it through double. Ambiguous
 * duplicate members are rejected; this does not rewrite the frozen payload. */
static const cJSON *evidence_unique_member(const cJSON *object,const char *name) {
  const cJSON *found=NULL,*item=NULL;
  if(!cJSON_IsObject(object)) return NULL;
  cJSON_ArrayForEach(item,object) if(item->string && !strcmp(item->string,name)) {
    if(found) return NULL;
    found=item;
  }
  return found;
}
static int evidence_member_equals(const cJSON *object,const char *name,const char *expected) {
  const cJSON *item=evidence_unique_member(object,name);
  return cJSON_IsString(item) && !strcmp(item->valuestring,expected);
}
static int evidence_terminal_source_valid(const edr_v1_BehaviorEvent *event) {
  if(event->has_behavior_alert || !event->process_start_key || !event->process_creation_filetime_100ns) return 0;
  cJSON *ctx=cJSON_ParseWithOpts(event->ave_result_json,NULL,1);
  const cJSON *terminal=evidence_unique_member(ctx,"enforcement_terminal");
  const cJSON *process=evidence_unique_member(terminal,"process");
  const cJSON *pid=evidence_unique_member(terminal,"process_pid");
  const cJSON *birth=evidence_unique_member(process,"creation_filetime_100ns");
  char generation[32];
  snprintf(generation,sizeof(generation),"startkey-%016llx",(unsigned long long)event->process_start_key);
  int valid=evidence_member_equals(terminal,"phase","result") &&
      evidence_member_equals(terminal,"source_event_key",event->event_id) &&
      evidence_member_equals(terminal,"source_event_id",event->event_id) &&
      cJSON_IsNumber(pid) && pid->valuedouble==(double)event->pid &&
      evidence_member_equals(process,"generation_key",generation) && cJSON_IsNumber(birth);
  static const char key[]="\"creation_filetime_100ns\"";
  const char *p=event->ave_result_json; unsigned found=0;
  while(valid && (p=strstr(p,key))) {
    p+=sizeof(key)-1u; while(isspace((unsigned char)*p)) ++p;
    if(*p++!=':') { valid=0; break; }
    while(isspace((unsigned char)*p)) ++p;
    uint64_t value=0; unsigned digits=0;
    if(*p<'1' || *p>'9') { valid=0; break; }
    while(*p>='0' && *p<='9') {
      if(value>(UINT64_MAX-(uint64_t)(*p-'0'))/10u) { valid=0; break; }
      value=value*10u+(uint64_t)(*p++-'0'); ++digits;
    }
    while(isspace((unsigned char)*p)) ++p;
    if(!valid || digits>20 || value!=event->process_creation_filetime_100ns ||
        (*p!=',' && *p!='}') || found++) { valid=0; break; }
  }
  cJSON_Delete(ctx); return valid && found==1u;
}
/* Existing BAT1/BLZ4 framing and nanopb messages, projected through the same
 * signed-purpose field selector as candidate rows. No raw wire enters JSON. */
static int authorized_queue_visit(const char *event_id,const EdrStorageQueueLocalEvidenceOwner *owner,
    const uint8_t *wire,size_t size,void *opaque) {
  EvidenceQueueQuery *q=opaque;
  const RtqFilter *f=q->filter;
  uint8_t *decoded=NULL;
  edr_v1_BehaviorEvent *event=NULL;
  cJSON *row=NULL; char *encoded=NULL;
  int result=-1;
  if(authorized_queue_cancel(q)) { q->error="evidence query deadline reached"; return -1; }
  if(!wire || size<=16 || size>4u*EDR_EVIDENCE_MANIFEST_MAX_BYTES || evidence_wire_u32(wire+4)!=1u) goto malformed;
  uint32_t magic=evidence_wire_u32(wire),raw=evidence_wire_u32(wire+8);
  if(raw<5 || raw>4u*EDR_EVIDENCE_MANIFEST_MAX_BYTES) goto malformed;
  const uint8_t *body=wire+12;
  if(magic==EDR_TRANSPORT_BATCH_MAGIC_RAW) { if(raw!=size-12) goto malformed; }
  else if(magic==EDR_TRANSPORT_BATCH_MAGIC_LZ4) {
#ifdef EDR_HAVE_LZ4
    decoded=malloc(raw); if(!decoded) goto allocation_failed;
    if(LZ4_decompress_safe((const char*)body,(char*)decoded,(int)(size-12),(int)raw)!=(int)raw) goto malformed;
    body=decoded;
#else
    q->error="evidence query compressed decoder unavailable"; goto done;
#endif
  } else goto malformed;
  if(evidence_wire_u32(body)!=raw-4u) goto malformed;
  event=calloc(1,sizeof(*event)); if(!event) goto allocation_failed;
  pb_istream_t stream=pb_istream_from_buffer(body+4,raw-4);
  if(!pb_decode(&stream,edr_v1_BehaviorEvent_fields,event) || stream.bytes_left ||
      strcmp(event->event_id,event_id) || strcmp(event->tenant_id,owner->tenant_id) ||
      strcmp(event->endpoint_id,owner->endpoint_id) || event->event_time_ns!=owner->event_time_ns ||
      event->type!=(int32_t)owner->event_type || event->pid!=owner->pid || event->ppid!=owner->parent_pid ||
      event->process_start_key!=owner->process_start_key ||
      event->process_creation_filetime_100ns!=owner->process_creation_filetime_100ns) goto malformed;
  if(!strcmp(owner->diagnostic_reason,"enforcement_terminal_result") && !evidence_terminal_source_valid(event)) goto malformed;
  const char *file=event->which_detail==edr_v1_BehaviorEvent_file_tag ? event->detail.file.target_path : "";
  const char *ip=event->which_detail==edr_v1_BehaviorEvent_network_tag ? event->detail.network.dst_ip : "";
  const char *dns=event->which_detail==edr_v1_BehaviorEvent_dns_tag ? event->detail.dns.query_name : "";
  const char *reg=event->which_detail==edr_v1_BehaviorEvent_registry_tag ? event->detail.registry.key_path : "";
  const char *value=event->which_detail==edr_v1_BehaviorEvent_registry_tag ? event->detail.registry.value_name : "";
  const char *op=event->which_detail==edr_v1_BehaviorEvent_registry_tag ? event->detail.registry.operation : "";
  uint32_t port=event->which_detail==edr_v1_BehaviorEvent_network_tag ? event->detail.network.dst_port : 0u;
  if(!rtq_match_common(f,(uint32_t)event->type,event->pid,event->event_time_ns,event->endpoint_id,event->process_name,
      event->cmdline,event->exe_path,file,ip,port,reg,event->process_start_key,event->process_creation_filetime_100ns)) {
    result=1; goto done;
  }
  if(f->cmdline_contains[0] && strlen(event->cmdline)>8192u) { q->error="requested command exceeds the authorized field byte budget"; goto done; }
  char start[32],creation[32],port_text[16];
  sqlite_u64_decimal(event->process_start_key,start); sqlite_u64_decimal(event->process_creation_filetime_100ns,creation);
  snprintf(port_text,sizeof(port_text),"%u",port);
  const char *fields[16]={event->endpoint_id,event->process_name,event->exe_path,event->cmdline,file,dns,ip,reg,value,op,
      start,creation,event->process_generation_source,event->source_completeness,event->truncated_fields,port_text};
  row=authorized_query_row(f,"event_queue",event->event_time_ns,(uint32_t)event->type,event->pid,event->ppid,fields);
  if(!row || !(encoded=cJSON_PrintUnformatted(row))) goto allocation_failed;
  *q->matched=1;
  size_t bytes=strlen(encoded)+1u;
  if(*q->returned>=f->limit || *q->encoded_bytes>q->envelope || bytes>q->envelope-*q->encoded_bytes) {
    *q->partial=1; result=0; goto done;
  }
  if(!cJSON_AddItemToArray(q->rows,row)) goto allocation_failed;
  row=NULL; *q->encoded_bytes+=bytes; ++*q->returned;
  result=*q->returned<f->limit ? 1 : 0;
  if(!result) *q->partial=1;
  goto done;
malformed:
  q->error="evidence query local wire identity or encoding invalid"; goto done;
allocation_failed:
  q->error="evidence query local projection allocation failed";
done:
  cJSON_free(encoded); cJSON_Delete(row); free(event); free(decoded); return result;
}

#endif

int edr_local_evidence_cache_query_authorized_json(const char *command_id,
    const EdrSoarCommandMeta *meta, char *out, size_t cap) {
  if (!out || cap < 256u) return -1;
  copy_s(out, cap, "evidence query authorization invalid");
  if (!command_id || !meta) return -1;
  const EdrCommandResultAuthorization *a = &meta->result_authorization;
  if (!memchr(a->command_id, 0, sizeof(a->command_id)) ||
      !memchr(a->command_type, 0, sizeof(a->command_type)) ||
      !memchr(a->tenant_id, 0, sizeof(a->tenant_id)) || !a->tenant_id[0] ||
      !memchr(a->endpoint_id, 0, sizeof(a->endpoint_id)) || !a->endpoint_id[0] ||
      !memchr(a->content_contract, 0, sizeof(a->content_contract)) ||
      strcmp(a->command_id, command_id) || strcmp(a->command_type, "rtq_query")) return -1;
  int64_t now_ms = now_unix_ns()/1000000LL;
  if (meta->issued_at_unix_ms <= 0 || !meta->deadline_ms ||
      meta->issued_at_unix_ms > INT64_MAX-(int64_t)meta->deadline_ms ||
      now_ms < meta->issued_at_unix_ms || now_ms >= meta->issued_at_unix_ms+meta->deadline_ms ||
      now_ms >= a->expires_unix_ms) { copy_s(out, cap, "evidence query authorization expired"); return -1; }
  cJSON *contract = edr_egress_parse_purpose_object(a->content_contract, strlen(a->content_contract));
  const cJSON *kind = cJSON_GetObjectItemCaseSensitive(contract, "kind");
  const cJSON *schema = cJSON_GetObjectItemCaseSensitive(contract, "schema");
  const cJSON *request = cJSON_GetObjectItemCaseSensitive(contract, "request");
  int64_t max_bytes, max_rows, window, issued;
  char *request_json = NULL;
  RtqFilter filter;
  if (!cJSON_IsString(kind) || strcmp(kind->valuestring, "cached_rtq") ||
      !cJSON_IsString(schema) || strcmp(schema->valuestring, "edr.command.result-purpose.v1") ||
      !cJSON_IsObject(request) || !authorized_query_number(contract, "max_bytes", 256, 16383, &max_bytes) ||
      !authorized_query_number(contract, "max_rows", 1, 1000, &max_rows) ||
      !authorized_query_number(contract, "window_s", 1, 604800, &window) ||
      !authorized_query_number(contract, "issued_unix_ms", 1, INT64_MAX/1000000LL-300000, &issued) ||
      issued != meta->issued_at_unix_ms || !(request_json = cJSON_PrintUnformatted(request)) ||
      parse_rtq_filter(request_json, &filter) || filter.limit != (uint32_t)max_rows ||
      filter.time_window_s != (uint32_t)window ||
      (filter.endpoint_id[0] && strcmp(filter.endpoint_id, a->endpoint_id)) ||
      strlen(a->endpoint_id) >= sizeof(filter.endpoint_id)) {
    cJSON_free(request_json); cJSON_Delete(contract); return -1;
  }
  cJSON_free(request_json); cJSON_Delete(contract);
  if (filter.file_sha256[0] && (filter.pid || filter.has_process_start_key || filter.has_process_creation_filetime_100ns ||
      filter.process_name_contains[0] || filter.process_path_contains[0] || filter.cmdline_contains[0] ||
      filter.remote_ip[0] || filter.remote_port || filter.registry_key_contains[0] ||
      (filter.has_type && filter.type != EDR_EVENT_FILE_WRITE))) {
    copy_s(out, cap, "evidence hash query does not support the requested combined scope"); return -1;
  }
  copy_s(filter.endpoint_id, sizeof(filter.endpoint_id), a->endpoint_id);
  int64_t from_ns = (issued-window*1000LL)*1000000LL;
  int64_t until_ns = (issued+300000LL)*1000000LL;
  /* Match the frozen request's clock, not a later execution wall clock. */
  filter.from_ns = from_ns; filter.until_ns = until_ns;
  size_t envelope = cap-1u < (size_t)max_bytes ? cap-1u : (size_t)max_bytes;
  if (!evidence_cache_try_query_lock()) {
    atomic_fetch_add_explicit(&s_query_pin_exhausted,1u,memory_order_relaxed);
    copy_s(out, cap, "evidence query pin capacity exhausted"); return -2;
  }
  int rc = -1, partial = 0, matched = 0;
  unsigned scanned = 0, returned = 0;
  size_t encoded_bytes = 256u; /* bounded result metadata and separators */
  cJSON *result = cJSON_CreateObject(), *rows = result ? cJSON_AddArrayToObject(result, "rows") : NULL;
#if defined(EDR_HAVE_SQLITE)
  sqlite3_stmt *st = NULL;
  EdrBehaviorRecord *command_identity = NULL;
  int transaction = 0;
  EvidenceQueryDeadline deadline = {meta->issued_at_unix_ms+meta->deadline_ms, 0};
  if (deadline.expires_ms > a->expires_unix_ms) deadline.expires_ms = a->expires_unix_ms;
  uint64_t mono = edr_monotonic_ns(), remaining = (uint64_t)(deadline.expires_ms-now_ms)*1000000ULL;
  deadline.until_mono_ns = UINT64_MAX-mono < remaining ? UINT64_MAX : mono+remaining;
  if (!s_db || !rows) { copy_s(out, cap, "evidence query storage unavailable"); goto finish; }
  if (filter.cmdline_contains[0]) {
    command_identity = calloc(1, sizeof(*command_identity));
    if (!command_identity) goto allocation_failed;
    copy_s(command_identity->tenant_id, sizeof(command_identity->tenant_id), a->tenant_id);
    copy_s(command_identity->endpoint_id, sizeof(command_identity->endpoint_id), a->endpoint_id);
  }
  sqlite3_progress_handler(s_db, 1000, authorized_query_interrupted, &deadline);
  if (exec_sql("BEGIN;") != 0) { copy_s(out, cap, "evidence query snapshot busy"); goto finish; }
  transaction = 1;
  if (!filter.file_sha256[0]) {
    for (unsigned i = 0; i < EDR_EVIDENCE_RING_SLOTS && returned < filter.limit; ++i) {
      const RingSlot *r = &s_ring[(s_ring_pos+EDR_EVIDENCE_RING_SLOTS-1u-i)%EDR_EVIDENCE_RING_SLOTS];
      if (!r->used || strcmp(r->tenant_id, a->tenant_id) || strcmp(r->endpoint_id, a->endpoint_id)) continue;
      ++scanned;
      if (!rtq_match_common(&filter, r->type, r->pid, r->event_time_ns, r->endpoint_id, r->process_name, "", "", r->file_path,
          r->net_dst, r->net_dport, "", r->generation.process_start_key, r->generation.creation_filetime_100ns)) continue;
      char start[32], creation[32], port[16];
      sqlite_u64_decimal(r->generation.process_start_key, start); sqlite_u64_decimal(r->generation.creation_filetime_100ns, creation);
      snprintf(port, sizeof(port), "%u", r->net_dport);
      const char *fields[16] = {r->endpoint_id, r->process_name, "", "", r->file_path, "", r->net_dst, "", "", "",
          start, creation, r->process_generation_source, r->source_completeness, r->source_truncated_fields, port};
      cJSON *row = authorized_query_row(&filter, "ring", r->event_time_ns, r->type, r->pid, r->ppid, fields);
      if (!row) goto allocation_failed;
      matched = 1;
      char *encoded = cJSON_PrintUnformatted(row);
      if (!encoded) { cJSON_Delete(row); goto allocation_failed; }
      size_t row_bytes = strlen(encoded)+1u; cJSON_free(encoded);
      if (encoded_bytes > envelope || row_bytes > envelope-encoded_bytes) { cJSON_Delete(row); partial=1; break; }
      if (!cJSON_AddItemToArray(rows, row)) { cJSON_Delete(row); goto allocation_failed; }
      encoded_bytes += row_bytes; ++returned;
    }
  }
  const char *sql = filter.file_sha256[0] ?
      "SELECT f.path,f.sha256,f.pid,f.last_seen_ns FROM file_evidence f "
      "WHERE f.endpoint_id=?1 AND f.last_seen_ns>=?3 AND f.last_seen_ns<=?4 AND f.sha256=?6 COLLATE NOCASE "
      "AND EXISTS(SELECT 1 FROM p0_candidates p WHERE p.endpoint_id=f.endpoint_id AND p.tenant_id=?2 AND p.file_path=f.path "
      "AND p.event_time_ns=f.last_seen_ns AND p.local_retention_state='retained' AND (?7=0 OR p.type=?7)) ORDER BY f.last_seen_ns DESC LIMIT ?5;" :
      "SELECT event_time_ns,type,pid,ppid,endpoint_id,process_name,exe_path,cmdline,file_path,dns_query,net_dst,net_dport,"
      "reg_key_path,reg_value_name,reg_op,process_start_key,process_creation_filetime_100ns,process_generation_source,"
      "source_completeness,source_truncated_fields,subject_command_fact_id FROM p0_candidates "
      "WHERE endpoint_id=?1 AND tenant_id=?2 AND event_time_ns>=?3 AND event_time_ns<=?4 AND local_retention_state='retained' "
      "ORDER BY event_time_ns DESC LIMIT ?5;";
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK ||
      sqlite3_bind_text(st, 1, a->endpoint_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
      sqlite3_bind_text(st, 2, a->tenant_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
      sqlite3_bind_int64(st, 3, from_ns) != SQLITE_OK || sqlite3_bind_int64(st, 4, until_ns) != SQLITE_OK ||
      sqlite3_bind_int(st, 5, (int)(filter.limit*20u+100u)) != SQLITE_OK ||
      (filter.file_sha256[0] && (sqlite3_bind_text(st, 6, filter.file_sha256, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
       sqlite3_bind_int64(st, 7, filter.has_type ? filter.type : 0u) != SQLITE_OK))) {
    copy_s(out, cap, "evidence query snapshot prepare failed"); goto finish;
  }
  int step = SQLITE_DONE;
  while (returned < filter.limit && (step = sqlite3_step(st)) == SQLITE_ROW) {
    ++scanned;
    cJSON *row = NULL;
    if (filter.file_sha256[0]) {
      const char *path = (const char *)sqlite3_column_text(st, 0), *sha = (const char *)sqlite3_column_text(st, 1);
      if (!contains_ci(path, filter.file_path_contains) || !path_ext_matches(path, filter.file_ext)) continue;
      row = cJSON_CreateObject();
      if (!row || !cJSON_AddStringToObject(row, "type", "file") || !cJSON_AddStringToObject(row, "source", "file_evidence") ||
          !cJSON_AddStringToObject(row, "path", path ? path : "") || !cJSON_AddStringToObject(row, "sha256", sha ? sha : "") ||
          !cJSON_AddBoolToObject(row, "cache_hit", 1)) { cJSON_Delete(row); goto allocation_failed; }
    } else {
      int64_t ts = sqlite3_column_int64(st, 0);
      uint32_t type = (uint32_t)sqlite3_column_int64(st, 1), pid = (uint32_t)sqlite3_column_int64(st, 2), ppid = (uint32_t)sqlite3_column_int64(st, 3);
      const int columns[] = {4,5,6,7,8,9,10,12,13,14,15,16,17,18,19,11};
      const char *fields[16];
      for (unsigned i = 0; i < 16; ++i) fields[i] = (const char *)sqlite3_column_text(st, columns[i]);
      uint64_t start = 0, creation = 0;
      (void)sqlite_decimal_u64(fields[10], &start); (void)sqlite_decimal_u64(fields[11], &creation);
      char *complete_command = NULL;
      const char *command_ref = (const char *)sqlite3_column_text(st, 20);
      if (command_identity && command_ref && command_ref[0]) {
        command_identity->pid = pid; command_identity->process_start_key = start;
        command_identity->process_creation_filetime_100ns = creation;
        char expected_ref[80];
        if (!command_fact_key(command_identity, expected_ref) || strcmp(expected_ref, command_ref) ||
            !(complete_command = read_command_fact_locked(command_identity))) {
          copy_s(out, cap, "evidence query command fact unavailable or conflicted"); goto finish;
        }
        fields[3] = complete_command;
      }
      if (!rtq_match_common(&filter, type, pid, ts, fields[0], fields[1], fields[3], fields[2], fields[4], fields[6],
          (uint32_t)sqlite3_column_int64(st, 11), fields[7], start, creation)) { free(complete_command); continue; }
      if (complete_command && strlen(complete_command) > 8192u) {
        free(complete_command); copy_s(out, cap, "requested command exceeds the authorized field byte budget"); goto finish;
      }
      row = authorized_query_row(&filter, "p0_candidates", ts, type, pid, ppid, fields);
      free(complete_command);
      if (!row) goto allocation_failed;
    }
    matched = 1;
    char *encoded = cJSON_PrintUnformatted(row);
    if (!encoded) { cJSON_Delete(row); goto allocation_failed; }
    size_t row_bytes = strlen(encoded)+1u; cJSON_free(encoded);
    if (encoded_bytes > envelope || row_bytes > envelope-encoded_bytes || returned == filter.limit) {
      cJSON_Delete(row); partial = 1; break;
    }
    if (!cJSON_AddItemToArray(rows, row)) { cJSON_Delete(row); goto allocation_failed; }
    encoded_bytes += row_bytes; ++returned;
  }
  if (step != SQLITE_DONE && step != SQLITE_ROW) { copy_s(out, cap, "evidence query snapshot failed or deadline reached"); goto finish; }
  if (returned == filter.limit || scanned >= filter.limit*20u+100u) partial = 1;
  sqlite3_finalize(st); st = NULL;
  if (authorized_query_interrupted(&deadline)) { copy_s(out, cap, "evidence query deadline reached"); goto finish; }
  if (exec_sql("COMMIT;") != 0) { copy_s(out, cap, "evidence query snapshot close failed"); goto finish; }
  transaction = 0;
  if(!filter.file_sha256[0] && returned<filter.limit) {
    EdrStorageQueueLocalQuery query={0};
    query.tenant_id=a->tenant_id; query.endpoint_id=a->endpoint_id;
    query.from_ns=from_ns; query.until_ns=until_ns; query.has_type=filter.has_type;
    query.event_type=filter.type; query.pid=filter.pid;
    query.has_process_start_key=filter.has_process_start_key;
    query.has_process_creation_filetime_100ns=filter.has_process_creation_filetime_100ns;
    query.process_start_key=filter.process_start_key; query.process_creation_filetime_100ns=filter.process_creation_filetime_100ns;
    query.max_rows=1000; query.max_scan=filter.limit*20u+100u;
    query.max_payload_bytes=4u*EDR_EVIDENCE_MANIFEST_MAX_BYTES; query.until_mono_ns=deadline.until_mono_ns;
    EvidenceQueueQuery context={&filter,&deadline,rows,envelope,&encoded_bytes,&returned,&matched,&partial,NULL};
    EdrStorageQueueLocalQueryStats query_stats={0};
    int queue_result=edr_storage_queue_query_local_snapshot(&query,authorized_queue_visit,authorized_queue_cancel,&context,&query_stats);
    scanned+=query_stats.scanned;
    if(queue_result<0) {
      if(queue_result==-2) atomic_fetch_add_explicit(&s_query_pin_exhausted,1u,memory_order_relaxed);
      copy_s(out,cap,context.error ? context.error : queue_result==-2 ? "evidence query queue pin unavailable or exhausted" :
          queue_result==-4 ? "evidence query local wire exceeds snapshot byte budget" :
          queue_result==-5 ? "evidence query deadline reached" : "evidence query queue integrity or storage failure");
      goto finish;
    }
    if(queue_result>0) partial=1;
  }
#else
  (void)from_ns; (void)until_ns; (void)scanned; (void)encoded_bytes;
  copy_s(out, cap, "evidence query storage unavailable"); goto finish;
#endif
  if (matched && !returned) { copy_s(out, cap, "evidence query result byte budget exhausted"); goto finish; }
  const char *reason = matched ? "available" :
      until_ns < now_unix_ns()-(int64_t)s_status.selected_retention_hours*3600LL*1000000000LL ?
      "outside_retention_window" : "not_collected_or_expired";
  if (!cJSON_AddStringToObject(result, "source", "mixed") || !cJSON_AddBoolToObject(result, "partial", partial) ||
      !cJSON_AddStringToObject(result, "availability_reason", reason) || !cJSON_AddBoolToObject(result, "absence_is_evidence", 0) ||
      !cJSON_AddNumberToObject(result, "rows_scanned", scanned) || !cJSON_AddNumberToObject(result, "rows_returned", returned)) goto allocation_failed;
  char *encoded = cJSON_PrintUnformatted(result);
  if (!encoded) goto allocation_failed;
  if (strlen(encoded) <= envelope) { copy_s(out, cap, encoded); rc = 0; }
  else copy_s(out, cap, "evidence query result byte budget exhausted");
  cJSON_free(encoded); goto finish;
allocation_failed:
  copy_s(out, cap, "evidence query result allocation or field validation failed");
finish:
#if defined(EDR_HAVE_SQLITE)
  sqlite3_finalize(st);
  if (s_db) sqlite3_progress_handler(s_db, 0, NULL, NULL);
  if (transaction) sqlite_rollback_silent();
  free(command_identity);
#endif
  cJSON_Delete(result);
  evidence_cache_unlock();
  return rc;
}

static int parent_context_scope_text(const char *value, size_t cap) {
  if (!value || !value[0]) return 0;
  for (size_t i = 0; i < cap; ++i) {
    unsigned char ch = (unsigned char)value[i];
    if (!ch) return 1;
    if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
          (ch >= '0' && ch <= '9') || strchr("_.:-", ch))) return 0;
  }
  return 0;
}

#if defined(EDR_HAVE_SQLITE)
static const char *parent_context_text(const cJSON *object, const char *key) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
  return cJSON_IsString(value) && value->valuestring ? value->valuestring : NULL;
}
static int parent_context_u64(const cJSON *object, const char *key, uint64_t *number) {
  const char *value = parent_context_text(object, key);
  return value && sqlite_decimal_u64(value, number);
}
static int parent_context_number(const cJSON *object, const char *key, uint32_t *number) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
  if (!cJSON_IsNumber(value) || value->valuedouble < 0 || value->valuedouble > UINT32_MAX ||
      value->valuedouble != (double)(uint32_t)value->valuedouble) return 0;
  *number = (uint32_t)value->valuedouble; return 1;
}
static int parent_context_quality(const char *value) {
  return value && (!strcmp(value, "complete") || !strcmp(value, "truncated") ||
      !strcmp(value, "missing") || !strcmp(value, "unknown"));
}
#endif

int edr_local_evidence_cache_query_parent_context_json(
    const EdrParentContextQuery *q, char *out, size_t cap) {
  if (!out || cap < 256u || cap > 16384u) return EDR_PARENT_CONTEXT_ERROR_BUDGET;
  out[0] = 0;
  if (!q || !parent_context_scope_text(q->tenant_id, sizeof(((EdrBehaviorRecord *)0)->tenant_id)) ||
      !parent_context_scope_text(q->endpoint_id, sizeof(((EdrBehaviorRecord *)0)->endpoint_id)) ||
      !parent_context_scope_text(q->source_event_id, sizeof(((EdrBehaviorRecord *)0)->event_id)) ||
      !q->child_pid || !q->child_process_start_key || !q->child_creation_filetime_100ns ||
      q->from_ns <= 0 || q->until_ns < q->from_ns || q->until_ns - q->from_ns > 600000000000LL ||
      (q->fields & ~(EDR_PARENT_CONTEXT_FIELD_NAME | EDR_PARENT_CONTEXT_FIELD_PATH | EDR_PARENT_CONTEXT_FIELD_CMDLINE)))
    return EDR_PARENT_CONTEXT_ERROR_INVALID;
  int64_t now_ms = now_unix_ns() / 1000000LL;
  if (q->expires_unix_ms <= now_ms) return EDR_PARENT_CONTEXT_ERROR_EXPIRED;
  if (!evidence_cache_try_query_lock()) {
    atomic_fetch_add_explicit(&s_query_pin_exhausted, 1u, memory_order_relaxed);
    return EDR_PARENT_CONTEXT_ERROR_BUSY;
  }
  int result = EDR_PARENT_CONTEXT_ERROR_STORAGE;
  cJSON *root = cJSON_CreateObject(), *child = NULL, *fact = NULL, *parent_out = NULL;
  EdrBehaviorRecord *identity = calloc(1u, sizeof(*identity));
  char *encoded = NULL, *command = NULL;
#if defined(EDR_HAVE_SQLITE)
  sqlite3_stmt *st = NULL;
  int transaction = 0;
  int64_t remaining = q->expires_unix_ms - now_ms;
  uint64_t mono = edr_monotonic_ns();
  EvidenceQueryDeadline deadline = {q->expires_unix_ms,
      mono + (uint64_t)(remaining < 2000 ? remaining : 2000) * 1000000ULL};
  if (!s_db || !root || !identity) goto done;
  sqlite3_progress_handler(s_db, 1000, authorized_query_interrupted, &deadline);
  if (exec_sql("BEGIN;") != 0) goto done;
  transaction = 1;
  copy_s(identity->tenant_id, sizeof(identity->tenant_id), q->tenant_id);
  copy_s(identity->endpoint_id, sizeof(identity->endpoint_id), q->endpoint_id);
  copy_s(identity->event_id, sizeof(identity->event_id), q->source_event_id);
  identity->pid = q->child_pid;
  identity->process_start_key = q->child_process_start_key;
  identity->process_creation_filetime_100ns = q->child_creation_filetime_100ns;
  char candidate[160], artifact[256], start[32], birth[32];
  candidate_id_for(identity, candidate, sizeof(candidate));
  sqlite_u64_decimal(q->child_process_start_key, start);
  sqlite_u64_decimal(q->child_creation_filetime_100ns, birth);
  int64_t event_time_ns = 0;
  uint32_t parent_pid = 0u, parent_state = EDR_PARENT_PID_UNKNOWN;
  const char *availability = "unavailable_or_expired";
  if (sqlite3_prepare_v2(s_db,
      "SELECT event_time_ns FROM p0_candidates WHERE candidate_id=?1 AND endpoint_id=?2 AND tenant_id=?3 "
      "AND pid=?4 AND process_start_key=?5 AND process_creation_filetime_100ns=?6 "
      "AND local_retention_state='retained' AND event_time_ns>=?7 AND event_time_ns<=?8;",
      -1, &st, NULL) != SQLITE_OK) goto done;
  bind_text(st, 1, candidate); bind_text(st, 2, q->endpoint_id); bind_text(st, 3, q->tenant_id);
  sqlite3_bind_int64(st, 4, q->child_pid); bind_text(st, 5, start); bind_text(st, 6, birth);
  sqlite3_bind_int64(st, 7, q->from_ns); sqlite3_bind_int64(st, 8, q->until_ns);
  int step = sqlite3_step(st);
  if (step != SQLITE_ROW && step != SQLITE_DONE) goto done;
  int candidate_found = step == SQLITE_ROW;
  if (candidate_found) event_time_ns = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st); st = NULL;
  if (candidate_found) {
    snprintf(artifact, sizeof(artifact), "%s:alert_parent_context", candidate);
    st = edr_context_store_prepare_lookup(&s_context_store);
    if (!st || edr_context_store_bind_lookup(&s_context_store, st, artifact) != 0) goto done;
    step = sqlite3_step(st);
    if (step != SQLITE_ROW && step != SQLITE_DONE) goto done;
    char fact_id[65] = "";
    if (step == SQLITE_ROW) {
      const char *owner = (const char *)sqlite3_column_text(st, 0);
      const char *id = (const char *)sqlite3_column_text(st, 1);
      if (!owner || strcmp(owner, candidate) || !id || sqlite3_column_bytes(st, 1) != 64 ||
          strlen(id) != 64u || !copy_s(fact_id, sizeof(fact_id), id) || sqlite3_step(st) != SQLITE_DONE) {
        result = EDR_PARENT_CONTEXT_ERROR_INTEGRITY; goto done;
      }
    }
    sqlite3_finalize(st); st = NULL;
    if (fact_id[0]) {
      if (sqlite3_prepare_v2(s_db,
          "SELECT manifest_template_json FROM context_facts WHERE fact_id=? AND endpoint_id=? AND tenant_id=?;",
          -1, &st, NULL) != SQLITE_OK) goto done;
      bind_text(st, 1, fact_id); bind_text(st, 2, q->endpoint_id); bind_text(st, 3, q->tenant_id);
      if (sqlite3_step(st) != SQLITE_ROW) { result = EDR_PARENT_CONTEXT_ERROR_INTEGRITY; goto done; }
      const char *json = (const char *)sqlite3_column_text(st, 0);
      int bytes = sqlite3_column_bytes(st, 0);
      char expected[65];
      if (!json || bytes <= 0 || bytes > 65536 || memchr(json, 0, (size_t)bytes) ||
          !(fact = edr_egress_parse_purpose_object(json, (size_t)bytes)) ||
          context_fact_id_for(identity, json, expected) != 0 || strcmp(expected, fact_id)) {
        result = EDR_PARENT_CONTEXT_ERROR_INTEGRITY; goto done;
      }
      sqlite3_finalize(st); st = NULL;
      uint64_t recorded_start = 0u, recorded_birth = 0u, recorded_time = 0u;
      uint32_t recorded_pid = 0u;
      const cJSON *captured_child = cJSON_GetObjectItemCaseSensitive(fact, "child");
      const char *schema = parent_context_text(fact, "schema");
      const char *source = parent_context_text(fact, "source_event_id");
      if (!schema || strcmp(schema, "edr.local-alert-parent-context.v1") || !source || strcmp(source, q->source_event_id) ||
          !parent_context_number(captured_child, "pid", &recorded_pid) || recorded_pid != q->child_pid ||
          !parent_context_u64(captured_child, "process_start_key", &recorded_start) || recorded_start != q->child_process_start_key ||
          !parent_context_u64(captured_child, "process_creation_filetime_100ns", &recorded_birth) || recorded_birth != q->child_creation_filetime_100ns ||
          !parent_context_u64(fact, "event_time_ns", &recorded_time) || recorded_time != (uint64_t)event_time_ns ||
          !parent_context_number(fact, "parent_pid", &parent_pid) ||
          !parent_context_number(fact, "parent_pid_state", &parent_state) || parent_state > EDR_PARENT_PID_CONFLICT) {
        result = EDR_PARENT_CONTEXT_ERROR_INTEGRITY; goto done;
      }
      const cJSON *captured_parent = cJSON_GetObjectItemCaseSensitive(fact, "parent");
      const cJSON *generation_conflict = cJSON_GetObjectItemCaseSensitive(fact, "parent_generation_conflict");
      if (!cJSON_IsBool(generation_conflict)) { result = EDR_PARENT_CONTEXT_ERROR_INTEGRITY; goto done; }
      availability = parent_state == EDR_PARENT_PID_CONFLICT || cJSON_IsTrue(generation_conflict) ? "parent_conflict" : "parent_unresolved";
      if (cJSON_IsObject(captured_parent)) {
        uint32_t pid = 0u, state = 0u;
        uint64_t key = 0u, creation = 0u;
        const char *name = parent_context_text(captured_parent, "name");
        if (cJSON_IsTrue(generation_conflict) || parent_state != EDR_PARENT_PID_KNOWN || !parent_pid || parent_pid == q->child_pid ||
            !parent_context_number(captured_parent, "pid", &pid) || pid != parent_pid ||
            !parent_context_number(captured_parent, "parent_pid_state", &state) || state != EDR_PARENT_PID_KNOWN ||
            !parent_context_u64(captured_parent, "process_start_key", &key) || !key ||
            !parent_context_u64(captured_parent, "process_creation_filetime_100ns", &creation) || !creation ||
            creation > q->child_creation_filetime_100ns || !name) {
          result = EDR_PARENT_CONTEXT_ERROR_INTEGRITY; goto done;
        }
        parent_out = cJSON_CreateObject();
        if (!parent_out || !manifest_add_u64(parent_out, "pid", pid) ||
            !manifest_add_u64(parent_out, "parent_pid_state", state) ||
            !manifest_add_u64_text(parent_out, "process_start_key", key) ||
            !manifest_add_u64_text(parent_out, "process_creation_filetime_100ns", creation) ||
            !manifest_add_text(parent_out, "name", name)) goto done;
        if (q->fields & EDR_PARENT_CONTEXT_FIELD_PATH) {
          const char *path = parent_context_text(captured_parent, "path");
          const char *quality = parent_context_text(captured_parent, "path_quality");
          if (!path || !parent_context_quality(quality)) { result = EDR_PARENT_CONTEXT_ERROR_INTEGRITY; goto done; }
          if (!manifest_add_text(parent_out, "path", path) || !manifest_add_text(parent_out, "path_quality", quality)) goto done;
        }
        if (q->fields & EDR_PARENT_CONTEXT_FIELD_CMDLINE) {
          const char *reference = parent_context_text(captured_parent, "command_fact_ref");
          const char *quality = parent_context_text(captured_parent, "cmdline_quality");
          if (!reference || !parent_context_quality(quality)) { result = EDR_PARENT_CONTEXT_ERROR_INTEGRITY; goto done; }
          if (reference[0]) {
            identity->pid = pid; identity->process_start_key = key; identity->process_creation_filetime_100ns = creation;
            char expected_ref[80];
            if (!command_fact_key(identity, expected_ref) || strcmp(expected_ref, reference) ||
                !(command = read_command_fact_locked(identity))) { result = EDR_PARENT_CONTEXT_ERROR_INTEGRITY; goto done; }
            if (strlen(command) >= cap) { result = EDR_PARENT_CONTEXT_ERROR_BUDGET; goto done; }
          }
          if (!manifest_add_text(parent_out, "cmdline", command ? command : "") ||
              !manifest_add_text(parent_out, "cmdline_quality", quality)) goto done;
        }
        availability = "available";
      } else if (!cJSON_IsNull(captured_parent)) { result = EDR_PARENT_CONTEXT_ERROR_INTEGRITY; goto done; }
    } else event_time_ns = 0;
  }
  child = cJSON_AddObjectToObject(root, "child");
  if (!child || !manifest_add_text(root, "schema", "edr.parent-context.v1") ||
      !manifest_add_text(root, "source_event_id", q->source_event_id) ||
      !manifest_add_u64_text(root, "event_time_ns", (uint64_t)event_time_ns) ||
      !manifest_add_text(root, "availability_reason", availability) ||
      !cJSON_AddBoolToObject(root, "absence_is_evidence", 0) ||
      !manifest_add_u64(child, "pid", q->child_pid) ||
      !manifest_add_u64_text(child, "process_start_key", q->child_process_start_key) ||
      !manifest_add_u64_text(child, "process_creation_filetime_100ns", q->child_creation_filetime_100ns) ||
      !manifest_add_u64(root, "parent_pid", parent_pid) || !manifest_add_u64(root, "parent_pid_state", parent_state)) goto done;
  if (parent_out) {
    if (!cJSON_AddItemToObject(root, "parent", parent_out)) goto done;
    parent_out = NULL;
  } else if (!cJSON_AddNullToObject(root, "parent")) goto done;
  if (authorized_query_interrupted(&deadline)) {
    result = now_unix_ns() / 1000000LL >= q->expires_unix_ms ?
        EDR_PARENT_CONTEXT_ERROR_EXPIRED : EDR_PARENT_CONTEXT_ERROR_BUDGET;
    goto done;
  }
  encoded = cJSON_PrintUnformatted(root);
  if (!encoded) goto done;
  if (strlen(encoded) >= cap) { result = EDR_PARENT_CONTEXT_ERROR_BUDGET; goto done; }
  if (exec_sql("COMMIT;") != 0) goto done;
  transaction = 0;
  copy_s(out, cap, encoded); result = 0;
done:
  sqlite3_finalize(st);
  if (s_db) sqlite3_progress_handler(s_db, 0, NULL, NULL);
  if (transaction) sqlite_rollback_silent();
  if (result == EDR_PARENT_CONTEXT_ERROR_STORAGE && authorized_query_interrupted(&deadline))
    result = now_unix_ns() / 1000000LL >= q->expires_unix_ms ?
        EDR_PARENT_CONTEXT_ERROR_EXPIRED : EDR_PARENT_CONTEXT_ERROR_BUDGET;
#else
  (void)child;
#endif
  cJSON_Delete(root); cJSON_Delete(fact); cJSON_Delete(parent_out);
  cJSON_free(encoded); free(command); free(identity);
  evidence_cache_unlock();
  return result;
}

int edr_local_evidence_cache_query_json(const char *payload_json, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return -1;
  }
  RtqFilter f;
  if (parse_rtq_filter(payload_json, &f) != 0) { out[0]=0; return -1; }
  evidence_cache_lock();
  size_t off = 0;
  int first = 1;
  uint32_t returned = 0;
  uint32_t scanned = 0;
  appendf(out, cap, &off, "{\"source\":\"mixed\",\"partial\":false,\"rows\":[");
  int hash_query = f.file_sha256[0] != '\0';
  if (!hash_query) {
    uint32_t ring_pos = s_ring_pos;
    for (uint32_t i = 0; i < EDR_EVIDENCE_RING_SLOTS && returned < f.limit; i++) {
      const RingSlot *r = &s_ring[(ring_pos + EDR_EVIDENCE_RING_SLOTS - 1u - i) % EDR_EVIDENCE_RING_SLOTS];
      if (!r->used) {
        continue;
      }
      scanned++;
      if (!rtq_match_common(&f, r->type, r->pid, r->event_time_ns, r->endpoint_id,
                            r->process_name, "", "", r->file_path, r->net_dst, r->net_dport, "",
                            r->generation.process_start_key,
                            r->generation.creation_filetime_100ns)) {
        continue;
      }
      char start_key[32];
      char creation[32];
      (void)snprintf(start_key, sizeof(start_key), "%llu",
                     (unsigned long long)r->generation.process_start_key);
      (void)snprintf(creation, sizeof(creation), "%llu",
                     (unsigned long long)r->generation.creation_filetime_100ns);
      append_event_json(out, cap, &off, &first, "ring", r->event_time_ns, r->type, r->pid,
                        r->ppid, r->endpoint_id, r->process_name, "", "", r->file_path,
                        "", r->net_dst, r->net_dport, "", "", "", start_key, creation,
                        r->process_generation_source, r->source_completeness,
                        r->source_truncated_fields);
      returned++;
    }
  }
#if defined(EDR_HAVE_SQLITE)
  if (s_db && hash_query && returned < f.limit) {
    size_t rows_cap = cap > 4096u ? cap - 1024u : 4096u;
    char *rows = (char *)malloc(rows_cap);
    uint32_t cache_returned = 0;
    uint32_t cache_scanned = 0;
    int cache_truncated = 0;
    if (rows &&
        evidence_cache_query_file_hash_json_locked(f.file_sha256, f.file_path_contains,
                                                    f.file_ext, f.limit - returned,
                                                    rows, rows_cap,
                                                    &cache_returned, &cache_scanned,
                                                    &cache_truncated) == 0) {
      append_json_array_items(out, cap, &off, &first, rows);
      returned += cache_returned;
      scanned += cache_scanned;
      if (cache_truncated) {
        char *partial_flag = strstr(out, "\"partial\":false");
        if (partial_flag) {
          memcpy(partial_flag + 10, "true ", 5u);
        }
      }
    }
    free(rows);
  }
  if (s_db && !hash_query && returned < f.limit) {
    const char *sql =
        "SELECT event_time_ns,type,pid,ppid,endpoint_id,process_name,exe_path,cmdline,"
        "file_path,dns_query,net_dst,net_dport,reg_key_path,reg_value_name,reg_op,"
        "process_start_key,process_creation_filetime_100ns,process_generation_source,"
        "source_completeness,source_truncated_fields "
        "FROM p0_candidates WHERE event_time_ns>=? ORDER BY event_time_ns DESC LIMIT ?;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
      int64_t cutoff = now_unix_ns() - (int64_t)f.time_window_s * 1000000000LL;
      sqlite3_bind_int64(st, 1, (sqlite3_int64)cutoff);
      sqlite3_bind_int64(st, 2, (sqlite3_int64)(f.limit * 20u + 100u));
      while (sqlite3_step(st) == SQLITE_ROW && returned < f.limit) {
        scanned++;
        int64_t ts = sqlite3_column_int64(st, 0);
        uint32_t ty = (uint32_t)sqlite3_column_int64(st, 1);
        uint32_t pid = (uint32_t)sqlite3_column_int64(st, 2);
        uint32_t ppid = (uint32_t)sqlite3_column_int64(st, 3);
        const char *ep = (const char *)sqlite3_column_text(st, 4);
        const char *pn = (const char *)sqlite3_column_text(st, 5);
        const char *xp = (const char *)sqlite3_column_text(st, 6);
        const char *cl = (const char *)sqlite3_column_text(st, 7);
        const char *fp = (const char *)sqlite3_column_text(st, 8);
        const char *dns = (const char *)sqlite3_column_text(st, 9);
        const char *rip = (const char *)sqlite3_column_text(st, 10);
        uint32_t dport = (uint32_t)sqlite3_column_int64(st, 11);
        const char *rk = (const char *)sqlite3_column_text(st, 12);
        const char *rv = (const char *)sqlite3_column_text(st, 13);
        const char *ro = (const char *)sqlite3_column_text(st, 14);
        const char *start_key = (const char *)sqlite3_column_text(st, 15);
        const char *creation = (const char *)sqlite3_column_text(st, 16);
        const char *generation_source = (const char *)sqlite3_column_text(st, 17);
        const char *source_completeness = (const char *)sqlite3_column_text(st, 18);
        const char *source_truncated_fields = (const char *)sqlite3_column_text(st, 19);
        uint64_t start_key_value = 0u;
        uint64_t creation_value = 0u;
        (void)sqlite_decimal_u64(start_key, &start_key_value);
        (void)sqlite_decimal_u64(creation, &creation_value);
        if (!rtq_match_common(&f, ty, pid, ts, ep, pn, cl, xp, fp, rip, dport, rk,
                              start_key_value, creation_value)) {
          continue;
        }
        append_event_json(out, cap, &off, &first, "p0_candidates", ts, ty, pid, ppid, ep, pn,
                          xp, cl, fp, dns, rip, dport, rk, rv, ro, start_key, creation,
                          generation_source, source_completeness, source_truncated_fields);
        returned++;
      }
      sqlite3_finalize(st);
    }
  }
#endif
  appendf(out, cap, &off, "],\"rows_scanned\":%u,\"rows_returned\":%u}", scanned, returned);
  out[cap - 1u] = '\0';
  evidence_cache_unlock();
  return 0;
}

static int append_proc_json(char *out, size_t cap, size_t *off, int *first,
                             const char *source, const ProcSlot *p) {
  char ep[120], tn[160], nm[320], path[1200], pn[320], pp[640], command_fields[192];
  char *complete = NULL;
  char reference[80] = "", sha[65] = "";
#if defined(EDR_HAVE_SQLITE)
  if (p && (!p->cmdline[0] || p->cmdline_truncated_fields[0])) {
    EdrBehaviorRecord *identity = (EdrBehaviorRecord *)calloc(1u, sizeof(*identity));
    if (identity) {
      copy_s(identity->tenant_id, sizeof(identity->tenant_id), p->tenant_id);
      copy_s(identity->endpoint_id, sizeof(identity->endpoint_id), p->endpoint_id);
      identity->pid = p->pid;
      identity->process_start_key = p->generation.process_start_key;
      identity->process_creation_filetime_100ns = p->generation.creation_filetime_100ns;
      complete = read_command_fact_locked(identity);
      if (complete && (!p->cmdline[0] || strncmp(complete, p->cmdline, strlen(p->cmdline)) == 0)) {
        (void)command_fact_key(identity, reference);
        (void)edr_sha256_hex((const uint8_t *)complete, strlen(complete), sha);
      } else { free(complete); complete = NULL; }
      free(identity);
    }
  }
#endif
  /* RTQ has its own caller-supplied envelope. It may show the preview with
   * an exact fact reference, but must not pretend it is the complete string. */
  size_t full_bytes = complete ? strlen(complete) : 0u;
  int full_fits = complete && cap > *off && full_bytes * 6u + 8192u < cap - *off;
  cJSON *command = cJSON_CreateString(full_fits ? complete : p ? p->cmdline : "");
  char *cmd = command ? cJSON_PrintUnformatted(command) : NULL;
  cJSON_Delete(command);
  free(complete);
  if (!cmd) return 0;
  const char *quality = full_fits ? "complete" : full_bytes ? "preview_full_fact_retained" : !p || !p->cmdline[0] ? "missing" :
      !command_quality_known(p) ?
      "unknown" : p->cmdline_truncated_fields[0] ? "truncated" : "complete";
  char username[640], domain[640], user_sid[640], logon_id[160];
  char identity_source[96], identity_quality[96], exe_hash[160];
  char generation_start[32], generation_creation[32], generation_source[160];
  char parent_generation_start[32], parent_generation_creation[32], parent_generation_source[160];
  json_escape(ep, sizeof(ep), p ? p->endpoint_id : "");
  json_escape(tn, sizeof(tn), p ? p->tenant_id : "");
  json_escape(nm, sizeof(nm), p ? p->name : "");
  json_escape(path, sizeof(path), p ? p->path : "");
  json_escape(command_fields, sizeof(command_fields), full_fits ? "" : command_quality_known(p) ? p->cmdline_truncated_fields : "");
  json_escape(pn, sizeof(pn), p ? p->parent_name : "");
  json_escape(pp, sizeof(pp), p ? p->parent_path : "");
  json_escape(username, sizeof(username), p ? p->username : "");
  json_escape(domain, sizeof(domain), p ? p->domain : "");
  json_escape(user_sid, sizeof(user_sid), p ? p->user_sid : "");
  json_escape(logon_id, sizeof(logon_id), p ? p->logon_id : "");
  json_escape(identity_source, sizeof(identity_source),
              p ? p->identity_source : "");
  json_escape(identity_quality, sizeof(identity_quality),
              p ? p->identity_quality : "");
  json_escape(exe_hash, sizeof(exe_hash), p ? p->exe_hash : "");
  (void)snprintf(generation_start, sizeof(generation_start), "%llu",
                 (unsigned long long)(p ? p->generation.process_start_key : 0u));
  (void)snprintf(generation_creation, sizeof(generation_creation), "%llu",
                 (unsigned long long)(p ? p->generation.creation_filetime_100ns : 0u));
  (void)snprintf(parent_generation_start, sizeof(parent_generation_start), "%llu",
                 (unsigned long long)(p ? p->parent_generation.process_start_key : 0u));
  (void)snprintf(parent_generation_creation, sizeof(parent_generation_creation), "%llu",
                 (unsigned long long)(p ? p->parent_generation.creation_filetime_100ns : 0u));
  json_escape(generation_source, sizeof(generation_source),
              p ? p->process_generation_source : "");
  json_escape(parent_generation_source, sizeof(parent_generation_source),
              p ? p->parent_process_generation_source : "");
  appendf(out, cap, off, "%s{\"source\":\"%s\",\"endpoint_id\":%s,\"tenant_id\":%s,"
                          "\"pid\":%u,\"ppid\":%u,\"parent_pid_state\":%u,\"name\":%s,\"path\":%s,\"cmdline\":%s,"
                          "\"cmdline_quality\":\"%s\",\"cmdline_truncated_fields\":%s,"
                          "\"cmdline_fact_ref\":\"%s\",\"cmdline_fact_sha256\":\"%s\",\"cmdline_fact_bytes\":%zu,"
                          "\"parent_name\":%s,\"parent_path\":%s,\"process_start_key\":\"%s\","
                          "\"process_creation_filetime_100ns\":\"%s\",\"process_generation_source\":%s,"
                          "\"parent_process_start_key\":\"%s\",\"parent_process_creation_filetime_100ns\":\"%s\","
                          "\"parent_process_generation_source\":%s,\"username\":%s,\"domain\":%s,"
                          "\"user_sid\":%s,\"logon_id\":%s,\"identity_source\":%s,"
                          "\"identity_quality\":%s,\"exe_hash\":%s,\"last_seen_ns\":%lld}",
          *first ? "" : ",", source ? source : "", ep, tn, p ? p->pid : 0u,
          p ? p->ppid : 0u, p ? p->parent_pid_state : 0u, nm, path, cmd, quality, command_fields, reference, sha, full_bytes, pn, pp, generation_start, generation_creation,
          generation_source, parent_generation_start, parent_generation_creation,
          parent_generation_source, username, domain, user_sid, logon_id,
          identity_source, identity_quality, exe_hash,
          p ? (long long)p->last_seen_ns : 0LL);
  *first = 0;
  cJSON_free(cmd);
  return *off < cap - 1u;
}

int edr_local_evidence_cache_process_tree_generation_json(
    uint32_t pid, const char *endpoint_id, uint64_t process_start_key,
    uint64_t process_creation_filetime_100ns, char *out, size_t cap) {
  if (!out || cap == 0u || pid == 0u) {
    return -1;
  }
  if ((process_start_key == 0u) != (process_creation_filetime_100ns == 0u)) {
    return -1;
  }
  const int generation_lookup = process_start_key != 0u;
  evidence_cache_lock();
  ProcSlot *memory_root = find_proc(pid, endpoint_id);
  const ProcSlot *root = memory_root;
  const char *root_source = "memory";
  if (generation_lookup &&
      (!root || !generation_bound(&root->generation) ||
       root->generation.process_start_key != process_start_key ||
       root->generation.creation_filetime_100ns != process_creation_filetime_100ns)) {
    root = NULL;
  }
#if defined(EDR_HAVE_SQLITE)
  ProcSlot durable_root;
  if (s_db && (!root || !generation_bound(&root->generation)) && endpoint_id && endpoint_id[0]) {
    const char *root_sql = generation_lookup
        ? "SELECT endpoint_id,tenant_id,pid,ppid,name,path,cmdline,parent_name,parent_path,last_seen_ns,"
          "process_start_key,process_creation_filetime_100ns,process_generation_source,"
          "parent_process_start_key,parent_process_creation_filetime_100ns,parent_process_generation_source,"
          "username,domain,user_sid,logon_id,identity_source,identity_quality,exe_hash,cmdline_truncated_fields,parent_pid_state "
          "FROM process_cache WHERE endpoint_id=? AND pid=? AND process_start_key=? "
          "AND process_creation_filetime_100ns=? LIMIT 1;"
        : "SELECT endpoint_id,tenant_id,pid,ppid,name,path,cmdline,parent_name,parent_path,last_seen_ns,"
          "process_start_key,process_creation_filetime_100ns,process_generation_source,"
          "parent_process_start_key,parent_process_creation_filetime_100ns,parent_process_generation_source,"
          "username,domain,user_sid,logon_id,identity_source,identity_quality,exe_hash,cmdline_truncated_fields,parent_pid_state "
          "FROM process_cache WHERE endpoint_id=? AND pid=? LIMIT 1;";
    sqlite3_stmt *root_st = NULL;
    if (sqlite3_prepare_v2(s_db, root_sql, -1, &root_st, NULL) == SQLITE_OK) {
      sqlite3_bind_text(root_st, 1, endpoint_id, -1, SQLITE_TRANSIENT);
      sqlite3_bind_int64(root_st, 2, (sqlite3_int64)pid);
      if (generation_lookup) {
        char start_text[32];
        char creation_text[32];
        sqlite_u64_decimal(process_start_key, start_text);
        sqlite_u64_decimal(process_creation_filetime_100ns, creation_text);
        sqlite3_bind_text(root_st, 3, start_text, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(root_st, 4, creation_text, -1, SQLITE_TRANSIENT);
      }
      if (sqlite3_step(root_st) == SQLITE_ROW && sqlite_read_process_cache_row(root_st, &durable_root)) {
        root = &durable_root;
        root_source = "sqlite";
      }
      sqlite3_finalize(root_st);
    }
  }
#endif
  /* A legacy PID-only row is not a process-tree identity.  Withhold it from
   * this RTQ view rather than presenting it as a restart-safe root. */
  if (root && !generation_bound(&root->generation)) {
    root = NULL;
  }
  size_t off = 0;
  int first = 1;
  uint32_t children = 0;
  int serialized = 1;
  appendf(out, cap, &off, "{\"pid\":%u,\"root\":", pid);
  if (root) {
    int only = 1;
    serialized = append_proc_json(out, cap, &off, &only, root_source, root);
  } else {
    appendf(out, cap, &off, "null");
  }
  appendf(out, cap, &off, ",\"children\":[");
  for (size_t i = 0; serialized && i < EDR_EVIDENCE_PROC_SLOTS && children < 64u; i++) {
    ProcSlot *p = &s_proc[i];
    if (!root || !generation_bound(&root->generation) || p->pid == 0u || p->ppid != pid || p->parent_pid_state != EDR_PARENT_PID_KNOWN ||
        !cached_parent_source_proven(p->parent_process_generation_source) ||
        !generation_equal(&p->parent_generation, &root->generation)) {
      continue;
    }
    if (endpoint_id && endpoint_id[0] && p->endpoint_id[0] && strcmp(endpoint_id, p->endpoint_id) != 0) {
      continue;
    }
    serialized = append_proc_json(out, cap, &off, &first, "memory", p);
    children++;
  }
#if defined(EDR_HAVE_SQLITE)
  if (serialized && s_db && root && generation_bound(&root->generation) && root->endpoint_id[0] && children < 64u) {
    const char *sql =
        "SELECT endpoint_id,tenant_id,pid,ppid,name,path,cmdline,parent_name,parent_path,last_seen_ns,"
        "process_start_key,process_creation_filetime_100ns,process_generation_source,"
        "parent_process_start_key,parent_process_creation_filetime_100ns,parent_process_generation_source,"
        "username,domain,user_sid,logon_id,identity_source,identity_quality,exe_hash,cmdline_truncated_fields,parent_pid_state "
        "FROM process_cache WHERE parent_pid_state IN (0,1) AND endpoint_id=? AND ppid=? AND parent_process_start_key=? "
        "AND parent_process_creation_filetime_100ns=? ORDER BY last_seen_ns DESC LIMIT 64;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
      char parent_start[32];
      char parent_creation[32];
      sqlite_u64_decimal(root->generation.process_start_key, parent_start);
      sqlite_u64_decimal(root->generation.creation_filetime_100ns, parent_creation);
      sqlite3_bind_text(st, 1, root->endpoint_id, -1, SQLITE_TRANSIENT);
      sqlite3_bind_int64(st, 2, (sqlite3_int64)pid);
      sqlite3_bind_text(st, 3, parent_start, -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(st, 4, parent_creation, -1, SQLITE_TRANSIENT);
      while (serialized && sqlite3_step(st) == SQLITE_ROW && children < 64u) {
        ProcSlot tmp;
        if (!sqlite_read_process_cache_row(st, &tmp) ||
            !cached_parent_source_proven(tmp.parent_process_generation_source) ||
            !generation_equal(&tmp.parent_generation, &root->generation)) {
          continue;
        }
        serialized = append_proc_json(out, cap, &off, &first, "sqlite", &tmp);
        children++;
      }
      sqlite3_finalize(st);
    }
  }
#endif
  appendf(out, cap, &off, "],\"child_count\":%u}", children);
  out[cap - 1u] = '\0';
  int found = root || children;
  if (!serialized || off >= cap - 1u) {
    out[0] = '\0';
    set_error("process tree JSON allocation or output budget exhausted");
    evidence_cache_unlock();
    return -3;
  }
  evidence_cache_unlock();
  return found ? 0 : -2;
}

int edr_local_evidence_cache_process_tree_json(uint32_t pid, const char *endpoint_id,
                                               char *out, size_t cap) {
  return edr_local_evidence_cache_process_tree_generation_json(
      pid, endpoint_id, 0u, 0u, out, cap);
}

static void metric_reason_json(char *out, size_t cap, const char *const *names,
                                const uint64_t *counts, size_t count) {
  size_t off = 0u;
  appendf(out, cap, &off, "{");
  for (size_t i = 0u; i < count; ++i)
    appendf(out, cap, &off, "%s\"%s\":%llu", i ? "," : "", names[i],
            (unsigned long long)counts[i]);
  appendf(out, cap, &off, "}");
}

int edr_local_evidence_cache_accounting_json(const EdrEvidenceCacheStatus *st, char *out, size_t cap) {
  if (!st || !out || !cap) return -1;
  char ordinary_reasons[512], candidate_failures[1024], context_failures[1024];
  metric_reason_json(ordinary_reasons, sizeof(ordinary_reasons), metric_names + METRIC_ORDINARY_BASE,
                    st->ordinary_reasons, EDR_EVIDENCE_ORDINARY_REASON_COUNT);
  metric_reason_json(candidate_failures, sizeof(candidate_failures), metric_names + METRIC_CANDIDATE_BASE,
                    st->candidate_failure_reasons, EDR_EVIDENCE_FAILURE_REASON_COUNT);
  metric_reason_json(context_failures, sizeof(context_failures), metric_names + METRIC_CONTEXT_BASE,
                    st->context_failure_reasons, EDR_EVIDENCE_FAILURE_REASON_COUNT);
  int written = snprintf(out, cap,
      "{\"scope\":\"current_process\",\"ordinary_unit\":\"record_behavior_call\",\"ordinary_reasons\":%s,"
      "\"failure_unit\":\"persistence_operation\",\"candidate_failures\":%s,\"context_failures\":%s,"
      "\"pmfe_followup\":{\"scheduled\":%u,\"running\":%u,\"result_bound\":%u,\"result_acked_await_queue\":%u,"
      "\"active\":%u,\"expired\":%u,\"capacity\":64,\"failures\":%llu,\"cause_code\":%u},"
      "\"budget_protection\":{\"physical_refusals\":%llu,\"physical_guard_failures\":%llu,\"query_pin_exhausted\":%llu,\"cause_code\":%u},"
      "\"local_retention\":{\"policy_version\":1,\"groups_retired\":%llu,\"held_decisions\":%llu,"
      "\"failures\":%llu,\"legacy_candidates_at_open\":%llu,\"recent_hours\":%u,\"selected_hours\":%u,"
      "\"active_ms\":%llu,\"clock_valid\":%u,\"clock_failures\":%llu,\"clock_cause_code\":%u,"
      "\"parent_protections\":%llu,\"floor_held\":%llu}}",
      ordinary_reasons, candidate_failures, context_failures,
      st->pmfe_scheduled,st->pmfe_running,st->pmfe_result_bound,st->pmfe_result_acked,
      st->pmfe_active,st->pmfe_expired,(unsigned long long)st->pmfe_failures,st->pmfe_cause_code,
      (unsigned long long)st->physical_refusals,(unsigned long long)st->physical_guard_failures,
      (unsigned long long)st->query_pin_exhausted,st->physical_cause_code,
      (unsigned long long)st->retention_groups_retired,(unsigned long long)st->retention_groups_held,
      (unsigned long long)st->retention_failures,(unsigned long long)st->retention_legacy_candidates,st->retention_hours,st->selected_retention_hours,
      (unsigned long long)st->retention_active_ms,st->retention_clock_valid,
      (unsigned long long)st->retention_clock_failures,st->retention_clock_cause_code,
      (unsigned long long)st->retention_parent_protections,(unsigned long long)st->retention_floor_held);
  if (written < 0 || (size_t)written >= cap) { out[0] = '\0'; return -1; }
  return 0;
}

void edr_local_evidence_cache_status_json(char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  EdrEvidenceCacheStatus st;
  edr_local_evidence_cache_get_status(&st);
  char path[640];
  char err[220];
  char eng[80];
  char context_ref_sources[8192];
  char accounting[2048];
  if (edr_local_evidence_cache_accounting_json(&st, accounting, sizeof(accounting)) != 0)
    snprintf(accounting, sizeof(accounting), "{\"status\":\"unavailable\"}");
  json_escape(path, sizeof(path), st.path);
  json_escape(err, sizeof(err), st.last_error);
  json_escape(eng, sizeof(eng), st.last_engine);
  if (context_ref_write_sources_json_from_status(
          &st, context_ref_sources, sizeof(context_ref_sources)) != 0) {
    snprintf(context_ref_sources, sizeof(context_ref_sources), "{}");
  }
  int written = snprintf(out, cap,
           "\"evidence_cache\":{\"db_open\":%s,\"storage_format\":%u,\"path\":%s,\"max_db_mb\":%u,"
           "\"retention_hours\":%u,\"db_bytes\":%llu,\"wal_bytes\":%llu,"
           "\"records_written\":%llu,\"records_dropped\":%llu,"
           "\"records_skipped\":%llu,\"hot_ring_ingested\":%llu,"
           "\"candidate_deduped\":%llu,\"candidate_dedup_reject_reasons\":{\"scope\":\"comparable_slot_checks\",\"overlapping\":true,\"generation_conflict\":%llu,\"source_shape\":%llu,\"semantic_mismatch\":%llu,\"skew\":%llu},\"candidate_admission\":{\"reuse_scope\":\"local_in_process_evidence\",\"requests\":%llu,\"reused\":%llu,\"attempts\":%llu,\"admitted\":%llu,\"rejected\":%llu,\"transaction_failures\":%llu},\"bounded_string_truncations\":%llu,\"manifest_rejections\":%llu,\"write_budget_dropped\":%llu,\"write_budget\":{\"scope\":\"context_only\",\"used\":%u,\"limit\":%u,\"base_limit\":%u,\"dropped\":%llu,\"candidate\":{\"mode\":\"exempt\",\"dropped\":%llu},\"critical_context\":{\"mode\":\"capacity_bound\",\"used\":%u,\"limit\":%u,\"dropped\":%llu},\"ordinary_context\":{\"used\":%u,\"limit\":%u,\"dropped\":%llu},\"context_dropped\":%llu},"
           "\"process_cache\":{\"hits\":%llu,\"misses\":%llu,\"evictions\":%llu,\"used\":%u,\"capacity\":%u},"
           "\"identity\":{\"observations_total\":%llu,\"none\":%llu,\"hits\":%llu,\"misses\":%llu,\"enrich_attempts\":%llu,\"upgrades\":%llu,\"stale_rejects\":%llu,\"generation_unknown_rejects\":%llu,\"generation_mismatch_rejects\":%llu,\"generation_unknown_update_rejects\":%llu,\"generation_mismatch_update_rejects\":%llu,\"generation_resets\":%llu,\"late_generation_rejects\":%llu,\"target_4688\":%llu,\"creator_fallback\":%llu,\"token_sid\":%llu},"
           "\"db_budget_dropped\":%llu,\"pressure_dropped\":%llu,"
           "\"pressure_active\":%s,\"lock_observability\":{\"histogram\":\"log2_ns_64\",\"samples\":%llu,\"wait_total_ns\":%llu,\"wait_max_ns\":%llu,\"wait_p95_ns\":%llu,\"wait_p99_ns\":%llu,\"hold_total_ns\":%llu,\"hold_max_ns\":%llu,\"hold_p95_ns\":%llu,\"hold_p99_ns\":%llu},\"ordinary_coalesced\":%llu,"
           "\"aggregate_slots_used\":%u,\"static_bytes\":%llu,"
           "\"capacity\":{\"process_slots\":%u,\"ring_events\":%u,"
           "\"hot_ring_events\":%u,\"context_windows\":%u,\"metrics\":%u,"
           "\"candidate_dedup\":%u,\"aggregate_slots\":%u},"
           "\"utilization_bps\":{\"db\":%u,\"process_slots\":%u,\"ring\":%u,\"hot_ring\":%u,\"metrics\":%u,\"aggregate\":%u,\"context_windows\":%u,\"candidate_dedup\":%u},"
           "\"evictions\":{\"ring\":%llu,\"hot_ring\":%llu,\"context_windows\":%llu,\"context_window_nominal_ended_replacements\":%llu,\"context_window_protected_replacements\":%llu,\"metrics\":%llu,\"metric_write_failures\":%llu,\"metric_unrecorded\":%llu,\"candidate_dedup\":%llu,\"aggregate\":%llu,\"db_retention_rows\":%llu,\"db_capacity_rows\":%llu},"
           "\"oldest\":{\"process_last_seen_ns\":%lld,\"ring_event_time_ns\":%lld,\"hot_ring_event_time_ns\":%lld,\"candidate_dedup_ns\":%lld,\"p0_candidate_event_time_ns\":%lld},"
           "\"maintenance_runs\":%llu,\"process_slots_used\":%u,\"ring_events\":%u,"
           "\"last_engine\":%s,\"last_event_time_ns\":%lld,\"last_error\":%s,"
           "\"partitions\":{\"hot_ring\":{\"events\":%u},"
           "\"p0_candidates\":{\"written\":%llu,\"rows\":%llu},"
           "\"artifacts\":{\"written\":%llu,\"context_facts_written\":%llu,"
           "\"context_refs_written\":%llu,\"context_ref_write_sources\":%s},"
           "\"command_results\":{\"written\":%llu,\"capacity_rejected\":%llu,\"failed\":%llu},\"metrics\":{\"minutes\":%u}},"
           "\"coalesced\":{\"file\":%llu,\"registry\":%llu,\"network\":%llu},"
           "\"drop_counters\":{\"file\":%llu,\"registry\":%llu,\"network\":%llu,\"other\":%llu},"
           "\"accounting\":%s,"
           "\"shm_bytes\":%llu,\"physical_bytes\":%llu}",
           st.db_open ? "true" : "false", st.storage_format, path, st.max_db_mb, st.retention_hours,
           (unsigned long long)st.db_bytes, (unsigned long long)st.wal_bytes,
           (unsigned long long)st.records_written, (unsigned long long)st.records_dropped,
           (unsigned long long)st.records_skipped, (unsigned long long)st.hot_ring_ingested,
           (unsigned long long)st.candidate_deduped,
           (unsigned long long)st.candidate_dedup_generation_conflict_rejects,
           (unsigned long long)st.candidate_dedup_source_shape_rejects,
           (unsigned long long)st.candidate_dedup_semantic_mismatch_rejects,
           (unsigned long long)st.candidate_dedup_skew_rejects,
           (unsigned long long)st.candidate_requests,
           (unsigned long long)st.candidate_reused,
           (unsigned long long)st.candidate_admission_attempts,
           (unsigned long long)st.candidate_admitted,
           (unsigned long long)st.candidate_rejected,
           (unsigned long long)st.candidate_transaction_failures,
           (unsigned long long)st.bounded_string_truncations,
           (unsigned long long)st.manifest_rejections,
           (unsigned long long)st.write_budget_dropped,
           st.write_budget_used, st.write_budget_limit, st.write_budget_base_limit,
           (unsigned long long)st.write_budget_dropped,
           (unsigned long long)st.write_budget_candidate_dropped,
           st.write_budget_critical_context_used,
           st.write_budget_critical_context_limit,
           (unsigned long long)st.write_budget_critical_context_dropped,
           st.write_budget_ordinary_context_used,
           st.write_budget_ordinary_context_limit,
           (unsigned long long)st.write_budget_ordinary_context_dropped,
           (unsigned long long)st.write_budget_context_dropped,
           (unsigned long long)st.process_cache_hits, (unsigned long long)st.process_cache_misses,
           (unsigned long long)st.process_cache_evictions, st.process_slots_used, st.process_slots_capacity,
           (unsigned long long)st.identity_observations_total, (unsigned long long)st.identity_none,
           (unsigned long long)st.identity_cache_hits, (unsigned long long)st.identity_cache_misses,
           (unsigned long long)st.identity_enrich_attempts, (unsigned long long)st.identity_upgrades,
           (unsigned long long)st.identity_stale_rejects, (unsigned long long)st.identity_generation_unknown_rejects,
           (unsigned long long)st.identity_generation_mismatch_rejects, (unsigned long long)st.generation_unknown_update_rejects,
           (unsigned long long)st.generation_mismatch_update_rejects, (unsigned long long)st.generation_resets,
           (unsigned long long)st.late_generation_rejects, (unsigned long long)st.identity_target_4688,
           (unsigned long long)st.identity_creator_fallback, (unsigned long long)st.identity_token_sid,
           (unsigned long long)st.db_budget_dropped,
           (unsigned long long)st.pressure_dropped,
           st.pressure_active ? "true" : "false",
           (unsigned long long)st.mutex_lock_samples,
           (unsigned long long)st.mutex_wait_total_ns,
           (unsigned long long)st.mutex_wait_max_ns,
           (unsigned long long)st.mutex_wait_p95_ns,
           (unsigned long long)st.mutex_wait_p99_ns,
           (unsigned long long)st.mutex_hold_total_ns,
           (unsigned long long)st.mutex_hold_max_ns,
           (unsigned long long)st.mutex_hold_p95_ns,
           (unsigned long long)st.mutex_hold_p99_ns,
           (unsigned long long)st.ordinary_coalesced, st.aggregate_slots_used,
           (unsigned long long)st.static_bytes,
           st.process_slots_capacity, st.ring_capacity, st.hot_ring_capacity,
           st.context_windows_capacity, st.metrics_capacity, st.candidate_dedup_capacity,
           st.aggregate_slots_capacity,
           st.db_utilization_bps, st.process_slots_utilization_bps,
           st.ring_utilization_bps, st.hot_ring_utilization_bps,
           st.metrics_utilization_bps, st.aggregate_utilization_bps,
           st.context_windows_utilization_bps, st.candidate_dedup_utilization_bps,
           (unsigned long long)st.ring_evictions,
           (unsigned long long)st.hot_ring_evictions,
           (unsigned long long)st.context_window_evictions,
           (unsigned long long)st.context_window_nominal_ended_replacements,
           (unsigned long long)st.context_window_protected_replacements,
           (unsigned long long)st.metric_slot_evictions,
           (unsigned long long)st.metric_write_failures,
           (unsigned long long)st.metric_unrecorded,
           (unsigned long long)st.candidate_dedup_evictions,
           (unsigned long long)st.aggregate_slot_evictions,
           (unsigned long long)st.db_retention_evicted,
           (unsigned long long)st.db_capacity_evicted,
           (long long)st.oldest_process_last_seen_ns,
           (long long)st.oldest_ring_event_time_ns,
           (long long)st.oldest_hot_ring_event_time_ns,
           (long long)st.oldest_candidate_dedup_ns,
           (long long)st.oldest_p0_candidate_event_time_ns,
           (unsigned long long)st.maintenance_runs, st.process_slots_used, st.ring_events,
           eng, (long long)st.last_event_time_ns, err, st.hot_ring_events,
           (unsigned long long)st.p0_candidates_written,
           (unsigned long long)st.p0_candidate_rows,
           (unsigned long long)st.artifacts_written,
           (unsigned long long)st.context_facts_written,
           (unsigned long long)st.context_refs_written, context_ref_sources,
           (unsigned long long)st.command_results_written,
           (unsigned long long)st.command_results_capacity_rejected,
           (unsigned long long)st.command_results_failed, st.metrics_minutes,
           (unsigned long long)st.file_coalesced,
           (unsigned long long)st.registry_coalesced,
           (unsigned long long)st.network_coalesced,
           (unsigned long long)st.metric_file_drops,
           (unsigned long long)st.metric_registry_drops,
           (unsigned long long)st.metric_network_drops,
           (unsigned long long)st.metric_other_drops, accounting,
           (unsigned long long)st.shm_bytes, (unsigned long long)st.physical_bytes);
  if (written < 0 || (size_t)written >= cap) {
    /* This function supplies a JSON member, not a complete document.  Keep
     * that member syntactically valid for older callers with a small buffer
     * instead of handing the enclosing health document a cut-off fragment. */
    (void)snprintf(out, cap, "\"evidence_cache\":{\"db_open\":%s,\"pressure_active\":%s,\"status\":\"truncated\"}",
                   st.db_open ? "true" : "false", st.pressure_active ? "true" : "false");
  }
}

int edr_local_evidence_cache_context_ref_write_sources_json(char *out, size_t cap) {
  EdrEvidenceCacheStatus st;
  if (!out || cap == 0u) {
    return -1;
  }
  edr_local_evidence_cache_get_status(&st);
  return context_ref_write_sources_json_from_status(&st, out, cap);
}
