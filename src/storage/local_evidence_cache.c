#include "edr/local_evidence_cache.h"

#include "edr/p0_rule_ir.h"
#include "edr/p0_rule_match.h"
#include "edr/process_tree_cache.h"
#include "edr/resource.h"
#include "edr/sha256.h"
#include "edr/time_util.h"
#include "edr/windows_event_policy.h"

#include "cJSON.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
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
  EvidenceProcessGeneration generation;
  char endpoint_id[48];
  char tenant_id[64];
  char candidate_id[160];
} ContextWindowSlot;

typedef struct {
  int64_t minute_unix;
  char endpoint_id[48];
  uint64_t file_drops;
  uint64_t registry_drops;
  uint64_t network_drops;
  uint64_t other_drops;
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
static CandidateDedupeSlot s_candidate_dedupe[EDR_EVIDENCE_CANDIDATE_DEDUP_SLOTS];
static OrdinaryAggregateSlot s_ordinary_agg[EDR_EVIDENCE_AGG_SLOTS];
static uint32_t s_ring_pos;
static uint32_t s_context_ring_pos;
static uint32_t s_context_window_next;
static EdrEvidenceCacheStatus s_status;
static uint64_t s_last_maintenance_ns;
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
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
static unsigned s_test_commit_failures;
static int s_test_commit_active;

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

void edr_local_evidence_cache_test_set_now_unix_ns(int64_t now_ns) {
  evidence_cache_lock();
  s_test_now_unix_ns = now_ns;
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
static int record_parent_snapshot(const EdrBehaviorRecord *r,
                                  ProcessTreeEntry *snapshot) {
  uint64_t child_birth_ns = 0u;
  uint64_t selector_ns;
  if (!r || !snapshot || r->ppid == 0u ||
      network_actor_generation_unbound(r)) {
    return 0;
  }
  selector_ns = r->event_time_ns > 0 ? (uint64_t)r->event_time_ns : 0u;
  if (generation_birth_unix_ns(r->process_creation_filetime_100ns,
                               &child_birth_ns)) {
    selector_ns = child_birth_ns;
  }
  memset(snapshot, 0, sizeof(*snapshot));
  if (selector_ns == 0u ||
      edr_pt_cache_snapshot_at(r->ppid, selector_ns, snapshot) != 0 ||
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

static int record_parent_generation(const EdrBehaviorRecord *r,
                                    EvidenceProcessGeneration *out) {
  ProcessTreeEntry snapshot;
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
             ? "child_birth_parent_snapshot"
             : "event_time_parent_snapshot";
}

static int proc_generation_matches_record(const ProcSlot *p,
                                          const EdrBehaviorRecord *r) {
  EvidenceProcessGeneration generation;
  return p && record_process_generation(r, &generation) &&
         generation_equal(&p->generation, &generation);
}

static int proc_parent_generation_matches_record(const ProcSlot *p,
                                                 const EdrBehaviorRecord *r) {
  /* Once an exact child lifetime owns a parent edge, a later actor event does
   * not need the parent generation to remain in the short-lived process-tree
   * history.  Requiring another snapshot here made a valid edge disappear
   * after the parent exit grace, or change when that PID was reused. */
  return p && r && proc_generation_matches_record(p, r) &&
         generation_bound(&p->parent_generation) &&
         (r->ppid == 0u || p->ppid == r->ppid);
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
        child->ppid != parent->pid || !generation_bound(&child->generation) ||
        generation->creation_filetime_100ns >
            child->generation.creation_filetime_100ns ||
        (child->endpoint_id[0] && parent->endpoint_id[0] &&
         strcmp(child->endpoint_id, parent->endpoint_id) != 0) ||
        !generation_birth_unix_ns(
            child->generation.creation_filetime_100ns, &child_birth_ns) ||
        edr_pt_cache_snapshot_at(parent->pid, child_birth_ns, &selected) != 0 ||
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
                                   "late_child_birth_parent_snapshot");
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
  if (r->ppid != 0u) {
    if (p->ppid != 0u && p->ppid != r->ppid) {
      p->parent_name[0] = '\0';
      p->parent_path[0] = '\0';
      p->parent_cmdline[0] = '\0';
      p->parent_path_truncated_fields[0] = '\0';
      p->parent_cmdline_truncated_fields[0] = '\0';
      p->grandparent_pid = 0u;
      p->grandparent_name[0] = '\0';
      p->grandparent_path[0] = '\0';
      p->grandparent_path_truncated_fields[0] = '\0';
      memset(&p->parent_generation, 0, sizeof(p->parent_generation));
      p->parent_process_generation_source[0] = '\0';
    }
    p->ppid = r->ppid;
  }
  p->last_seen_ns = record_time_ns(r);
  if (incoming_parent_generation_known &&
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
    return;
  }
  evidence_cache_lock();
  s_status.identity_enrich_attempts++;
  ProcSlot *p = find_proc(r->pid, r->endpoint_id);
  if (p) {
    s_status.process_cache_hits++;
    int process_safe = proc_generation_matches_record(p, r);
    if (!process_safe) {
      if (!generation_bound(&p->generation)) s_status.identity_generation_unknown_rejects++;
      else s_status.identity_generation_mismatch_rejects++;
      if (p->username[0] || p->user_sid[0]) {
        s_status.identity_stale_rejects++;
        if (!r->username[0] && !r->user_sid[0]) s_status.identity_cache_misses++;
      }
    } else {
      if (r->ppid == 0u && p->ppid != 0u) {
        r->ppid = p->ppid;
      }
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
      if (proc_parent_generation_matches_record(p, r)) {
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
  if ((!r->parent_name[0] || !r->parent_path[0] || !r->parent_cmdline[0]) && r->ppid != 0u) {
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
  evidence_cache_unlock();
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

static MetricSlot *metric_slot_for(const EdrBehaviorRecord *r, int64_t event_time_ns) {
  int64_t minute = (event_time_ns / 1000000000LL) / 60LL;
  const char *endpoint_id = (r && r->endpoint_id[0]) ? r->endpoint_id : "";
  MetricSlot *empty = NULL;
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
  }
  MetricSlot *m = empty ? empty : oldest;
  if (!empty && m->minute_unix != 0) {
    s_status.metric_slot_evictions++;
  }
  memset(m, 0, sizeof(*m));
  m->minute_unix = minute;
  copy_s(m->endpoint_id, sizeof(m->endpoint_id), endpoint_id);
  return m;
}

static void record_metric_drop(const EdrBehaviorRecord *r, int64_t event_time_ns) {
  MetricSlot *m = metric_slot_for(r, event_time_ns);
  uint32_t type = r ? (uint32_t)r->type : 0u;
  if (is_file_event_type(type)) {
    m->file_drops++;
    s_status.metric_file_drops++;
  } else if (is_registry_event_type(type)) {
    m->registry_drops++;
    s_status.metric_registry_drops++;
  } else if (is_network_event_type(type)) {
    m->network_drops++;
    s_status.metric_network_drops++;
  } else {
    m->other_drops++;
    s_status.metric_other_drops++;
  }
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

static int ordinary_aggregate_should_coalesce(const EdrBehaviorRecord *r, int64_t ts) {
  uint32_t kind = 0u;
  if (!ordinary_aggregate_kind(r, &kind)) {
    return 0;
  }
  char prefix[160];
  if (!ordinary_aggregate_prefix(r, kind, prefix, sizeof(prefix))) {
    return 0;
  }
  int64_t minute = (ts / 1000000000LL) / 60LL;
  size_t replace_i = 0u;
  int64_t oldest = INT64_MAX;
  for (size_t i = 0; i < EDR_EVIDENCE_AGG_SLOTS; i++) {
    OrdinaryAggregateSlot *s = &s_ordinary_agg[i];
    if (!s->used) {
      replace_i = i;
      oldest = INT64_MIN;
      break;
    }
    if (s->minute_unix < oldest) {
      oldest = s->minute_unix;
      replace_i = i;
    }
    if (s->minute_unix == minute && s->pid == r->pid && s->kind == kind &&
        strncmp(s->endpoint_id, r->endpoint_id, sizeof(s->endpoint_id)) == 0 &&
        strncmp(s->prefix, prefix, sizeof(s->prefix)) == 0) {
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
  copy_s(slot->prefix, sizeof(slot->prefix), prefix);
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
  if (!emit) {
    return;
  }
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
static void sqlite_maintenance(void);

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
      {"script_path", "ALTER TABLE p0_candidates ADD COLUMN script_path TEXT;"},
      {"exe_hash", "ALTER TABLE p0_candidates ADD COLUMN exe_hash TEXT;"},
      {"username", "ALTER TABLE p0_candidates ADD COLUMN username TEXT;"},
      {"user_sid", "ALTER TABLE p0_candidates ADD COLUMN user_sid TEXT;"},
      {"identity_source",
       "ALTER TABLE p0_candidates ADD COLUMN identity_source TEXT;"},
      {"identity_quality",
       "ALTER TABLE p0_candidates ADD COLUMN identity_quality TEXT;"},
  };
  for (size_t i = 0u; i < sizeof(columns) / sizeof(columns[0]); ++i) {
    int has_column = sqlite_p0_candidates_has_column(columns[i].name);
    if (has_column < 0 || (has_column == 0 && exec_sql(columns[i].alter) != 0)) {
      return -1;
    }
  }
  return 0;
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
  if (sqlite_decimal_u64(parent_start_key, &out->parent_generation.process_start_key) &&
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
    return;
  }
  char wal_path[640];
  snprintf(wal_path, sizeof(wal_path), "%s-wal", s_status.path);
  s_status.wal_bytes = path_size_bytes(wal_path);
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

static int sqlite_size_budget_allow(void) {
  if (!db_size_over_limit()) {
    return 1;
  }
  uint64_t now = edr_monotonic_ns();
  if (now - s_last_maintenance_ns >= 10000000000ULL) {
    s_last_maintenance_ns = now;
    sqlite_maintenance();
  }
  if (!db_size_over_limit()) {
    return 1;
  }
  s_status.db_budget_dropped++;
  set_error("evidence cache size budget exceeded");
  return 0;
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
      "FROM process_cache WHERE endpoint_id=? AND ppid=? AND pid<>?;";
  static const char *update_sql =
      "UPDATE process_cache SET parent_process_start_key=?,"
      "parent_process_creation_filetime_100ns=?,"
      "parent_process_generation_source=?,parent_name=?,parent_path=? "
      "WHERE endpoint_id=? AND pid=? AND ppid=? AND process_start_key=? "
      "AND process_creation_filetime_100ns=?;";
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
        edr_pt_cache_snapshot_at(parent->pid, child_birth_ns, &selected) != 0 ||
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
    bind_text(update_st, 3, "late_child_birth_parent_snapshot");
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
  char command_fields[64];
  if (!s_db || !should_update_process_cache(r) ||
      !record_process_generation(r, &generation)) {
    /* Unknown PID-only metadata is never durable authority. It may remain in
     * the bounded in-memory display cache, but must not overwrite a known
     * restarted lifetime in SQLite. */
    return 0;
  }
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
        "SELECT identity_quality,cmdline,cmdline_truncated_fields FROM process_cache WHERE endpoint_id=? AND pid=? "
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
      "identity_quality,exe_hash,cmdline_truncated_fields) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,pid) DO UPDATE SET "
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
      "parent_name=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns OR "
      "(excluded.ppid<>0 AND process_cache.ppid IS NOT excluded.ppid) OR "
      "(excluded.parent_process_start_key<>'' AND (process_cache.ppid IS NOT excluded.ppid OR "
      "process_cache.parent_process_start_key IS NOT excluded.parent_process_start_key OR "
      "process_cache.parent_process_creation_filetime_100ns IS NOT excluded.parent_process_creation_filetime_100ns)) "
      "THEN excluded.parent_name WHEN excluded.parent_name<>'' THEN excluded.parent_name ELSE process_cache.parent_name END,"
      "parent_path=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
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
      "parent_process_start_key=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns OR "
      "(excluded.ppid<>0 AND process_cache.ppid IS NOT excluded.ppid) OR "
      "excluded.parent_process_start_key<>'' THEN excluded.parent_process_start_key ELSE process_cache.parent_process_start_key END,"
      "parent_process_creation_filetime_100ns=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns OR "
      "(excluded.ppid<>0 AND process_cache.ppid IS NOT excluded.ppid) OR "
      "excluded.parent_process_start_key<>'' THEN excluded.parent_process_creation_filetime_100ns ELSE process_cache.parent_process_creation_filetime_100ns END,"
      "parent_process_generation_source=CASE WHEN process_cache.process_start_key IS NOT excluded.process_start_key OR "
      "process_cache.process_creation_filetime_100ns IS NOT excluded.process_creation_filetime_100ns OR "
      "(excluded.ppid<>0 AND process_cache.ppid IS NOT excluded.ppid) OR "
      "excluded.parent_process_start_key<>'' THEN excluded.parent_process_generation_source ELSE process_cache.parent_process_generation_source END,"
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
  sqlite3_bind_int64(st, 4, (sqlite3_int64)r->ppid);
  bind_text(st, 5, r->process_name);
  bind_text(st, 6, r->exe_path);
  bind_text(st, 7, r->cmdline);
  /* Parent display and generation must come from one child-birth snapshot.
   * Never persist a newly recomputed tuple beside stale fields carried by an
   * earlier record revision. */
  bind_text(st, 8, parent_known ? parent_snapshot.process_name : r->parent_name);
  bind_text(st, 9, parent_known ? parent_snapshot.exe_path : r->parent_path);
  sqlite3_bind_int64(st, 10, (sqlite3_int64)ts);
  sqlite3_bind_int64(st, 11, (sqlite3_int64)ts);
  bind_text(st, 12, start_key);
  bind_text(st, 13, creation);
  bind_text(st, 14, record_process_generation_source(r));
  bind_text(st, 15, parent_start_key);
  bind_text(st, 16, parent_creation);
  bind_text(st, 17, parent_known ? record_parent_generation_source(r) : "");
  bind_text(st, 18, preserve_stronger_identity ? "" : r->username);
  bind_text(st, 19, preserve_stronger_identity ? "" : r->domain);
  bind_text(st, 20, preserve_stronger_identity ? "" : r->user_sid);
  bind_text(st, 21, preserve_stronger_identity ? "" : r->logon_id);
  bind_text(st, 22, preserve_stronger_identity ? "" : r->identity_source);
  bind_text(st, 23, preserve_stronger_identity ? "" : r->identity_quality);
  bind_text(st, 24, r->exe_hash);
  bind_text(st, 25, command_fields);
  sqlite3_bind_int(st, 26, replace_command);
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

static void manifest_rejected(const char *reason) {
  s_status.manifest_rejections++;
  set_error(reason ? reason : "context manifest rejected");
}

static int manifest_add_text(cJSON *object, const char *name, const char *value) {
  return object && name && manifest_utf8_valid(value) &&
         cJSON_AddStringToObject(object, name, value ? value : "") != NULL;
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
  return number && cJSON_AddItemToObject(object, name, number);
}

static int manifest_add_u64(cJSON *object, const char *name, uint64_t value) {
  char decimal[32];
  int written;
  cJSON *number;
  if (!object || !name) return 0;
  written = snprintf(decimal, sizeof(decimal), "%llu", (unsigned long long)value);
  if (written < 0 || (size_t)written >= sizeof(decimal)) return 0;
  number = cJSON_CreateRaw(decimal);
  return number && cJSON_AddItemToObject(object, name, number);
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
  int ok;
  if (!root || !r) return 0;
  edr_p0_normalize_command_for_evidence(r->cmdline, normalized,
                                        sizeof(normalized));
  (void)edr_p0_extract_script_path(r->cmdline, script_path,
                                   sizeof(script_path));
  command = cJSON_CreateObject();
  identity = cJSON_CreateObject();
  artifact = cJSON_CreateObject();
  if (!command || !identity || !artifact) goto fail;
  ok = manifest_add_text(command, "raw", r->cmdline) &&
       manifest_add_text(command, "normalized", normalized) &&
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
  if (!manifest_utf8_valid(value)) return 0;
  cJSON_ArrayForEach(item, array) {
    if (cJSON_IsString(item) && item->valuestring &&
        strcmp(item->valuestring, value) == 0) {
      return 1;
    }
  }
  if (*count >= EDR_EVIDENCE_SOURCE_EVENT_ALIASES_MAX) return 0;
  item = cJSON_CreateString(value);
  if (!item || !cJSON_AddItemToArray(array, item)) {
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
  int generation_known;
  const char *generation_source;
  int ok;
  int rc = -1;
  if (!r || !out) {
    manifest_rejected("context manifest missing source record");
    return -1;
  }
  generation_known = record_process_generation(r, &generation);
  generation_source = generation_known ? record_process_generation_source(r) : "";
  root = cJSON_CreateObject();
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
  int generation_known;
  const char *generation_source;
  int ok;
  int rc = -1;
  if (!r || !out) {
    manifest_rejected("post-context manifest missing source record");
    return -1;
  }
  generation_known = record_process_generation(r, &generation);
  generation_source = generation_known ? record_process_generation_source(r) : "";
  root = cJSON_CreateObject();
  ok = root &&
       manifest_add_text(root, "schema", "p0_post_context_event.v1") &&
       cJSON_AddNullToObject(root, "candidate_id") &&
       manifest_add_text(root, "source_event_id", r->event_id) &&
       manifest_add_i64(root, "event_time_ns", record_time_ns(r)) &&
       manifest_add_u64(root, "type", (uint32_t)r->type) &&
       manifest_add_u64(root, "pid", r->pid) &&
       manifest_add_u64(root, "ppid", r->ppid) &&
       manifest_add_u64_text(root, "process_start_key",
                             generation_known ? generation.process_start_key : 0u) &&
       manifest_add_u64_text(root, "process_creation_filetime_100ns",
                             generation_known ? generation.creation_filetime_100ns : 0u) &&
       manifest_add_text(root, "process_generation_source", generation_source) &&
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
    return NULL;
  }
  value = cJSON_CreateString(candidate_id);
  if (!value) return NULL;
  json = cJSON_PrintUnformatted(value);
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
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare context fact replay lookup failed");
    return -1;
  }
  bind_text(st, 1, prepared->fact_id);
  step = sqlite3_step(st);
  if (step == SQLITE_ROW) {
    const char *existing = (const char *)sqlite3_column_text(st, 0);
    if (!existing || strcmp(existing, prepared->manifest_template) != 0) {
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
  if (!s_db || !r || !candidate_ids || candidate_count == 0u || !prepared) {
    return -1;
  }
  memset(prepared, 0, sizeof(*prepared));
  if (sqlite_prepare_context_fact(r, prepared) != 0) {
    sqlite_free_prepared_context_artifacts(prepared);
    return -1;
  }
  prepared->refs = (PreparedContextRef *)calloc(
      candidate_count, sizeof(PreparedContextRef));
  if (!prepared->refs) {
    set_error("allocate post-context replay plan failed");
    sqlite_free_prepared_context_artifacts(prepared);
    return -1;
  }
  for (uint32_t i = 0u; i < candidate_count; ++i) {
    PreparedContextRef *ref = &prepared->refs[prepared->ref_count];
    sqlite3_stmt *st = NULL;
    int step;
    if (!candidate_ids[i][0] ||
        artifact_id_for(r, candidate_ids[i], "post_context", ref->artifact_id,
                        sizeof(ref->artifact_id)) != 0) {
      sqlite_free_prepared_context_artifacts(prepared);
      return -1;
    }
    if (sqlite3_prepare_v2(
            s_db,
            "SELECT candidate_id,fact_id FROM candidate_context_refs WHERE artifact_id=?;",
            -1, &st, NULL) != SQLITE_OK) {
      set_error("prepare context reference replay lookup failed");
      sqlite_free_prepared_context_artifacts(prepared);
      return -1;
    }
    bind_text(st, 1, ref->artifact_id);
    step = sqlite3_step(st);
    if (step == SQLITE_ROW) {
      const char *existing_candidate = (const char *)sqlite3_column_text(st, 0);
      const char *existing_fact = (const char *)sqlite3_column_text(st, 1);
      int candidate_matches = existing_candidate &&
                              strcmp(existing_candidate, candidate_ids[i]) == 0;
      int exact = candidate_matches && existing_fact &&
                  strcmp(existing_fact, prepared->fact_id) == 0;
      sqlite3_finalize(st);
      if (exact) continue;
      if (!candidate_matches) {
        set_error("context reference candidate conflict");
        sqlite_free_prepared_context_artifacts(prepared);
        return -1;
      }
    } else {
      sqlite3_finalize(st);
    }
    if (step != SQLITE_ROW && step != SQLITE_DONE) {
      set_error("read context reference replay state failed");
      sqlite_free_prepared_context_artifacts(prepared);
      return -1;
    }
    ref->candidate_id_json = context_candidate_id_json(candidate_ids[i]);
    if (!ref->candidate_id_json) {
      set_error("encode context reference candidate id failed");
      sqlite_free_prepared_context_artifacts(prepared);
      return -1;
    }
    ref->candidate_index = i;
    prepared->ref_count++;
  }
  return 0;
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
  for (uint32_t i = 0u; i < prepared->ref_count; ++i) {
    static const char ref_sql[] =
        "INSERT INTO candidate_context_refs(artifact_id,candidate_id,fact_id,"
        "candidate_id_json,created_ns,upload_status,minio_key) "
        "VALUES(?,?,?,?,?,'local_manifest','') "
        "ON CONFLICT(artifact_id) DO UPDATE SET fact_id=excluded.fact_id,"
        "candidate_id_json=excluded.candidate_id_json,"
        "created_ns=excluded.created_ns,upload_status=excluded.upload_status,"
        "minio_key=excluded.minio_key;";
    const PreparedContextRef *ref = &prepared->refs[i];
    uint32_t candidate_index = ref->candidate_index;
    sqlite3_stmt *st = NULL;
    if (!candidate_ids[candidate_index][0] ||
        sqlite3_prepare_v2(s_db, ref_sql, -1, &st, NULL) != SQLITE_OK) {
      set_error("prepare context reference insert failed");
      sqlite3_finalize(st);
      sqlite_rollback_silent();
      return -1;
    }
    bind_text(st, 1, ref->artifact_id);
    bind_text(st, 2, candidate_ids[candidate_index]);
    bind_text(st, 3, prepared->fact_id);
    bind_text(st, 4, ref->candidate_id_json);
    sqlite3_bind_int64(st, 5, written_ns);
    if (sqlite3_step(st) != SQLITE_DONE) {
      set_error("insert context reference failed");
      sqlite3_finalize(st);
      sqlite_rollback_silent();
      return -1;
    }
    sqlite3_finalize(st);
  }
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
  PreparedContextArtifacts prepared;
  uint32_t budget_units;
  uint32_t materialized_changes;
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
  if (!sqlite_size_budget_allow() ||
      !sqlite_write_budget_allow(budget_units, ts, write_class)) {
    sqlite_free_prepared_context_artifacts(&prepared);
    return -1;
  }
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
      "LEFT JOIN candidate_context_refs r ON r.artifact_id=a.artifact_id "
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
  static const char ref_sql[] =
      "INSERT INTO candidate_context_refs(artifact_id,candidate_id,fact_id,"
      "candidate_id_json,created_ns,upload_status,minio_key) VALUES(?,?,?,?,?,?,?) "
      "ON CONFLICT(artifact_id) DO UPDATE SET "
      "candidate_id=excluded.candidate_id,fact_id=excluded.fact_id,"
      "candidate_id_json=excluded.candidate_id_json,"
      "created_ns=MAX(candidate_context_refs.created_ns,excluded.created_ns),"
      "upload_status=excluded.upload_status,minio_key=excluded.minio_key;";
  sqlite3_stmt *select_st = NULL;
  sqlite3_stmt *normalize_st = NULL;
  sqlite3_stmt *fact_st = NULL;
  sqlite3_stmt *fact_lookup_st = NULL;
  sqlite3_stmt *ref_st = NULL;
  int result = -1;
  if (!s_db || exec_sql("BEGIN IMMEDIATE;") != 0) return -1;
  if (sqlite3_prepare_v2(s_db, select_sql, -1, &select_st, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(s_db, normalize_sql, -1, &normalize_st, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(s_db, fact_sql, -1, &fact_st, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(s_db, fact_lookup_sql, -1, &fact_lookup_st, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(s_db, ref_sql, -1, &ref_st, NULL) != SQLITE_OK) {
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
    sqlite3_reset(ref_st);
    sqlite3_clear_bindings(ref_st);
    bind_text(ref_st, 1, artifact_id);
    bind_text(ref_st, 2, candidate_id);
    bind_text(ref_st, 3, fact_id);
    bind_text(ref_st, 4, candidate_json);
    sqlite3_bind_int64(ref_st, 5, created_ns);
    bind_text(ref_st, 6, upload_status ? upload_status : "local_manifest");
    bind_text(ref_st, 7, minio_key ? minio_key : "");
    if (sqlite3_step(ref_st) != SQLITE_DONE) {
      set_error("migrate legacy context reference failed");
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
  sqlite3_finalize(ref_st);
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
  int exists = 0;
  if (!s_db || !candidate_id || !candidate_id[0]) {
    return 0;
  }
  if (sqlite3_prepare_v2(s_db, "SELECT 1 FROM p0_candidates WHERE candidate_id=? LIMIT 1;",
                         -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare p0_candidates lookup failed");
    return -1;
  }
  sqlite3_bind_text(st, 1, candidate_id, -1, SQLITE_TRANSIENT);
  exists = sqlite3_step(st) == SQLITE_ROW;
  sqlite3_finalize(st);
  return exists;
}

static int sqlite_record_candidate(const EdrBehaviorRecord *r, const char *candidate_id,
                                   uint32_t pre_count, int64_t post_until_ns) {
  EvidenceProcessGeneration generation;
  int generation_known;
  const char *generation_source;
  char normalized_command[EDR_BR_STR_LONG];
  char script_path[EDR_BR_STR_LONG];
  if (!s_db || !r) {
    set_error("evidence cache database unavailable");
    return -1;
  }
  generation_known = record_process_generation(r, &generation);
  generation_source = generation_known ? record_process_generation_source(r) : "";
  edr_p0_normalize_command_for_evidence(r->cmdline, normalized_command,
                                        sizeof(normalized_command));
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
  if (upsert_process_sqlite(r) != 0) {
    sqlite_rollback_silent();
    return -1;
  }
  const char *sql =
      "INSERT INTO p0_candidates(candidate_id,endpoint_id,tenant_id,event_time_ns,type,pid,ppid,"
      "process_name,exe_path,cmdline,file_path,dns_query,net_dst,net_dport,reg_key_path,"
      "reg_value_name,reg_op,detection_context,context_pre_count,context_post_until_ns,created_ns,"
      "process_start_key,process_creation_filetime_100ns,process_generation_source,"
      "source_completeness,source_truncated_fields,normalized_command,script_path,exe_hash,"
      "username,user_sid,identity_source,identity_quality) "
      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
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
      "script_path=CASE WHEN excluded.script_path<>'' THEN excluded.script_path ELSE p0_candidates.script_path END,"
      "exe_hash=CASE WHEN excluded.exe_hash<>'' THEN excluded.exe_hash ELSE p0_candidates.exe_hash END,"
      "username=CASE WHEN excluded.username<>'' THEN excluded.username ELSE p0_candidates.username END,"
      "user_sid=CASE WHEN excluded.user_sid<>'' THEN excluded.user_sid ELSE p0_candidates.user_sid END,"
      "identity_source=CASE WHEN excluded.identity_source<>'' THEN excluded.identity_source ELSE p0_candidates.identity_source END,"
      "identity_quality=CASE WHEN excluded.identity_quality<>'' THEN excluded.identity_quality ELSE p0_candidates.identity_quality END;";
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
  bind_text(st, 28, script_path);
  bind_text(st, 29, r->exe_hash);
  bind_text(st, 30, r->username);
  bind_text(st, 31, r->user_sid);
  bind_text(st, 32, r->identity_source);
  bind_text(st, 33, r->identity_quality);
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
  if (artifact_rc != 0 || sqlite_commit_candidate_transaction() != 0) {
    sqlite_rollback_silent();
    return -1;
  }
  /* These counters describe durable candidate commits, never a statement
   * that was later rolled back. */
  s_status.records_written++;
  s_status.p0_candidates_written++;
  s_status.artifacts_written++;
  return 0;
}

static void sqlite_flush_metrics(void) {
  if (!s_db) {
    return;
  }
  const char *sql =
      "INSERT INTO metrics(minute_unix,endpoint_id,metric_name,value) VALUES(?,?,?,?) "
      "ON CONFLICT(minute_unix,endpoint_id,metric_name) DO UPDATE SET value=excluded.value;";
  for (size_t i = 0; i < EDR_EVIDENCE_METRIC_SLOTS; i++) {
    MetricSlot *m = &s_metrics[i];
    if (m->minute_unix == 0) {
      continue;
    }
    const struct {
      const char *name;
      uint64_t value;
    } metrics[] = {
        {"file_drops", m->file_drops},
        {"registry_drops", m->registry_drops},
        {"network_drops", m->network_drops},
        {"other_drops", m->other_drops},
    };
    for (size_t j = 0; j < sizeof(metrics) / sizeof(metrics[0]); j++) {
      if (metrics[j].value == 0u) {
        continue;
      }
      sqlite3_stmt *st = NULL;
      if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
        return;
      }
      sqlite3_bind_int64(st, 1, (sqlite3_int64)m->minute_unix);
      bind_text(st, 2, m->endpoint_id);
      bind_text(st, 3, metrics[j].name);
      sqlite3_bind_int64(st, 4, (sqlite3_int64)metrics[j].value);
      (void)sqlite3_step(st);
      sqlite3_finalize(st);
    }
  }
}

/* DELETE changes live pages, not the allocated file length. Use live pages
 * only to decide whether more evidence must be evicted; admission still uses
 * the physical database + WAL budget after reclamation. On inspection failure
 * do not delete evidence speculatively. */
static int sqlite_live_size_over_limit(void) {
  sqlite3_stmt *st = NULL;
  int over = -1;
  if (sqlite3_prepare_v2(s_db,
      "SELECT (page_count-freelist_count)*page_size "
      "FROM pragma_page_count,pragma_freelist_count,pragma_page_size;",
      -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
    sqlite3_int64 bytes = sqlite3_column_int64(st, 0);
    if (bytes >= 0) {
      over = (uint64_t)bytes > (uint64_t)s_status.max_db_mb * 1024ULL * 1024ULL;
    }
  }
  sqlite3_finalize(st);
  if (over < 0) set_error("evidence cache live-page size query failed");
  return over;
}

static void sqlite_maintenance(void) {
  if (!s_db) {
    return;
  }
  s_status.maintenance_runs++;
  sqlite_flush_metrics();
  int64_t cutoff = now_unix_ns() - (int64_t)s_status.retention_hours * 3600LL * 1000000000LL;
  int64_t cutoff_minute = (cutoff / 1000000000LL) / 60LL;
  sqlite3_stmt *st = NULL;
  const char *tables[] = {"p0_candidates", "process_cache", "file_evidence", "network_ioc",
                          "registry_evidence", "artifacts", "candidate_context_refs",
                          "command_results"};
  const char *cols[] = {"event_time_ns", "last_seen_ns", "last_seen_ns", "last_seen_ns",
                        "last_seen_ns", "created_ns", "created_ns", "updated_ns"};
  for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
    char sql[160];
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE %s < ?;", tables[i], cols[i]);
    if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
      sqlite3_bind_int64(st, 1, (sqlite3_int64)cutoff);
      int rc = sqlite3_step(st);
      int changes = rc == SQLITE_DONE ? sqlite3_changes(s_db) : 0;
      sqlite3_finalize(st);
      st = NULL;
      if (changes > 0) {
        s_status.db_retention_evicted += (uint64_t)changes;
      }
    }
  }
  if (sqlite3_prepare_v2(s_db, "DELETE FROM metrics WHERE minute_unix < ?;", -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, (sqlite3_int64)cutoff_minute);
    int rc = sqlite3_step(st);
    int changes = rc == SQLITE_DONE ? sqlite3_changes(s_db) : 0;
    sqlite3_finalize(st);
    st = NULL;
    if (changes > 0) {
      s_status.db_retention_evicted += (uint64_t)changes;
    }
  }
  if (exec_sql("DELETE FROM context_facts WHERE NOT EXISTS ("
               "SELECT 1 FROM candidate_context_refs "
               "WHERE candidate_context_refs.fact_id=context_facts.fact_id);") == 0) {
    int changes = sqlite3_changes(s_db);
    if (changes > 0) s_status.db_retention_evicted += (uint64_t)changes;
  }
  if (db_size_over_limit()) {
    /* A WAL or already-free pages can account for the excess. Reclaim before
     * deleting candidates, and stop deleting once the live set fits. */
    (void)exec_sql("PRAGMA wal_checkpoint(TRUNCATE);");
    for (int pass = 0; pass < 4 && sqlite_live_size_over_limit() > 0; pass++) {
      if (exec_sql("DELETE FROM p0_candidates WHERE rowid IN (SELECT rowid FROM p0_candidates ORDER BY event_time_ns ASC LIMIT 1000);") == 0) {
        int changes = sqlite3_changes(s_db);
        if (changes > 0) s_status.db_capacity_evicted += (uint64_t)changes;
      }
      if (exec_sql("DELETE FROM artifacts WHERE rowid IN (SELECT rowid FROM artifacts ORDER BY created_ns ASC LIMIT 1000);") == 0) {
        int changes = sqlite3_changes(s_db);
        if (changes > 0) s_status.db_capacity_evicted += (uint64_t)changes;
      }
      if (exec_sql("DELETE FROM candidate_context_refs WHERE rowid IN ("
                   "SELECT rowid FROM candidate_context_refs "
                   "ORDER BY created_ns ASC LIMIT 1000);") == 0) {
        int changes = sqlite3_changes(s_db);
        if (changes > 0) s_status.db_capacity_evicted += (uint64_t)changes;
      }
      if (exec_sql("DELETE FROM context_facts WHERE NOT EXISTS ("
                   "SELECT 1 FROM candidate_context_refs "
                   "WHERE candidate_context_refs.fact_id=context_facts.fact_id);") == 0) {
        int changes = sqlite3_changes(s_db);
        if (changes > 0) s_status.db_capacity_evicted += (uint64_t)changes;
      }
    }
    (void)exec_sql("PRAGMA wal_checkpoint(TRUNCATE);");
    if (db_size_over_limit()) {
      (void)exec_sql("VACUUM;");
      /* In WAL mode VACUUM writes replacement pages into the WAL. */
      (void)exec_sql("PRAGMA wal_checkpoint(TRUNCATE);");
    }
  } else {
    (void)exec_sql("PRAGMA wal_checkpoint(PASSIVE);");
  }
  (void)exec_sql("PRAGMA shrink_memory;");
  (void)sqlite3_db_release_memory(s_db);
  (void)sqlite3_release_memory(0);
  refresh_db_size_status();
}
#endif

void edr_local_evidence_cache_record_command_result(
    const char *command_id, const char *command_type, const char *status,
    int execution_status, int exit_code, const char *detail, const char *artifacts) {
  evidence_cache_lock();
#if defined(EDR_HAVE_SQLITE)
  if (!s_db || !command_id || !command_id[0]) {
    evidence_cache_unlock();
    return;
  }
  const char *sql =
      "INSERT INTO command_results(command_id,command_type,status,execution_status,exit_code,"
      "detail,artifacts,updated_ns) VALUES(?,?,?,?,?,?,?,?) "
      "ON CONFLICT(command_id) DO UPDATE SET command_type=excluded.command_type,"
      "status=excluded.status,execution_status=excluded.execution_status,"
      "exit_code=excluded.exit_code,detail=excluded.detail,artifacts=excluded.artifacts,"
      "updated_ns=excluded.updated_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare command_results failed");
    evidence_cache_unlock();
    return;
  }
  bind_text(st, 1, command_id);
  bind_text(st, 2, command_type);
  bind_text(st, 3, status);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)execution_status);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)exit_code);
  bind_text(st, 6, detail);
  bind_text(st, 7, artifacts);
  sqlite3_bind_int64(st, 8, (sqlite3_int64)now_unix_ns());
  if (sqlite3_step(st) == SQLITE_DONE) {
    s_status.command_results_written++;
  } else {
    set_error("upsert command_results failed");
  }
  sqlite3_finalize(st);
  evidence_cache_unlock();
#else
  (void)command_id;
  (void)command_type;
  (void)status;
  (void)execution_status;
  (void)exit_code;
  (void)detail;
  (void)artifacts;
  evidence_cache_unlock();
#endif
}

static void evidence_cache_close_locked(void) {
#if defined(EDR_HAVE_SQLITE)
  if (s_db) {
    (void)exec_sql("PRAGMA wal_checkpoint(TRUNCATE);");
    sqlite3_close(s_db);
    s_db = NULL;
  }
#endif
  s_status.db_open = 0;
}

int edr_local_evidence_cache_open(const char *path, uint32_t max_db_mb,
                                  uint32_t retention_hours) {
  evidence_cache_lock();
  evidence_cache_close_locked();
  memset(&s_status, 0, sizeof(s_status));
  memset(s_proc, 0, sizeof(s_proc));
  memset(s_ring, 0, sizeof(s_ring));
  memset(s_context_ring, 0, sizeof(s_context_ring));
  memset(s_context_windows, 0, sizeof(s_context_windows));
  memset(s_metrics, 0, sizeof(s_metrics));
  memset(s_candidate_dedupe, 0, sizeof(s_candidate_dedupe));
  memset(s_ordinary_agg, 0, sizeof(s_ordinary_agg));
  s_ring_pos = 0;
  s_context_ring_pos = 0;
  s_context_window_next = 0;
  s_last_maintenance_ns = 0u;
  s_write_budget_minute = 0;
  s_write_budget_count = 0u;
  s_write_budget_ordinary_context_count = 0u;
  s_status.max_db_mb = max_db_mb ? max_db_mb : 128u;
  s_status.retention_hours = retention_hours ? retention_hours : 24u;
  copy_s(s_status.path, sizeof(s_status.path), (path && path[0]) ? path : "local_evidence_cache.db");

#if defined(EDR_HAVE_SQLITE)
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
  s_status.db_open = 1;
#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
  s_test_commit_failures = 0u;
  s_test_commit_active = 0;
  (void)sqlite3_commit_hook(s_db, evidence_cache_test_commit_hook, NULL);
#endif
  (void)exec_sql("PRAGMA journal_mode=WAL;");
  (void)exec_sql("PRAGMA synchronous=NORMAL;");
  (void)exec_sql("PRAGMA cache_size=-1024;");
  (void)exec_sql("PRAGMA mmap_size=0;");
  const char *schema =
      "CREATE TABLE IF NOT EXISTS process_cache ("
      "endpoint_id TEXT NOT NULL,tenant_id TEXT,pid INTEGER NOT NULL,ppid INTEGER,"
      "name TEXT,path TEXT,cmdline TEXT,parent_name TEXT,parent_path TEXT,"
      "first_seen_ns INTEGER,last_seen_ns INTEGER,process_start_key TEXT,"
      "process_creation_filetime_100ns TEXT,process_generation_source TEXT,"
      "parent_process_start_key TEXT,parent_process_creation_filetime_100ns TEXT,"
      "parent_process_generation_source TEXT,username TEXT,domain TEXT,user_sid TEXT,"
      "logon_id TEXT,identity_source TEXT,identity_quality TEXT,exe_hash TEXT,cmdline_truncated_fields TEXT,"
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
      "script_path TEXT,exe_hash TEXT,username TEXT,user_sid TEXT,identity_source TEXT,"
      "identity_quality TEXT);"
      "CREATE INDEX IF NOT EXISTS idx_p0_candidates_ep_time ON p0_candidates(endpoint_id,event_time_ns);"
      "CREATE INDEX IF NOT EXISTS idx_p0_candidates_pid_time ON p0_candidates(endpoint_id,pid,event_time_ns);"
      "CREATE TABLE IF NOT EXISTS artifacts ("
      "artifact_id TEXT PRIMARY KEY,endpoint_id TEXT,tenant_id TEXT,candidate_id TEXT,"
      "artifact_type TEXT,path TEXT,sha256 TEXT,manifest_json TEXT,created_ns INTEGER,"
      "upload_status TEXT,minio_key TEXT);"
      "CREATE INDEX IF NOT EXISTS idx_artifacts_ep_time ON artifacts(endpoint_id,created_ns);"
      "CREATE TABLE IF NOT EXISTS context_facts ("
      "fact_id TEXT PRIMARY KEY,endpoint_id TEXT,tenant_id TEXT,"
      "manifest_template_json TEXT NOT NULL,created_ns INTEGER,updated_ns INTEGER);"
      "CREATE INDEX IF NOT EXISTS idx_context_facts_ep_time "
      "ON context_facts(endpoint_id,updated_ns);"
      "CREATE TABLE IF NOT EXISTS candidate_context_refs ("
      "artifact_id TEXT PRIMARY KEY,candidate_id TEXT NOT NULL,fact_id TEXT NOT NULL,"
      "candidate_id_json TEXT NOT NULL,created_ns INTEGER,upload_status TEXT,minio_key TEXT,"
      "UNIQUE(candidate_id,fact_id));"
      "CREATE INDEX IF NOT EXISTS idx_candidate_context_refs_candidate "
      "ON candidate_context_refs(candidate_id,created_ns);"
      "CREATE INDEX IF NOT EXISTS idx_candidate_context_refs_fact "
      "ON candidate_context_refs(fact_id);"
      "CREATE VIEW IF NOT EXISTS materialized_artifacts AS "
      "SELECT artifact_id,endpoint_id,tenant_id,candidate_id,artifact_type,path,sha256,"
      "manifest_json,created_ns,upload_status,minio_key FROM artifacts a "
      "WHERE a.artifact_type<>'post_context' OR NOT EXISTS ("
      "SELECT 1 FROM candidate_context_refs r WHERE r.artifact_id=a.artifact_id) "
      "UNION ALL "
      "SELECT r.artifact_id,f.endpoint_id,f.tenant_id,r.candidate_id,'post_context','','',"
      "replace(f.manifest_template_json,'\"candidate_id\":null',"
      "'\"candidate_id\":'||r.candidate_id_json),"
      "CASE WHEN f.updated_ns>r.created_ns THEN f.updated_ns ELSE r.created_ns END,"
      "r.upload_status,r.minio_key FROM candidate_context_refs r "
      "JOIN context_facts f ON f.fact_id=r.fact_id;"
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
      "CREATE TABLE IF NOT EXISTS forensic_jobs ("
      "task_id TEXT PRIMARY KEY,status TEXT,evidence_refs TEXT,upload_refs TEXT,error TEXT,"
      "retryable INTEGER,updated_ns INTEGER);";
  if (exec_sql(schema) != 0) {
    evidence_cache_close_locked();
    evidence_cache_unlock();
    return -1;
  }
  if (sqlite_ensure_process_cache_generation_columns() != 0 ||
      sqlite_ensure_p0_candidate_columns() != 0 ||
      sqlite_migrate_legacy_context_artifacts() != 0) {
    evidence_cache_close_locked();
    evidence_cache_unlock();
    return -1;
  }
  sqlite_maintenance();
  evidence_cache_unlock();
  return 0;
#else
  (void)path;
  set_error("sqlite disabled");
  evidence_cache_unlock();
  return -1;
#endif
}

void edr_local_evidence_cache_close(void) {
  evidence_cache_lock();
  evidence_cache_close_locked();
  evidence_cache_unlock();
}

#if defined(EDR_HAVE_SQLITE) && defined(EDR_LOCAL_EVIDENCE_CACHE_TESTING)
void edr_local_evidence_cache_test_fail_next_commits(unsigned count) {
  evidence_cache_lock();
  s_test_commit_failures = count;
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

static int evidence_is_low_value_file_noise(const EdrBehaviorRecord *r) {
  if (!r || !is_file_event_type((uint32_t)r->type)) {
    return 0;
  }
  const char *path = r->file_path[0] ? r->file_path : r->exe_path;
  if (!path || !path[0]) {
    return 0;
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

static int evidence_text_has_high_signal(const EdrBehaviorRecord *r) {
  static const char *const tokens[] = {
      "encodedcommand", "-enc", "frombase64string", "invoke-expression", "iex ",
      "downloadstring", "downloadfile", "sekurlsa", "mimikatz", "ntdsutil",
      "vssadmin delete", "wbadmin delete", "bcdedit /set", "wevtutil cl",
      "sc create", "binpath=", "psexec", "admin$", "wmic process call create",
      "regsvr32", "mshta", "certutil -urlcache", "bitsadmin /transfer",
      "add-mppreference", "set-mppreference", "disableantispyware",
      "ransom_counter=1", "webshell_candidate", "shellcode", "pmfe",
  };
  if (!r) {
    return 0;
  }
  for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
    if (evidence_contains_ci(r->cmdline, tokens[i]) ||
        evidence_contains_ci(r->script_snippet, tokens[i]) ||
        evidence_contains_ci(r->detection_context, tokens[i])) {
      return 1;
    }
  }
  return 0;
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
  return evidence_contains_ci(r->detection_context, "\"severity\":\"P0\"") ||
         evidence_contains_ci(r->detection_context, "\"severity\":\"P1\"") ||
         evidence_contains_ci(r->detection_context, "\"priority\":\"P0\"") ||
         evidence_contains_ci(r->detection_context, "\"priority\":\"P1\"") ||
         evidence_contains_ci(r->detection_context, "\"confidence\":0.8") ||
         evidence_contains_ci(r->detection_context, "\"confidence\":0.9") ||
         evidence_contains_ci(r->detection_context, "\"confidence\":1");
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

static void mark_one_context_window(uint32_t pid,
                                    const EvidenceProcessGeneration *generation,
                                    const char *endpoint_id,
                                    const char *tenant_id,
                                    const char *candidate_id, int64_t from_ns,
                                    int64_t until_ns) {
  if (pid == 0u || !generation_bound(generation) || !candidate_id || !candidate_id[0]) {
    return;
  }
  for (size_t i = 0; i < EDR_EVIDENCE_CONTEXT_WINDOWS; i++) {
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
  ContextWindowSlot *w = &s_context_windows[s_context_window_next++ % EDR_EVIDENCE_CONTEXT_WINDOWS];
  if (w->pid != 0u) {
    s_status.context_window_evictions++;
  }
  memset(w, 0, sizeof(*w));
  w->pid = pid;
  w->from_ns = from_ns;
  w->until_ns = until_ns;
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
 * generation; when it evicts a live entry the existing health eviction counter
 * makes that bounded completeness loss visible instead of silently replacing a
 * prior candidate for the same PID. */
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
    record_metric_drop(r, ts);
    s_status.records_skipped++;
    goto done;
  }
  if (!store_candidate && !store_context && evidence_cache_pressure_active()) {
    record_metric_drop(r, ts);
    s_status.pressure_dropped++;
    s_status.records_skipped++;
    goto done;
  }
  if (!store_candidate && !store_context && ordinary_aggregate_should_coalesce(r, ts)) {
    record_metric_drop(r, ts);
    s_status.records_skipped++;
    goto done;
  }
  if (!store_candidate && !store_context) {
    context_ring_capture(r);
    s_status.hot_ring_ingested++;
    record_metric_drop(r, ts);
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
      s_status.candidate_rejected++;
      s_status.records_dropped++;
      context_ring_capture(r);
      s_status.hot_ring_ingested++;
      goto done;
    }
    if (!candidate_existing && r->event_id[0]) {
      int exists = sqlite_candidate_exists(candidate_id);
      if (exists < 0) {
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
      /* P0/P1 candidates are deliberately outside the telemetry-rate budget.
       * Durable size/retention and transaction outcomes remain authoritative
       * resource and failure bounds. */
      if (!sqlite_size_budget_allow()) {
        s_status.candidate_rejected++;
        s_status.records_dropped++;
        context_ring_capture(r);
        s_status.hot_ring_ingested++;
        goto done;
      }
    }
    if (sqlite_record_candidate(r, candidate_id, pre_count, post_until_ns) != 0) {
      s_status.candidate_rejected++;
      s_status.candidate_transaction_failures++;
      s_status.records_dropped++;
      context_ring_capture(r);
      s_status.hot_ring_ingested++;
      goto done;
    }
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
        s_status.records_dropped++;
      } else {
        s_status.artifacts_written += context_artifacts_written;
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
      s_status.records_dropped++;
      goto done;
    }
    s_status.artifacts_written += context_artifacts_written;
  } else if (store_context) {
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
    s_status.candidate_rejected++;
    s_status.records_dropped++;
    context_ring_capture(r);
    s_status.hot_ring_ingested++;
  } else if (store_context) {
    context_ring_capture(r);
    s_status.hot_ring_ingested++;
    ring_record(r);
  }
#endif
done:
  evidence_cache_unlock();
}

void edr_local_evidence_cache_poll_maintenance(void) {
  uint64_t now = edr_monotonic_ns();
  evidence_cache_lock();
  if (now - s_last_maintenance_ns < 60000000000ULL) {
    evidence_cache_unlock();
    return;
  }
  s_last_maintenance_ns = now;
#if defined(EDR_HAVE_SQLITE)
  sqlite_maintenance();
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
  st.pressure_active = evidence_cache_pressure_active() ? 1u : 0u;
#if defined(EDR_HAVE_SQLITE)
  refresh_db_size_status();
  st.db_bytes = s_status.db_bytes;
  st.wal_bytes = s_status.wal_bytes;
  st.db_utilization_bps = utilization_bps(st.db_bytes + st.wal_bytes,
                                          (uint64_t)st.max_db_mb * 1024ULL * 1024ULL);
  refresh_candidate_inventory_status(&st);
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
  char endpoint_id[48];
  char process_name_contains[128];
  char cmdline_contains[256];
  char file_path_contains[256];
  char file_sha256[65];
  char file_ext[32];
  char remote_ip[64];
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

static int json_get_u32(const char *json, const char *key, uint32_t *out) {
  if (!json || !key || !out) {
    return -1;
  }
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
  while (*++colon && (isspace((unsigned char)*colon) || *colon == '"')) {
  }
  char *end = NULL;
  unsigned long v = strtoul(colon, &end, 10);
  if (end == colon || v > 0xffffffffUL) {
    return -1;
  }
  *out = (uint32_t)v;
  return 0;
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

static void parse_rtq_filter(const char *json, RtqFilter *f) {
  memset(f, 0, sizeof(*f));
  f->limit = 50u;
  f->time_window_s = 600u;
  if (!json) {
    return;
  }
  (void)json_get_string(json, "endpoint_id", f->endpoint_id, sizeof(f->endpoint_id));
  (void)json_get_string(json, "process_name_contains", f->process_name_contains,
                        sizeof(f->process_name_contains));
  (void)json_get_string(json, "cmdline_contains", f->cmdline_contains, sizeof(f->cmdline_contains));
  (void)json_get_string(json, "file_path_contains", f->file_path_contains,
                        sizeof(f->file_path_contains));
  if (f->file_path_contains[0] == '\0') {
    (void)json_get_string(json, "file_path", f->file_path_contains,
                          sizeof(f->file_path_contains));
  }
  if (json_get_string(json, "file_sha256", f->file_sha256, sizeof(f->file_sha256)) != 0) {
    (void)json_get_string(json, "sha256", f->file_sha256, sizeof(f->file_sha256));
  }
  (void)json_get_string(json, "file_ext", f->file_ext, sizeof(f->file_ext));
  (void)json_get_string(json, "remote_ip", f->remote_ip, sizeof(f->remote_ip));
  (void)json_get_string(json, "registry_key_contains", f->registry_key_contains,
                        sizeof(f->registry_key_contains));
  (void)json_get_u32(json, "pid", &f->pid);
  if (json_get_u64(json, "process_start_key", &f->process_start_key) == 0) {
    f->has_process_start_key = f->process_start_key != 0u;
  }
  if (json_get_u64(json, "process_creation_filetime_100ns",
                   &f->process_creation_filetime_100ns) == 0) {
    f->has_process_creation_filetime_100ns =
        f->process_creation_filetime_100ns != 0u;
  }
  (void)json_get_u32(json, "limit", &f->limit);
  (void)json_get_u32(json, "time_window_s", &f->time_window_s);
  if (f->limit == 0u || f->limit > 500u) {
    f->limit = 50u;
  }
  if (f->time_window_s == 0u || f->time_window_s > 86400u) {
    f->time_window_s = 600u;
  }
  char et[64];
  if (json_get_string(json, "event_type", et, sizeof(et)) != 0) {
    (void)json_get_string(json, "type", et, sizeof(et));
  }
  if (et[0]) {
    int ok = 0;
    uint32_t ty = event_type_from_name(et, &ok);
    if (ok) {
      f->has_type = 1;
      f->type = ty;
    }
  }
}

static int rtq_match_common(const RtqFilter *f, uint32_t type, uint32_t pid,
                            int64_t event_time_ns, const char *endpoint_id,
                            const char *process_name, const char *cmdline,
                            const char *file_path, const char *remote_ip,
                            const char *registry_key, uint64_t process_start_key,
                            uint64_t process_creation_filetime_100ns) {
  int64_t cutoff = now_unix_ns() - (int64_t)f->time_window_s * 1000000000LL;
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

int edr_local_evidence_cache_query_json(const char *payload_json, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return -1;
  }
  RtqFilter f;
  parse_rtq_filter(payload_json, &f);
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
                            r->process_name, "", r->file_path, r->net_dst, "",
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
        if (!rtq_match_common(&f, ty, pid, ts, ep, pn, cl, fp, rip, rk,
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
  cJSON *command = cJSON_CreateString(p ? p->cmdline : "");
  char *cmd = command ? cJSON_PrintUnformatted(command) : NULL;
  cJSON_Delete(command);
  if (!cmd) return 0;
  const char *quality = !p || !p->cmdline[0] ? "missing" :
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
  json_escape(command_fields, sizeof(command_fields), command_quality_known(p) ? p->cmdline_truncated_fields : "");
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
                          "\"pid\":%u,\"ppid\":%u,\"name\":%s,\"path\":%s,\"cmdline\":%s,"
                          "\"cmdline_quality\":\"%s\",\"cmdline_truncated_fields\":%s,"
                          "\"parent_name\":%s,\"parent_path\":%s,\"process_start_key\":\"%s\","
                          "\"process_creation_filetime_100ns\":\"%s\",\"process_generation_source\":%s,"
                          "\"parent_process_start_key\":\"%s\",\"parent_process_creation_filetime_100ns\":\"%s\","
                          "\"parent_process_generation_source\":%s,\"username\":%s,\"domain\":%s,"
                          "\"user_sid\":%s,\"logon_id\":%s,\"identity_source\":%s,"
                          "\"identity_quality\":%s,\"exe_hash\":%s,\"last_seen_ns\":%lld}",
          *first ? "" : ",", source ? source : "", ep, tn, p ? p->pid : 0u,
          p ? p->ppid : 0u, nm, path, cmd, quality, command_fields, pn, pp, generation_start, generation_creation,
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
          "username,domain,user_sid,logon_id,identity_source,identity_quality,exe_hash,cmdline_truncated_fields "
          "FROM process_cache WHERE endpoint_id=? AND pid=? AND process_start_key=? "
          "AND process_creation_filetime_100ns=? LIMIT 1;"
        : "SELECT endpoint_id,tenant_id,pid,ppid,name,path,cmdline,parent_name,parent_path,last_seen_ns,"
          "process_start_key,process_creation_filetime_100ns,process_generation_source,"
          "parent_process_start_key,parent_process_creation_filetime_100ns,parent_process_generation_source,"
          "username,domain,user_sid,logon_id,identity_source,identity_quality,exe_hash,cmdline_truncated_fields "
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
    if (!root || !generation_bound(&root->generation) || p->pid == 0u || p->ppid != pid ||
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
        "username,domain,user_sid,logon_id,identity_source,identity_quality,exe_hash,cmdline_truncated_fields "
        "FROM process_cache WHERE endpoint_id=? AND ppid=? AND parent_process_start_key=? "
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
  json_escape(path, sizeof(path), st.path);
  json_escape(err, sizeof(err), st.last_error);
  json_escape(eng, sizeof(eng), st.last_engine);
  if (context_ref_write_sources_json_from_status(
          &st, context_ref_sources, sizeof(context_ref_sources)) != 0) {
    snprintf(context_ref_sources, sizeof(context_ref_sources), "{}");
  }
  int written = snprintf(out, cap,
           "\"evidence_cache\":{\"db_open\":%s,\"path\":%s,\"max_db_mb\":%u,"
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
           "\"evictions\":{\"ring\":%llu,\"hot_ring\":%llu,\"context_windows\":%llu,\"metrics\":%llu,\"candidate_dedup\":%llu,\"aggregate\":%llu,\"db_retention_rows\":%llu,\"db_capacity_rows\":%llu},"
           "\"oldest\":{\"process_last_seen_ns\":%lld,\"ring_event_time_ns\":%lld,\"hot_ring_event_time_ns\":%lld,\"candidate_dedup_ns\":%lld,\"p0_candidate_event_time_ns\":%lld},"
           "\"maintenance_runs\":%llu,\"process_slots_used\":%u,\"ring_events\":%u,"
           "\"last_engine\":%s,\"last_event_time_ns\":%lld,\"last_error\":%s,"
           "\"partitions\":{\"hot_ring\":{\"events\":%u},"
           "\"p0_candidates\":{\"written\":%llu,\"rows\":%llu},"
           "\"artifacts\":{\"written\":%llu,\"context_facts_written\":%llu,"
           "\"context_refs_written\":%llu,\"context_ref_write_sources\":%s},"
           "\"command_results\":{\"written\":%llu},\"metrics\":{\"minutes\":%u}},"
           "\"coalesced\":{\"file\":%llu,\"registry\":%llu,\"network\":%llu},"
           "\"drop_counters\":{\"file\":%llu,\"registry\":%llu,\"network\":%llu,\"other\":%llu}}",
           st.db_open ? "true" : "false", path, st.max_db_mb, st.retention_hours,
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
           (unsigned long long)st.metric_slot_evictions,
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
           (unsigned long long)st.command_results_written, st.metrics_minutes,
           (unsigned long long)st.file_coalesced,
           (unsigned long long)st.registry_coalesced,
           (unsigned long long)st.network_coalesced,
           (unsigned long long)st.metric_file_drops,
           (unsigned long long)st.metric_registry_drops,
           (unsigned long long)st.metric_network_drops,
           (unsigned long long)st.metric_other_drops);
  if (written < 0 || (size_t)written >= cap) {
    /* This function supplies a JSON member, not a complete document.  Keep
     * that member syntactically valid for older callers with a small buffer
     * instead of handing the enclosing health document a cut-off fragment. */
    (void)snprintf(out, cap, "\"evidence_cache\":{\"db_open\":%s,\"status\":\"truncated\"}",
                   st.db_open ? "true" : "false");
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
