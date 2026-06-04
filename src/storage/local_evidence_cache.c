#include "edr/local_evidence_cache.h"

#include "edr/p0_rule_ir.h"
#include "edr/resource.h"
#include "edr/time_util.h"
#include "edr/windows_event_policy.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(EDR_HAVE_SQLITE)
#include <sqlite3.h>
#include <sys/stat.h>
#endif

#define EDR_EVIDENCE_PROC_SLOTS 1024u
#define EDR_EVIDENCE_RING_SLOTS 2048u
#define EDR_EVIDENCE_CONTEXT_RING_SLOTS 512u
#define EDR_EVIDENCE_CONTEXT_WINDOWS 256u
#define EDR_EVIDENCE_METRIC_SLOTS 180u
#define EDR_EVIDENCE_CANDIDATE_DEDUP_SLOTS 512u
#define EDR_EVIDENCE_AGG_SLOTS 512u

typedef struct {
  uint32_t pid;
  uint32_t ppid;
  int64_t last_seen_ns;
  char endpoint_id[48];
  char tenant_id[64];
  char name[256];
  char path[1024];
  char cmdline[1024];
  char parent_name[256];
  char parent_path[512];
  char parent_cmdline[1024];
  char username[256];
  char domain[256];
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
  char endpoint_id[48];
  char process_name[128];
  char file_path[256];
  char net_dst[64];
  uint32_t net_dport;
} RingSlot;

typedef struct {
  uint32_t pid;
  int64_t until_ns;
  char endpoint_id[48];
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
  char signal[160];
} CandidateDedupeSlot;

typedef struct {
  uint8_t used;
  int64_t minute_unix;
  uint32_t pid;
  uint32_t kind;
  char endpoint_id[48];
  char prefix[160];
  uint64_t count;
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

#if defined(EDR_HAVE_SQLITE)
static sqlite3 *s_db;
#endif

static void json_escape(char *dst, size_t cap, const char *s);
static void appendf(char *out, size_t cap, size_t *off, const char *fmt, ...);
static uint32_t evidence_context_window_s(void);
static int ring_related_to_record(const RingSlot *s, const EdrBehaviorRecord *r);

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

static void copy_s(char *dst, size_t cap, const char *src) {
  if (!dst || cap == 0u) {
    return;
  }
  snprintf(dst, cap, "%s", src ? src : "");
}

static int64_t now_unix_ns(void) {
  time_t t = time(NULL);
  return (int64_t)t * 1000000000LL;
}

static int64_t record_time_ns(const EdrBehaviorRecord *r) {
  if (r && r->event_time_ns > 0) {
    return r->event_time_ns;
  }
  return now_unix_ns();
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
  memset(p, 0, sizeof(*p));
  p->pid = pid;
  return p;
}

static int should_update_process_cache(const EdrBehaviorRecord *r) {
  if (!r || r->pid == 0u) {
    return 0;
  }
  return r->process_name[0] || r->exe_path[0] || r->cmdline[0] || r->ppid != 0u ||
         r->parent_name[0] || r->parent_path[0] || r->parent_cmdline[0] ||
         r->username[0] || r->domain[0] || r->integrity_level[0] ||
         r->token_elevation != 0u || r->exe_hash[0] || r->current_directory[0] ||
         r->process_creation_time[0];
}

static void process_cache_update(const EdrBehaviorRecord *r) {
  if (!should_update_process_cache(r)) {
    return;
  }
  ProcSlot *p = alloc_proc(r->pid, r);
  if (!p) {
    return;
  }
  p->pid = r->pid;
  if (r->ppid != 0u) {
    p->ppid = r->ppid;
  }
  p->last_seen_ns = record_time_ns(r);
  if (r->endpoint_id[0]) {
    copy_s(p->endpoint_id, sizeof(p->endpoint_id), r->endpoint_id);
  }
  if (r->tenant_id[0]) {
    copy_s(p->tenant_id, sizeof(p->tenant_id), r->tenant_id);
  }
  if (r->process_name[0]) {
    copy_s(p->name, sizeof(p->name), r->process_name);
  } else if (r->exe_path[0] && !p->name[0]) {
    copy_s(p->name, sizeof(p->name), base_name(r->exe_path));
  }
  if (r->exe_path[0]) {
    copy_s(p->path, sizeof(p->path), r->exe_path);
  }
  if (r->cmdline[0]) {
    copy_s(p->cmdline, sizeof(p->cmdline), r->cmdline);
  }
  if (r->parent_name[0]) {
    copy_s(p->parent_name, sizeof(p->parent_name), r->parent_name);
  }
  if (r->parent_path[0]) {
    copy_s(p->parent_path, sizeof(p->parent_path), r->parent_path);
  }
  if (r->parent_cmdline[0]) {
    copy_s(p->parent_cmdline, sizeof(p->parent_cmdline), r->parent_cmdline);
  }
  if (r->username[0]) {
    copy_s(p->username, sizeof(p->username), r->username);
  }
  if (r->domain[0]) {
    copy_s(p->domain, sizeof(p->domain), r->domain);
  }
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
}

void edr_local_evidence_cache_enrich_behavior(EdrBehaviorRecord *r) {
  if (!r) {
    return;
  }
  ProcSlot *p = find_proc(r->pid, r->endpoint_id);
  if (p) {
    if (r->ppid == 0u && p->ppid != 0u) {
      r->ppid = p->ppid;
    }
    if (!r->process_name[0] && p->name[0]) {
      copy_s(r->process_name, sizeof(r->process_name), p->name);
    }
    if (!r->exe_path[0] && p->path[0]) {
      copy_s(r->exe_path, sizeof(r->exe_path), p->path);
    }
    if (!r->cmdline[0] && p->cmdline[0]) {
      copy_s(r->cmdline, sizeof(r->cmdline), p->cmdline);
    }
    if (!r->parent_name[0] && p->parent_name[0]) {
      copy_s(r->parent_name, sizeof(r->parent_name), p->parent_name);
    }
    if (!r->parent_path[0] && p->parent_path[0]) {
      copy_s(r->parent_path, sizeof(r->parent_path), p->parent_path);
    }
    if (!r->parent_cmdline[0] && p->parent_cmdline[0]) {
      copy_s(r->parent_cmdline, sizeof(r->parent_cmdline), p->parent_cmdline);
    }
    if (!r->username[0] && p->username[0]) {
      copy_s(r->username, sizeof(r->username), p->username);
    }
    if (!r->domain[0] && p->domain[0]) {
      copy_s(r->domain, sizeof(r->domain), p->domain);
    }
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
  if (!r->parent_name[0] && r->ppid != 0u) {
    ProcSlot *pp = find_proc(r->ppid, r->endpoint_id);
    if (pp) {
      if (pp->name[0]) {
        copy_s(r->parent_name, sizeof(r->parent_name), pp->name);
      }
      if (pp->path[0]) {
        copy_s(r->parent_path, sizeof(r->parent_path), pp->path);
      }
    }
  }
  if (!r->process_name[0] && r->exe_path[0]) {
    copy_s(r->process_name, sizeof(r->process_name), base_name(r->exe_path));
  }
}

static void ring_record_to(RingSlot *ring, uint32_t slots, uint32_t *pos,
                           const EdrBehaviorRecord *r) {
  if (!ring || slots == 0u || !pos || !r) {
    return;
  }
  RingSlot *s = &ring[(*pos)++ % slots];
  memset(s, 0, sizeof(*s));
  s->used = 1u;
  s->event_time_ns = record_time_ns(r);
  s->type = (uint32_t)r->type;
  s->pid = r->pid;
  s->ppid = r->ppid;
  s->net_dport = r->net_dport;
  copy_s(s->endpoint_id, sizeof(s->endpoint_id), r->endpoint_id);
  copy_s(s->process_name, sizeof(s->process_name), r->process_name);
  copy_s(s->file_path, sizeof(s->file_path), r->file_path);
  copy_s(s->net_dst, sizeof(s->net_dst), r->net_dst);
}

static void ring_copy_to(RingSlot *ring, uint32_t slots, uint32_t *pos,
                         const RingSlot *src) {
  if (!ring || slots == 0u || !pos || !src || !src->used) {
    return;
  }
  RingSlot *dst = &ring[(*pos)++ % slots];
  *dst = *src;
}

static void ring_record(const EdrBehaviorRecord *r) {
  ring_record_to(s_ring, EDR_EVIDENCE_RING_SLOTS, &s_ring_pos, r);
}

static void context_ring_capture(const EdrBehaviorRecord *r) {
  ring_record_to(s_context_ring, EDR_EVIDENCE_CONTEXT_RING_SLOTS, &s_context_ring_pos, r);
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
static uint32_t env_u32_clamped(const char *name, uint32_t fallback, uint32_t min_v,
                                uint32_t max_v);

static uint32_t candidate_dedupe_window_s(void) {
  return env_u32_clamped("EDR_EVIDENCE_CACHE_CANDIDATE_DEDUP_WINDOW_S",
                         60u, 1u, 600u);
}

static uint64_t evidence_hash_ci(const char *s) {
  uint64_t h = 1469598103934665603ULL;
  if (!s) {
    return h;
  }
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '/' || c == '\\') {
      c = '\\';
    } else {
      c = (unsigned char)tolower(c);
    }
    h ^= (uint64_t)c;
    h *= 1099511628211ULL;
  }
  return h;
}

static void candidate_id_for(const EdrBehaviorRecord *r, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  char signal[160];
  candidate_signal_for(r, signal, sizeof(signal));
  uint32_t win_s = candidate_dedupe_window_s();
  int64_t bucket = record_time_ns(r) / ((int64_t)win_s * 1000000000LL);
  unsigned long long sig_hash = (unsigned long long)evidence_hash_ci(signal);
  snprintf(out, cap, "p0-%s-%lld-%u-%u-%016llx",
           (r && r->endpoint_id[0]) ? r->endpoint_id : "unknown",
           (long long)bucket, r ? r->pid : 0u, r ? (uint32_t)r->type : 0u,
           sig_hash);
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
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!r) {
    return;
  }
  if (extract_json_string_field(r->detection_context, "\"rule_id\":\"", out, cap) ||
      extract_json_string_field(r->detection_context, "\"rid\":\"", out, cap) ||
      extract_json_string_field(r->detection_context, "\"rule\":\"", out, cap)) {
    return;
  }
  const char *target = r->cmdline[0] ? r->cmdline :
                       r->script_snippet[0] ? r->script_snippet :
                       r->file_path[0] ? r->file_path :
                       r->reg_key_path[0] ? r->reg_key_path :
                       r->net_dst[0] ? r->net_dst :
                       r->exe_path[0] ? r->exe_path : r->process_name;
  unsigned long long target_hash = (unsigned long long)evidence_hash_ci(target);
  snprintf(out, cap, "type=%u;proc=%s;target_hash=%016llx;port=%u",
           (uint32_t)r->type, r->process_name, target_hash, r->net_dport);
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

static void ordinary_aggregate_prefix(const EdrBehaviorRecord *r, uint32_t kind,
                                      char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!r) {
    return;
  }
  if (kind == 1u) {
    path_parent_prefix(out, cap, r->file_path[0] ? r->file_path : r->exe_path);
  } else if (kind == 2u) {
    normalize_prefix_copy(out, cap, r->reg_key_path);
  } else if (kind == 3u) {
    char tmp[220];
    snprintf(tmp, sizeof(tmp), "%s:%u:%s", r->net_dst, r->net_dport, r->dns_query);
    normalize_prefix_copy(out, cap, tmp);
  }
  if (!out[0]) {
    snprintf(out, cap, "kind=%u;type=%u", kind, (uint32_t)r->type);
  }
}

static int ordinary_aggregate_should_coalesce(const EdrBehaviorRecord *r, int64_t ts) {
  uint32_t kind = 0u;
  if (!ordinary_aggregate_kind(r, &kind)) {
    return 0;
  }
  char prefix[160];
  ordinary_aggregate_prefix(r, kind, prefix, sizeof(prefix));
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
  memset(slot, 0, sizeof(*slot));
  slot->used = 1u;
  slot->minute_unix = minute;
  slot->pid = r ? r->pid : 0u;
  slot->kind = kind;
  slot->count = 1u;
  copy_s(slot->endpoint_id, sizeof(slot->endpoint_id), r ? r->endpoint_id : "");
  copy_s(slot->prefix, sizeof(slot->prefix), prefix);
  return 0;
}

static int evidence_cache_pressure_active(void) {
  return edr_resource_preprocess_throttle_active() ? 1 : 0;
}

static int candidate_dedupe_should_skip(const EdrBehaviorRecord *r, int64_t ts) {
  if (!r) {
    return 0;
  }
  uint32_t win_s = candidate_dedupe_window_s();
  if (win_s == 0u) {
    return 0;
  }
  char signal[160];
  candidate_signal_for(r, signal, sizeof(signal));
  int64_t cutoff = ts - (int64_t)win_s * 1000000000LL;
  size_t replace_i = 0;
  int64_t oldest = INT64_MAX;
  for (size_t i = 0; i < EDR_EVIDENCE_CANDIDATE_DEDUP_SLOTS; i++) {
    CandidateDedupeSlot *s = &s_candidate_dedupe[i];
    if (!s->used) {
      replace_i = i;
      oldest = INT64_MIN;
      break;
    }
    if (s->last_ns < oldest) {
      oldest = s->last_ns;
      replace_i = i;
    }
    if (s->last_ns >= cutoff && s->pid == r->pid && s->type == (uint32_t)r->type &&
        strncmp(s->endpoint_id, r->endpoint_id, sizeof(s->endpoint_id)) == 0 &&
        strncmp(s->signal, signal, sizeof(s->signal)) == 0) {
      s->last_ns = ts;
      s_status.candidate_deduped++;
      return 1;
    }
  }
  CandidateDedupeSlot *slot = &s_candidate_dedupe[replace_i];
  memset(slot, 0, sizeof(*slot));
  slot->used = 1u;
  slot->last_ns = ts;
  slot->pid = r->pid;
  slot->type = (uint32_t)r->type;
  copy_s(slot->endpoint_id, sizeof(slot->endpoint_id), r->endpoint_id);
  copy_s(slot->signal, sizeof(slot->signal), signal);
  return 0;
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

static int sqlite_write_budget_allow(uint32_t units, int64_t ts) {
  uint32_t limit = env_u32_clamped("EDR_EVIDENCE_CACHE_WRITE_BUDGET_PER_MIN",
                                   600u, 0u, 100000u);
  if (limit == 0u) {
    return 1;
  }
  if (units == 0u) {
    units = 1u;
  }
  int64_t minute = (ts / 1000000000LL) / 60LL;
  if (minute != s_write_budget_minute) {
    s_write_budget_minute = minute;
    s_write_budget_count = 0u;
  }
  if (s_write_budget_count >= limit || units > limit - s_write_budget_count) {
    s_status.write_budget_dropped++;
    set_error("evidence cache write budget exceeded");
    return 0;
  }
  s_write_budget_count += units;
  return 1;
}

static void bind_text(sqlite3_stmt *st, int idx, const char *s) {
  sqlite3_bind_text(st, idx, s ? s : "", -1, SQLITE_TRANSIENT);
}

static void upsert_process_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r || r->pid == 0u) {
    return;
  }
  const char *sql =
      "INSERT INTO process_cache(endpoint_id,tenant_id,pid,ppid,name,path,cmdline,parent_name,parent_path,"
      "first_seen_ns,last_seen_ns) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,pid) DO UPDATE SET "
      "tenant_id=excluded.tenant_id,ppid=CASE WHEN excluded.ppid<>0 THEN excluded.ppid ELSE process_cache.ppid END,"
      "name=CASE WHEN excluded.name<>'' THEN excluded.name ELSE process_cache.name END,"
      "path=CASE WHEN excluded.path<>'' THEN excluded.path ELSE process_cache.path END,"
      "cmdline=CASE WHEN excluded.cmdline<>'' THEN excluded.cmdline ELSE process_cache.cmdline END,"
      "parent_name=CASE WHEN excluded.parent_name<>'' THEN excluded.parent_name ELSE process_cache.parent_name END,"
      "parent_path=CASE WHEN excluded.parent_path<>'' THEN excluded.parent_path ELSE process_cache.parent_path END,"
      "last_seen_ns=excluded.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare process_cache failed");
    return;
  }
  int64_t ts = record_time_ns(r);
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->tenant_id);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)r->ppid);
  bind_text(st, 5, r->process_name);
  bind_text(st, 6, r->exe_path);
  bind_text(st, 7, r->cmdline);
  bind_text(st, 8, r->parent_name);
  bind_text(st, 9, r->parent_path);
  sqlite3_bind_int64(st, 10, (sqlite3_int64)ts);
  sqlite3_bind_int64(st, 11, (sqlite3_int64)ts);
  if (sqlite3_step(st) != SQLITE_DONE) {
    set_error("upsert process_cache failed");
  }
  sqlite3_finalize(st);
}

static void upsert_file_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r || (!r->file_path[0] && !r->exe_path[0])) {
    return;
  }
  const char *sql =
      "INSERT INTO file_evidence(endpoint_id,path,sha256,pid,last_seen_ns) VALUES(?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,path) DO UPDATE SET sha256=excluded.sha256,pid=excluded.pid,"
      "last_seen_ns=excluded.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->file_path[0] ? r->file_path : r->exe_path);
  bind_text(st, 3, r->exe_hash);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)record_time_ns(r));
  (void)sqlite3_step(st);
  sqlite3_finalize(st);
}

static void upsert_network_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r || (!r->net_dst[0] && !r->dns_query[0])) {
    return;
  }
  const char *sql =
      "INSERT INTO network_ioc(endpoint_id,remote_ip,remote_url,dst_port,pid,last_seen_ns) "
      "VALUES(?,?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,remote_ip,remote_url,dst_port,pid) DO UPDATE SET "
      "last_seen_ns=excluded.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->net_dst);
  bind_text(st, 3, r->dns_query);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)r->net_dport);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 6, (sqlite3_int64)record_time_ns(r));
  (void)sqlite3_step(st);
  sqlite3_finalize(st);
}

static void upsert_registry_sqlite(const EdrBehaviorRecord *r) {
  if (!s_db || !r || !r->reg_key_path[0]) {
    return;
  }
  const char *sql =
      "INSERT INTO registry_evidence(endpoint_id,key_path,value_name,op,pid,last_seen_ns) "
      "VALUES(?,?,?,?,?,?) "
      "ON CONFLICT(endpoint_id,key_path,value_name,op,pid) DO UPDATE SET last_seen_ns=excluded.last_seen_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, r->endpoint_id);
  bind_text(st, 2, r->reg_key_path);
  bind_text(st, 3, r->reg_value_name);
  bind_text(st, 4, r->reg_op);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)r->pid);
  sqlite3_bind_int64(st, 6, (sqlite3_int64)record_time_ns(r));
  (void)sqlite3_step(st);
  sqlite3_finalize(st);
}

static void build_context_manifest_json(const EdrBehaviorRecord *r, const char *candidate_id,
                                        uint32_t pre_count, int64_t post_until_ns,
                                        char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  size_t off = 0;
  char cid[160], ep[140], pn[320], fp[1200], nd[120];
  json_escape(cid, sizeof(cid), candidate_id);
  json_escape(ep, sizeof(ep), r ? r->endpoint_id : "");
  json_escape(pn, sizeof(pn), r ? r->process_name : "");
  json_escape(fp, sizeof(fp), r ? (r->file_path[0] ? r->file_path : r->exe_path) : "");
  json_escape(nd, sizeof(nd), r ? r->net_dst : "");
  appendf(out, cap, &off,
          "{\"schema\":\"p0_context_bundle.v1\",\"candidate_id\":%s,"
          "\"endpoint_id\":%s,\"event_time_ns\":%lld,\"pid\":%u,\"type\":%u,"
          "\"process_name\":%s,\"path\":%s,\"remote_ip\":%s,\"remote_port\":%u,"
          "\"pre_window_s\":%u,\"post_window_s\":%u,\"pre_context_count\":%u,"
          "\"post_until_ns\":%lld,\"context\":[",
          cid, ep, (long long)record_time_ns(r), r ? r->pid : 0u,
          r ? (uint32_t)r->type : 0u, pn, fp, nd, r ? r->net_dport : 0u,
          evidence_context_window_s(), evidence_context_window_s(), pre_count,
          (long long)post_until_ns);
  int first = 1;
  int64_t cutoff = record_time_ns(r) - (int64_t)evidence_context_window_s() * 1000000000LL;
  uint32_t pos = s_context_ring_pos;
  uint32_t added = 0;
  for (uint32_t i = 0; i < EDR_EVIDENCE_CONTEXT_RING_SLOTS && added < 32u; i++) {
    const RingSlot *s = &s_context_ring[(pos + EDR_EVIDENCE_CONTEXT_RING_SLOTS - 1u - i) %
                                        EDR_EVIDENCE_CONTEXT_RING_SLOTS];
    if (!s->used) {
      continue;
    }
    if (s->event_time_ns < cutoff) {
      break;
    }
    if (!ring_related_to_record(s, r)) {
      continue;
    }
    char spn[320], sfp[640], snd[120], sep[140];
    json_escape(sep, sizeof(sep), s->endpoint_id);
    json_escape(spn, sizeof(spn), s->process_name);
    json_escape(sfp, sizeof(sfp), s->file_path);
    json_escape(snd, sizeof(snd), s->net_dst);
    appendf(out, cap, &off,
            "%s{\"event_time_ns\":%lld,\"type\":%u,\"pid\":%u,\"ppid\":%u,"
            "\"endpoint_id\":%s,\"process_name\":%s,\"file_path\":%s,"
            "\"remote_ip\":%s,\"remote_port\":%u}",
            first ? "" : ",", (long long)s->event_time_ns, s->type, s->pid, s->ppid,
            sep, spn, sfp, snd, s->net_dport);
    first = 0;
    added++;
  }
  appendf(out, cap, &off, "]}");
  out[cap - 1u] = '\0';
}

static void insert_artifact_sqlite(const EdrBehaviorRecord *r, const char *candidate_id,
                                   const char *artifact_type, const char *path,
                                   const char *sha256, const char *manifest_json,
                                   const char *upload_status) {
  if (!s_db || !candidate_id || !candidate_id[0]) {
    return;
  }
  const char *sql =
      "INSERT INTO artifacts(artifact_id,endpoint_id,tenant_id,candidate_id,artifact_type,path,"
      "sha256,manifest_json,created_ns,upload_status,minio_key) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
      "ON CONFLICT(artifact_id) DO UPDATE SET upload_status=excluded.upload_status,"
      "manifest_json=excluded.manifest_json,created_ns=excluded.created_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare artifacts failed");
    return;
  }
  char artifact_id[256];
  snprintf(artifact_id, sizeof(artifact_id), "%s:%s", candidate_id,
           artifact_type && artifact_type[0] ? artifact_type : "artifact");
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
  if (sqlite3_step(st) == SQLITE_DONE) {
    s_status.artifacts_written++;
  } else {
    set_error("insert artifacts failed");
  }
  sqlite3_finalize(st);
}

static void sqlite_record_context_artifact(const EdrBehaviorRecord *r, const char *candidate_id) {
  if (!s_db || !r || !candidate_id || !candidate_id[0]) {
    return;
  }
  char cid[220], pn[320], fp[1200], dns[640], nd[120], rk[1200], rv[640], ro[80];
  char manifest[4096];
  json_escape(cid, sizeof(cid), candidate_id);
  json_escape(pn, sizeof(pn), r->process_name);
  json_escape(fp, sizeof(fp), r->file_path[0] ? r->file_path : r->exe_path);
  json_escape(dns, sizeof(dns), r->dns_query);
  json_escape(nd, sizeof(nd), r->net_dst);
  json_escape(rk, sizeof(rk), r->reg_key_path);
  json_escape(rv, sizeof(rv), r->reg_value_name);
  json_escape(ro, sizeof(ro), r->reg_op);
  snprintf(manifest, sizeof(manifest),
           "{\"schema\":\"p0_post_context_event.v1\",\"candidate_id\":%s,"
           "\"event_time_ns\":%lld,\"type\":%u,\"pid\":%u,\"ppid\":%u,"
           "\"process_name\":%s,\"path\":%s,\"dns_query\":%s,\"remote_ip\":%s,"
           "\"remote_port\":%u,\"registry_key\":%s,\"registry_value\":%s,\"registry_op\":%s}",
           cid, (long long)record_time_ns(r), (uint32_t)r->type, r->pid, r->ppid,
           pn, fp, dns, nd, r->net_dport, rk, rv, ro);
  char artifact_type[96];
  snprintf(artifact_type, sizeof(artifact_type), "post_context_%lld_%u_%u",
           (long long)record_time_ns(r), r->pid, (uint32_t)r->type);
  insert_artifact_sqlite(r, candidate_id, artifact_type, "", "", manifest, "local_manifest");
}

static void sqlite_record_candidate(const EdrBehaviorRecord *r, uint32_t pre_count,
                                    int64_t post_until_ns) {
  if (!s_db) {
    return;
  }
  char candidate_id[160];
  candidate_id_for(r, candidate_id, sizeof(candidate_id));
  (void)exec_sql("BEGIN IMMEDIATE;");
  upsert_process_sqlite(r);
  const char *sql =
      "INSERT INTO p0_candidates(candidate_id,endpoint_id,tenant_id,event_time_ns,type,pid,ppid,"
      "process_name,exe_path,cmdline,file_path,dns_query,net_dst,net_dport,reg_key_path,"
      "reg_value_name,reg_op,detection_context,context_pre_count,context_post_until_ns,created_ns) "
      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
      "ON CONFLICT(candidate_id) DO UPDATE SET context_pre_count=excluded.context_pre_count,"
      "context_post_until_ns=excluded.context_post_until_ns,created_ns=excluded.created_ns;";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    set_error("prepare p0_candidates failed");
    (void)exec_sql("ROLLBACK;");
    s_status.records_dropped++;
    return;
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
  if (sqlite3_step(st) != SQLITE_DONE) {
    set_error("insert p0_candidates failed");
    s_status.records_dropped++;
    sqlite3_finalize(st);
    (void)exec_sql("ROLLBACK;");
    return;
  }
  sqlite3_finalize(st);
  s_status.records_written++;
  s_status.p0_candidates_written++;
  upsert_file_sqlite(r);
  upsert_network_sqlite(r);
  upsert_registry_sqlite(r);
  char manifest[4096];
  build_context_manifest_json(r, candidate_id, pre_count, post_until_ns, manifest, sizeof(manifest));
  insert_artifact_sqlite(r, candidate_id, "p0_context_bundle", "", "", manifest, "local_manifest");
  (void)exec_sql("COMMIT;");
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
                          "registry_evidence", "artifacts", "command_results"};
  const char *cols[] = {"event_time_ns", "last_seen_ns", "last_seen_ns", "last_seen_ns",
                        "last_seen_ns", "created_ns", "updated_ns"};
  for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
    char sql[160];
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE %s < ?;", tables[i], cols[i]);
    if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
      sqlite3_bind_int64(st, 1, (sqlite3_int64)cutoff);
      (void)sqlite3_step(st);
      sqlite3_finalize(st);
      st = NULL;
    }
  }
  if (sqlite3_prepare_v2(s_db, "DELETE FROM metrics WHERE minute_unix < ?;", -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, (sqlite3_int64)cutoff_minute);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
    st = NULL;
  }
  if (db_size_over_limit()) {
    for (int pass = 0; pass < 4 && db_size_over_limit(); pass++) {
      (void)exec_sql("DELETE FROM p0_candidates WHERE rowid IN (SELECT rowid FROM p0_candidates ORDER BY event_time_ns ASC LIMIT 1000);");
      (void)exec_sql("DELETE FROM artifacts WHERE rowid IN (SELECT rowid FROM artifacts ORDER BY created_ns ASC LIMIT 1000);");
    }
    (void)exec_sql("PRAGMA wal_checkpoint(TRUNCATE);");
    if (db_size_over_limit()) {
      (void)exec_sql("VACUUM;");
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
#if defined(EDR_HAVE_SQLITE)
  if (!s_db || !command_id || !command_id[0]) {
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
#else
  (void)command_id;
  (void)command_type;
  (void)status;
  (void)execution_status;
  (void)exit_code;
  (void)detail;
  (void)artifacts;
#endif
}

int edr_local_evidence_cache_open(const char *path, uint32_t max_db_mb,
                                  uint32_t retention_hours) {
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
  s_write_budget_minute = 0;
  s_write_budget_count = 0u;
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
    return -1;
  }
  s_status.db_open = 1;
  (void)exec_sql("PRAGMA journal_mode=WAL;");
  (void)exec_sql("PRAGMA synchronous=NORMAL;");
  (void)exec_sql("PRAGMA cache_size=-1024;");
  (void)exec_sql("PRAGMA mmap_size=0;");
  const char *schema =
      "CREATE TABLE IF NOT EXISTS process_cache ("
      "endpoint_id TEXT NOT NULL,tenant_id TEXT,pid INTEGER NOT NULL,ppid INTEGER,"
      "name TEXT,path TEXT,cmdline TEXT,parent_name TEXT,parent_path TEXT,"
      "first_seen_ns INTEGER,last_seen_ns INTEGER,PRIMARY KEY(endpoint_id,pid));"
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
      "context_post_until_ns INTEGER,created_ns INTEGER);"
      "CREATE INDEX IF NOT EXISTS idx_p0_candidates_ep_time ON p0_candidates(endpoint_id,event_time_ns);"
      "CREATE INDEX IF NOT EXISTS idx_p0_candidates_pid_time ON p0_candidates(endpoint_id,pid,event_time_ns);"
      "CREATE TABLE IF NOT EXISTS artifacts ("
      "artifact_id TEXT PRIMARY KEY,endpoint_id TEXT,tenant_id TEXT,candidate_id TEXT,"
      "artifact_type TEXT,path TEXT,sha256 TEXT,manifest_json TEXT,created_ns INTEGER,"
      "upload_status TEXT,minio_key TEXT);"
      "CREATE INDEX IF NOT EXISTS idx_artifacts_ep_time ON artifacts(endpoint_id,created_ns);"
      "CREATE TABLE IF NOT EXISTS command_results ("
      "command_id TEXT PRIMARY KEY,command_type TEXT,status TEXT,execution_status INTEGER,"
      "exit_code INTEGER,detail TEXT,artifacts TEXT,updated_ns INTEGER);"
      "CREATE TABLE IF NOT EXISTS metrics ("
      "minute_unix INTEGER,endpoint_id TEXT,metric_name TEXT,value INTEGER,"
      "PRIMARY KEY(minute_unix,endpoint_id,metric_name));"
      "CREATE TABLE IF NOT EXISTS file_evidence ("
      "endpoint_id TEXT NOT NULL,path TEXT NOT NULL,sha256 TEXT,pid INTEGER,last_seen_ns INTEGER,"
      "PRIMARY KEY(endpoint_id,path));"
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
    edr_local_evidence_cache_close();
    return -1;
  }
  sqlite_maintenance();
  return 0;
#else
  (void)path;
  set_error("sqlite disabled");
  return -1;
#endif
}

void edr_local_evidence_cache_close(void) {
#if defined(EDR_HAVE_SQLITE)
  if (s_db) {
    (void)exec_sql("PRAGMA wal_checkpoint(TRUNCATE);");
    sqlite3_close(s_db);
    s_db = NULL;
  }
#endif
  s_status.db_open = 0;
}

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

static int evidence_should_store_record(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  if (evidence_contains_ci(r->detection_context, "\"severity\":\"P0\"") ||
      evidence_contains_ci(r->detection_context, "\"severity\":\"P1\"") ||
      evidence_contains_ci(r->detection_context, "\"priority\":\"P0\"") ||
      evidence_contains_ci(r->detection_context, "\"priority\":\"P1\"") ||
      evidence_contains_ci(r->detection_context, "\"confidence\":0.8") ||
      evidence_contains_ci(r->detection_context, "\"confidence\":0.9") ||
      evidence_contains_ci(r->detection_context, "\"confidence\":1")) {
    return 1;
  }
  if (evidence_is_low_value_file_noise(r)) {
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
    return evidence_text_has_high_signal(r);
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

static int same_ep_window(const ContextWindowSlot *w, const EdrBehaviorRecord *r) {
  if (!w || !r) {
    return 0;
  }
  if (w->endpoint_id[0] && r->endpoint_id[0] && strcmp(w->endpoint_id, r->endpoint_id) != 0) {
    return 0;
  }
  return 1;
}

static void mark_one_context_window(uint32_t pid, const char *endpoint_id,
                                    const char *candidate_id, int64_t until_ns) {
  if (pid == 0u) {
    return;
  }
  for (size_t i = 0; i < EDR_EVIDENCE_CONTEXT_WINDOWS; i++) {
    if (s_context_windows[i].pid == pid &&
        (!s_context_windows[i].endpoint_id[0] || !endpoint_id || !endpoint_id[0] ||
         strcmp(s_context_windows[i].endpoint_id, endpoint_id) == 0)) {
      s_context_windows[i].until_ns = until_ns;
      copy_s(s_context_windows[i].endpoint_id, sizeof(s_context_windows[i].endpoint_id), endpoint_id);
      copy_s(s_context_windows[i].candidate_id, sizeof(s_context_windows[i].candidate_id), candidate_id);
      return;
    }
  }
  ContextWindowSlot *w = &s_context_windows[s_context_window_next++ % EDR_EVIDENCE_CONTEXT_WINDOWS];
  memset(w, 0, sizeof(*w));
  w->pid = pid;
  w->until_ns = until_ns;
  copy_s(w->endpoint_id, sizeof(w->endpoint_id), endpoint_id);
  copy_s(w->candidate_id, sizeof(w->candidate_id), candidate_id);
}

static int64_t mark_context_window(const EdrBehaviorRecord *r, int64_t now_ns,
                                   const char *candidate_id) {
  uint32_t win_s = evidence_context_window_s();
  int64_t until_ns = now_ns + (int64_t)win_s * 1000000000LL;
  mark_one_context_window(r ? r->pid : 0u, r ? r->endpoint_id : "", candidate_id, until_ns);
  mark_one_context_window(r ? r->ppid : 0u, r ? r->endpoint_id : "", candidate_id, until_ns);
  return until_ns;
}

static int in_context_window(const EdrBehaviorRecord *r, int64_t now_ns,
                             char *candidate_id, size_t candidate_id_cap) {
  if (!r || (r->pid == 0u && r->ppid == 0u)) {
    return 0;
  }
  for (size_t i = 0; i < EDR_EVIDENCE_CONTEXT_WINDOWS; i++) {
    ContextWindowSlot *w = &s_context_windows[i];
    if (w->pid == 0u || w->until_ns < now_ns || !same_ep_window(w, r)) {
      continue;
    }
    if (w->pid == r->pid || (r->ppid != 0u && w->pid == r->ppid)) {
      if (candidate_id && candidate_id_cap > 0u) {
        copy_s(candidate_id, candidate_id_cap, w->candidate_id);
      }
      return 1;
    }
  }
  return 0;
}

static int ring_related_to_record(const RingSlot *s, const EdrBehaviorRecord *r) {
  if (!s || !s->used || !r) {
    return 0;
  }
  if (s->endpoint_id[0] && r->endpoint_id[0] && strcmp(s->endpoint_id, r->endpoint_id) != 0) {
    return 0;
  }
  if (r->pid != 0u && (s->pid == r->pid || s->ppid == r->pid)) {
    return 1;
  }
  if (r->ppid != 0u && (s->pid == r->ppid || s->ppid == r->ppid)) {
    return 1;
  }
  return 0;
}

static uint32_t promote_context_before_window(const EdrBehaviorRecord *r, int64_t now_ns) {
  uint32_t win_s = evidence_context_window_s();
  int64_t cutoff = now_ns - (int64_t)win_s * 1000000000LL;
  uint32_t pos = s_context_ring_pos;
  uint32_t copied = 0;
  for (uint32_t i = 0; i < EDR_EVIDENCE_CONTEXT_RING_SLOTS; i++) {
    const RingSlot *s = &s_context_ring[(pos + EDR_EVIDENCE_CONTEXT_RING_SLOTS - 1u - i) %
                                        EDR_EVIDENCE_CONTEXT_RING_SLOTS];
    if (!s->used) {
      continue;
    }
    if (s->event_time_ns < cutoff) {
      break;
    }
    if (ring_related_to_record(s, r)) {
      ring_copy_to(s_ring, EDR_EVIDENCE_RING_SLOTS, &s_ring_pos, s);
      copied++;
    }
  }
  return copied;
}

void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *r) {
  if (!r) {
    return;
  }
  int64_t ts = record_time_ns(r);
  process_cache_update(r);
  int store_candidate = evidence_should_store_record(r);
  if (store_candidate && candidate_dedupe_should_skip(r, ts)) {
    context_ring_capture(r);
    s_status.hot_ring_ingested++;
    record_metric_drop(r, ts);
    s_status.records_skipped++;
    return;
  }
  char candidate_id[160] = "";
  char context_candidate_id[160] = "";
  if (store_candidate) {
    candidate_id_for(r, candidate_id, sizeof(candidate_id));
  }
  int store_context = in_context_window(r, ts, context_candidate_id, sizeof(context_candidate_id));
  uint32_t pre_count = 0;
  int64_t post_until_ns = 0;
  if (store_candidate) {
    pre_count = promote_context_before_window(r, ts);
    post_until_ns = mark_context_window(r, ts, candidate_id);
  }
  if (!store_candidate && !store_context && evidence_is_low_value_file_noise(r)) {
    record_metric_drop(r, ts);
    s_status.records_skipped++;
    return;
  }
  if (!store_candidate && !store_context && evidence_cache_pressure_active()) {
    record_metric_drop(r, ts);
    s_status.pressure_dropped++;
    s_status.records_skipped++;
    return;
  }
  if (!store_candidate && !store_context && ordinary_aggregate_should_coalesce(r, ts)) {
    record_metric_drop(r, ts);
    s_status.records_skipped++;
    return;
  }
  context_ring_capture(r);
  s_status.hot_ring_ingested++;
  if (!store_candidate && !store_context) {
    record_metric_drop(r, ts);
    s_status.records_skipped++;
    return;
  }
  ring_record(r);
  const char *eng = engine_from_context(r->detection_context);
  if (eng[0]) {
    copy_s(s_status.last_engine, sizeof(s_status.last_engine), eng);
  }
  s_status.last_event_time_ns = ts;
#if defined(EDR_HAVE_SQLITE)
  if (s_db && store_candidate) {
    if (!sqlite_size_budget_allow() || !sqlite_write_budget_allow(2u, ts)) {
      s_status.records_dropped++;
      return;
    }
    sqlite_record_candidate(r, pre_count, post_until_ns);
  } else if (!s_db && store_candidate) {
    s_status.records_dropped++;
  } else if (s_db && store_context && context_candidate_id[0]) {
    if (!sqlite_size_budget_allow() || !sqlite_write_budget_allow(1u, ts)) {
      s_status.records_dropped++;
      return;
    }
    sqlite_record_context_artifact(r, context_candidate_id);
  }
#else
  (void)candidate_id;
  (void)context_candidate_id;
  (void)pre_count;
  (void)post_until_ns;
  if (store_candidate) {
    s_status.records_dropped++;
  }
#endif
}

void edr_local_evidence_cache_poll_maintenance(void) {
  uint64_t now = edr_monotonic_ns();
  if (now - s_last_maintenance_ns < 60000000000ULL) {
    return;
  }
  s_last_maintenance_ns = now;
#if defined(EDR_HAVE_SQLITE)
  sqlite_maintenance();
#endif
}

void edr_local_evidence_cache_get_status(EdrEvidenceCacheStatus *out) {
  if (!out) {
    return;
  }
  EdrEvidenceCacheStatus st = s_status;
  uint32_t proc_n = 0;
  uint32_t ring_n = 0;
  uint32_t hot_n = 0;
  uint32_t agg_n = 0;
  for (size_t i = 0; i < EDR_EVIDENCE_PROC_SLOTS; i++) {
    if (s_proc[i].pid != 0u) {
      proc_n++;
    }
  }
  for (size_t i = 0; i < EDR_EVIDENCE_RING_SLOTS; i++) {
    if (s_ring[i].used) {
      ring_n++;
    }
  }
  for (size_t i = 0; i < EDR_EVIDENCE_CONTEXT_RING_SLOTS; i++) {
    if (s_context_ring[i].used) {
      hot_n++;
    }
  }
  for (size_t i = 0; i < EDR_EVIDENCE_AGG_SLOTS; i++) {
    if (s_ordinary_agg[i].used) {
      agg_n++;
    }
  }
  st.process_slots_used = proc_n;
  st.ring_events = ring_n;
  st.hot_ring_events = hot_n;
  st.metrics_minutes = metric_slots_used();
  st.aggregate_slots_used = agg_n;
  st.pressure_active = evidence_cache_pressure_active() ? 1u : 0u;
#if defined(EDR_HAVE_SQLITE)
  refresh_db_size_status();
  st.db_bytes = s_status.db_bytes;
  st.wal_bytes = s_status.wal_bytes;
#endif
  *out = st;
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
  uint32_t limit;
  uint32_t time_window_s;
  char endpoint_id[48];
  char process_name_contains[128];
  char cmdline_contains[256];
  char file_path_contains[256];
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
  (void)json_get_string(json, "remote_ip", f->remote_ip, sizeof(f->remote_ip));
  (void)json_get_string(json, "registry_key_contains", f->registry_key_contains,
                        sizeof(f->registry_key_contains));
  (void)json_get_u32(json, "pid", &f->pid);
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
                            const char *registry_key) {
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
                              const char *registry_op) {
  char ep[120], pn[320], xp[1200], cl[1200], fp[1200], dns[640], rip[120], rk[1200], rv[640], ro[80];
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
  appendf(out, cap, off, "%s{\"source\":\"%s\",\"event_time_ns\":%lld,\"type\":%u,"
                          "\"pid\":%u,\"ppid\":%u,\"endpoint_id\":%s,\"process_name\":%s,"
                          "\"exe_path\":%s,\"cmdline\":%s,\"file_path\":%s,\"dns_query\":%s,"
                          "\"remote_ip\":%s,\"dst_port\":%u,\"registry_key\":%s,"
                          "\"registry_value\":%s,\"registry_op\":%s}",
          *first ? "" : ",", source ? source : "", (long long)event_time_ns, type, pid, ppid,
          ep, pn, xp, cl, fp, dns, rip, dst_port, rk, rv, ro);
  *first = 0;
}

int edr_local_evidence_cache_query_json(const char *payload_json, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return -1;
  }
  RtqFilter f;
  parse_rtq_filter(payload_json, &f);
  size_t off = 0;
  int first = 1;
  uint32_t returned = 0;
  uint32_t scanned = 0;
  appendf(out, cap, &off, "{\"source\":\"mixed\",\"partial\":false,\"rows\":[");
  uint32_t ring_pos = s_ring_pos;
  for (uint32_t i = 0; i < EDR_EVIDENCE_RING_SLOTS && returned < f.limit; i++) {
    const RingSlot *r = &s_ring[(ring_pos + EDR_EVIDENCE_RING_SLOTS - 1u - i) % EDR_EVIDENCE_RING_SLOTS];
    if (!r->used) {
      continue;
    }
    scanned++;
    if (!rtq_match_common(&f, r->type, r->pid, r->event_time_ns, r->endpoint_id,
                          r->process_name, "", r->file_path, r->net_dst, "")) {
      continue;
    }
    append_event_json(out, cap, &off, &first, "ring", r->event_time_ns, r->type, r->pid,
                      r->ppid, r->endpoint_id, r->process_name, "", "", r->file_path,
                      "", r->net_dst, r->net_dport, "", "", "");
    returned++;
  }
#if defined(EDR_HAVE_SQLITE)
  if (s_db && returned < f.limit) {
    const char *sql =
        "SELECT event_time_ns,type,pid,ppid,endpoint_id,process_name,exe_path,cmdline,"
        "file_path,dns_query,net_dst,net_dport,reg_key_path,reg_value_name,reg_op "
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
        if (!rtq_match_common(&f, ty, pid, ts, ep, pn, cl, fp, rip, rk)) {
          continue;
        }
        append_event_json(out, cap, &off, &first, "p0_candidates", ts, ty, pid, ppid, ep, pn,
                          xp, cl, fp, dns, rip, dport, rk, rv, ro);
        returned++;
      }
      sqlite3_finalize(st);
    }
  }
#endif
  appendf(out, cap, &off, "],\"rows_scanned\":%u,\"rows_returned\":%u}", scanned, returned);
  out[cap - 1u] = '\0';
  return 0;
}

static void append_proc_json(char *out, size_t cap, size_t *off, int *first,
                             const char *source, const ProcSlot *p) {
  char ep[120], tn[160], nm[320], path[1200], cmd[1200], pn[320], pp[640];
  json_escape(ep, sizeof(ep), p ? p->endpoint_id : "");
  json_escape(tn, sizeof(tn), p ? p->tenant_id : "");
  json_escape(nm, sizeof(nm), p ? p->name : "");
  json_escape(path, sizeof(path), p ? p->path : "");
  json_escape(cmd, sizeof(cmd), p ? p->cmdline : "");
  json_escape(pn, sizeof(pn), p ? p->parent_name : "");
  json_escape(pp, sizeof(pp), p ? p->parent_path : "");
  appendf(out, cap, off, "%s{\"source\":\"%s\",\"endpoint_id\":%s,\"tenant_id\":%s,"
                          "\"pid\":%u,\"ppid\":%u,\"name\":%s,\"path\":%s,\"cmdline\":%s,"
                          "\"parent_name\":%s,\"parent_path\":%s,\"last_seen_ns\":%lld}",
          *first ? "" : ",", source ? source : "", ep, tn, p ? p->pid : 0u,
          p ? p->ppid : 0u, nm, path, cmd, pn, pp, p ? (long long)p->last_seen_ns : 0LL);
  *first = 0;
}

int edr_local_evidence_cache_process_tree_json(uint32_t pid, const char *endpoint_id,
                                               char *out, size_t cap) {
  if (!out || cap == 0u || pid == 0u) {
    return -1;
  }
  ProcSlot *root = find_proc(pid, endpoint_id);
  size_t off = 0;
  int first = 1;
  uint32_t children = 0;
  appendf(out, cap, &off, "{\"pid\":%u,\"root\":", pid);
  if (root) {
    int only = 1;
    append_proc_json(out, cap, &off, &only, "memory", root);
  } else {
    appendf(out, cap, &off, "null");
  }
  appendf(out, cap, &off, ",\"children\":[");
  for (size_t i = 0; i < EDR_EVIDENCE_PROC_SLOTS && children < 64u; i++) {
    ProcSlot *p = &s_proc[i];
    if (p->pid == 0u || p->ppid != pid) {
      continue;
    }
    if (endpoint_id && endpoint_id[0] && p->endpoint_id[0] && strcmp(endpoint_id, p->endpoint_id) != 0) {
      continue;
    }
    append_proc_json(out, cap, &off, &first, "memory", p);
    children++;
  }
#if defined(EDR_HAVE_SQLITE)
  if (s_db && children < 64u) {
    const char *sql =
        "SELECT endpoint_id,tenant_id,pid,ppid,name,path,cmdline,parent_name,parent_path,last_seen_ns "
        "FROM process_cache WHERE ppid=? ORDER BY last_seen_ns DESC LIMIT 64;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
      sqlite3_bind_int64(st, 1, (sqlite3_int64)pid);
      while (sqlite3_step(st) == SQLITE_ROW && children < 64u) {
        ProcSlot tmp;
        memset(&tmp, 0, sizeof(tmp));
        copy_s(tmp.endpoint_id, sizeof(tmp.endpoint_id), (const char *)sqlite3_column_text(st, 0));
        if (endpoint_id && endpoint_id[0] && tmp.endpoint_id[0] && strcmp(endpoint_id, tmp.endpoint_id) != 0) {
          continue;
        }
        copy_s(tmp.tenant_id, sizeof(tmp.tenant_id), (const char *)sqlite3_column_text(st, 1));
        tmp.pid = (uint32_t)sqlite3_column_int64(st, 2);
        tmp.ppid = (uint32_t)sqlite3_column_int64(st, 3);
        copy_s(tmp.name, sizeof(tmp.name), (const char *)sqlite3_column_text(st, 4));
        copy_s(tmp.path, sizeof(tmp.path), (const char *)sqlite3_column_text(st, 5));
        copy_s(tmp.cmdline, sizeof(tmp.cmdline), (const char *)sqlite3_column_text(st, 6));
        copy_s(tmp.parent_name, sizeof(tmp.parent_name), (const char *)sqlite3_column_text(st, 7));
        copy_s(tmp.parent_path, sizeof(tmp.parent_path), (const char *)sqlite3_column_text(st, 8));
        tmp.last_seen_ns = sqlite3_column_int64(st, 9);
        append_proc_json(out, cap, &off, &first, "sqlite", &tmp);
        children++;
      }
      sqlite3_finalize(st);
    }
  }
#endif
  appendf(out, cap, &off, "],\"child_count\":%u}", children);
  out[cap - 1u] = '\0';
  return root || children ? 0 : -2;
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
  json_escape(path, sizeof(path), st.path);
  json_escape(err, sizeof(err), st.last_error);
  json_escape(eng, sizeof(eng), st.last_engine);
  snprintf(out, cap,
           "\"evidence_cache\":{\"db_open\":%s,\"path\":%s,\"max_db_mb\":%u,"
           "\"retention_hours\":%u,\"db_bytes\":%llu,\"wal_bytes\":%llu,"
           "\"records_written\":%llu,\"records_dropped\":%llu,"
           "\"records_skipped\":%llu,\"hot_ring_ingested\":%llu,"
           "\"candidate_deduped\":%llu,\"write_budget_dropped\":%llu,"
           "\"db_budget_dropped\":%llu,\"pressure_dropped\":%llu,"
           "\"pressure_active\":%s,\"ordinary_coalesced\":%llu,"
           "\"aggregate_slots_used\":%u,"
           "\"maintenance_runs\":%llu,\"process_slots_used\":%u,\"ring_events\":%u,"
           "\"last_engine\":%s,\"last_event_time_ns\":%lld,\"last_error\":%s,"
           "\"partitions\":{\"hot_ring\":{\"events\":%u},"
           "\"p0_candidates\":{\"written\":%llu},\"artifacts\":{\"written\":%llu},"
           "\"command_results\":{\"written\":%llu},\"metrics\":{\"minutes\":%u}},"
           "\"coalesced\":{\"file\":%llu,\"registry\":%llu,\"network\":%llu},"
           "\"drop_counters\":{\"file\":%llu,\"registry\":%llu,\"network\":%llu,\"other\":%llu}}",
           st.db_open ? "true" : "false", path, st.max_db_mb, st.retention_hours,
           (unsigned long long)st.db_bytes, (unsigned long long)st.wal_bytes,
           (unsigned long long)st.records_written, (unsigned long long)st.records_dropped,
           (unsigned long long)st.records_skipped, (unsigned long long)st.hot_ring_ingested,
           (unsigned long long)st.candidate_deduped,
           (unsigned long long)st.write_budget_dropped,
           (unsigned long long)st.db_budget_dropped,
           (unsigned long long)st.pressure_dropped,
           st.pressure_active ? "true" : "false",
           (unsigned long long)st.ordinary_coalesced, st.aggregate_slots_used,
           (unsigned long long)st.maintenance_runs, st.process_slots_used, st.ring_events,
           eng, (long long)st.last_event_time_ns, err, st.hot_ring_events,
           (unsigned long long)st.p0_candidates_written,
           (unsigned long long)st.artifacts_written,
           (unsigned long long)st.command_results_written, st.metrics_minutes,
           (unsigned long long)st.file_coalesced,
           (unsigned long long)st.registry_coalesced,
           (unsigned long long)st.network_coalesced,
           (unsigned long long)st.metric_file_drops,
           (unsigned long long)st.metric_registry_drops,
           (unsigned long long)st.metric_network_drops,
           (unsigned long long)st.metric_other_drops);
}
