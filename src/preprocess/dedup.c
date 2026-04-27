#include "edr/dedup.h"
#include "edr/emit_rules.h"
#include "edr/types.h"

#include <stdlib.h>
#include <string.h>

/* §4.3：去重窗口与高频阈值由 edr_dedup_configure（§11）设定 */

static uint64_t s_dedup_window_ns = 30ULL * 1000000000ULL;
static uint32_t s_rate_max_per_sec = 100u;

#define EDR_DEDUP_SLOTS 8192u
#define EDR_RATE_SLOTS 512u

typedef struct {
  uint64_t key;
  uint64_t last_ns;
} DedupSlot;

typedef struct {
  uint32_t pid;
  uint32_t type;
  uint64_t sec_bucket;
  uint32_t count;
} RateSlot;

static DedupSlot s_dedup[EDR_DEDUP_SLOTS];
static RateSlot s_rate[EDR_RATE_SLOTS];

static uint64_t s_stat_dedup_drop;
static uint64_t s_stat_rate_drop;
static uint64_t s_stat_junk_parse_failed;

static uint64_t fnv64_update(uint64_t h, const unsigned char *p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    h ^= (uint64_t)p[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static uint64_t edr_target_fingerprint(const EdrBehaviorRecord *r) {
  uint64_t h = 14695981039346656037ULL;
  const char *parts[] = {r->cmdline, r->exe_path,  r->file_path, r->dns_query,
                           r->net_dst, r->network_aux_path, r->script_snippet, r->pmfe_snapshot,
                           r->reg_key_path, r->reg_value_name, r->reg_value_data};
  size_t k;
  for (k = 0; k < sizeof(parts) / sizeof(parts[0]); k++) {
    const char *s = parts[k];
    if (!s || !s[0]) {
      continue;
    }
    h = fnv64_update(h, (const unsigned char *)s, strlen(s));
    h ^= 0xFFULL;
  }
  return h;
}

static uint64_t edr_dedup_key(const EdrBehaviorRecord *r) {
  uint64_t h = (uint64_t)r->pid;
  h ^= (uint64_t)r->type << 20;
  h ^= edr_target_fingerprint(r);
  return h;
}

static uint32_t rate_idx(uint32_t pid, EdrEventType ty) {
  uint64_t x = (uint64_t)pid * 1315423911ULL ^ (uint64_t)ty * 1009ULL;
  return (uint32_t)(x % (uint64_t)EDR_RATE_SLOTS);
}

static int rate_allow(const EdrBehaviorRecord *r) {
  uint32_t idx = rate_idx(r->pid, r->type);
  int64_t t = r->event_time_ns;
  uint64_t now = (uint64_t)(t < 0 ? 0 : t);
  uint64_t sec = now / 1000000000ULL;
  RateSlot *s = &s_rate[idx];
  if (s->pid != r->pid || s->type != (uint32_t)r->type || s->sec_bucket != sec) {
    s->pid = r->pid;
    s->type = (uint32_t)r->type;
    s->sec_bucket = sec;
    s->count = 1;
    return 1;
  }
  s->count++;
  if (s->count > s_rate_max_per_sec) {
    s_stat_rate_drop++;
    return 0;
  }
  return 1;
}

static int dedup_allow(const EdrBehaviorRecord *r) {
  uint64_t k = edr_dedup_key(r);
  int64_t t = r->event_time_ns;
  uint64_t now = (uint64_t)(t < 0 ? 0 : t);
  uint32_t idx = (uint32_t)(k & (EDR_DEDUP_SLOTS - 1u));
  size_t probe;
  for (probe = 0; probe < 64u; probe++) {
    uint32_t i = (idx + (uint32_t)probe) & (EDR_DEDUP_SLOTS - 1u);
    DedupSlot *sl = &s_dedup[i];
    int empty = (sl->key == 0 && sl->last_ns == 0);
    int expired =
        (!empty && (now - sl->last_ns >= s_dedup_window_ns));
    if (empty || expired) {
      sl->key = k;
      sl->last_ns = now;
      return 1;
    }
    if (sl->key == k) {
      if (now - sl->last_ns < s_dedup_window_ns) {
        s_stat_dedup_drop++;
        return 0;
      }
      sl->last_ns = now;
      return 1;
    }
  }
  return 1;
}

void edr_dedup_configure(uint32_t dedup_window_s, uint32_t high_freq_threshold_per_sec) {
  uint32_t w = dedup_window_s ? dedup_window_s : 30u;
  if (w > 3600u) {
    w = 3600u;
  }
  s_dedup_window_ns = (uint64_t)w * 1000000000ULL;
  uint32_t r = high_freq_threshold_per_sec ? high_freq_threshold_per_sec : 100u;
  if (r > 100000u) {
    r = 100000u;
  }
  s_rate_max_per_sec = r;
}

void edr_dedup_init(void) { edr_dedup_reset(); }

void edr_dedup_reset(void) {
  memset(s_dedup, 0, sizeof(s_dedup));
  memset(s_rate, 0, sizeof(s_rate));
  s_stat_dedup_drop = 0;
  s_stat_rate_drop = 0;
  s_stat_junk_parse_failed = 0;
}

/* ASCII: 1 / true / yes / on 视为允许上送（恢复默认丢弃的 parse=failed 噪声） */
static int str_ieq_ascii(const char *a, const char *b) {
  if (!a || !b) {
    return 0;
  }
  for (; *a && *b; a++, b++) {
    char ca = *a;
    char cb = *b;
    if (ca >= 'A' && ca <= 'Z') {
      ca = (char)(ca - 'A' + 'a');
    }
    if (cb >= 'A' && cb <= 'Z') {
      cb = (char)(cb - 'A' + 'a');
    }
    if (ca != cb) {
      return 0;
    }
  }
  return *a == *b;
}

static int allow_parse_failed_reemit(void) {
  const char *e = getenv("EDR_PREPROCESS_ALLOW_UNPARSED_NET_EVENTS");
  if (!e || e[0] == '\0') {
    return 0;
  }
  if (e[0] == '1' && e[1] == '\0') {
    return 1;
  }
  return str_ieq_ascii(e, "true") || str_ieq_ascii(e, "yes") || str_ieq_ascii(e, "on");
}

static int is_high_value_event_type(EdrEventType t) {
  switch (t) {
  case EDR_EVENT_PROTOCOL_SHELLCODE:
  case EDR_EVENT_WEBSHELL_DETECTED:
  case EDR_EVENT_FIREWALL_RULE_CHANGE:
  case EDR_EVENT_PMFE_SCAN_RESULT:
  case EDR_EVENT_BEHAVIOR_ONNX_ALERT:
    return 1;
  default:
    return 0;
  }
}

/**
 * `behavior_from_slot` 在 ETW1 失败且原 payload 非可打印时仅填 `raw_etw…parse=failed`、清 cmdline；
 * 可打印副本则进 cmdline，不视为垃圾。高价值/专用事件类型不丢弃。
 */
static int is_junk_parse_failed_event(const EdrBehaviorRecord *r) {
  const char *ss;
  if (!r) {
    return 0;
  }
  if (r->cmdline[0] != '\0') {
    return 0; /* 可打印原始字节在 cmdline，保留下游可见 */
  }
  ss = r->script_snippet;
  if (ss[0] == '\0' || strstr(ss, "raw_etw_payload_bytes") == NULL || strstr(ss, "parse=failed") == NULL) {
    return 0;
  }
  if (r->reg_key_path[0] || r->reg_value_name[0] || r->file_path[0] || r->file_op[0] || r->dns_query[0] ||
      r->net_dst[0] || r->net_src[0] || r->network_aux_path[0] || r->pmfe_snapshot[0]) {
    return 0;
  }
  if (r->net_dport != 0u || r->net_sport != 0u) {
    return 0;
  }
  if (r->net_proto[0]) {
    return 0;
  }
  if (is_high_value_event_type(r->type)) {
    return 0;
  }
  return 1;
}

uint64_t edr_dedup_junk_parse_failed_drops(void) { return s_stat_junk_parse_failed; }

int edr_preprocess_should_emit(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  if (!allow_parse_failed_reemit() && is_junk_parse_failed_event(r)) {
    s_stat_junk_parse_failed++;
    return 0;
  }
  if (r->priority == 0u) {
    return 1;
  }
  {
    int rr = edr_emit_rules_evaluate(r);
    if (rr == 0) {
      return 0;
    }
    if (rr == 1) {
      return 1;
    }
  }
  if (!dedup_allow(r)) {
    return 0;
  }
  if (!rate_allow(r)) {
    return 0;
  }
  return 1;
}

void edr_dedup_get_stats(uint64_t *out_dedup_drops, uint64_t *out_rate_drops) {
  if (out_dedup_drops) {
    *out_dedup_drops = s_stat_dedup_drop;
  }
  if (out_rate_drops) {
    *out_rate_drops = s_stat_rate_drop;
  }
}
