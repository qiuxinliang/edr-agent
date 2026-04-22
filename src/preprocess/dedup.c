#include "edr/dedup.h"
#include "edr/emit_rules.h"

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
                           r->net_dst, r->script_snippet, r->pmfe_snapshot,
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
}

int edr_preprocess_should_emit(const EdrBehaviorRecord *r) {
  if (!r) {
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
