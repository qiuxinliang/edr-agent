#include "edr/dedup.h"
#include "edr/emit_rules.h"
#include "edr/windows_event_policy.h"

#include <stdlib.h>
#include <string.h>

/* §4.3：去重窗口与高频阈值由 edr_dedup_configure（§11）设定 */

static uint64_t s_dedup_window_ns = 30ULL * 1000000000ULL;
static uint32_t s_rate_max_per_sec = 100u;

#define EDR_DEDUP_SLOTS 8192u
#define EDR_RATE_SLOTS 512u
#define EDR_SCRIPT_SENSOR_DEDUP_SLOTS 2048u
#define EDR_SCRIPT_SENSOR_DEDUP_DEFAULT_WINDOW_S 60u

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
static DedupSlot s_script_sensor_dedup[EDR_SCRIPT_SENSOR_DEDUP_SLOTS];
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

static char fold_ascii(char c) {
  if (c == '/') {
    return '\\';
  }
  if (c >= 'A' && c <= 'Z') {
    return (char)(c - 'A' + 'a');
  }
  return c;
}

static int contains_ci(const char *s, const char *needle) {
  size_t nn;
  if (!s || !needle || !needle[0]) {
    return 0;
  }
  nn = strlen(needle);
  for (; *s; s++) {
    size_t i = 0u;
    while (i < nn && s[i] && fold_ascii(s[i]) == fold_ascii(needle[i])) {
      i++;
    }
    if (i == nn) {
      return 1;
    }
  }
  return 0;
}

static const char *find_ci(const char *s, const char *needle) {
  size_t nn;
  if (!s || !needle || !needle[0]) {
    return NULL;
  }
  nn = strlen(needle);
  for (; *s; s++) {
    size_t i = 0u;
    while (i < nn && s[i] && fold_ascii(s[i]) == fold_ascii(needle[i])) {
      i++;
    }
    if (i == nn) {
      return s;
    }
  }
  return NULL;
}

static uint64_t fnv64_update_folded_token(uint64_t h, const char *s, size_t max_n) {
  size_t i;
  if (!s) {
    return h;
  }
  for (i = 0; s[i] && i < max_n; i++) {
    char c = s[i];
    if (c == '\r' || c == '\n' || c == '\t' || c == ' ' || c == ';' || c == ',') {
      break;
    }
    c = fold_ascii(c);
    h ^= (uint64_t)(unsigned char)c;
    h *= 1099511628211ULL;
  }
  return h;
}

static uint64_t fnv64_update_folded_line(uint64_t h, const char *s, size_t max_n) {
  size_t i;
  int last_space = 0;
  if (!s) {
    return h;
  }
  for (i = 0; s[i] && i < max_n; i++) {
    char c = s[i];
    if (c == '\r' || c == '\n') {
      break;
    }
    if (c == '\t' || c == ' ') {
      if (last_space) {
        continue;
      }
      c = ' ';
      last_space = 1;
    } else {
      c = fold_ascii(c);
      last_space = 0;
    }
    h ^= (uint64_t)(unsigned char)c;
    h *= 1099511628211ULL;
  }
  return h;
}

static int append_field_value_ci(uint64_t *h, const char *s, const char *key, size_t max_n) {
  const char *p = find_ci(s, key);
  if (!h || !p) {
    return 0;
  }
  p += strlen(key);
  *h = fnv64_update(*h, (const unsigned char *)key, strlen(key));
  *h = fnv64_update_folded_token(*h, p, max_n);
  *h ^= 0xA5ULL;
  return 1;
}

static int append_field_line_ci(uint64_t *h, const char *s, const char *key, size_t max_n) {
  const char *p = find_ci(s, key);
  if (!h || !p) {
    return 0;
  }
  p += strlen(key);
  *h = fnv64_update(*h, (const unsigned char *)key, strlen(key));
  *h = fnv64_update_folded_line(*h, p, max_n);
  *h ^= 0x5AULL;
  return 1;
}

static int append_raw_line(uint64_t *h, const char *label, const char *s, size_t max_n) {
  if (!h || !s || !s[0]) {
    return 0;
  }
  if (label && label[0]) {
    *h = fnv64_update(*h, (const unsigned char *)label, strlen(label));
  }
  *h = fnv64_update_folded_line(*h, s, max_n);
  *h ^= 0x3CULL;
  return 1;
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

static uint32_t script_sensor_window_s(void) {
  const char *v = getenv("EDR_SCRIPT_SENSOR_DEDUP_WINDOW_S");
  unsigned long out = EDR_SCRIPT_SENSOR_DEDUP_DEFAULT_WINDOW_S;
  if (v && v[0]) {
    out = strtoul(v, NULL, 10);
  }
  if (out > 300UL) {
    out = 300UL;
  }
  return (uint32_t)out;
}

static uint64_t script_sensor_dedup_key(const EdrBehaviorRecord *r) {
  const char *s;
  uint64_t h;
  int has_stable_id = 0;
  int has_content = 0;
  if (!r || !(r->type == EDR_EVENT_SCRIPT_POWERSHELL || r->type == EDR_EVENT_SCRIPT_WMI)) {
    return 0u;
  }
  s = r->script_snippet[0] ? r->script_snippet : r->cmdline;
  if (!s || !s[0]) {
    return 0u;
  }
  if (!(contains_ci(s, "sensor=scriptblock") || contains_ci(s, "sensor=amsi") ||
        contains_ci(s, "provider=Microsoft-Windows-PowerShell") ||
        contains_ci(s, "provider=Microsoft-Antimalware-Scan-Interface"))) {
    return 0u;
  }
  h = 14695981039346656037ULL;
  h ^= (uint64_t)r->pid;
  h *= 1099511628211ULL;
  h ^= (uint64_t)r->type;
  h *= 1099511628211ULL;
  if (contains_ci(s, "sensor=amsi") ||
      contains_ci(s, "provider=Microsoft-Antimalware-Scan-Interface")) {
    h = fnv64_update(h, (const unsigned char *)"amsi", 4u);
  } else {
    h = fnv64_update(h, (const unsigned char *)"scriptblock", 11u);
  }
  has_content |= append_field_line_ci(&h, s, "script=", 2048u);
  has_content |= append_field_line_ci(&h, s, "script_content=", 2048u);
  has_content |= append_field_line_ci(&h, s, "script_text=", 2048u);
  has_content |= append_field_line_ci(&h, s, "amsi_content=", 2048u);
  has_content |= append_field_value_ci(&h, s, "script_hash=", 128u);
  if (!has_content) {
    has_content |= append_raw_line(&h, "cmdline=", r->cmdline, 1024u);
  }
  if (!has_content) {
    has_stable_id |= append_field_value_ci(&h, s, "scriptblock_id=", 128u);
    has_stable_id |= append_field_value_ci(&h, s, "amsi_session=", 128u);
  }
  if (!has_content && !has_stable_id) {
    h = fnv64_update_folded_token(h, s, 512u);
  }
  return h ? h : 1u;
}

static int script_sensor_dedup_allow(const EdrBehaviorRecord *r) {
  uint64_t k = script_sensor_dedup_key(r);
  uint64_t window_ns;
  int64_t t;
  uint64_t now;
  uint32_t idx;
  if (k == 0u) {
    return 1;
  }
  window_ns = (uint64_t)script_sensor_window_s() * 1000000000ULL;
  if (window_ns == 0u) {
    return 1;
  }
  t = r->event_time_ns;
  now = (uint64_t)(t < 0 ? 0 : t);
  idx = (uint32_t)(k & (EDR_SCRIPT_SENSOR_DEDUP_SLOTS - 1u));
  for (size_t probe = 0; probe < 16u; probe++) {
    uint32_t i = (idx + (uint32_t)probe) & (EDR_SCRIPT_SENSOR_DEDUP_SLOTS - 1u);
    DedupSlot *sl = &s_script_sensor_dedup[i];
    int empty = (sl->key == 0u && sl->last_ns == 0u);
    int expired = (!empty && (now - sl->last_ns >= window_ns));
    if (empty || expired) {
      sl->key = k;
      sl->last_ns = now;
      return 1;
    }
    if (sl->key == k) {
      if (now - sl->last_ns < window_ns) {
        s_stat_dedup_drop++;
        return 0;
      }
      sl->last_ns = now;
      return 1;
    }
  }
  return 1;
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
  memset(s_script_sensor_dedup, 0, sizeof(s_script_sensor_dedup));
  memset(s_rate, 0, sizeof(s_rate));
  s_stat_dedup_drop = 0;
  s_stat_rate_drop = 0;
}

int edr_preprocess_should_emit(const EdrBehaviorRecord *r) {
  int rr;
  if (!r) {
    return 0;
  }
  rr = edr_emit_rules_evaluate(r);
  if (rr == 0) {
    return 0;
  }
  if (!edr_windows_event_policy_should_emit(r)) {
    return 0;
  }
  if (!script_sensor_dedup_allow(r)) {
    return 0;
  }
  if (r->priority == 0u || rr == 1) {
    return 1;
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
