/* P0 优化 #2：流级首段扫描去重 —— 见 include/edr/flow_dedup.h */

#include "edr/flow_dedup.h"

#include <stdlib.h>
#include <string.h>

/* 槽位陈旧阈值：超过该时长未命中的连接可被新流直接复用（120s，覆盖正常会话起止）。 */
#define EDR_FLOW_STALE_NS (120ULL * 1000000000ULL)

typedef struct {
  uint8_t used;
  EdrFlowKey key;
  uint32_t scanned_bytes;
  uint64_t last_ns;
} FlowSlot;

struct EdrFlowTable {
  FlowSlot *slots;
  uint32_t mask; /* slot_count - 1（slot_count 为 2 的幂） */
};

uint32_t edr_flow_hash_str(const char *s) {
  uint32_t h = 2166136261u;
  if (!s) {
    return h;
  }
  for (; *s; s++) {
    h ^= (unsigned char)*s;
    h *= 16777619u;
  }
  return h;
}

void edr_flow_key_make(EdrFlowKey *out, uint32_t src_hash, uint16_t src_port, uint32_t dst_hash, uint16_t dst_port) {
  if (!out) {
    return;
  }
  /* 规范化：按 (hash,port) 排序两端，使双向同一连接映射到同一键。 */
  int swap;
  if (src_hash != dst_hash) {
    swap = (src_hash > dst_hash);
  } else {
    swap = (src_port > dst_port);
  }
  if (swap) {
    out->ha = dst_hash;
    out->pa = dst_port;
    out->hb = src_hash;
    out->pb = src_port;
  } else {
    out->ha = src_hash;
    out->pa = src_port;
    out->hb = dst_hash;
    out->pb = dst_port;
  }
}

static uint32_t key_index(const EdrFlowKey *k, uint32_t mask) {
  uint32_t h = 2166136261u;
  h = (h ^ k->ha) * 16777619u;
  h = (h ^ k->hb) * 16777619u;
  h = (h ^ k->pa) * 16777619u;
  h = (h ^ k->pb) * 16777619u;
  return h & mask;
}

static int key_eq(const EdrFlowKey *a, const EdrFlowKey *b) {
  return a->ha == b->ha && a->hb == b->hb && a->pa == b->pa && a->pb == b->pb;
}

EdrFlowTable *edr_flow_table_create(uint32_t slots) {
  uint32_t n = 64u;
  while (n < slots && n < (1u << 20)) {
    n <<= 1;
  }
  EdrFlowTable *t = (EdrFlowTable *)calloc(1, sizeof(*t));
  if (!t) {
    return NULL;
  }
  t->slots = (FlowSlot *)calloc(n, sizeof(FlowSlot));
  if (!t->slots) {
    free(t);
    return NULL;
  }
  t->mask = n - 1u;
  return t;
}

void edr_flow_table_destroy(EdrFlowTable *t) {
  if (!t) {
    return;
  }
  free(t->slots);
  free(t);
}

int edr_flow_table_admit(EdrFlowTable *t, const EdrFlowKey *k, uint32_t payload_len, uint32_t budget_bytes,
                         uint64_t now_ns) {
  if (!t || !k) {
    return 1; /* 无表则不去重，始终深扫 */
  }
  if (budget_bytes == 0u) {
    return 1; /* 不限：等价旧行为 */
  }
  FlowSlot *s = &t->slots[key_index(k, t->mask)];
  int stale = s->used && (now_ns > s->last_ns) && (now_ns - s->last_ns) > EDR_FLOW_STALE_NS;
  if (s->used && !stale && key_eq(&s->key, k)) {
    s->last_ns = now_ns;
    if (s->scanned_bytes >= budget_bytes) {
      return 0; /* 预算用尽，跳过深扫 */
    }
    s->scanned_bytes += payload_len;
    return 1;
  }
  /* 未命中 / 碰撞 / 陈旧 —— 占用槽位，重置计数（过扫安全，不会漏扫会话起始）。 */
  s->used = 1u;
  s->key = *k;
  s->scanned_bytes = payload_len;
  s->last_ns = now_ns;
  return 1;
}

int edr_token_bucket_admit(EdrTokenBucket *tb, uint32_t per_sec, uint64_t now_ns) {
  if (!tb) {
    return 1;
  }
  if (per_sec == 0u) {
    return 1; /* 不限速 */
  }
  const double cap = (double)per_sec; /* 1 秒突发容量 */
  if (tb->last_ns == 0u) {
    tb->last_ns = now_ns;
    tb->tokens = cap;
  } else if (now_ns > tb->last_ns) {
    double elapsed = (double)(now_ns - tb->last_ns) / 1e9;
    tb->tokens += elapsed * (double)per_sec;
    tb->last_ns = now_ns;
    if (tb->tokens > cap) {
      tb->tokens = cap;
    }
  }
  if (tb->tokens >= 1.0) {
    tb->tokens -= 1.0;
    return 1;
  }
  return 0;
}
