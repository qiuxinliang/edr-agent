/* 端侧网络扇出/扫描检测器 —— 可测核心(不依赖 agent 全局)。见 net_fanout_detector.h */

#include "net_fanout_internal.h"

#include <stdlib.h>
#include <string.h>

static uint32_t nf_fnv32(const char *s) {
  uint32_t h = 2166136261u;
  if (!s) {
    return h;
  }
  for (; *s; s++) {
    h ^= (unsigned char)*s;
    h *= 16777619u;
  }
  return h ? h : 1u; /* 0 保留为空槽标记 */
}

static int nf_port_match(const EdrNetFanoutCfg *c, uint16_t dport) {
  if (c->n_ports <= 0) {
    return 1; /* 不限端口 */
  }
  for (int i = 0; i < c->n_ports && i < 32; i++) {
    if (c->ports[i] == dport) {
      return 1;
    }
  }
  return 0;
}

/* 返回 1=新增 IP,0=已存在/集满。 */
static int nf_ipset_add(NfBucket *b, uint32_t h) {
  uint32_t idx = h % EDR_NF_IPSET;
  for (uint32_t i = 0; i < EDR_NF_IPSET; i++) {
    uint32_t slot = (idx + i) % EDR_NF_IPSET;
    if (b->ipset[slot] == 0u) {
      b->ipset[slot] = h;
      return 1;
    }
    if (b->ipset[slot] == h) {
      return 0; /* 已存在 */
    }
  }
  return 0; /* 集满(distinct 已远超阈值) */
}

EdrNetFanoutState *edr_net_fanout_state_create(const EdrNetFanoutCfg *cfg) {
  if (!cfg) {
    return NULL;
  }
  EdrNetFanoutState *s = (EdrNetFanoutState *)calloc(1, sizeof(*s));
  if (!s) {
    return NULL;
  }
  s->cfg = *cfg;
  if (s->cfg.window_s == 0u) {
    s->cfg.window_s = 120u;
  }
  if (s->cfg.distinct_ip_threshold == 0u) {
    s->cfg.distinct_ip_threshold = 50u;
  }
  s->window_ns = (uint64_t)s->cfg.window_s * 1000000000ull;
  return s;
}

void edr_net_fanout_state_destroy(EdrNetFanoutState *s) { free(s); }

int edr_net_fanout_observe(EdrNetFanoutState *s, uint32_t pid, uint16_t dport, const char *dst_ip, uint64_t now_ns) {
  if (!s || !dst_ip || !dst_ip[0]) {
    return 0;
  }
  if (!nf_port_match(&s->cfg, dport)) {
    return 0;
  }
  uint32_t key = (pid * 2654435761u) ^ ((uint32_t)dport * 40503u);
  NfBucket *b = &s->buckets[key % EDR_NF_BUCKETS];
  int expired = b->used && (now_ns > b->window_start_ns) && (now_ns - b->window_start_ns > s->window_ns);
  if (!b->used || expired || b->pid != pid || b->dport != dport) {
    /* 新建/重置该桶(窗口过期、碰撞或首次) */
    memset(b, 0, sizeof(*b));
    b->used = 1u;
    b->pid = pid;
    b->dport = dport;
    b->window_start_ns = now_ns;
  }
  if (nf_ipset_add(b, nf_fnv32(dst_ip))) {
    b->distinct++;
  }
  if (!b->alerted && b->distinct >= s->cfg.distinct_ip_threshold) {
    b->alerted = 1u;
    return (int)b->distinct; /* 刚跨阈值 → 返回 distinct 数(供产警) */
  }
  return 0;
}
