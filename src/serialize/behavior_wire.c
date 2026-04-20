#include "edr/behavior_record.h"
#include "edr/behavior_wire.h"

#include <string.h>

static size_t edr_strnlen_l(const char *s, size_t max) {
  size_t i;
  for (i = 0; i < max && s[i]; i++) {
  }
  return i;
}

#pragma pack(push, 1)
typedef struct {
  uint32_t magic;
  uint16_t version;
  uint16_t reserved;
  uint32_t event_type;
  int64_t event_time_ns;
  uint32_t pid;
  uint32_t ppid;
  uint32_t priority;
  uint32_t session_id;
  uint32_t net_sport;
  uint32_t net_dport;
  uint8_t mitre_count;
  uint8_t pad[3];
} EdrWireHdr;
#pragma pack(pop)

static uint8_t *wr_u16_str(uint8_t *p, uint8_t *end, const char *s) {
  size_t L = strlen(s);
  if (L > 65535u) {
    L = 65535u;
  }
  if (p + 2 + L > end) {
    return NULL;
  }
  p[0] = (uint8_t)(L & 0xffu);
  p[1] = (uint8_t)((L >> 8) & 0xffu);
  p += 2;
  if (L > 0) {
    memcpy(p, s, L);
    p += L;
  }
  return p;
}

size_t edr_behavior_wire_encode(const EdrBehaviorRecord *r, uint8_t *out, size_t out_cap) {
  if (!r || !out || out_cap < sizeof(EdrWireHdr) + 16u) {
    return 0;
  }

  int mc = r->mitre_ttp_count;
  if (mc < 0) {
    mc = 0;
  }
  if (mc > (int)EDR_BR_MAX_MITRE) {
    mc = (int)EDR_BR_MAX_MITRE;
  }

  size_t need = sizeof(EdrWireHdr) + (size_t)mc * 16u;
  const char *fields[] = {
      r->event_id,     r->endpoint_id, r->tenant_id,   r->process_name, r->cmdline,
      r->exe_path,     r->username,    r->parent_name, r->parent_path,  r->file_op,
      r->file_path,    r->net_src,     r->net_dst,     r->dns_query,    r->script_snippet,
      r->pmfe_snapshot,
  };
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    size_t L = strlen(fields[i]);
    if (L > 65535u) {
      L = 65535u;
    }
    need += 2u + L;
  }

  if (need > out_cap) {
    return 0;
  }

  EdrWireHdr *h = (EdrWireHdr *)out;
  memset(h, 0, sizeof(*h));
  h->magic = EDR_BEHAVIOR_WIRE_MAGIC;
  h->version = (uint16_t)EDR_BEHAVIOR_WIRE_VER;
  h->event_type = (uint32_t)r->type;
  h->event_time_ns = r->event_time_ns;
  h->pid = r->pid;
  h->ppid = r->ppid;
  h->priority = r->priority;
  h->session_id = r->session_id;
  h->net_sport = r->net_sport;
  h->net_dport = r->net_dport;
  h->mitre_count = (uint8_t)mc;

  uint8_t *p = out + sizeof(EdrWireHdr);
  uint8_t *end = out + out_cap;
  {
    int j;
    for (j = 0; j < mc; j++) {
      memset(p, 0, 16u);
      size_t ml = edr_strnlen_l(r->mitre_ttps[j], 15u);
      memcpy(p, r->mitre_ttps[j], ml);
      p += 16u;
    }
  }
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    uint8_t *n = wr_u16_str(p, end, fields[i]);
    if (!n) {
      return 0;
    }
    p = n;
  }
  return (size_t)(p - out);
}
