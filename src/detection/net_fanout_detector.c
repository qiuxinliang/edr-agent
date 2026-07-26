/* 端侧网络扇出/扫描检测器 —— agent 集成(文件内单例)。见 net_fanout_detector.h */

#include "net_fanout_internal.h"

#include "edr/behavior_alert_emit.h"
#include "edr/behavior_record.h"
#include "edr/config.h"
#include "edr/resource.h"
#include "edr/time_util.h"
#include "edr/types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static EdrNetFanoutState *s_inst;

static unsigned long nf_env_ulong(const char *name, unsigned long defv) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return defv;
  }
  char *end = NULL;
  unsigned long x = strtoul(v, &end, 10);
  return end == v ? defv : x;
}

static void nf_parse_ports(const char *csv, EdrNetFanoutCfg *cfg) {
  static const uint16_t kDefault[] = {445, 139, 3389, 22, 135, 5985, 1433, 3306, 23, 5432};
  cfg->n_ports = 0;
  if (!csv || !csv[0]) {
    for (size_t i = 0; i < sizeof(kDefault) / sizeof(kDefault[0]) && cfg->n_ports < 32; i++) {
      cfg->ports[cfg->n_ports++] = kDefault[i];
    }
    return;
  }
  const char *p = csv;
  while (*p && cfg->n_ports < 32) {
    while (*p == ' ' || *p == ',') {
      p++;
    }
    if (!*p) {
      break;
    }
    char *end = NULL;
    unsigned long v = strtoul(p, &end, 10);
    if (end == p) {
      break;
    }
    if (v > 0 && v <= 65535) {
      cfg->ports[cfg->n_ports++] = (uint16_t)v;
    }
    p = end;
  }
  if (cfg->n_ports == 0) {
    for (size_t i = 0; i < sizeof(kDefault) / sizeof(kDefault[0]) && cfg->n_ports < 32; i++) {
      cfg->ports[cfg->n_ports++] = kDefault[i];
    }
  }
}

EdrError edr_net_fanout_init(const EdrConfig *cfg) {
  if (s_inst) {
    return EDR_OK;
  }
  int enabled = (cfg && cfg->net_fanout.enabled) ? 1 : 0;
  const char *env = getenv("EDR_NET_FANOUT_ENABLE");
  if (env && env[0]) {
    enabled = (env[0] == '1') ? 1 : 0;
  }
  if (!enabled) {
    return EDR_OK;
  }
  EdrNetFanoutCfg fc;
  memset(&fc, 0, sizeof(fc));
  fc.window_s = (uint32_t)nf_env_ulong("EDR_NET_FANOUT_WINDOW_S", cfg ? cfg->net_fanout.window_s : 120u);
  fc.distinct_ip_threshold =
      (uint32_t)nf_env_ulong("EDR_NET_FANOUT_THRESHOLD", cfg ? cfg->net_fanout.distinct_ip_threshold : 50u);
  const char *ports_env = getenv("EDR_NET_FANOUT_PORTS");
  nf_parse_ports(ports_env ? ports_env : (cfg ? cfg->net_fanout.ports : ""), &fc);
  s_inst = edr_net_fanout_state_create(&fc);
  if (!s_inst) {
    return EDR_ERR_INTERNAL;
  }
  fprintf(stderr, "[net_fanout] enabled window=%us threshold=%u ports=%d\n", fc.window_s, fc.distinct_ip_threshold,
          fc.n_ports);
  return EDR_OK;
}

void edr_net_fanout_on_event(const EdrBehaviorRecord *br) {
  if (!s_inst || !br || br->type != EDR_EVENT_NET_CONNECT) {
    return;
  }
  if (br->net_dport == 0u || br->net_dst[0] == '\0') {
    return;
  }
  if (edr_resource_preprocess_throttle_active()) {
    return; /* 资源压力下不累计 */
  }
  uint64_t now = br->event_time_ns ? (uint64_t)br->event_time_ns : edr_monotonic_ns();
  int distinct = edr_net_fanout_observe(s_inst, br->pid, (uint16_t)br->net_dport, br->net_dst, now);
  if (distinct <= 0) {
    return;
  }
  AVEBehaviorAlert a;
  memset(&a, 0, sizeof(a));
  a.pid = br->pid;
  snprintf(a.process_name, sizeof(a.process_name), "%s", br->process_name);
  snprintf(a.process_path, sizeof(a.process_path), "%s", br->exe_path);
  a.anomaly_score = 0.8f;
  a.needs_l2_review = true;
  a.timestamp_ns = br->event_time_ns;
  snprintf(a.triggered_tactics, sizeof(a.triggered_tactics), "%s", "T1046,T1018");
  snprintf(a.related_iocs_json, sizeof(a.related_iocs_json),
           "{\"detector\":\"net_fanout\",\"dport\":%u,\"distinct_ips\":%d,\"window_s\":%u}",
           (unsigned)br->net_dport, distinct, s_inst->cfg.window_s);
  edr_behavior_alert_emit_to_batch(&a);
  fprintf(stderr, "[net_fanout] scan/fanout: pid=%u proc=%s dport=%u distinct_ips=%d\n", br->pid, br->process_name,
          (unsigned)br->net_dport, distinct);
}

void edr_net_fanout_shutdown(void) {
  if (s_inst) {
    edr_net_fanout_state_destroy(s_inst);
    s_inst = NULL;
  }
}
