/*
 * P0 直出：与 edr-backend/platform/config/p0_golden_vectors.json + dynamicrules 对拍（CI：
 * validate_p0_golden_vectors.py、go test TestP0RuleGolden_FromManifest）。改 C 端匹配时务必同步
 * 向量与 Go 测试，并跑 edr-backend/scripts/verify_p0_bundle_version_alignment.sh。
 */
#include "edr/p0_rule_direct_emit.h"
#include "edr/p0_rule_match.h"
#include "edr/p0_rule_ir.h"

#include "edr/ave_sdk.h"
#include "edr/behavior_alert_emit.h"
#include "edr/behavior_record.h"
#include "edr/types.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <time.h>
#endif

#ifndef EDR_P0_RULES_BUNDLE_VERSION
#define EDR_P0_RULES_BUNDLE_VERSION "edr-dynamic-rules-v1-r218-9ae52519"
#endif

/* 同一 (rule_id, endpoint_id, pid) 在窗口内不重复上送，减轻 alerts 与批次洪泛（B2.3） */
#define P0_DEDUP_SLOTS 32u
struct p0_dedup_slot {
  char rule_id[24];
  char endpoint_id[EDR_BR_ID_LEN];
  uint32_t pid;
  uint64_t last_ms;
};
static struct p0_dedup_slot s_p0_dedup[P0_DEDUP_SLOTS];
static uint32_t s_p0_dedup_next;

/* 全进程滑动 60s 内 BehaviorAlert 直出条数上限（B2.3）；未设置或 0=不限制 */
static uint64_t s_p0_gwin_start_ms;
static uint32_t s_p0_gcount;

/* 每 tenant_id 独立滑动 60s 内直出条数（B2.3）；与全局上限叠加；未设置时默认 60/分；0=不限制 */
#define P0_TENANT_RATE_SLOTS 32u
struct p0_tenant_rate_slot {
  char tenant[64];
  uint64_t win_start_ms;
  uint32_t count;
};
static struct p0_tenant_rate_slot s_tenant_rate[P0_TENANT_RATE_SLOTS];
static uint32_t s_tenant_rate_next;

/* 每 endpoint_id 独立滑动 60s 内直出条数；未设置时默认 0=不限制（B2.3 可选，与全局限流/tenant 叠加） */
#define P0_EP_RATE_SLOTS 64u
struct p0_ep_rate_slot {
  char ep[EDR_BR_ID_LEN];
  uint64_t win_start_ms;
  uint32_t count;
};
static struct p0_ep_rate_slot s_ep_rate[P0_EP_RATE_SLOTS];
static uint32_t s_ep_rate_next;

static uint64_t p0_monotonic_ms(void) {
#if defined(_WIN32)
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
#endif
}

/* 若允许上送则占槽并返回 1；在冷却窗口内返回 0。EDR_P0_DEDUP_SEC=0 关闭。默认 2 秒。 */
static int p0_dedup_allow(const char *rule_id, const EdrBehaviorRecord *br) {
  const char *v = getenv("EDR_P0_DEDUP_SEC");
  if (v && (v[0] == '0' && (v[1] == 0 || v[1] == ' '))) {
    return 1;
  }
  unsigned long win_sec = 2;
  if (v && *v) {
    win_sec = strtoul(v, NULL, 10);
  }
  if (win_sec == 0) {
    return 1;
  }
  uint64_t window_ms = win_sec * 1000u;
  uint64_t now = p0_monotonic_ms();
  if (now == 0) {
    return 1;
  }
  for (uint32_t i = 0; i < P0_DEDUP_SLOTS; i++) {
    if (s_p0_dedup[i].pid == br->pid && strcmp(s_p0_dedup[i].rule_id, rule_id) == 0 &&
        strcmp(s_p0_dedup[i].endpoint_id, br->endpoint_id) == 0) {
      if (now < s_p0_dedup[i].last_ms + window_ms) {
        return 0;
      }
      s_p0_dedup[i].last_ms = now;
      return 1;
    }
  }
  struct p0_dedup_slot *s = &s_p0_dedup[s_p0_dedup_next % P0_DEDUP_SLOTS];
  s_p0_dedup_next++;
  snprintf(s->rule_id, sizeof(s->rule_id), "%s", rule_id ? rule_id : "");
  snprintf(s->endpoint_id, sizeof(s->endpoint_id), "%s", br->endpoint_id);
  s->pid = br->pid;
  s->last_ms = now;
  return 1;
}

static unsigned long p0_max_emits_per_min(void) {
  const char *e = getenv("EDR_P0_MAX_EMITS_PER_MIN");
  if (!e || !*e) {
    return 0;
  }
  return strtoul(e, NULL, 10);
}

/* 在即将上送前调用：本分钟内是否未超上限（不修改计数，仅滚动窗口） */
static int p0_global_rate_ok(void) {
  unsigned long cap = p0_max_emits_per_min();
  if (cap == 0) {
    return 1;
  }
  uint64_t now = p0_monotonic_ms();
  if (now == 0) {
    return 1;
  }
  if (s_p0_gwin_start_ms == 0u || (now - s_p0_gwin_start_ms) >= 60000ull) {
    s_p0_gwin_start_ms = now;
    s_p0_gcount = 0u;
  }
  return (uint64_t)s_p0_gcount < (uint64_t)cap;
}

static void p0_global_rate_bump(void) {
  if (p0_max_emits_per_min() == 0) {
    return;
  }
  s_p0_gcount++;
}

static unsigned long p0_tenant_max_emits_per_min(void) {
  const char *e = getenv("EDR_P0_MAX_EMITS_PER_MIN_PER_TENANT");
  if (!e || !*e) {
    return 60u;
  }
  return strtoul(e, NULL, 10);
}

/* 返回匹配 tenant 的槽；无则占一轮换槽。tenant 全空时统一按 "" 桶 */
static struct p0_tenant_rate_slot *p0_tenant_rate_slot(const char *tid) {
  const char *t = (tid && tid[0]) ? tid : "";
  for (uint32_t i = 0; i < P0_TENANT_RATE_SLOTS; i++) {
    if (strcmp(s_tenant_rate[i].tenant, t) == 0) {
      return &s_tenant_rate[i];
    }
  }
  struct p0_tenant_rate_slot *s = &s_tenant_rate[s_tenant_rate_next % P0_TENANT_RATE_SLOTS];
  s_tenant_rate_next++;
  memset(s, 0, sizeof(*s));
  snprintf(s->tenant, sizeof(s->tenant), "%s", t);
  return s;
}

static int p0_tenant_rate_ok(const char *tid) {
  unsigned long cap = p0_tenant_max_emits_per_min();
  if (cap == 0) {
    return 1;
  }
  uint64_t now = p0_monotonic_ms();
  if (now == 0) {
    return 1;
  }
  struct p0_tenant_rate_slot *s = p0_tenant_rate_slot(tid);
  if (s->win_start_ms == 0u || (now - s->win_start_ms) >= 60000ull) {
    s->win_start_ms = now;
    s->count = 0u;
  }
  return (uint64_t)s->count < (uint64_t)cap;
}

static void p0_tenant_rate_bump(const char *tid) {
  if (p0_tenant_max_emits_per_min() == 0) {
    return;
  }
  uint64_t now = p0_monotonic_ms();
  if (now == 0) {
    return;
  }
  struct p0_tenant_rate_slot *s = p0_tenant_rate_slot(tid);
  if (s->win_start_ms == 0u || (now - s->win_start_ms) >= 60000ull) {
    s->win_start_ms = now;
    s->count = 0u;
  }
  s->count++;
}

static unsigned long p0_ep_max_emits_per_min(void) {
  const char *e = getenv("EDR_P0_MAX_EMITS_PER_MIN_PER_ENDPOINT");
  if (!e || !*e) {
    return 0u;
  }
  return strtoul(e, NULL, 10);
}

static struct p0_ep_rate_slot *p0_ep_rate_slot(const char *ep) {
  const char *e = (ep && ep[0]) ? ep : "";
  for (uint32_t i = 0; i < P0_EP_RATE_SLOTS; i++) {
    if (strcmp(s_ep_rate[i].ep, e) == 0) {
      return &s_ep_rate[i];
    }
  }
  struct p0_ep_rate_slot *s = &s_ep_rate[s_ep_rate_next % P0_EP_RATE_SLOTS];
  s_ep_rate_next++;
  memset(s, 0, sizeof(*s));
  snprintf(s->ep, sizeof(s->ep), "%s", e);
  return s;
}

static int p0_ep_rate_ok(const char *ep) {
  unsigned long cap = p0_ep_max_emits_per_min();
  if (cap == 0) {
    return 1;
  }
  uint64_t now = p0_monotonic_ms();
  if (now == 0) {
    return 1;
  }
  struct p0_ep_rate_slot *s = p0_ep_rate_slot(ep);
  if (s->win_start_ms == 0u || (now - s->win_start_ms) >= 60000ull) {
    s->win_start_ms = now;
    s->count = 0u;
  }
  return (uint64_t)s->count < (uint64_t)cap;
}

static void p0_ep_rate_bump(const char *ep) {
  if (p0_ep_max_emits_per_min() == 0) {
    return;
  }
  uint64_t now = p0_monotonic_ms();
  if (now == 0) {
    return;
  }
  struct p0_ep_rate_slot *s = p0_ep_rate_slot(ep);
  if (s->win_start_ms == 0u || (now - s->win_start_ms) >= 60000ull) {
    s->win_start_ms = now;
    s->count = 0u;
  }
  s->count++;
}

static int getenv_int01(const char *k) {
  const char *v = getenv(k);
  return (v && v[0] == '1' && (v[1] == 0 || v[1] == ' ')) ? 1 : 0;
}

static float sev3_anomaly(void) { return 0.40f + 0.10f * 3.0f; }

static int emit_for_rule(const EdrBehaviorRecord *br, const char *rule_id, const char *title,
                        const char *mitre_comma) {
  if (!p0_global_rate_ok()) {
    return 0;
  }
  if (!p0_tenant_rate_ok(br->tenant_id)) {
    return 0;
  }
  if (!p0_ep_rate_ok(br->endpoint_id)) {
    return 0;
  }
  if (!p0_dedup_allow(rule_id, br)) {
    return 0;
  }
  AVEBehaviorAlert a;
  memset(&a, 0, sizeof(a));
  a.pid = br->pid;
  a.timestamp_ns = br->event_time_ns;
  snprintf(a.process_name, sizeof(a.process_name), "%s", br->process_name);
  snprintf(a.process_path, sizeof(a.process_path), "%s", br->exe_path);
  a.anomaly_score = sev3_anomaly();
  snprintf(a.triggered_tactics, sizeof(a.triggered_tactics), "%s", mitre_comma);
  a.skip_ai_analysis = true;
  a.needs_l2_review = false;

  /* related_iocs_json 留空；元数据在 user_subject_json */
  {
    int n = snprintf(
        a.user_subject_json, sizeof(a.user_subject_json),
        "{\"subject_type\":\"edr_dynamic_rule\",\"rule_id\":\"%s\",\"rules_bundle_version\":\"%s\","
        "\"display_title\":\"%s\"}",
        rule_id, EDR_P0_RULES_BUNDLE_VERSION, title);
    if (n < 0 || (size_t)n >= sizeof(a.user_subject_json)) {
      a.user_subject_json[0] = 0;
      return 0;
    }
  }
  edr_behavior_alert_emit_to_batch(&a);
  p0_global_rate_bump();
  p0_tenant_rate_bump(br->tenant_id);
  p0_ep_rate_bump(br->endpoint_id);
  return 1;
}

void edr_p0_rule_try_emit(const EdrBehaviorRecord *br) {
  if (!br) {
    return;
  }
  if (!getenv_int01("EDR_P0_DIRECT_EMIT")) {
    return;
  }
  const char *cmd = br->cmdline;
  const char *pn = br->process_name;
  const char *par = br->parent_name[0] ? br->parent_name : NULL;
  int ch = (int)br->process_chain_depth;
  edr_p0_rule_ir_lazy_init();
  if (edr_p0_rule_ir_is_ready()) {
    int i;
    int n = edr_p0_rule_ir_rule_count();
    for (i = 0; i < n; i++) {
      if (!edr_p0_rule_ir_br_matches_index(br, i)) {
        continue;
      }
      const char *rid = NULL;
      if (!edr_p0_rule_ir_rule_id_at(i, &rid) || !rid) {
        continue;
      }
      const char *title = NULL;
      const char *mitre = NULL;
      (void)edr_p0_rule_ir_get_meta(rid, &title, &mitre);
      (void)emit_for_rule(
          br, rid, (title && title[0]) ? title : rid, (mitre && mitre[0]) ? mitre : ""
      );
    }
  } else {
    if (br->type != EDR_EVENT_PROCESS_CREATE) {
      return;
    }
    if (edr_p0_rule_matches3("R-EXEC-001", pn, cmd, par, ch)) {
      (void)emit_for_rule(br, "R-EXEC-001", "PowerShell 编码命令执行", "T1059.001");
    }
    if (edr_p0_rule_matches3("R-CRED-001", pn, cmd, par, ch)) {
      (void)emit_for_rule(br, "R-CRED-001", "导出 SAM/SYSTEM/SECURITY", "T1003.002");
    }
    if (edr_p0_rule_matches3("R-FILELESS-001", pn, cmd, par, ch)) {
      (void)emit_for_rule(br, "R-FILELESS-001", "PowerShell 反射/IEX 无文件执行特征", "T1059.001,T1027");
    }
  }
}
