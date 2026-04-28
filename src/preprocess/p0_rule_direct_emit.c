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
#include "edr/enrich_parent_info.h"

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

/* 若允许上送则占槽并返回 1；在冷却窗口内返回 0。EDR_P0_DEDUP_SEC=0 关闭。默认 10 秒（放宽以支持测试）。 */
static int p0_dedup_allow(const char *rule_id, const EdrBehaviorRecord *br) {
  const char *v = getenv("EDR_P0_DEDUP_SEC");
  if (v && (v[0] == '0' && (v[1] == 0 || v[1] == ' '))) {
    return 1;
  }
  unsigned long win_sec = 10;
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

static int getenv_int01_disabled_on_zero(const char *k) {
  const char *v = getenv(k);
  if (!v || v[0] == '\0') {
    return 1;
  }
  if ((v[0] == '0' || v[0] == 'O' || v[0] == 'o') && (v[1] == '\0' || v[1] == ' ' || v[1] == '\n')) {
    return 0;
  }
  if ((v[0] == '1' || v[0] == 'I' || v[0] == 'i') && (v[1] == '\0' || v[1] == ' ' || v[1] == '\n')) {
    return 1;
  }
  if (v[0] == 'N' || v[0] == 'n') {
    return 0;
  }
  return 1;
}

static float sev3_anomaly(void) { return 0.40f + 0.10f * 3.0f; }

/**
 * RFC 8259 JSON string escape into out. max_in caps raw input bytes (0 = use full C string until NUL).
 * Returns 1 on success; 0 if output buffer too small — caller should treat as empty string.
 */
static int p0_json_escape(const char *in, char *out, size_t out_cap, size_t max_in) {
  if (!out || out_cap < 2u) {
    return 0;
  }
  if (!in) {
    in = "";
  }
  size_t lim = max_in > 0 ? max_in : strlen(in);
  size_t w = 0;
  for (size_t n = 0; n < lim && in[n]; n++) {
    if (w + 8u >= out_cap) {
      return 0;
    }
    unsigned char c = (unsigned char)in[n];
    switch (c) {
      case '"':
        out[w++] = '\\';
        out[w++] = '"';
        break;
      case '\\':
        out[w++] = '\\';
        out[w++] = '\\';
        break;
      case '\b':
        memcpy(out + w, "\\b", 2u);
        w += 2u;
        break;
      case '\f':
        memcpy(out + w, "\\f", 2u);
        w += 2u;
        break;
      case '\n':
        memcpy(out + w, "\\n", 2u);
        w += 2u;
        break;
      case '\r':
        memcpy(out + w, "\\r", 2u);
        w += 2u;
        break;
      case '\t':
        memcpy(out + w, "\\t", 2u);
        w += 2u;
        break;
      default:
        if (c < 0x20u) {
          int k = snprintf((char *)out + w, out_cap - w, "\\u%04x", (unsigned)c);
          if (k < 0 || (size_t)k >= out_cap - w) {
            return 0;
          }
          w += (size_t)k;
        } else {
          out[w++] = (char)c;
        }
        break;
    }
  }
  out[w] = '\0';
  return 1;
}

static void p0_json_escape_or_empty(const char *in, char *out, size_t out_cap, size_t max_in) {
  if (!p0_json_escape(in, out, out_cap, max_in)) {
    out[0] = '\0';
  }
}

static int emit_for_rule(const EdrBehaviorRecord *br, const char *rule_id, const char *title,
                        const char *mitre_comma) {
  static int s_debug_enabled = -1;
  if (s_debug_enabled < 0) {
    s_debug_enabled = (getenv("EDR_P0_DEBUG") != NULL) ? 1 : 0;
  }
  if (!p0_global_rate_ok()) {
    if (s_debug_enabled) fprintf(stderr, "[P0 DEBUG] emit blocked: global rate limit\n");
    return 0;
  }
  if (!p0_tenant_rate_ok(br->tenant_id)) {
    if (s_debug_enabled) fprintf(stderr, "[P0 DEBUG] emit blocked: tenant rate limit\n");
    return 0;
  }
  if (!p0_ep_rate_ok(br->endpoint_id)) {
    if (s_debug_enabled) fprintf(stderr, "[P0 DEBUG] emit blocked: endpoint rate limit\n");
    return 0;
  }
  if (!p0_dedup_allow(rule_id, br)) {
    if (s_debug_enabled) fprintf(stderr, "[P0 DEBUG] emit blocked: dedup (rule=%s pid=%u)\n", rule_id, br->pid);
    return 0;
  }
  AVEBehaviorAlert a;
  memset(&a, 0, sizeof(a));
  a.pid = br->pid;
  a.timestamp_ns = br->event_time_ns;
  snprintf(a.process_name, sizeof(a.process_name), "%s", br->process_name ? br->process_name : "");
  snprintf(a.process_path, sizeof(a.process_path), "%s", br->exe_path ? br->exe_path : "");
  a.anomaly_score = sev3_anomaly();
  snprintf(a.triggered_tactics, sizeof(a.triggered_tactics), "%s", mitre_comma ? mitre_comma : "");
  a.skip_ai_analysis = true;
  a.needs_l2_review = false;

  /* user_subject_json：所有嵌入字符串必须 JSON 转义，否则 \\ 未写成 \\\\ 会导致非法 JSON，ingest 不入库、标题退回默认。 */
  {
    char esc_rule_id[80];
    char esc_bundle[160];
    char esc_title[640];
    char esc_proc[384];
    char esc_exe[1024];
    char cmdline_esc[2048];
    char esc_exe_hash[160];
    char esc_path_hash[160];
    char parent_name_esc[384];
    char parent_path_esc[1024];
    char esc_parent_cmdline[2048];
    char esc_gp[256];
    char username_esc[512];
    char esc_ep[96];
    char esc_tenant[96];
    char esc_host[256];
    char esc_domain[256];
    char esc_cwd[512];
    char esc_il[96];
    char esc_pct[192];
    char esc_ppt[192];
    char esc_child[384];
    char esc_psb[1024];
    char esc_clo[256];
    char esc_ect[96];

    /* 如果缺少父进程信息，通过API补充（须在 JSON 转义前填充 br） */
    if (!br->parent_name[0] && br->ppid > 0) {
      enrich_parent_info_by_pid(br->ppid, br->parent_name, sizeof(br->parent_name), br->parent_path,
                                sizeof(br->parent_path));
    }

    p0_json_escape_or_empty(rule_id, esc_rule_id, sizeof(esc_rule_id), 48);
    p0_json_escape_or_empty(EDR_P0_RULES_BUNDLE_VERSION, esc_bundle, sizeof(esc_bundle), 128);
    p0_json_escape_or_empty(title ? title : "", esc_title, sizeof(esc_title), 240);
    p0_json_escape_or_empty(br->process_name ? br->process_name : "", esc_proc, sizeof(esc_proc), 160);
    p0_json_escape_or_empty(br->exe_path[0] ? br->exe_path : "", esc_exe, sizeof(esc_exe), 400);
    p0_json_escape_or_empty(br->cmdline ? br->cmdline : "", cmdline_esc, sizeof(cmdline_esc), 480);
    p0_json_escape_or_empty(br->exe_hash[0] ? br->exe_hash : "", esc_exe_hash, sizeof(esc_exe_hash), 96);
    p0_json_escape_or_empty(br->process_path_hash[0] ? br->process_path_hash : "", esc_path_hash,
                            sizeof(esc_path_hash), 96);
    p0_json_escape_or_empty(br->parent_name[0] ? br->parent_name : "", parent_name_esc, sizeof(parent_name_esc),
                            160);
    p0_json_escape_or_empty(br->parent_path[0] ? br->parent_path : "", parent_path_esc, sizeof(parent_path_esc),
                            400);
    p0_json_escape_or_empty(br->parent_cmdline[0] ? br->parent_cmdline : "", esc_parent_cmdline,
                            sizeof(esc_parent_cmdline), 480);
    p0_json_escape_or_empty(br->grandparent_name[0] ? br->grandparent_name : "", esc_gp, sizeof(esc_gp), 128);
    p0_json_escape_or_empty(br->username[0] ? br->username : "", username_esc, sizeof(username_esc), 160);
    p0_json_escape_or_empty(br->endpoint_id[0] ? br->endpoint_id : "", esc_ep, sizeof(esc_ep), 80);
    p0_json_escape_or_empty(br->tenant_id[0] ? br->tenant_id : "", esc_tenant, sizeof(esc_tenant), 64);
    p0_json_escape_or_empty(br->hostname[0] ? br->hostname : "", esc_host, sizeof(esc_host), 128);
    p0_json_escape_or_empty(br->domain[0] ? br->domain : "", esc_domain, sizeof(esc_domain), 128);
    p0_json_escape_or_empty(br->current_directory[0] ? br->current_directory : "", esc_cwd, sizeof(esc_cwd), 240);
    p0_json_escape_or_empty(br->integrity_level[0] ? br->integrity_level : "Unknown", esc_il, sizeof(esc_il), 48);
    p0_json_escape_or_empty(br->process_creation_time[0] ? br->process_creation_time : "", esc_pct, sizeof(esc_pct),
                            96);
    p0_json_escape_or_empty(br->parent_creation_time[0] ? br->parent_creation_time : "", esc_ppt, sizeof(esc_ppt),
                            96);
    p0_json_escape_or_empty(br->child_pids[0] ? br->child_pids : "", esc_child, sizeof(esc_child), 160);
    p0_json_escape_or_empty(br->powershell_script_block[0] ? br->powershell_script_block : "", esc_psb,
                            sizeof(esc_psb), 360);
    p0_json_escape_or_empty(br->command_line_origin[0] ? br->command_line_origin : "", esc_clo, sizeof(esc_clo),
                            96);
    p0_json_escape_or_empty(br->encoded_command_type[0] ? br->encoded_command_type : "", esc_ect, sizeof(esc_ect),
                            64);

    int n = snprintf(
        a.user_subject_json, sizeof(a.user_subject_json),
        "{"
        "\"subject_type\":\"edr_dynamic_rule\","
        "\"rule_id\":\"%s\","
        "\"rules_bundle_version\":\"%s\","
        "\"display_title\":\"%s\","
        "\"context\":{"
          "\"pid\":%u,"
          "\"ppid\":%u,"
          "\"process_name\":\"%s\","
          "\"process_path\":\"%s\","
          "\"cmdline\":\"%s\","
          "\"exe_hash\":\"%s\","
          "\"exe_path_hash\":\"%s\","
          "\"parent_name\":\"%s\","
          "\"parent_path\":\"%s\","
          "\"parent_cmdline\":\"%s\","
          "\"grandparent_name\":\"%s\","
          "\"username\":\"%s\","
          "\"process_chain_depth\":%u,"
          "\"endpoint_id\":\"%s\","
          "\"tenant_id\":\"%s\","
          "\"event_type\":%d,"
          "\"hostname\":\"%s\","
          "\"domain\":\"%s\","
          "\"current_directory\":\"%s\","
          "\"logon_time_ns\":%llu,"
          "\"integrity_level\":\"%s\","
          "\"token_elevation\":%u,"
          "\"process_creation_time\":\"%s\","
          "\"parent_creation_time\":\"%s\","
          "\"child_pids\":\"%s\","
          "\"powershell_script_block\":\"%s\","
          "\"command_line_origin\":\"%s\","
          "\"encoded_command_type\":\"%s\""
        "}"
        "}",
        esc_rule_id,
        esc_bundle,
        esc_title,
        br->pid,
        br->ppid,
        esc_proc,
        esc_exe,
        cmdline_esc,
        esc_exe_hash,
        esc_path_hash,
        parent_name_esc,
        parent_path_esc,
        esc_parent_cmdline,
        esc_gp,
        username_esc,
        br->process_chain_depth,
        esc_ep,
        esc_tenant,
        (int)br->type,
        esc_host,
        esc_domain,
        esc_cwd,
        (unsigned long long)br->logon_time_ns,
        esc_il,
        br->token_elevation,
        esc_pct,
        esc_ppt,
        esc_child,
        esc_psb,
        esc_clo,
        esc_ect);
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
  const char *p0_env = getenv("EDR_P0_DIRECT_EMIT");
  if (!getenv_int01_disabled_on_zero("EDR_P0_DIRECT_EMIT")) {
    static int s_logged_once = 0;
    if (!s_logged_once) {
      fprintf(stderr, "[P0] INFO: EDR_P0_DIRECT_EMIT=%s, P0 rule engine disabled\n", p0_env ? p0_env : "(not set)");
      s_logged_once = 1;
    }
    return;
  }
  const char *cmd = br->cmdline;
  const char *pn = br->process_name;
  const char *par = br->parent_name[0] ? br->parent_name : NULL;
  int ch = (int)br->process_chain_depth;

  /* 调试日志：仅打印含有效数据的 P0 事件，统计空事件（原因：TDH 未产生 img/cmd 行） */
  static int s_debug_enabled = -1;
  static uint64_t s_debug_empty_count;
  if (s_debug_enabled < 0) {
    s_debug_enabled = (getenv("EDR_P0_DEBUG") != NULL) ? 1 : 0;
  }
  if (s_debug_enabled) {
    int has_data = ((pn && pn[0]) || (cmd && cmd[0]));
    if (has_data) {
      fprintf(stderr, "[P0 DEBUG] event: type=%d pid=%u process=%s cmdline=%s\n",
              br->type, br->pid, pn ? pn : "(null)", cmd ? cmd : "(null)");
    } else {
      s_debug_empty_count++;
      if (s_debug_empty_count == 1u || (s_debug_empty_count & 1023u) == 0u) {
        fprintf(stderr, "[P0 DEBUG] empty events skipped (no img/cmd): count=%llu (last: type=%d pid=%u)\n",
                (unsigned long long)s_debug_empty_count, br->type, br->pid);
      }
    }
  }

  edr_p0_rule_ir_lazy_init();
  if (edr_p0_rule_ir_is_ready()) {
    int i;
    int n = edr_p0_rule_ir_rule_count();
    for (i = 0; i < n; i++) {
      int hit = edr_p0_rule_ir_br_matches_index(br, i);
      edr_p0_rule_ir_stats_record(i, hit);
      if (!hit) {
        continue;
      }
      const char *rid = NULL;
      if (!edr_p0_rule_ir_rule_id_at(i, &rid) || !rid) {
        continue;
      }
      const char *title = NULL;
      const char *mitre = NULL;
      (void)edr_p0_rule_ir_get_meta(rid, &title, &mitre);
      fprintf(stderr, "[P0] IR rule matched: rid=%s title=%s\n", rid, title ? title : "(null)");
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
