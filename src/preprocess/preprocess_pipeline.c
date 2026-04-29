#include "edr/preprocess.h"

#include "edr/resource.h"
#include "edr/attack_surface_report.h"
#include "edr/config.h"
#include "edr/behavior_from_slot.h"
#include "edr/behavior_proto.h"
#include "edr/behavior_proto_c.h"
#include "edr/behavior_wire.h"
#include "edr/dedup.h"
#include "edr/emit_rules.h"
#include "edr/p0_rule_direct_emit.h"
#include "edr/event_batch.h"
#include "edr/event_bus.h"
#include "edr/ave_cross_engine_feed.h"
#include "edr/pid_history_pmfe.h"
#include "edr/pmfe.h"
#include "edr/process_chain_depth.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
#include "edr/types.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static HANDLE s_thread;
static volatile LONG s_stop_preprocess;
#else
#include <pthread.h>
#include <unistd.h>
static pthread_t s_thread;
static volatile int s_stop_preprocess;
#endif

static int s_preprocess_active;
enum { EDR_PREPROCESS_POP_BURST = 32 };

static EdrEventBus *s_bus;
static int s_l2_split_enabled;
static double s_l2_unmatched_keep_ratio;
static int s_l3_pressure_enabled;
static uint32_t s_l3_pressure_high_pct;
static uint32_t s_l3_pressure_recover_pct;
static uint32_t s_l3_drop_permille;
static int s_l3_pressure_active;
static int s_procname_gate_enabled;
static uint32_t s_procname_gate_keep_unknown_permille;
static uint32_t s_drop_l2_unmatched;
static uint32_t s_drop_l3_pressure;
static int s_strict_behavior_gate_enabled;
static uint32_t s_drop_strict_behavior_gate;
static uint32_t s_drop_procname_gate;
static uint32_t s_rng_state = 0x12345678u;

/** 与 [agent] 对齐，写入每条 BehaviorRecord（线格式 / nanopb 与 gRPC endpoint_id 一致） */
static char s_cfg_endpoint_id[128];
static char s_cfg_tenant_id[128];

static void sync_agent_ids_from_cfg(const EdrConfig *cfg) {
  if (!cfg) {
    return;
  }
  snprintf(s_cfg_endpoint_id, sizeof(s_cfg_endpoint_id), "%s", cfg->agent.endpoint_id);
  snprintf(s_cfg_tenant_id, sizeof(s_cfg_tenant_id), "%s", cfg->agent.tenant_id);
}

static void apply_agent_ids_to_record(EdrBehaviorRecord *br) {
  if (!br) {
    return;
  }
  if (s_cfg_tenant_id[0]) {
    snprintf(br->tenant_id, sizeof(br->tenant_id), "%s", s_cfg_tenant_id);
  }
  if (s_cfg_endpoint_id[0] && strcmp(s_cfg_endpoint_id, "auto") != 0) {
    snprintf(br->endpoint_id, sizeof(br->endpoint_id), "%s", s_cfg_endpoint_id);
  }
}

static int slot_is_high_value(const EdrEventSlot *slot) {
  if (!slot) {
    return 0;
  }
  if (slot->priority == 0u || slot->attack_surface_hint != 0u) {
    return 1;
  }
  switch (slot->type) {
    case EDR_EVENT_PROCESS_INJECT:
    case EDR_EVENT_THREAD_CREATE_REMOTE:
    case EDR_EVENT_PROTOCOL_SHELLCODE:
    case EDR_EVENT_WEBSHELL_DETECTED:
    case EDR_EVENT_FIREWALL_RULE_CHANGE:
      return 1;
    default:
      return 0;
  }
}

static int slot_is_behavior_engine_process_event(const EdrEventSlot *slot) {
  if (!slot) {
    return 0;
  }
  switch (slot->type) {
    case EDR_EVENT_PROCESS_CREATE:
    case EDR_EVENT_PROCESS_INJECT:
      return 1;
    default:
      return 0;
  }
}

static int str_ieq_ascii(const char *a, const char *b) {
  if (!a || !b) {
    return 0;
  }
  while (*a && *b) {
    char ca = *a++;
    char cb = *b++;
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
  return *a == '\0' && *b == '\0';
}

static int process_name_in_gate_allowlist(const char *name) {
  /* procname_gate 白名单：只采集最高风险进程的完整行为
   * 可通过环境变量 EDR_PROCNAME_GATE_WHITELIST 覆盖
   * 默认配置仅包含最关键的攻击工具（精简版）
   */
  static const char *const kDefaultHotProcNames[] = {
      // 脚本引擎 (最高风险)
      "powershell.exe",
      "pwsh.exe",
      // 可执行文件生成/下载 (高风险)
      "mshta.exe",
      "rundll32.exe",
      "regsvr32.exe",
      "cmstp.exe",
      "msbuild.exe",
      "certutil.exe",
      "bitsadmin.exe",
      // 下载/网络工具
      "curl.exe",
      "wget.exe",
  };
  static const char *s_custom_whitelist = NULL;
  static char *s_whitelist_copy = NULL;
  static int s_whitelist_initialized = 0;

  if (!name || !name[0]) {
    return 0;
  }

  if (!s_whitelist_initialized) {
    s_whitelist_initialized = 1;
    s_custom_whitelist = getenv("EDR_PROCNAME_GATE_WHITELIST");
    if (s_custom_whitelist && s_custom_whitelist[0]) {
      size_t len = strlen(s_custom_whitelist) + 1;
      s_whitelist_copy = (char *)malloc(len);
      if (s_whitelist_copy) {
        memcpy(s_whitelist_copy, s_custom_whitelist, len);
      }
    }
  }

  if (s_whitelist_copy && s_whitelist_copy[0]) {
    const char *p = s_whitelist_copy;
    while (*p) {
      const char *end = strchr(p, ',');
      size_t len = end ? (size_t)(end - p) : strlen(p);
      if (len > 0) {
        char proc_name[64] = {0};
        if (len >= sizeof(proc_name)) {
          len = sizeof(proc_name) - 1;
        }
        memcpy(proc_name, p, len);
        if (str_ieq_ascii(name, proc_name)) {
          return 1;
        }
      }
      p = end ? end + 1 : p + strlen(p);
    }
    return 0;
  }

  for (size_t i = 0; i < sizeof(kDefaultHotProcNames) / sizeof(kDefaultHotProcNames[0]); i++) {
    if (str_ieq_ascii(name, kDefaultHotProcNames[i])) {
      return 1;
    }
  }
  return 0;
}

static uint32_t rng_next_u32(void) {
  s_rng_state = s_rng_state * 1664525u + 1013904223u;
  return s_rng_state;
}

static int rng_hit_permille(uint32_t p) {
  if (p == 0u) {
    return 0;
  }
  if (p >= 1000u) {
    return 1;
  }
  return (rng_next_u32() % 1000u) < p;
}

static uint32_t clamp_u32(uint32_t v, uint32_t lo, uint32_t hi) {
  if (v < lo) {
    return lo;
  }
  if (v > hi) {
    return hi;
  }
  return v;
}

static double getenv_double_default(const char *key, double defv) {
  const char *v = getenv(key);
  if (!v || !v[0]) {
    return defv;
  }
  return atof(v);
}

static void preprocess_init_l2_l3_controls(const EdrConfig *cfg) {
  /* 默认去重窗口5秒（严格模式），可通过环境变量 EDR_DEDUP_WINDOW_SECONDS 覆盖 */
  uint32_t dedup_window_s = (uint32_t)edr_getenv_int_default("EDR_DEDUP_WINDOW_SECONDS", cfg ? cfg->preprocessing.dedup_window_s : 5);
  /* 默认速率限制20/秒/PID（严格模式），可通过环境变量 EDR_RATE_LIMIT_PER_SEC 覆盖 */
  uint32_t rate_limit_per_sec = (uint32_t)edr_getenv_int_default("EDR_RATE_LIMIT_PER_SEC", cfg ? cfg->preprocessing.high_freq_threshold : 20);
  if (dedup_window_s == 0) {
    dedup_window_s = 5;
  }
  if (rate_limit_per_sec == 0) {
    rate_limit_per_sec = 50;
  }
  if (dedup_window_s > 3600) {
    dedup_window_s = 3600;
  }
  if (rate_limit_per_sec > 1000) {
    rate_limit_per_sec = 1000;
  }
  edr_dedup_configure(dedup_window_s, rate_limit_per_sec);

  s_l2_split_enabled = edr_getenv_int_default("EDR_PREPROCESS_L2_SPLIT", 0) == 1 ? 1 : 0;
  s_l2_unmatched_keep_ratio = cfg ? cfg->preprocessing.sampling_rate_whitelist : 0.1;
  s_l2_unmatched_keep_ratio =
      getenv_double_default("EDR_PREPROCESS_L2_KEEP_RATIO", s_l2_unmatched_keep_ratio);
  if (s_l2_unmatched_keep_ratio < 0.0) {
    s_l2_unmatched_keep_ratio = 0.0;
  }
  if (s_l2_unmatched_keep_ratio > 0.10) {
    s_l2_unmatched_keep_ratio = 0.10;
  }

  s_l3_pressure_enabled = edr_getenv_int_default("EDR_PREPROCESS_L3_PRESSURE", 1) == 1 ? 1 : 0;
  s_l3_pressure_high_pct = (uint32_t)edr_getenv_int_default("EDR_PREPROCESS_L3_HIGH_PCT", 70);
  s_l3_pressure_recover_pct = (uint32_t)edr_getenv_int_default("EDR_PREPROCESS_L3_RECOVER_PCT", 50);
  s_l3_drop_permille = (uint32_t)edr_getenv_int_default("EDR_PREPROCESS_L3_DROP_PERMILLE", 950);
  s_l3_pressure_high_pct = clamp_u32(s_l3_pressure_high_pct, 50u, 99u);
  s_l3_pressure_recover_pct = clamp_u32(s_l3_pressure_recover_pct, 10u, s_l3_pressure_high_pct);
  s_l3_drop_permille = clamp_u32(s_l3_drop_permille, 0u, 1000u);
  s_procname_gate_enabled = edr_getenv_int_default("EDR_PREPROCESS_PROCNAME_GATE", 1) == 1 ? 1 : 0;
  s_procname_gate_keep_unknown_permille =
      (uint32_t)edr_getenv_int_default("EDR_PREPROCESS_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE", 10);
  s_procname_gate_keep_unknown_permille =
      clamp_u32(s_procname_gate_keep_unknown_permille, 0u, 1000u);
  s_l3_pressure_active = 0;
  s_drop_l2_unmatched = 0u;
  s_drop_l3_pressure = 0u;
  s_strict_behavior_gate_enabled =
      edr_getenv_int_default("EDR_PREPROCESS_STRICT_BEHAVIOR_GATE", 0) == 1 ? 1 : 0;
  s_drop_strict_behavior_gate = 0u;
  s_drop_procname_gate = 0u;
  if (cfg) {
    s_rng_state ^= cfg->collection.max_event_queue_size;
    s_rng_state ^= cfg->upload.batch_max_events << 1;
  }
  fprintf(stderr,
          "[preprocess/config] L2_SPLIT=%d L2_KEEP_RATIO=%.3f L3_PRESSURE=%d L3_HIGH_PCT=%u "
          "L3_RECOVER_PCT=%u L3_DROP_PERMILLE=%u PROCNAME_GATE=%d PROCNAME_KEEP_UNKNOWN_PERMILLE=%u "
          "STRICT_BEHAVIOR_GATE=%d\n",
          s_l2_split_enabled, s_l2_unmatched_keep_ratio, s_l3_pressure_enabled,
          (unsigned)s_l3_pressure_high_pct, (unsigned)s_l3_pressure_recover_pct,
          (unsigned)s_l3_drop_permille, s_procname_gate_enabled,
          (unsigned)s_procname_gate_keep_unknown_permille, s_strict_behavior_gate_enabled);
}

/** 高价值安全事件类型——即使资源受限也应触发 P0 检测 */
static int slot_is_p0_eligible(const EdrEventSlot *slot) {
  if (!slot) {
    return 0;
  }
  switch (slot->type) {
    case EDR_EVENT_PROCESS_CREATE:
    case EDR_EVENT_PROCESS_INJECT:
    case EDR_EVENT_THREAD_CREATE_REMOTE:
    case EDR_EVENT_PROTOCOL_SHELLCODE:
    case EDR_EVENT_WEBSHELL_DETECTED:
    case EDR_EVENT_PMFE_SCAN_RESULT:
      return 1;
    default:
      return 0;
  }
}

static int process_name_looks_like_exe(const char *name) {
  size_t len;
  if (!name || !name[0]) return 0;
  len = strlen(name);
  if (len < 5) return 0;
  {
    const char *ext = name + len - 4;
    char c0 = (char)(ext[0] | 32);
    char c1 = (char)(ext[1] | 32);
    char c2 = (char)(ext[2] | 32);
    char c3 = (char)(ext[3] | 32);
    if (c0 == '.' && c1 == 'e' && c2 == 'x' && c3 == 'e') return 1;
    if (c0 == '.' && c1 == 'c' && c2 == 'o' && c3 == 'm') return 1;
    if (c0 == '.' && c1 == 'b' && c2 == 'a' && c3 == 't') return 1;
    if (c0 == '.' && c1 == 'c' && c2 == 'm' && c3 == 'd') return 1;
    if (c0 == '.' && c1 == 'p' && c2 == 's' && c3 == '1') return 1;
    if (c0 == '.' && c1 == 'p' && c2 == 's' && c3 == '2') return 1;
    if (c0 == '.' && c1 == 'v' && c2 == 'b' && c3 == 's') return 1;
    if (c0 == '.' && c1 == 'j' && c2 == 's' && c3 == 's') return 1;
    if (c0 == '.' && c1 == 'j' && c2 == 's' && c3 == 'e') return 1;
    if (c0 == '.' && c1 == 'v' && c2 == 'b' && c3 == 'e') return 1;
    if (c0 == '.' && c1 == 'w' && c2 == 's' && c3 == 'f') return 1;
    if (c0 == '.' && c1 == 'w' && c2 == 's' && c3 == 'h') return 1;
    if (c0 == '.' && c1 == 'm' && c2 == 's' && c3 == 'i') return 1;
    if (c0 == '.' && c1 == 'm' && c2 == 's' && c3 == 'p') return 1;
    if (c0 == '.' && c1 == 'm' && c2 == 's' && c3 == 'c') return 1;
    if (c0 == '.' && c1 == 'c' && c2 == 'p' && c3 == 'l') return 1;
    if (c0 == '.' && c1 == 'c' && c2 == 'x' && c3 == 'x') return 1;
    if (c0 == '.' && c1 == 'g' && c2 == 'a' && c3 == 'd') return 1;
    if (c0 == '.' && c1 == 'r' && c2 == 'e' && c3 == 'g') return 1;
    if (c0 == '.' && c1 == 's' && c2 == 'c' && c3 == 'f') return 1;
    if (c0 == '.' && c1 == 'i' && c2 == 'n' && c3 == 'i') return 1;
    if (c0 == '.' && c1 == 'l' && c2 == 'n' && c3 == 'k') return 1;
    if (c0 == '.' && c1 == 'p' && c2 == 'i' && c3 == 'f') return 1;
    if (c0 == '.' && c1 == 's' && c2 == 'c' && c3 == 'r') return 1;
    if (c0 == '.' && c1 == 'h' && c2 == 't' && c3 == 'a') return 1;
    if (c0 == '.' && c1 == 'a' && c2 == 'p' && c3 == 'p') return 1;
    if (c0 == '.' && c1 == 'a' && c2 == 'p' && c3 == 'p' && len > 4) {
      char c4 = (char)(name[len - 5] | 32);
      if (c4 == 'x' || c4 == 'e') return 1;
    }
  }
  return 0;
}

/** 判断 behavior record 是否含有可上送的实质数据。无进程名、无命令行、无脚本/文件/网络/注册表字段的时间件应跳过。 */
static int behavior_record_has_meaningful_data(const EdrBehaviorRecord *br, EdrEventType slot_type) {
  if (!br) return 0;
  if (br->process_name[0] || br->cmdline[0] || br->exe_path[0]) return 1;
  if (br->script_snippet[0]) return 1;
  if (br->file_path[0] || br->dns_query[0] || br->net_dst[0] || br->reg_key_path[0]) return 1;
  /* PROCESS_TERMINATE：进程已退出，TDH 不可回溯。仅 pid 无其他字段 → 跳过 */
  if (slot_type == EDR_EVENT_PROCESS_TERMINATE) return 0;
  /* NET_CONNECT/LISTEN：pid=0 的内核态网络事件无进程上下文 */
  if ((slot_type == EDR_EVENT_NET_CONNECT || slot_type == EDR_EVENT_NET_LISTEN) && br->pid == 0) return 0;
  /* SCRIPT 事件：无脚本片段、无命令行 → 跳过 */
  if (slot_type == EDR_EVENT_SCRIPT_POWERSHELL || slot_type == EDR_EVENT_SCRIPT_WMI) return 0;
  return 1;
}

static void process_one_slot(const EdrEventSlot *slot) {
  /* AGT-010：资源压力下跳过低优先级槽位；保留 priority==0 与 §19.10 attack_surface_hint */
  if (edr_resource_preprocess_throttle_active() && slot && slot->priority != 0u &&
      slot->attack_surface_hint == 0u) {
    /* 即使在资源压力下被丢弃，仍然尝试P0检测（关键告警不应被压制） */
    if (slot_is_p0_eligible(slot)) {
      EdrBehaviorRecord br;
      edr_behavior_from_slot(slot, &br);
      edr_behavior_record_fill_process_chain_depth(&br);
      apply_agent_ids_to_record(&br);
      if (slot->type != EDR_EVENT_PROCESS_CREATE ||
          !br.process_name[0] || process_name_looks_like_exe(br.process_name)) {
        edr_p0_rule_try_emit(&br);
      }
    }
    return;
  }
  if (slot && slot->attack_surface_hint) {
    edr_attack_surface_etw_signal();
  }
#if defined(__linux__) && !defined(_WIN32)
  /* Windows 在 ETW 回调中调用；Linux 行为事件（含未来 audit/eBPF 注入）在此对齐 */
  if (slot && (slot->type == EDR_EVENT_PROCESS_CREATE || slot->type == EDR_EVENT_PROCESS_TERMINATE)) {
    edr_pmfe_on_process_lifecycle_hint();
  }
#endif
  uint8_t buf[16384];
  EdrBehaviorRecord br;
  edr_behavior_from_slot(slot, &br);
  edr_behavior_record_fill_process_chain_depth(&br);
  apply_agent_ids_to_record(&br);

  /* 丢弃 PROCESS_CREATE 事件中非可执行程序的进程名（img= 指向 DLL/SYS 等非 exe 模块） */
  if (slot && slot->type == EDR_EVENT_PROCESS_CREATE &&
      br.process_name[0] && !process_name_looks_like_exe(br.process_name)) {
    return;
  }

  /* 空事件过滤：无进程名、无有效数据的 PROCESS_TERMINATE/NET_CONNECT/SCRIPT 等跳过。
   * 仅在非 P0 类型上生效，P0 eligible 事件仍走 P0 检测路径（某些规则匹配 file_path 等非进程字段）。 */
  if (!slot_is_p0_eligible(slot) &&
      !behavior_record_has_meaningful_data(&br, slot->type)) {
    return;
  }

  /* P0检测：尽早执行，确保关键告警不被后续丢弃逻辑遗漏 */
  if (slot_is_p0_eligible(slot)) {
    edr_p0_rule_try_emit(&br);
  }

  if (s_procname_gate_enabled && br.priority != 0u &&
      slot && slot->type == EDR_EVENT_PROCESS_CREATE &&
      !process_name_in_gate_allowlist(br.process_name)) {
    if (!rng_hit_permille(s_procname_gate_keep_unknown_permille)) {
      s_drop_procname_gate++;
      return;
    }
  }
  /* 将进程名门控扩展到非进程事件：仅 hot 进程产生的 file/registry/network 事件才送入下游 */
  if (s_procname_gate_enabled && br.priority != 0u &&
      slot && slot->type != EDR_EVENT_PROCESS_CREATE &&
      br.process_name[0] && !process_name_in_gate_allowlist(br.process_name)) {
    if (!rng_hit_permille(s_procname_gate_keep_unknown_permille)) {
      return;
    }
  }
  edr_pid_history_pmfe_fill_record(&br);
  edr_pmfe_on_preprocess_slot(slot, &br);
  if (s_l2_split_enabled && br.priority != 0u &&
      slot_is_behavior_engine_process_event(slot)) {
    int rr = edr_emit_rules_evaluate(&br);
    if (rr < 0) {
      uint32_t keep_permille = (uint32_t)(s_l2_unmatched_keep_ratio * 1000.0 + 0.5);
      if (!rng_hit_permille(keep_permille)) {
        s_drop_l2_unmatched++;
        return;
      }
    }
  }
  /* P2 T9：Shellcode / Webshell / PMFE → AVE 行为槽（E 组 46–47、53–54） */
  edr_ave_cross_engine_feed_from_record(&br);
  if (!edr_preprocess_should_emit(&br)) {
    /* P0 直出与主行为上送（dedup/限流/动态规则门控）解耦；否则应上送主路径为 0 时 P0 永不执行 */
    /* 注意：上面已执行过P0检测，但edr_p0_rule_try_emit内部有幂等保护 */
    edr_p0_rule_try_emit(&br);
    return;
  }
  size_t n = 0;
  const char *enc = getenv("EDR_BEHAVIOR_ENCODING");
  if (enc && strcmp(enc, "protobuf") == 0) {
#ifdef EDR_HAVE_NANOPB
    n = edr_behavior_record_encode_protobuf(&br, buf, sizeof(buf));
#endif
    if (n == 0) {
      n = edr_behavior_wire_encode(&br, buf, sizeof(buf));
    }
  } else if (enc && strcmp(enc, "protobuf_c") == 0) {
    n = edr_behavior_record_encode_protobuf_c(&br, buf, sizeof(buf));
    if (n == 0) {
      n = edr_behavior_wire_encode(&br, buf, sizeof(buf));
    }
  } else {
    n = edr_behavior_wire_encode(&br, buf, sizeof(buf));
  }
  if (n > 0) {
    (void)edr_event_batch_push(buf, n);
  }
  /* P0检测已在早期执行，避免重复调用 */
}

#ifdef _WIN32
static DWORD WINAPI preprocess_main(void *arg) {
#else
static void *preprocess_main(void *arg) {
#endif
  (void)arg;
  for (;;) {
    EdrEventSlot slots[EDR_PREPROCESS_POP_BURST];
    if (s_l3_pressure_enabled && s_bus) {
      uint32_t cap = edr_event_bus_capacity(s_bus);
      if (cap > 0u) {
        uint32_t used = edr_event_bus_used_approx(s_bus);
        uint32_t pct = (used * 100u) / cap;
        if (!s_l3_pressure_active && pct >= s_l3_pressure_high_pct) {
          s_l3_pressure_active = 1;
        } else if (s_l3_pressure_active && pct <= s_l3_pressure_recover_pct) {
          s_l3_pressure_active = 0;
        }
      }
    }
    uint32_t n = edr_event_bus_try_pop_many(s_bus, slots, EDR_PREPROCESS_POP_BURST);
    if (n > 0u) {
      for (uint32_t i = 0; i < n; i++) {
        if (s_strict_behavior_gate_enabled &&
            !slot_is_behavior_engine_process_event(&slots[i])) {
          s_drop_strict_behavior_gate++;
          continue;
        }
        if (s_l3_pressure_active && !slot_is_high_value(&slots[i])) {
          if (!rng_hit_permille(1000u - s_l3_drop_permille)) {
            s_drop_l3_pressure++;
            continue;
          }
        }
        process_one_slot(&slots[i]);
      }
      edr_event_batch_poll_timeout();
      edr_storage_queue_poll_drain();
      continue;
    }
    edr_event_batch_poll_timeout();
    edr_storage_queue_poll_drain();
#ifdef _WIN32
    if (s_stop_preprocess) {
      for (;;) {
        uint32_t rn = edr_event_bus_try_pop_many(s_bus, slots, EDR_PREPROCESS_POP_BURST);
        if (rn == 0u) {
          break;
        }
        for (uint32_t i = 0; i < rn; i++) {
          process_one_slot(&slots[i]);
        }
      }
      edr_storage_queue_poll_drain();
      break;
    }
    Sleep(1);
#else
    if (s_stop_preprocess) {
      for (;;) {
        uint32_t rn = edr_event_bus_try_pop_many(s_bus, slots, EDR_PREPROCESS_POP_BURST);
        if (rn == 0u) {
          break;
        }
        for (uint32_t i = 0; i < rn; i++) {
          process_one_slot(&slots[i]);
        }
      }
      edr_storage_queue_poll_drain();
      break;
    }
    usleep(1000);
#endif
  }
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

EdrError edr_preprocess_start(EdrEventBus *bus, const EdrConfig *cfg) {
  EdrConfig defaults;
  if (!bus) {
    return EDR_ERR_INVALID_ARG;
  }
  if (s_preprocess_active) {
    return EDR_OK;
  }
  if (!cfg) {
    edr_config_apply_defaults(&defaults);
    cfg = &defaults;
  }
  {
    size_t max_bytes = (size_t)cfg->upload.batch_max_size_mb * 1024u * 1024u;
    if (max_bytes == 0) {
      max_bytes = EDR_EVENT_BATCH_CAP;
    }
    EdrError be = edr_event_batch_init(max_bytes, cfg->upload.batch_max_events,
                                       cfg->upload.batch_timeout_s);
    if (be != EDR_OK) {
      return be;
    }
    fprintf(stderr,
            "[batch] batch_max_size_mb=%u batch_max_events=%u batch_timeout_s=%d (exit stats: "
            "EDR_AGENT_SHUTDOWN_LOG=1 or EDR_AGENT_VERBOSE=1; tune after metrics: "
            "docs/WP6_TRANSPORT_BATCH_QUANTIFIED_OPS.md)\n",
            (unsigned)cfg->upload.batch_max_size_mb, (unsigned)cfg->upload.batch_max_events,
            cfg->upload.batch_timeout_s);
  }
  edr_dedup_configure(cfg->preprocessing.dedup_window_s,
                      cfg->preprocessing.high_freq_threshold);
  edr_emit_rules_configure(cfg);
  edr_dedup_init();
  preprocess_init_l2_l3_controls(cfg);
  sync_agent_ids_from_cfg(cfg);
  s_bus = bus;
#ifdef _WIN32
  s_stop_preprocess = 0;
  s_thread = CreateThread(NULL, 0, preprocess_main, NULL, 0, NULL);
  if (!s_thread) {
    s_bus = NULL;
    edr_event_batch_shutdown();
    return EDR_ERR_INTERNAL;
  }
#else
  s_stop_preprocess = 0;
  if (pthread_create(&s_thread, NULL, preprocess_main, NULL) != 0) {
    s_bus = NULL;
    edr_event_batch_shutdown();
    return EDR_ERR_INTERNAL;
  }
#endif
  s_preprocess_active = 1;
  return EDR_OK;
}

void edr_preprocess_apply_config(const EdrConfig *cfg) {
  if (!s_preprocess_active || !cfg) {
    return;
  }
  edr_dedup_configure(cfg->preprocessing.dedup_window_s, cfg->preprocessing.high_freq_threshold);
  edr_emit_rules_configure(cfg);
  preprocess_init_l2_l3_controls(cfg);
  sync_agent_ids_from_cfg(cfg);
}

void edr_preprocess_copy_agent_ids(char *endpoint_id, size_t endpoint_cap, char *tenant_id, size_t tenant_cap) {
  if (endpoint_id && endpoint_cap > 0) {
    snprintf(endpoint_id, endpoint_cap, "%s", s_cfg_endpoint_id);
  }
  if (tenant_id && tenant_cap > 0) {
    snprintf(tenant_id, tenant_cap, "%s", s_cfg_tenant_id);
  }
}

void edr_preprocess_stop(void) {
  if (!s_preprocess_active) {
    return;
  }
#ifdef _WIN32
  InterlockedExchange(&s_stop_preprocess, 1);
  if (s_thread) {
    WaitForSingleObject(s_thread, 60000);
    CloseHandle(s_thread);
    s_thread = NULL;
  }
#else
  s_stop_preprocess = 1;
  pthread_join(s_thread, NULL);
#endif
  s_bus = NULL;
  s_preprocess_active = 0;
  if (s_drop_l2_unmatched > 0u || s_drop_l3_pressure > 0u ||
      s_drop_procname_gate > 0u ||
      s_drop_strict_behavior_gate > 0u) {
    fprintf(stderr,
            "[preprocess/l2l3] strict_behavior_gate_drop=%u procname_gate_drop=%u "
            "l2_unmatched_drop=%u l3_pressure_drop=%u\n",
            s_drop_strict_behavior_gate, s_drop_procname_gate, s_drop_l2_unmatched,
            s_drop_l3_pressure);
  }
  edr_event_batch_shutdown();
  edr_emit_rules_configure(NULL);
  edr_dedup_reset();
}
