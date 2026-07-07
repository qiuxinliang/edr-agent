#include "edr/preprocess.h"

#include "edr/resource.h"
#include "edr/attack_surface_report.h"
#include "edr/config.h"
#include "edr/behavior_from_slot.h"
#include "edr/behavior_proto.h"
#include "edr/behavior_proto_c.h"
#include "edr/behavior_wire.h"
#include "edr/command.h"
#include "edr/dedup.h"
#include "edr/detection_decision.h"
#include "edr/emit_rules.h"
#include "edr/event_batch.h"
#include "edr/event_bus.h"
#include "edr/heartbeat.h"
#include "edr/net_fanout_detector.h"
#include "edr/ave_cross_engine_feed.h"
#include "edr/local_evidence_cache.h"
#include "edr/pid_history_pmfe.h"
#include "edr/correlation_engine.h"
#include "edr/p0_rule_direct_emit.h"
#include "edr/p0_rule_ir.h"
#include "edr/pmfe.h"
#include "edr/process_tree_cache.h"
#include "edr/sha256.h"
#include "edr/storage_queue.h"
#include "edr/time_util.h"
#include "edr/transport_sink.h"
#include "edr/types.h"
#include "edr/windows_event_policy.h"
#include "edr/enrich_parent_info.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

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

#ifndef EDR_P0_RULES_BUNDLE_VERSION
#define EDR_P0_RULES_BUNDLE_VERSION "unknown"
#endif

static int s_preprocess_active;

static EdrEventBus *s_bus;
static unsigned s_telemetry_sampling_pct = 100u;
static uint64_t s_sampling_dropped;
static uint64_t s_sampling_kept;

/** 与 [agent] 对齐，写入每条 BehaviorRecord（线格式 / nanopb 与 gRPC endpoint_id 一致） */
static char s_cfg_endpoint_id[128];
static char s_cfg_tenant_id[128];

static void copy_trunc(char *dst, size_t cap, const char *src) {
  size_t i = 0;
  if (!dst || cap == 0u) {
    return;
  }
  if (!src) {
    dst[0] = '\0';
    return;
  }
  for (; i + 1u < cap && src[i]; i++) {
    dst[i] = src[i];
  }
  dst[i] = '\0';
}

static void sync_agent_ids_from_cfg(const EdrConfig *cfg) {
  if (!cfg) {
    return;
  }
  copy_trunc(s_cfg_endpoint_id, sizeof(s_cfg_endpoint_id), cfg->agent.endpoint_id);
  copy_trunc(s_cfg_tenant_id, sizeof(s_cfg_tenant_id), cfg->agent.tenant_id);
}

static void apply_agent_ids_to_record(EdrBehaviorRecord *br) {
  if (!br) {
    return;
  }
  if (s_cfg_tenant_id[0]) {
    copy_trunc(br->tenant_id, sizeof(br->tenant_id), s_cfg_tenant_id);
  }
  if (s_cfg_endpoint_id[0] && strcmp(s_cfg_endpoint_id, "auto") != 0) {
    copy_trunc(br->endpoint_id, sizeof(br->endpoint_id), s_cfg_endpoint_id);
  }
}

static void sync_sampling_from_cfg(const EdrConfig *cfg) {
  unsigned pct = 100u;
  if (cfg) {
    pct = cfg->platform.telemetry_sampling_pct;
  }
  if (pct > 100u) {
    pct = 100u;
  }
  s_telemetry_sampling_pct = pct;
}

static uint32_t sampling_hash_bytes(uint32_t h, const void *data, size_t len) {
  const unsigned char *p = (const unsigned char *)data;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint32_t)p[i];
    h *= 16777619u;
  }
  return h;
}

static uint32_t sampling_hash_cstr(uint32_t h, const char *s) {
  return s && s[0] ? sampling_hash_bytes(h, s, strlen(s)) : h;
}

static uint32_t edr_preprocess_sampling_hash_record(const EdrBehaviorRecord *br) {
  uint32_t h = 2166136261u;
  if (!br) {
    return h;
  }
  h = sampling_hash_bytes(h, &br->type, sizeof(br->type));
  h = sampling_hash_bytes(h, &br->pid, sizeof(br->pid));
  h = sampling_hash_bytes(h, &br->event_time_ns, sizeof(br->event_time_ns));
  h = sampling_hash_cstr(h, br->endpoint_id);
  h = sampling_hash_cstr(h, br->process_name);
  h = sampling_hash_cstr(h, br->cmdline);
  h = sampling_hash_cstr(h, br->exe_path);
  h = sampling_hash_cstr(h, br->file_path);
  h = sampling_hash_cstr(h, br->dns_query);
  h = sampling_hash_cstr(h, br->net_dst);
  h = sampling_hash_bytes(h, &br->net_dport, sizeof(br->net_dport));
  return h;
}

static int edr_preprocess_sampling_exempt(const EdrBehaviorRecord *br) {
  if (!br) {
    return 0;
  }
  if (br->priority == 0u) {
    return 1;
  }
  switch (br->type) {
  case EDR_EVENT_PROCESS_INJECT:
  case EDR_EVENT_THREAD_CREATE_REMOTE:
  case EDR_EVENT_PROTOCOL_SHELLCODE:
  case EDR_EVENT_WEBSHELL_DETECTED:
  case EDR_EVENT_PMFE_SCAN_RESULT:
  case EDR_EVENT_BEHAVIOR_ONNX_ALERT:
    return 1;
  default:
    return 0;
  }
}

static int edr_preprocess_sampling_allow(const EdrBehaviorRecord *br) {
  unsigned pct = s_telemetry_sampling_pct;
  if (!br) {
    return 0;
  }
  if (pct >= 100u || edr_preprocess_sampling_exempt(br)) {
    s_sampling_kept++;
    return 1;
  }
  if (pct == 0u) {
    s_sampling_dropped++;
    return 0;
  }
  if ((edr_preprocess_sampling_hash_record(br) % 100u) < pct) {
    s_sampling_kept++;
    return 1;
  }
  s_sampling_dropped++;
  return 0;
}

uint64_t edr_preprocess_sampling_dropped_count(void) { return s_sampling_dropped; }
uint64_t edr_preprocess_sampling_kept_count(void) { return s_sampling_kept; }
uint32_t edr_preprocess_sampling_pct(void) { return s_telemetry_sampling_pct; }

static int p0_direct_emit_enabled(void) {
  const char *v = getenv("EDR_P0_DIRECT_EMIT");
  if (!v || !v[0]) {
    return 1;
  }
  if ((v[0] == '0' || v[0] == 'n' || v[0] == 'N' || v[0] == 'o' || v[0] == 'O') &&
      (v[1] == '\0' || v[1] == ' ' || v[1] == '\t' || v[1] == '\r' || v[1] == '\n')) {
    return 0;
  }
  return 1;
}

static void format_record_time_ns(int64_t ns, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (ns <= 0) {
    return;
  }
  time_t sec = (time_t)(ns / 1000000000LL);
  struct tm tmv;
#ifdef _WIN32
  if (gmtime_s(&tmv, &sec) != 0) {
    return;
  }
#else
  if (!gmtime_r(&sec, &tmv)) {
    return;
  }
#endif
  (void)strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

static int process_hash_enabled(void) {
  const char *v = getenv("EDR_PROCESS_EXE_HASH");
  if (!v || !v[0]) {
    return 1;
  }
  return !(v[0] == '0' || v[0] == 'n' || v[0] == 'N' || v[0] == 'o' || v[0] == 'O');
}

static uint64_t process_hash_max_bytes(void) {
  const char *v = getenv("EDR_PROCESS_EXE_HASH_MAX_MB");
  long mb = v && v[0] ? strtol(v, NULL, 10) : 64L;
  if (mb < 1L) {
    mb = 1L;
  }
  if (mb > 512L) {
    mb = 512L;
  }
  return (uint64_t)mb * 1024ULL * 1024ULL;
}

static int is_drive_path(const char *path) {
  return path && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
         path[1] == ':' && (path[2] == '\\' || path[2] == '/');
}

static int file_size_within_limit(FILE *f, uint64_t limit) {
  if (!f) {
    return 0;
  }
#ifdef _WIN32
  if (_fseeki64(f, 0, SEEK_END) != 0) {
    rewind(f);
    return 1;
  }
  __int64 sz = _ftelli64(f);
  rewind(f);
  if (sz < 0) {
    return 1;
  }
  return (uint64_t)sz <= limit;
#else
  if (fseeko(f, 0, SEEK_END) != 0) {
    rewind(f);
    return 1;
  }
  off_t sz = ftello(f);
  rewind(f);
  if (sz < 0) {
    return 1;
  }
  return (uint64_t)sz <= limit;
#endif
}

static int hash_file_sha256_bounded(const char *path, char out65[65]) {
  if (!out65) {
    return -1;
  }
  out65[0] = '\0';
  if (!process_hash_enabled() || !is_drive_path(path)) {
    return -1;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  if (!file_size_within_limit(f, process_hash_max_bytes())) {
    fclose(f);
    return -1;
  }
  EdrSha256Ctx ctx;
  edr_sha256_init(&ctx);
  uint8_t buf[32768];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    edr_sha256_update(&ctx, buf, n);
  }
  if (ferror(f)) {
    fclose(f);
    out65[0] = '\0';
    return -1;
  }
  fclose(f);
  uint8_t d[EDR_SHA256_DIGEST_LEN];
  edr_sha256_final(&ctx, d);
  static const char hx[] = "0123456789abcdef";
  for (size_t i = 0; i < EDR_SHA256_DIGEST_LEN; i++) {
    out65[i * 2u] = hx[(d[i] >> 4) & 0xfu];
    out65[i * 2u + 1u] = hx[d[i] & 0xfu];
  }
  out65[64] = '\0';
  return 0;
}

static void enrich_process_integrity_context(EdrBehaviorRecord *br) {
  if (!br || br->type != EDR_EVENT_PROCESS_CREATE || br->pid == 0u) {
    return;
  }
  if (!br->parent_name[0] && br->ppid > 0u) {
    (void)enrich_parent_info_by_pid(br->ppid, br->parent_name, sizeof(br->parent_name),
                                    br->parent_path, sizeof(br->parent_path));
  }
  (void)edr_pt_cache_put(br->pid, br->ppid, br->process_name, br->cmdline, br->exe_path,
                         br->parent_name, (uint64_t)(br->event_time_ns > 0 ? br->event_time_ns : 0));
  {
    uint32_t chain_depth = 0u;
    edr_pt_cache_fill_record(br->pid,
                             br->grandparent_name, sizeof(br->grandparent_name),
                             br->grandparent_path, sizeof(br->grandparent_path),
                             &br->grandparent_pid,
                             br->parent_cmdline, sizeof(br->parent_cmdline),
                             &chain_depth);
    if (chain_depth > 0u) {
      br->process_chain_depth = chain_depth;
    }
  }
  if (!br->process_creation_time[0]) {
    format_record_time_ns(br->event_time_ns, br->process_creation_time, sizeof(br->process_creation_time));
  }
  if (!br->exe_hash[0] && br->exe_path[0]) {
    (void)hash_file_sha256_bounded(br->exe_path, br->exe_hash);
  }
}

static void log_p0_runtime_state(void) {
  edr_p0_rule_ir_lazy_init();
  const char *ir_source = "";
  const char *ir_sha256 = "";
  size_t ir_plain_size = 0u;
  (void)edr_p0_rule_ir_get_bundle_info(&ir_source, &ir_plain_size, &ir_sha256);
  fprintf(stderr, "[P0] direct_emit=%s ir_ready=%d rules=%d bundle=%s ir_plain_size=%zu ir_sha256=%s ir_source=%s\n",
          p0_direct_emit_enabled() ? "on" : "off",
          edr_p0_rule_ir_is_ready(),
          edr_p0_rule_ir_rule_count(),
          EDR_P0_RULES_BUNDLE_VERSION,
          ir_plain_size,
          (ir_sha256 && ir_sha256[0]) ? ir_sha256 : "unknown",
          (ir_source && ir_source[0]) ? ir_source : "unknown");
}

static void emit_behavior_record(const EdrBehaviorRecord *br) {
  if (!br) {
    return;
  }
  uint8_t buf[16384];
  size_t n = 0;
  const char *enc = getenv("EDR_BEHAVIOR_ENCODING");
  if (!enc || enc[0] == '\0' || strcmp(enc, "protobuf") == 0) {
#ifdef EDR_HAVE_NANOPB
    n = edr_behavior_record_encode_protobuf(br, buf, sizeof(buf));
#endif
    if (n == 0) {
      n = edr_behavior_wire_encode(br, buf, sizeof(buf));
    }
  } else if (enc && strcmp(enc, "protobuf_c") == 0) {
    n = edr_behavior_record_encode_protobuf_c(br, buf, sizeof(buf));
    if (n == 0) {
      n = edr_behavior_wire_encode(br, buf, sizeof(buf));
    }
  } else {
    n = edr_behavior_wire_encode(br, buf, sizeof(buf));
  }
  if (n > 0) {
    (void)edr_event_batch_push(buf, n);
  }
}

/* behavior_summary flush 的 emit 回调：直接复用统一编码 + 入批次路径。 */
static void emit_summary_record(const EdrBehaviorRecord *br) {
  emit_behavior_record(br);
}

/* 节流的行为簇摘要 flush：最多每 ~30s 扫描一次已关闭窗口的聚合槽。 */
static void poll_summary_flush(void) {
  static uint64_t s_last_flush_mono_ns;
  uint64_t mono = edr_monotonic_ns();
  if (s_last_flush_mono_ns != 0u && mono - s_last_flush_mono_ns < 30000000000ULL) {
    return;
  }
  s_last_flush_mono_ns = mono;
  int64_t now_ns = (int64_t)time(NULL) * 1000000000LL;
  edr_local_evidence_cache_flush_summaries(now_ns, emit_summary_record);
}

static void process_one_slot(const EdrEventSlot *slot) {
  /* AGT-010：资源压力下跳过低优先级槽位；保留 priority==0 与 §19.10 attack_surface_hint */
  if (edr_resource_preprocess_throttle_active() && slot && slot->priority != 0u &&
      slot->attack_surface_hint == 0u) {
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
  EdrBehaviorRecord br;
  edr_behavior_from_slot(slot, &br);
  apply_agent_ids_to_record(&br);
  enrich_process_integrity_context(&br);
  edr_local_evidence_cache_enrich_behavior(&br);
  edr_windows_event_policy_apply(&br);
  edr_pid_history_pmfe_fill_record(&br);
  edr_p0_rule_try_emit(&br);
  edr_correlation_evaluate(&br); /* 集成点 B：序列/合流关联（总开关默认关时为 no-op） */
  edr_net_fanout_on_event(&br);
  {
    EdrDetectionDecision dd;
    edr_detection_decision_evaluate(&br, &dd);
    if (dd.drop) {
      edr_local_evidence_cache_record_behavior(&br);
      return;
    }
    /* EQS enforcement：低上传价值（local_only）不投递平台，仅进本地证据缓存
     * （普通事件在缓存内 coalesce → 由 behavior_summary 周期性以一条摘要替代逐条）。
     * 仅 emit_context / emit_alert 继续走候选与上传路径。drop 已在上面拦下。 */
    if (dd.selection_action[0] != '\0' && strcmp(dd.selection_action, "local_only") == 0) {
      edr_local_evidence_cache_record_behavior(&br);
      return;
    }
  }
  if (!edr_preprocess_should_emit(&br)) {
    return;
  }
  edr_local_evidence_cache_record_behavior(&br);
  edr_pmfe_on_preprocess_slot(slot, &br);
  /* P2 T9：Shellcode / Webshell / PMFE → AVE 行为槽（E 组 46–47、53–54） */
  if (edr_windows_event_policy_should_emit(&br)) {
    edr_ave_cross_engine_feed_from_record(&br);
  }
  (void)edr_command_dispatch_recommended_forensics(&br);
  if (!edr_local_evidence_cache_is_candidate(&br)) {
    return;
  }
  if (!edr_preprocess_sampling_allow(&br)) {
    return;
  }
  emit_behavior_record(&br);
}

#ifdef _WIN32
static DWORD WINAPI preprocess_main(void *arg) {
#else
static void *preprocess_main(void *arg) {
#endif
  (void)arg;
  for (;;) {
    edr_health_beat(EDR_HEALTH_PREPROCESS);
    EdrEventSlot slot;
    if (edr_event_bus_try_pop(s_bus, &slot)) {
      process_one_slot(&slot);
      edr_event_batch_poll_timeout();
      edr_storage_queue_poll_drain();
      edr_local_evidence_cache_poll_maintenance();
      edr_correlation_poll_maintenance(0); /* 内部节流；同预处理线程，满足契约 */
      poll_summary_flush();
      continue;
    }
    edr_event_batch_poll_timeout();
    edr_storage_queue_poll_drain();
    edr_local_evidence_cache_poll_maintenance();
    edr_correlation_poll_maintenance(0); /* 空闲期兜底排空注入 + 定期清扫 */
    poll_summary_flush();
#ifdef _WIN32
    if (s_stop_preprocess) {
      while (edr_event_bus_try_pop(s_bus, &slot)) {
        process_one_slot(&slot);
      }
      edr_storage_queue_poll_drain();
      edr_local_evidence_cache_poll_maintenance();
      break;
    }
    Sleep(1);
#else
    if (s_stop_preprocess) {
      while (edr_event_bus_try_pop(s_bus, &slot)) {
        process_one_slot(&slot);
      }
      edr_storage_queue_poll_drain();
      edr_local_evidence_cache_poll_maintenance();
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
  }
  edr_dedup_configure(cfg->preprocessing.dedup_window_s,
                      cfg->preprocessing.high_freq_threshold);
  edr_emit_rules_configure(cfg);
  sync_sampling_from_cfg(cfg);
  log_p0_runtime_state();
  edr_dedup_init();
  edr_pt_cache_init();
  (void)edr_pt_cache_warmup();
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
  sync_sampling_from_cfg(cfg);
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
  edr_pt_cache_shutdown();
  edr_event_batch_shutdown();
  edr_emit_rules_configure(NULL);
  edr_dedup_reset();
}
