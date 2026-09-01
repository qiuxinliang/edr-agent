/**
 * AVEngine SDK — rule, allow-list, and behavior-heuristic operations.
 */

#include "edr/ave_sdk.h"

#include "edr/ave.h"
#include "edr/config.h"
#include "edr/sha256.h"

#include "ave_sign_whitelist.h"
#include "ave_suppression.h"
#include "ave_rules_meta.h"
#include "ave_behavior_pipeline.h"
#include "ave_db_update.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

static EdrConfig g_cfg;
/** 1：`AVE_Init` 拥有 g_cfg；0：`AVE_InitFromEdrConfig` 引用外部配置 */
static int s_owns_edr_config;
static const EdrConfig *s_ext_cfg;
static int g_initialized;
static float s_l3_trigger = 0.60f;
static float s_fp_floor = 0.60f;
static AVECallbacks s_callbacks;
static int s_callbacks_set;

#ifdef _WIN32
static CRITICAL_SECTION s_scan_mu;
static int s_scan_mu_inited;
#else
static pthread_mutex_t s_scan_mu = PTHREAD_MUTEX_INITIALIZER;
#endif

static void scan_lock(void) {
#ifdef _WIN32
  if (s_scan_mu_inited) {
    EnterCriticalSection(&s_scan_mu);
  }
#else
  (void)pthread_mutex_lock(&s_scan_mu);
#endif
}

static void scan_unlock(void) {
#ifdef _WIN32
  if (s_scan_mu_inited) {
    LeaveCriticalSection(&s_scan_mu);
  }
#else
  (void)pthread_mutex_unlock(&s_scan_mu);
#endif
}

static void ensure_scan_mutex(void) {
#ifdef _WIN32
  if (!s_scan_mu_inited) {
    InitializeCriticalSection(&s_scan_mu);
    s_scan_mu_inited = 1;
  }
#endif
}

static const EdrConfig *active_edr_config(void) {
  if (s_owns_edr_config) {
    return &g_cfg;
  }
  return s_ext_cfg;
}

static int edr_err_to_ave(EdrError e) {
  switch (e) {
    case EDR_OK:
      return AVE_OK;
    case EDR_ERR_INVALID_ARG:
      return AVE_ERR_INVALID_PARAM;
    case EDR_ERR_AVE_LOAD_FAILED:
      return AVE_ERR_MODEL_LOAD;
    case EDR_ERR_AVE_VERSION_MISMATCH:
      return AVE_ERR_MODEL_VERSION;
    case EDR_ERR_AVE_SCAN_TIMEOUT:
      return AVE_ERR_TIMEOUT;
    case EDR_ERR_NOT_IMPL:
      return AVE_ERR_NOT_IMPL;
    default:
      return AVE_ERR_INTERNAL;
  }
}

static int64_t mono_ms(void) {
#ifdef _WIN32
  return (int64_t)GetTickCount64();
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

/* Result fields are authoritative scan evidence.  A caller must not receive a
 * prefix that looks like a complete path or model version. */
static int copy_cstr_exact(char *out, size_t out_cap, const char *value) {
  size_t value_len;
  if (!out || out_cap == 0u || !value) {
    return 0;
  }
  value_len = strlen(value);
  if (value_len >= out_cap) {
    out[0] = '\0';
    return 0;
  }
  memcpy(out, value, value_len + 1u);
  return 1;
}

static int hash_file_sha256(const char *path, char out65[65]) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  EdrSha256Ctx ctx;
  edr_sha256_init(&ctx);
  uint8_t buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    edr_sha256_update(&ctx, buf, n);
  }
  fclose(f);
  uint8_t d[EDR_SHA256_DIGEST_LEN];
  edr_sha256_final(&ctx, d);
  static const char *hex = "0123456789abcdef";
  for (int i = 0; i < EDR_SHA256_DIGEST_LEN; i++) {
    out65[i * 2] = hex[d[i] >> 4];
    out65[i * 2 + 1] = hex[d[i] & 0xf];
  }
  out65[64] = '\0';
  return 0;
}

/** L3 IOC：已知恶意哈希优先于 L2 哈希白名单，避免双库冲突误放行。 */
static void fill_ioc_file_hash(AVEScanResult *out, int severity) {
  (void)severity;
  out->raw_ai_verdict = VERDICT_MALWARE;
  out->final_verdict = VERDICT_IOC_CONFIRMED;
  out->raw_confidence = 1.f;
  out->final_confidence = 1.f;
  snprintf(out->verification_layer, sizeof(out->verification_layer), "L3");
  snprintf(out->rule_name, sizeof(out->rule_name), "ioc_file_hash");
  out->skip_ai_analysis = true;
}

/** L2：文件哈希白名单。 */
static void fill_file_hash_whitelist(AVEScanResult *out) {
  out->raw_ai_verdict = VERDICT_CLEAN;
  out->final_verdict = VERDICT_WHITELISTED;
  out->raw_confidence = 0.f;
  out->final_confidence = 0.f;
  snprintf(out->verification_layer, sizeof(out->verification_layer), "L2");
  snprintf(out->rule_name, sizeof(out->rule_name), "file_hash_whitelist");
  out->skip_ai_analysis = true;
}

static const char *verdict_name(EDRVerdict v) {
  switch (v) {
    case VERDICT_CLEAN:
      return "clean";
    case VERDICT_SUSPICIOUS:
      return "suspicious";
    case VERDICT_MALWARE:
      return "malware";
    case VERDICT_IOC_CONFIRMED:
      return "ioc_confirmed";
    case VERDICT_WHITELISTED:
      return "whitelisted";
    default:
      return "unknown";
  }
}

static void apply_tenant_noise_policy(const EdrConfig *pcfg, AVEScanResult *out) {
  if (!pcfg || !out) {
    return;
  }
  if (out->final_verdict == VERDICT_IOC_CONFIRMED || out->final_verdict == VERDICT_WHITELISTED) {
    return;
  }
  char model_version[64];
  const char *override = getenv("EDR_AVE_POLICY_MODEL_VERSION");
  if (override && override[0]) {
    if (!copy_cstr_exact(model_version, sizeof(model_version), override)) {
      return;
    }
  } else {
    (void)copy_cstr_exact(model_version, sizeof(model_version), "rules-only-v1");
  }
  EdrAveTenantNoiseDecision dec;
  if (!edr_ave_tenant_noise_lookup(pcfg, pcfg->agent.tenant_id, model_version, out->rule_name,
                                   out->final_confidence, &dec)) {
    return;
  }
  const char *shadow = verdict_name(out->final_verdict);
  if (dec.suppress) {
    out->final_verdict = VERDICT_WHITELISTED;
    out->final_confidence = dec.adjusted_confidence;
    out->skip_ai_analysis = true;
    (void)copy_cstr_exact(out->verification_layer, sizeof(out->verification_layer), "TP");
    (void)copy_cstr_exact(out->rule_name, sizeof(out->rule_name), "tenant_noise_suppressed");
  } else if (dec.needs_review) {
    out->needs_l2_review = true;
    out->final_confidence = dec.adjusted_confidence;
    (void)copy_cstr_exact(out->verification_layer, sizeof(out->verification_layer), "TR");
  } else if (!dec.observe_only) {
    out->final_confidence = dec.adjusted_confidence;
  }
  if (dec.gray_percent > 0u || dec.observe_only) {
    (void)edr_ave_gray_eval_record(pcfg, pcfg->agent.tenant_id, model_version, dec.policy_version, out->rule_name,
                                   out->raw_confidence, out->final_confidence, dec.action, shadow);
  }
}

int AVE_Init(const AVEConfig *config) {
  if (g_initialized) {
    return AVE_ERR_ALREADY_INIT;
  }
  if (!config) {
    return AVE_ERR_INVALID_PARAM;
  }

  s_ext_cfg = NULL;
  s_owns_edr_config = 0;
  memset(&g_cfg, 0, sizeof(g_cfg));
  EdrError ce = edr_config_load(NULL, &g_cfg);
  if (ce != EDR_OK) {
    edr_config_free_heap(&g_cfg);
    memset(&g_cfg, 0, sizeof(g_cfg));
    return AVE_ERR_INTERNAL;
  }

  int threads = config->max_concurrent_scans > 0 ? config->max_concurrent_scans : 4;
  if (threads < 1) {
    threads = 1;
  }
  if (threads > 16) {
    threads = 16;
  }
  g_cfg.ave.scan_threads = threads;

  s_l3_trigger = config->l3_trigger_threshold > 0.0f ? config->l3_trigger_threshold : 0.60f;
  s_fp_floor = config->fp_suppression_threshold > 0.0f ? config->fp_suppression_threshold : 0.60f;

  if (config->cert_whitelist_db_path && config->cert_whitelist_db_path[0]) {
    snprintf(g_cfg.ave.cert_whitelist_db_path, sizeof(g_cfg.ave.cert_whitelist_db_path), "%s",
             config->cert_whitelist_db_path);
  }
  if (config->whitelist_db_path && config->whitelist_db_path[0]) {
    snprintf(g_cfg.ave.file_whitelist_db_path, sizeof(g_cfg.ave.file_whitelist_db_path), "%s",
             config->whitelist_db_path);
  }
  if (config->ioc_db_path && config->ioc_db_path[0]) {
    snprintf(g_cfg.ave.ioc_db_path, sizeof(g_cfg.ave.ioc_db_path), "%s", config->ioc_db_path);
  }
  if (config->behavior_policy_db_path && config->behavior_policy_db_path[0]) {
    snprintf(g_cfg.ave.behavior_policy_db_path, sizeof(g_cfg.ave.behavior_policy_db_path), "%s",
             config->behavior_policy_db_path);
  }
  g_cfg.ave.behavior_monitor_enabled = config->behavior_monitor_enabled;
  g_cfg.ave.cert_revocation_check = config->strict_revocation_check;
  g_cfg.ave.l4_realtime_behavior_link = config->l4_realtime_behavior_link;
  {
    float th = config->l4_realtime_anomaly_threshold;
    g_cfg.ave.l4_realtime_anomaly_threshold = (th > 0.f) ? th : 0.65f;
  }

  EdrError e = edr_ave_init(&g_cfg);
  if (e != EDR_OK) {
    edr_config_free_heap(&g_cfg);
    memset(&g_cfg, 0, sizeof(g_cfg));
    return edr_err_to_ave(e);
  }

  s_owns_edr_config = 1;
  s_ext_cfg = NULL;
  ensure_scan_mutex();

  edr_ave_bp_init();
  edr_ave_bp_configure_resource_limits(&g_cfg);
  g_initialized = 1;
  return AVE_OK;
}

int AVE_InitFromEdrConfig(const EdrConfig *cfg) {
  if (g_initialized) {
    return AVE_ERR_ALREADY_INIT;
  }
  if (!cfg) {
    return AVE_ERR_INVALID_PARAM;
  }

  s_l3_trigger = 0.60f;
  s_fp_floor = 0.60f;
  s_owns_edr_config = 0;
  s_ext_cfg = cfg;

  EdrError e = edr_ave_init(cfg);
  if (e != EDR_OK) {
    s_ext_cfg = NULL;
    return edr_err_to_ave(e);
  }

  {
    const char *vkw = getenv("EDR_AVE_TRUSTED_VENDOR_KEYWORDS");
    if (vkw && vkw[0]) {
      fprintf(stderr, "[ave/config] EDR_AVE_TRUSTED_VENDOR_KEYWORDS=%s\n", vkw);
    } else {
      fprintf(stderr, "%s", "[ave/config] EDR_AVE_TRUSTED_VENDOR_KEYWORDS=<builtin_only>\n");
    }
  }

  ensure_scan_mutex();

  edr_ave_bp_init();
  edr_ave_bp_configure_resource_limits(cfg);
  g_initialized = 1;
  return AVE_OK;
}

int AVE_SyncFromEdrConfig(const EdrConfig *cfg) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!cfg) {
    return AVE_ERR_INVALID_PARAM;
  }
  edr_ave_bp_configure_resource_limits(cfg);
  return AVE_OK;
}

int AVE_RegisterCallbacks(const AVECallbacks *callbacks) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!callbacks) {
    return AVE_ERR_INVALID_PARAM;
  }
  s_callbacks = *callbacks;
  s_callbacks_set = 1;
  edr_ave_bp_set_callbacks(callbacks);
  return AVE_OK;
}

int AVE_StartBehaviorMonitor(void) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!s_callbacks_set) {
    return AVE_ERR_INVALID_PARAM;
  }
  const EdrConfig *pcfg = active_edr_config();
  if (!pcfg) {
    return AVE_ERR_INTERNAL;
  }
  return edr_ave_bp_start_monitor(pcfg);
}

void AVE_Shutdown(void) {
  if (!g_initialized) {
    return;
  }
  scan_lock();
  edr_ave_bp_shutdown();
  edr_ave_shutdown();
  if (s_owns_edr_config) {
    edr_config_free_heap(&g_cfg);
    memset(&g_cfg, 0, sizeof(g_cfg));
  }
  s_owns_edr_config = 0;
  s_ext_cfg = NULL;
  g_initialized = 0;
  s_callbacks_set = 0;
  memset(&s_callbacks, 0, sizeof(s_callbacks));
  scan_unlock();
}

const char *AVE_GetVersion(void) { return "2.5.0"; }

int AVE_GetStatus(AVEStatus *status_out) {
  if (!status_out) {
    return AVE_ERR_INVALID_PARAM;
  }
  memset(status_out, 0, sizeof(*status_out));
  status_out->initialized = g_initialized ? true : false;
  status_out->behavior_monitor_running = edr_ave_bp_monitor_running() ? true : false;
  status_out->behavior_event_queue_size = (int)edr_ave_bp_queue_depth();
#ifdef EDR_HAVE_SQLITE
  {
    const EdrConfig *pcfg = active_edr_config();
    if (g_initialized && pcfg) {
      (void)edr_ave_db_meta_get(pcfg->ave.ioc_db_path, "rules_version", status_out->ioc_rules_version,
                               sizeof(status_out->ioc_rules_version));
      (void)edr_ave_db_meta_get(pcfg->ave.file_whitelist_db_path, "rules_version",
                                status_out->whitelist_version, sizeof(status_out->whitelist_version));
      (void)edr_ave_db_meta_get(pcfg->ave.cert_whitelist_db_path, "rules_version",
                                status_out->cert_whitelist_version,
                                sizeof(status_out->cert_whitelist_version));
      {
        int n = edr_ave_db_count_ioc_rows(pcfg->ave.ioc_db_path);
        if (n >= 0) {
          status_out->ioc_entry_count = n;
        }
      }
    }
  }
#endif
  edr_ave_bp_fill_metrics(status_out);
  return AVE_OK;
}

/** 将 static 扫描结论写入行为槽，供主机行为上下文与服务端关联分析使用。 */
static void ave_bp_merge_static_if_subject(uint32_t subject_pid, const AVEScanResult *r) {
  if (subject_pid == 0u || !r) {
    return;
  }
  edr_ave_bp_merge_static_scan(subject_pid, r->final_confidence, (int)r->final_verdict);
}

static int env_skip_ext_enabled(void) {
  const char *e = getenv("EDR_AVE_SKIP_BY_EXT");
  if (e && (e[0] == '0' || e[0] == 'n' || e[0] == 'N')) {
    return 0;
  }
  return 1;  // 默认启用
}

static const char *safe_file_ext(const char *path) {
  if (!path) return NULL;
  const char *base = strrchr(path, '/');
  if (!base) base = strrchr(path, '\\');
  if (!base) base = path;
  else base++;
  const char *dot = strrchr(base, '.');
  if (!dot || dot == base) return NULL;
  return dot + 1;
}

static int is_known_safe_ext(const char *ext) {
  static const char *safe_exts[] = {
    "jpg", "jpeg", "png", "gif", "bmp", "ico", "webp", "svg",  // 图片
    "mp3", "wav", "ogg", "flac", "aac", "m4a",               // 音频
    "mp4", "avi", "mkv", "mov", "wmv", "flv", "webm",         // 视频
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz",             // 压缩包
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",        // 文档
    "txt", "rtf", "csv", "json", "xml", "html", "htm",        // 文本
    "css", "js", "ts", "jsx", "tsx",                           // Web
    "ttf", "otf", "woff", "woff2",                            // 字体
  };
  if (!ext) return 0;
  for (size_t i = 0; i < sizeof(safe_exts) / sizeof(safe_exts[0]); i++) {
#ifdef _WIN32
    if (_stricmp(ext, safe_exts[i]) == 0) return 1;
#else
    if (strcasecmp(ext, safe_exts[i]) == 0) return 1;
#endif
  }
  return 0;
}

static int64_t get_file_size_fast(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  fseek(f, 0, SEEK_END);
  int64_t sz = (int64_t)ftell(f);
  fclose(f);
  return sz;
}

static int ave_scan_file_impl(const char *file_path, uint32_t subject_pid, AVEScanResult *result_out) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!file_path || !file_path[0] || !result_out) {
    return AVE_ERR_INVALID_PARAM;
  }

  memset(result_out, 0, sizeof(*result_out));
  if (!copy_cstr_exact(result_out->scanned_path, sizeof(result_out->scanned_path), file_path)) {
    return AVE_ERR_INVALID_PARAM;
  }

  if (env_skip_ext_enabled()) {
    const char *ext = safe_file_ext(file_path);
    if (ext && is_known_safe_ext(ext)) {
      result_out->final_verdict = VERDICT_WHITELISTED;
      result_out->final_confidence = 0.01f;
      result_out->scan_duration_ms = 0;
      (void)copy_cstr_exact(result_out->verification_layer,
                            sizeof(result_out->verification_layer), "L2");
      (void)copy_cstr_exact(result_out->rule_name, sizeof(result_out->rule_name),
                            "extension_filter");
      return AVE_OK;
    }
  }

  int64_t fsize = get_file_size_fast(file_path);
  if (fsize < 0) {
    return AVE_ERR_INTERNAL;
  }

  FILE *probe = fopen(file_path, "rb");
  if (!probe) {
    if (errno == ENOENT) {
      return AVE_ERR_FILE_NOT_FOUND;
    }
    if (errno == EACCES) {
      return AVE_ERR_ACCESS_DENIED;
    }
    return AVE_ERR_INTERNAL;
  }
  fclose(probe);

  if (hash_file_sha256(file_path, result_out->sha256) != 0) {
    return AVE_ERR_INTERNAL;
  }

  int64_t t0 = mono_ms();
  const EdrConfig *pcfg = active_edr_config();
  if (!pcfg) {
    return AVE_ERR_INTERNAL;
  }
  if (fsize == 0) {
    int ioc_sev_empty = 3;
    if (edr_ave_ioc_file_hit(pcfg, result_out->sha256, &ioc_sev_empty)) {
      if (pcfg->ave.ioc_precheck_enabled) {
        fill_ioc_file_hash(result_out, ioc_sev_empty);
      } else {
        edr_ave_overlay_ioc_post_ai(result_out, ioc_sev_empty);
      }
    } else {
      result_out->final_verdict = VERDICT_WHITELISTED;
      result_out->final_confidence = 0.0f;
      (void)copy_cstr_exact(result_out->verification_layer,
                            sizeof(result_out->verification_layer), "L2");
      (void)copy_cstr_exact(result_out->rule_name, sizeof(result_out->rule_name), "empty_file");
    }
    result_out->scan_duration_ms = 0;
    ave_bp_merge_static_if_subject(subject_pid, result_out);
    return AVE_OK;
  }

  int skip_static_analysis = 0;
  if (pcfg->ave.cert_whitelist_enabled) {
    edr_ave_sign_stage0(pcfg, file_path, result_out->sha256, result_out, &skip_static_analysis);
  }
  if (skip_static_analysis) {
    int64_t t1done = mono_ms();
    result_out->scan_duration_ms = t1done - t0;
    ave_bp_merge_static_if_subject(subject_pid, result_out);
    return AVE_OK;
  }

  /* L3 IOC 预检（可关）：先于 L2 哈希白名单；关闭时仍在规则阶段二次核对。 */
  if (pcfg->ave.ioc_precheck_enabled) {
    int ioc_sev = 3;
    if (edr_ave_ioc_file_hit(pcfg, result_out->sha256, &ioc_sev)) {
      fill_ioc_file_hash(result_out, ioc_sev);
      int64_t t1done = mono_ms();
      result_out->scan_duration_ms = t1done - t0;
      ave_bp_merge_static_if_subject(subject_pid, result_out);
      return AVE_OK;
    }
  }
  if (edr_ave_file_hash_whitelist_hit(pcfg, result_out->sha256)) {
    fill_file_hash_whitelist(result_out);
    int64_t t1done = mono_ms();
    result_out->scan_duration_ms = t1done - t0;
    ave_bp_merge_static_if_subject(subject_pid, result_out);
    return AVE_OK;
  }

  /* Endpoint model execution was retired.  A file that did not match a
   * trusted rule stays clean; later L4 and tenant policy may still elevate or
   * suppress the result using signed policy and behavior evidence. */
  result_out->raw_ai_verdict = VERDICT_CLEAN;
  result_out->final_verdict = VERDICT_CLEAN;
  result_out->raw_confidence = 0.f;
  result_out->final_confidence = 0.f;
  snprintf(result_out->verification_layer, sizeof(result_out->verification_layer), "R0");
  snprintf(result_out->rule_name, sizeof(result_out->rule_name), "rules_only_no_match");
  {
    int ioc_sev2 = 3;
    if (edr_ave_ioc_file_hit(pcfg, result_out->sha256, &ioc_sev2)) {
      edr_ave_overlay_ioc_post_ai(result_out, ioc_sev2);
    }
  }
  {
    int esc = 1;
    if (edr_ave_l4_non_exempt_hit(pcfg, result_out->sha256, &esc)) {
      edr_ave_apply_l4_non_exempt(result_out, esc, s_fp_floor, s_l3_trigger);
    }
  }
  {
    int link = pcfg->ave.l4_realtime_behavior_link ? 1 : 0;
    const char *el = getenv("EDR_AVE_L4_BEHAVIOR_LINK");
    if (el && el[0] == '1') {
      link = 1;
    }
    if (el && el[0] == '0') {
      link = 0;
    }
    if (link && subject_pid != 0u) {
      float sc = 0.f;
      if (edr_ave_bp_get_score(subject_pid, &sc) == AVE_OK &&
          sc >= pcfg->ave.l4_realtime_anomaly_threshold) {
        edr_ave_apply_l4_realtime_behavior(result_out, 1, s_fp_floor, s_l3_trigger);
      }
    }
  }
  result_out->scan_duration_ms = mono_ms() - t0;
  apply_tenant_noise_policy(pcfg, result_out);
  ave_bp_merge_static_if_subject(subject_pid, result_out);
  return AVE_OK;
}

int AVE_ScanFile(const char *file_path, AVEScanResult *result_out) {
  return ave_scan_file_impl(file_path, 0u, result_out);
}

int AVE_ScanFileWithSubject(const char *file_path, const AVEScanSubject *subject, AVEScanResult *result_out) {
  uint32_t pid = 0u;
  if (subject) {
    pid = subject->subject_pid;
  }
  return ave_scan_file_impl(file_path, pid, result_out);
}

int64_t AVE_ScanFileAsync(const char *file_path) {
  (void)file_path;
  return (int64_t)AVE_ERR_NOT_IMPL;
}

int AVE_ScanMemory(const uint8_t *buffer, size_t size, const char *hint_name, AVEScanResult *result_out) {
  (void)buffer;
  (void)size;
  (void)hint_name;
  (void)result_out;
  return AVE_ERR_NOT_IMPL;
}

int AVE_CancelScan(int64_t scan_id) {
  (void)scan_id;
  return AVE_ERR_NOT_IMPL;
}

typedef struct AVEBehaviorEventV26 {
  uint32_t pid;
  uint32_t ppid;
  AVEEventType event_type;
  uint8_t severity_hint;
  int64_t timestamp_ns;
  char target_path[512];
  char target_ip[46];
  char target_domain[256];
  uint16_t target_port;
  float ave_confidence;
  float shellcode_score;
  float webshell_score;
  float pmfe_confidence;
  float pmfe_dns_tunnel;
  uint8_t pmfe_pe_found;
  char file_sha256_hex[65];
  uint8_t ioc_ip_hit;
  uint8_t ioc_domain_hit;
  uint8_t ioc_sha256_hit;
  AVEBehaviorFlags behavior_flags;
  uint8_t target_has_motw;
  uint8_t cert_revoked_ancestor;
} AVEBehaviorEventV26;

static int ave_feed_event_current(const AVEBehaviorEvent *event) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!event) {
    return AVE_ERR_INVALID_PARAM;
  }
  AVEBehaviorEvent ev = *event;
  const EdrConfig *pcfg = active_edr_config();
  if (pcfg && !pcfg->ave.behavior_monitor_enabled) {
    return AVE_OK;
  }
  if (pcfg) {
    edr_ave_behavior_event_apply_ioc(pcfg, &ev);
  }
  edr_ave_bp_feed(&ev);
  return AVE_OK;
}

void AVE_FeedEvent(const AVEBehaviorEvent *event) {
  if (!event) {
    return;
  }
  const AVEBehaviorEventV26 *legacy = (const AVEBehaviorEventV26 *)(const void *)event;
  AVEBehaviorEvent current;
  memset(&current, 0, sizeof(current));
  current.pid = legacy->pid;
  current.ppid = legacy->ppid;
  current.event_type = legacy->event_type;
  current.severity_hint = legacy->severity_hint;
  current.timestamp_ns = legacy->timestamp_ns;
  memcpy(current.target_path, legacy->target_path, sizeof(legacy->target_path));
  memcpy(current.target_ip, legacy->target_ip, sizeof(legacy->target_ip));
  memcpy(current.target_domain, legacy->target_domain, sizeof(legacy->target_domain));
  current.target_port = legacy->target_port;
  current.ave_confidence = legacy->ave_confidence;
  current.shellcode_score = legacy->shellcode_score;
  current.webshell_score = legacy->webshell_score;
  current.pmfe_confidence = legacy->pmfe_confidence;
  current.pmfe_dns_tunnel = legacy->pmfe_dns_tunnel;
  current.pmfe_pe_found = legacy->pmfe_pe_found;
  memcpy(current.file_sha256_hex, legacy->file_sha256_hex, sizeof(legacy->file_sha256_hex));
  current.ioc_ip_hit = legacy->ioc_ip_hit;
  current.ioc_domain_hit = legacy->ioc_domain_hit;
  current.ioc_sha256_hit = legacy->ioc_sha256_hit;
  current.behavior_flags = legacy->behavior_flags;
  current.target_has_motw = legacy->target_has_motw;
  current.cert_revoked_ancestor = legacy->cert_revoked_ancestor;
  (void)ave_feed_event_current(&current);
}

int AVE_FeedEventEx(const AVEBehaviorEvent *event, size_t event_size) {
  if (event_size != sizeof(AVEBehaviorEvent)) {
    return AVE_ERR_INVALID_PARAM;
  }
  return ave_feed_event_current(event);
}

int AVE_GetProcessAnomalyScore(uint32_t pid, float *score_out) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  return edr_ave_bp_get_score(pid, score_out);
}

int AVE_GetProcessBehaviorFlags(uint32_t pid, AVEBehaviorFlags *flags_out) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  return edr_ave_bp_get_flags(pid, flags_out);
}

void AVE_NotifyProcessExit(uint32_t pid) {
  if (!g_initialized) {
    return;
  }
  edr_ave_bp_notify_exit(pid);
}

static int append_ave_feedback_line(const char *kind, const char *sha256, const char *file_path) {
  if (!sha256 || !sha256[0]) {
    return -1;
  }
  char pathbuf[1200];
  const char *ev = getenv("EDR_AVE_FEEDBACK_PATH");
  if (ev && ev[0]) {
    snprintf(pathbuf, sizeof(pathbuf), "%s", ev);
  } else {
    const EdrConfig *pcfg = active_edr_config();
    if (pcfg && pcfg->logging.log_dir[0]) {
      snprintf(pathbuf, sizeof(pathbuf), "%s/ave_feedback.log", pcfg->logging.log_dir);
    } else {
      snprintf(pathbuf, sizeof(pathbuf), "%s", "ave_feedback.log");
    }
  }
  FILE *f = fopen(pathbuf, "a");
  if (!f) {
    return -1;
  }
  int64_t ms = mono_ms();
  const char *fp = file_path ? file_path : "";
  fprintf(f, "%lld %s sha256=%s path=%s\n", (long long)ms, kind, sha256, fp);
  fclose(f);
  return 0;
}

int AVE_ReportFalsePositive(const char *sha256, const char *file_path) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!sha256 || !sha256[0]) {
    return AVE_ERR_INVALID_PARAM;
  }
  if (append_ave_feedback_line("fp", sha256, file_path) != 0) {
    return AVE_ERR_INTERNAL;
  }
  return AVE_OK;
}

int AVE_ReportTruePositive(const char *sha256) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!sha256 || !sha256[0]) {
    return AVE_ERR_INVALID_PARAM;
  }
  if (append_ave_feedback_line("tp", sha256, NULL) != 0) {
    return AVE_ERR_INTERNAL;
  }
  return AVE_OK;
}

int AVE_UpdateWhitelist(const char *entries_json) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!entries_json || !entries_json[0]) {
    return AVE_ERR_INVALID_PARAM;
  }
  const EdrConfig *pcfg = active_edr_config();
  if (!pcfg) {
    return AVE_ERR_INTERNAL;
  }
  return edr_err_to_ave(edr_ave_update_whitelist_json(pcfg, entries_json));
}

int AVE_UpdateIOC(const char *ioc_json) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!ioc_json || !ioc_json[0]) {
    return AVE_ERR_INVALID_PARAM;
  }
  const EdrConfig *pcfg = active_edr_config();
  if (!pcfg) {
    return AVE_ERR_INTERNAL;
  }
  return edr_err_to_ave(edr_ave_update_ioc_json(pcfg, ioc_json));
}

int AVE_IsWhitelisted(const char *sha256) {
  if (!g_initialized || !sha256 || !sha256[0]) {
    return 0;
  }
  const EdrConfig *pcfg = active_edr_config();
  if (!pcfg) {
    return 0;
  }
  return edr_ave_file_hash_whitelist_hit(pcfg, sha256) ? 1 : 0;
}

#ifdef _WIN32
int AVE_VerifySignature(const wchar_t *file_path, SignatureVerifyResult *sig_result_out,
                        TrustLevel *trust_level_out, char *vendor_id_out, char *vendor_name_out) {
  if (!file_path || !sig_result_out) {
    return AVE_ERR_INVALID_PARAM;
  }
  const EdrConfig *pcfg = active_edr_config();
  return edr_ave_verify_signature_file(pcfg, file_path, sig_result_out, trust_level_out, vendor_id_out,
                                       vendor_name_out);
}
#endif
