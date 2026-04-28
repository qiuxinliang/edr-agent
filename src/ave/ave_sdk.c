/**
 * AVEngine SDK — Phase 1：对接 edr_ave_* / ONNX 推理，完整 API 占位见 ave_sdk.h。
 */

#include "edr/ave_sdk.h"

#include "edr/fl_feature_provider.h"

#include "edr/ave.h"
#include "edr/config.h"
#include "edr/sha256.h"

#include "ave_sign_whitelist.h"
#include "ave_suppression.h"
#include "ave_rules_meta.h"
#include "ave_behavior_pipeline.h"
#include "ave_onnx_infer.h"
#include "ave_hotfix.h"
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

/** 将后端 score（可能为 logit）映射到 (0,1) 便于与阈值比较 */
static float score_to_unit(float s) {
  if (s >= 0.0f && s <= 1.0f) {
    return s;
  }
  return 1.0f / (1.0f + expf(-s));
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

#ifndef EDR_AVE_INFER_CACHE_CAP
#define EDR_AVE_INFER_CACHE_CAP 256u
#endif

typedef struct {
  char sha256[65];
  EdrAveInferResult infer;
  int64_t inserted_ms;
} AveInferCacheEntry;

static AveInferCacheEntry s_infer_cache[EDR_AVE_INFER_CACHE_CAP];
static size_t s_infer_cache_n;

void edr_ave_infer_cache_clear(void) {
  s_infer_cache_n = 0;
  memset(s_infer_cache, 0, sizeof(s_infer_cache));
}

static void infer_cache_mru_touch(size_t idx) {
  if (idx == 0u || idx >= s_infer_cache_n) {
    return;
  }
  AveInferCacheEntry t = s_infer_cache[idx];
  memmove(&s_infer_cache[1], s_infer_cache, idx * sizeof(AveInferCacheEntry));
  s_infer_cache[0] = t;
}

static uint32_t infer_cache_max_effective(const EdrConfig *pcfg) {
  uint32_t m = pcfg->ave.static_infer_cache_max_entries;
  const char *ev = getenv("EDR_AVE_STATIC_INFER_CACHE_MAX");
  if (ev && ev[0]) {
    char *end = NULL;
    unsigned long v = strtoul(ev, &end, 10);
    (void)end;
    if (v <= (unsigned long)EDR_AVE_INFER_CACHE_CAP) {
      m = (uint32_t)v;
    }
  }
  if (m > (uint32_t)EDR_AVE_INFER_CACHE_CAP) {
    m = (uint32_t)EDR_AVE_INFER_CACHE_CAP;
  }
  return m;
}

static uint32_t infer_cache_ttl_effective(const EdrConfig *pcfg) {
  uint32_t t = pcfg->ave.static_infer_cache_ttl_s;
  const char *ev = getenv("EDR_AVE_STATIC_INFER_CACHE_TTL_S");
  if (ev && ev[0]) {
    char *end = NULL;
    unsigned long v = strtoul(ev, &end, 10);
    (void)end;
    if (v <= 8640000UL) {
      t = (uint32_t)v;
    }
  }
  return t;
}

static int infer_cache_get(const char *sha256, EdrAveInferResult *out, uint32_t ttl_s) {
  int64_t now = mono_ms();
  for (size_t i = 0; i < s_infer_cache_n; i++) {
    if (strcmp(s_infer_cache[i].sha256, sha256) != 0) {
      continue;
    }
    if (ttl_s > 0u) {
      int64_t age = now - s_infer_cache[i].inserted_ms;
      if (age > (int64_t)ttl_s * 1000) {
        memmove(&s_infer_cache[i], &s_infer_cache[i + 1u],
                (s_infer_cache_n - i - 1u) * sizeof(AveInferCacheEntry));
        s_infer_cache_n--;
        return 0;
      }
    }
    *out = s_infer_cache[i].infer;
    infer_cache_mru_touch(i);
    return 1;
  }
  return 0;
}

static void infer_cache_put(const char *sha256, const EdrAveInferResult *infer, size_t max_n) {
  if (max_n == 0u) {
    return;
  }
  if (max_n > (size_t)EDR_AVE_INFER_CACHE_CAP) {
    max_n = (size_t)EDR_AVE_INFER_CACHE_CAP;
  }
  for (size_t i = 0; i < s_infer_cache_n; i++) {
    if (strcmp(s_infer_cache[i].sha256, sha256) == 0) {
      memmove(&s_infer_cache[i], &s_infer_cache[i + 1u],
              (s_infer_cache_n - i - 1u) * sizeof(AveInferCacheEntry));
      s_infer_cache_n--;
      break;
    }
  }
  if (s_infer_cache_n >= max_n) {
    if (max_n < 1u) {
      return;
    }
    s_infer_cache_n--;
  }
  memmove(&s_infer_cache[1], s_infer_cache, s_infer_cache_n * sizeof(AveInferCacheEntry));
  snprintf(s_infer_cache[0].sha256, sizeof(s_infer_cache[0].sha256), "%s", sha256);
  s_infer_cache[0].infer = *infer;
  s_infer_cache[0].inserted_ms = mono_ms();
  s_infer_cache_n++;
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

static void apply_infer_verdict(const EdrAveInferResult *infer, AVEScanResult *out) {
  if (infer->onnx_layout == 1) {
    static const char *const kFam[32] = {
        "Ransomware",      "Trojan.Dropper", "Trojan.Downloader", "Backdoor",   "Rootkit",
        "Spyware",         "Adware",         "Worm",              "Exploit",    "Cryptominer",
        "Infostealer",     "RAT",            "Banker",            "Fileless",   "Packer.Malicious",
        "Emotet",          "TrickBot",       "Lockbit",           "Cobalt_Strike", "Mimikatz",
        "Meterpreter",     "AgentTesla",     "AsyncRAT",          "NJRat",      "RedLineStealer",
        "Qakbot",          "IcedID",         "PlugX",             "ShadowPad",  "APT_Tool_Generic",
        "Hacktool_Generic", "Unknown_Malware"};
    int vi = 0;
    float mx = infer->verdict_probs[0];
    for (int i = 1; i < 4; i++) {
      if (infer->verdict_probs[i] > mx) {
        mx = infer->verdict_probs[i];
        vi = i;
      }
    }
    /* 静态 SUSPICIOUS 低置信 → 降 CLEAN；0.40 与《11》§7 `EDR_AVE_BEH_SCORE_MEDIUM_LOW` 同刻度，规则域不同 */
    if (vi == 1 && infer->verdict_probs[1] < 0.40f) {
      vi = 0;
      mx = infer->verdict_probs[0];
    }
    out->raw_confidence = mx;
    out->final_confidence = mx;
    switch (vi) {
      case 0:
        out->raw_ai_verdict = VERDICT_CLEAN;
        out->final_verdict = VERDICT_CLEAN;
        break;
      case 1:
        out->raw_ai_verdict = VERDICT_SUSPICIOUS;
        out->final_verdict = VERDICT_SUSPICIOUS;
        break;
      case 2:
        out->raw_ai_verdict = VERDICT_MALWARE;
        out->final_verdict = VERDICT_MALWARE;
        break;
      case 3:
        out->raw_ai_verdict = VERDICT_SUSPICIOUS;
        out->final_verdict = VERDICT_SUSPICIOUS;
        out->needs_l2_review = true;
        break;
      default:
        out->raw_ai_verdict = VERDICT_CLEAN;
        out->final_verdict = VERDICT_CLEAN;
        break;
    }
    snprintf(out->verification_layer, sizeof(out->verification_layer), "AI");
    snprintf(out->rule_name, sizeof(out->rule_name), "%s", "static_onnx");
    out->family_name[0] = '\0';
    {
      int fi = 0;
      float fmx = infer->family_probs[0];
      for (int i = 1; i < 32; i++) {
        if (infer->family_probs[i] > fmx) {
          fmx = infer->family_probs[i];
          fi = i;
        }
      }
      if (fmx > 0.50f) {
        snprintf(out->family_name, sizeof(out->family_name), "%s", kFam[fi]);
      }
    }
    out->is_packed = false;
    for (int i = 0; i < 8; i++) {
      if (infer->packer_probs[i] > 0.60f) {
        out->is_packed = true;
        break;
      }
    }
    return;
  }

  float c = score_to_unit(infer->score);
  out->raw_confidence = c;
  out->final_confidence = c;
  if (c >= s_l3_trigger) {
    out->raw_ai_verdict = VERDICT_MALWARE;
    out->final_verdict = VERDICT_MALWARE;
  } else if (c >= s_fp_floor) {
    out->raw_ai_verdict = VERDICT_SUSPICIOUS;
    out->final_verdict = VERDICT_SUSPICIOUS;
  } else {
    out->raw_ai_verdict = VERDICT_CLEAN;
    out->final_verdict = VERDICT_CLEAN;
  }
  snprintf(out->verification_layer, sizeof(out->verification_layer), "AI");
}

static void apply_onnx_boost(AVEScanResult *out, float boost) {
  if (boost <= 0.f) {
    return;
  }
  out->final_confidence = fminf(1.f, out->final_confidence + boost);
  out->raw_confidence = fminf(1.f, out->raw_confidence + boost);
  if (out->final_confidence >= s_l3_trigger) {
    out->final_verdict = VERDICT_MALWARE;
    out->raw_ai_verdict = VERDICT_MALWARE;
  } else if (out->final_confidence >= s_fp_floor) {
    out->final_verdict = VERDICT_SUSPICIOUS;
    out->raw_ai_verdict = VERDICT_SUSPICIOUS;
  }
}

/** L3 IOC：已知恶意哈希，跳过 ONNX（优先于 L2 哈希白名单，避免双库冲突误放行） */
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

/** L2：文件哈希白名单，跳过 ONNX */
static void fill_file_hash_whitelist(AVEScanResult *out) {
  out->raw_ai_verdict = VERDICT_CLEAN;
  out->final_verdict = VERDICT_WHITELISTED;
  out->raw_confidence = 0.f;
  out->final_confidence = 0.f;
  snprintf(out->verification_layer, sizeof(out->verification_layer), "L2");
  snprintf(out->rule_name, sizeof(out->rule_name), "file_hash_whitelist");
  out->skip_ai_analysis = true;
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

  if (config->model_dir && config->model_dir[0]) {
    snprintf(g_cfg.ave.model_dir, sizeof(g_cfg.ave.model_dir), "%s", config->model_dir);
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
  EdrError e = edr_ave_reload_models(cfg);
  if (e == EDR_OK) {
    edr_ave_infer_cache_clear();
  }
  return edr_err_to_ave(e);
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
  edr_ave_infer_cache_clear();
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
  edr_onnx_static_model_version(status_out->static_model_version, sizeof(status_out->static_model_version));
  edr_onnx_behavior_model_version(status_out->behavior_model_version, sizeof(status_out->behavior_model_version));
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

/** B3b：将 static 扫描结论写入行为槽（§5.5 维 44–45），供 behavior.onnx 特征使用 */
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
  snprintf(result_out->scanned_path, sizeof(result_out->scanned_path), "%s", file_path);

  if (env_skip_ext_enabled()) {
    const char *ext = safe_file_ext(file_path);
    if (ext && is_known_safe_ext(ext)) {
      result_out->final_verdict = VERDICT_WHITELISTED;
      result_out->final_confidence = 0.01f;
      result_out->scan_duration_ms = 0;
      snprintf(result_out->verification_layer, sizeof(result_out->verification_layer), "ext_filter");
      return AVE_OK;
    }
  }

  int64_t fsize = get_file_size_fast(file_path);
  if (fsize < 0) {
    return AVE_ERR_INTERNAL;
  }
  if (fsize == 0) {
    result_out->final_verdict = VERDICT_WHITELISTED;
    result_out->final_confidence = 0.0f;
    result_out->scan_duration_ms = 0;
    snprintf(result_out->verification_layer, sizeof(result_out->verification_layer), "empty_file");
    return AVE_OK;
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

  int skip_onnx = 0;
  float onnx_boost = 0.f;
  if (pcfg->ave.cert_whitelist_enabled) {
    edr_ave_sign_stage0(pcfg, file_path, result_out->sha256, result_out, &skip_onnx, &onnx_boost);
  }
  if (skip_onnx) {
    int64_t t1done = mono_ms();
    result_out->scan_duration_ms = t1done - t0;
    ave_bp_merge_static_if_subject(subject_pid, result_out);
    return AVE_OK;
  }

  /* L3 IOC 预检（可关）：先于 L2 哈希白名单；关则仅 ONNX 后二次核对 */
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

  scan_lock();
  EdrAveInferResult infer;
  memset(&infer, 0, sizeof(infer));
  EdrError ie;
  {
    const char *dry = getenv("EDR_AVE_INFER_DRY_RUN");
    int skip_cache = (dry && dry[0] == '1');
    uint32_t cmax = infer_cache_max_effective(pcfg);
    uint32_t cttl = infer_cache_ttl_effective(pcfg);
    if (!skip_cache && cmax > 0u && infer_cache_get(result_out->sha256, &infer, cttl)) {
      ie = EDR_OK;
    } else {
      ie = edr_ave_infer_file(pcfg, file_path, &infer);
      if (ie == EDR_OK && !skip_cache && cmax > 0u) {
        infer_cache_put(result_out->sha256, &infer, (size_t)cmax);
      }
    }
  }
  scan_unlock();
  int64_t t1 = mono_ms();
  result_out->scan_duration_ms = t1 - t0;

  if (ie == EDR_OK) {
    apply_infer_verdict(&infer, result_out);
    if (onnx_boost > 0.f) {
      apply_onnx_boost(result_out, onnx_boost);
    }
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
    ave_bp_merge_static_if_subject(subject_pid, result_out);
    return AVE_OK;
  }

  if (ie == EDR_ERR_NOT_IMPL) {
    result_out->raw_ai_verdict = VERDICT_ERROR;
    result_out->final_verdict = VERDICT_ERROR;
    snprintf(result_out->verification_layer, sizeof(result_out->verification_layer), "");
    return AVE_ERR_NOT_IMPL;
  }

  return edr_err_to_ave(ie);
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

void AVE_FeedEvent(const AVEBehaviorEvent *event) {
  if (!g_initialized) {
    return;
  }
  if (!event) {
    return;
  }
  AVEBehaviorEvent ev = *event;
  const EdrConfig *pcfg = active_edr_config();
  if (pcfg) {
    edr_ave_behavior_event_apply_ioc(pcfg, &ev);
  }
  edr_ave_bp_feed(&ev);
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

int AVE_GetFLSampleCount(int *confirmed_malware_count, int *confirmed_clean_count) {
  if (!confirmed_malware_count || !confirmed_clean_count) {
    return AVE_ERR_INVALID_PARAM;
  }
  *confirmed_malware_count = 0;
  *confirmed_clean_count = 0;
  return AVE_OK;
}

int AVE_ApplyHotfix(const char *hotfix_path) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!hotfix_path || !hotfix_path[0]) {
    return AVE_ERR_INVALID_PARAM;
  }
  const EdrConfig *pcfg = active_edr_config();
  if (!pcfg) {
    return AVE_ERR_INTERNAL;
  }
  EdrError he = edr_ave_apply_hotfix_path(pcfg, hotfix_path);
  if (he != EDR_OK) {
    return edr_err_to_ave(he);
  }
  he = edr_ave_reload_models(pcfg);
  if (he == EDR_OK) {
    edr_ave_infer_cache_clear();
  }
  return he == EDR_OK ? AVE_OK : edr_err_to_ave(he);
}

int AVE_UpdateModel(const char *model_path, const char *pca_path) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  const EdrConfig *pcfg = active_edr_config();
  if (!pcfg) {
    return AVE_ERR_INTERNAL;
  }
  if (model_path && model_path[0]) {
    EdrError e = edr_onnx_runtime_load(model_path, pcfg);
    if (e != EDR_OK) {
      return edr_err_to_ave(e);
    }
    edr_ave_infer_cache_clear();
  }
  if (pca_path && pca_path[0]) {
    EdrError e = edr_onnx_behavior_load(pca_path, pcfg);
    if (e != EDR_OK) {
      return edr_err_to_ave(e);
    }
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

/** 64 位十六进制 + '\0'（联邦 FL 样本 SHA256） */
static int is_sha256_hex64(const char *s) {
  if (!s) {
    return 0;
  }
  for (int i = 0; i < 64; i++) {
    char c = s[i];
    if (c >= '0' && c <= '9') {
      continue;
    }
    if (c >= 'a' && c <= 'f') {
      continue;
    }
    if (c >= 'A' && c <= 'F') {
      continue;
    }
    return 0;
  }
  return s[64] == '\0';
}

int AVE_ExportFeatureVector(const char *sha256, float *out_512d) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!out_512d) {
    return AVE_ERR_INVALID_PARAM;
  }
  if (!is_sha256_hex64(sha256)) {
    return AVE_ERR_INVALID_PARAM;
  }
  {
    int r = edr_fl_feature_lookup_dispatch(sha256, out_512d, 512u, EDR_FL_TARGET_STATIC);
    if (r == 0) {
      return AVE_OK;
    }
    if (r == 1) {
      return AVE_ERR_FL_SAMPLE_NOT_FOUND;
    }
  }
  /* 无注册或内部错误：C0 兼容全零 */
  for (int i = 0; i < 512; i++) {
    out_512d[i] = 0.0f;
  }
  return AVE_OK;
}

int AVE_ExportFeatureVectorEx(const char *sha256, float *out, size_t dim, int target) {
  size_t i;

  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!out || dim == 0u || dim > AVE_FL_FEATURE_DIM_MAX) {
    return AVE_ERR_INVALID_PARAM;
  }
  if (!is_sha256_hex64(sha256)) {
    return AVE_ERR_INVALID_PARAM;
  }
  {
    int r = edr_fl_feature_lookup_dispatch(sha256, out, dim, target);
    if (r == 0) {
      return AVE_OK;
    }
    if (r == 1) {
      return AVE_ERR_FL_SAMPLE_NOT_FOUND;
    }
  }
  for (i = 0; i < dim; i++) {
    out[i] = 0.0f;
  }
  return AVE_OK;
}

int AVE_ExportModelWeights(const char *target, void *buf, size_t *size) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!target || !target[0] || !size) {
    return AVE_ERR_INVALID_PARAM;
  }
  if (strcmp(target, "static") != 0 && strcmp(target, "behavior") != 0) {
    return AVE_ERR_INVALID_PARAM;
  }
  if (strcmp(target, "static") == 0) {
    int r = edr_onnx_static_export_weights(buf, size);
    if (r == -1) {
      return AVE_ERR_INVALID_PARAM;
    }
    if (r == 1) {
      return AVE_ERR_NOT_IMPL;
    }
    if (r == 2) {
      return AVE_ERR_BUFFER_TOO_SMALL;
    }
    if (r == 3) {
      return AVE_ERR_INTERNAL;
    }
    return AVE_OK;
  }
  /* behavior：导出磁盘 behavior.onnx 整文件字节（联邦 / P3 T10·T11），与 ORT 加载源一致；≠ 实施计划 §0「B3c」（M3b+§7/§8） */
  int r = edr_onnx_behavior_export_weights(buf, size);
  if (r == -1) {
    return AVE_ERR_INVALID_PARAM;
  }
  if (r == 1) {
    return AVE_ERR_NOT_IMPL;
  }
  if (r == 2) {
    return AVE_ERR_BUFFER_TOO_SMALL;
  }
  if (r == 3) {
    return AVE_ERR_INTERNAL;
  }
  return AVE_OK;
}

int AVE_ExportBehaviorFlTrainableTensors(float *out, size_t *out_nelem, char *manifest_json,
                                         size_t manifest_cap) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!out_nelem) {
    return AVE_ERR_INVALID_PARAM;
  }
  int r = edr_onnx_behavior_export_fl_trainable_floats(out, out_nelem, manifest_json, manifest_cap);
  if (r == -1) {
    return AVE_ERR_INVALID_PARAM;
  }
  if (r == 1) {
    return AVE_ERR_NOT_IMPL;
  }
  if (r == 2) {
    return AVE_ERR_BUFFER_TOO_SMALL;
  }
  if (r == 3) {
    return AVE_ERR_INTERNAL;
  }
  return AVE_OK;
}

int AVE_ImportModelWeights(const char *target, const void *buf, size_t size) {
  if (!g_initialized) {
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (!target || !target[0]) {
    return AVE_ERR_INVALID_PARAM;
  }
  (void)buf;
  (void)size;
  if (strcmp(target, "static") != 0 && strcmp(target, "behavior") != 0) {
    return AVE_ERR_INVALID_PARAM;
  }
  /* FL3 梯度封装（协调方解密）；勿当作 ONNX 权重导入。 */
  if (buf && size >= 4u && memcmp(buf, "FL3", 3) == 0 && ((const uint8_t *)buf)[3] == 2u) {
    return AVE_ERR_NOT_SUPPORTED;
  }
  /* C6：开发占位——`FLSTUB1` / `FL2` 前缀视为校验通过（非生产权重加载）。梯度 **FL3**（`fl_crypto_seal_gradient`）由协调方持有私钥解密，端上 `fl_crypto_open_gradient` 对 FL3 返回 `-5`，不用于本接口。 */
  if (buf && size >= 7u && memcmp(buf, "FLSTUB1", 7) == 0) {
    return AVE_OK;
  }
  if (buf && size >= 4u && memcmp(buf, "FL2", 3) == 0) {
    return AVE_OK;
  }
  return AVE_ERR_NOT_IMPL;
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
