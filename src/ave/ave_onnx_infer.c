/**
 * AVE 真推理：ONNX Runtime C API（可选，编译宏 EDR_HAVE_ONNXRUNTIME）。
 * static：首个 float 输入；512 维且三输出名匹配时走《static_onnx》§7.2；否则 legacy 字节填充（动态轴默认 4096）。
 * behavior：behavior.onnx；(1,128,64) / (128,64) / 展平 8192 与 PidHistory 对齐；feat 默认 64；双输出 anomaly_score + tactic_probs。
 */

#include "ave_onnx_infer.h"

#include "ave_static_features.h"

#include "edr/ave.h"
#include "edr/config.h"
#include "edr/edr_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** static 会话首输入元素数上限（含动态维用默认长度展开后的乘积）；与训练导出大图对齐 */
#define EDR_AVE_STATIC_INPUT_NELEM_MAX (20 * 1024 * 1024)

/** 成功 load behavior.onnx 后的磁盘路径（ORT 与 stub 共用）；release/卸载时清空 */
static char g_beh_model_path[2048];
/** static.onnx（首个非 behavior 的 ORT 会话）磁盘路径；与 behavior 导出语义一致 */
static char g_static_model_path[2048];

const char *edr_onnx_behavior_loaded_path(void) { return g_beh_model_path[0] ? g_beh_model_path : NULL; }

static int export_onnx_file_blob(const char *path, void *buf, size_t *size_io) {
  if (!size_io) {
    return -1;
  }
  if (!path || !path[0]) {
    return 1;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 3;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return 3;
  }
  long flen = ftell(f);
  if (flen < 0) {
    fclose(f);
    return 3;
  }
  size_t need = (size_t)flen;
  if (buf == NULL) {
    *size_io = need;
    fclose(f);
    return 0;
  }
  if (*size_io < need) {
    *size_io = need;
    fclose(f);
    return 2;
  }
  rewind(f);
  size_t r = fread(buf, 1, need, f);
  fclose(f);
  if (r != need) {
    return 3;
  }
  *size_io = need;
  return 0;
}

int edr_onnx_behavior_export_weights(void *buf, size_t *size_io) {
  return export_onnx_file_blob(g_beh_model_path, buf, size_io);
}

int edr_onnx_static_export_weights(void *buf, size_t *size_io) {
  return export_onnx_file_blob(g_static_model_path, buf, size_io);
}

#if defined(EDR_HAVE_ONNXRUNTIME)
#include <ctype.h>
#endif

#if !defined(EDR_HAVE_ONNXRUNTIME)

int edr_onnx_runtime_ready(void) { return 0; }

EdrError edr_onnx_infer_file(const EdrConfig *cfg, const char *path, EdrAveInferResult *out) {
  (void)cfg;
  (void)path;
  (void)out;
  return EDR_ERR_NOT_IMPL;
}

void edr_onnx_runtime_cleanup(void) {
  memset(g_static_model_path, 0, sizeof(g_static_model_path));
  memset(g_beh_model_path, 0, sizeof(g_beh_model_path));
}

EdrError edr_onnx_runtime_load(const char *onnx_path, const EdrConfig *cfg) {
  (void)cfg;
  memset(g_static_model_path, 0, sizeof(g_static_model_path));
  if (onnx_path && onnx_path[0]) {
    snprintf(g_static_model_path, sizeof(g_static_model_path), "%s", onnx_path);
  }
  return EDR_OK;
}

int edr_onnx_behavior_ready(void) { return 0; }

EdrError edr_onnx_behavior_load(const char *behavior_onnx_path, const EdrConfig *cfg) {
  (void)cfg;
  memset(g_beh_model_path, 0, sizeof(g_beh_model_path));
  if (behavior_onnx_path && behavior_onnx_path[0]) {
    snprintf(g_beh_model_path, sizeof(g_beh_model_path), "%s", behavior_onnx_path);
  }
  return EDR_OK;
}

EdrError edr_onnx_behavior_infer(const float *feature, size_t n_float, float *out_score,
                                 float *tactic_probs) {
  (void)feature;
  (void)n_float;
  (void)out_score;
  (void)tactic_probs;
  return EDR_ERR_INVALID_ARG;
}

size_t edr_onnx_behavior_input_nelem(void) { return 0u; }

size_t edr_onnx_behavior_input_seq_len(void) { return 1u; }

void edr_onnx_behavior_model_version(char *buf, size_t cap) {
  if (!buf || cap == 0u) {
    return;
  }
  snprintf(buf, cap, "heuristic_v1");
}

void edr_onnx_static_model_version(char *buf, size_t cap) {
  if (!buf || cap == 0u) {
    return;
  }
  if (!g_static_model_path[0]) {
    snprintf(buf, cap, "not_loaded");
    return;
  }
#ifdef _WIN32
  const char *base = g_static_model_path;
  for (const char *p = g_static_model_path; *p; p++) {
    if (*p == '\\' || *p == '/') {
      base = p + 1;
    }
  }
#else
  const char *base = strrchr(g_static_model_path, '/');
  base = base ? base + 1 : g_static_model_path;
#endif
  snprintf(buf, cap, "onnx:%s", base);
}

#else

#include <onnxruntime_c_api.h>

#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#endif

static const OrtApi *g_ort;
static OrtEnv *g_env;
static OrtMemoryInfo *g_mem;
static OrtAllocator *g_alloc;

/* static 文件扫描模型 */
static OrtSession *g_session;
static char *g_in_name;
static char *g_out_name;
/** 与 g_out_name 独立：§7.2 三路输出名（SessionGetOutputName 分配） */
static char *g_out_spec_verdict;
static char *g_out_spec_family;
static char *g_out_spec_packer;
static int g_static_spec_triple;
static int g_ready;
static int g_in_ndim;
static int64_t g_in_shape[4];
static int64_t g_in_nelem;

/* static.onnx 内存池 - 性能优化 */
static float *s_static_input_buf;  // 复用的输入缓冲区

/* behavior.onnx */
static OrtSession *g_beh_session;
static char *g_beh_in_name;
static char *g_beh_out_name;
static char *g_beh_out_tactic_name;
static int g_beh_dual_out;
static int g_beh_ready;
static int g_beh_in_ndim;
static int64_t g_beh_in_shape[4];
static int64_t g_beh_in_nelem;
static char g_beh_ver_tag[32];
static char g_static_ver_tag[32];

/* behavior.onnx 内存池 - 性能优化 */
static float *s_behavior_input_buf;  // 复用的输入缓冲区

static void ort_free_str(char *s) {
  if (s && g_alloc) {
    g_alloc->Free(g_alloc, s);
  }
}

static void release_file_session(void) {
  ort_free_str(g_in_name);
  g_in_name = NULL;
  ort_free_str(g_out_name);
  g_out_name = NULL;
  ort_free_str(g_out_spec_verdict);
  g_out_spec_verdict = NULL;
  ort_free_str(g_out_spec_family);
  g_out_spec_family = NULL;
  ort_free_str(g_out_spec_packer);
  g_out_spec_packer = NULL;
  g_static_spec_triple = 0;
  if (g_ort && g_session) {
    g_ort->ReleaseSession(g_session);
    g_session = NULL;
  }
  g_ready = 0;
  g_in_ndim = 0;
  g_in_nelem = 0;
  memset(g_static_model_path, 0, sizeof(g_static_model_path));
  memset(g_static_ver_tag, 0, sizeof(g_static_ver_tag));
  
  // 释放内存池
  if (s_static_input_buf) {
    free(s_static_input_buf);
    s_static_input_buf = NULL;
  }
}

static void release_behavior_session(void) {
  ort_free_str(g_beh_in_name);
  g_beh_in_name = NULL;
  ort_free_str(g_beh_out_name);
  g_beh_out_name = NULL;
  ort_free_str(g_beh_out_tactic_name);
  g_beh_out_tactic_name = NULL;
  g_beh_dual_out = 0;
  if (g_ort && g_beh_session) {
    g_ort->ReleaseSession(g_beh_session);
    g_beh_session = NULL;
  }
  g_beh_ready = 0;
  g_beh_in_ndim = 0;
  g_beh_in_nelem = 0;
  memset(g_beh_ver_tag, 0, sizeof(g_beh_ver_tag));
  memset(g_beh_model_path, 0, sizeof(g_beh_model_path));
  
  // 释放内存池
  if (s_behavior_input_buf) {
    free(s_behavior_input_buf);
    s_behavior_input_buf = NULL;
  }
}

static void release_ort_full(void) {
  release_file_session();
  release_behavior_session();
  if (g_ort) {
    if (g_mem) {
      g_ort->ReleaseMemoryInfo(g_mem);
      g_mem = NULL;
    }
    if (g_env) {
      g_ort->ReleaseEnv(g_env);
      g_env = NULL;
    }
  }
  g_alloc = NULL;
  g_ort = NULL;
}

static int64_t env_default_static_len(void) {
  const char *e = getenv("EDR_AVE_ONNX_IN_LEN");
  if (e && e[0]) {
    char *end = NULL;
    long v = strtol(e, &end, 10);
    if (end != e && v > 0 && v <= EDR_AVE_STATIC_INPUT_NELEM_MAX) {
      return (int64_t)v;
    }
  }
  return 4096;
}

static int64_t env_default_behavior_len(void) {
  const char *e = getenv("EDR_AVE_BEH_IN_LEN");
  if (e && e[0]) {
    char *end = NULL;
    long v = strtol(e, &end, 10);
    if (end != e && v > 0 && v <= 65536) {
      return (int64_t)v;
    }
  }
  return 64;
}

static void copy_onnx_path_tag(char *dst, size_t cap, const char *path) {
  memset(dst, 0, cap);
  if (!path || !path[0]) {
    snprintf(dst, cap, "onnx");
    return;
  }
#ifdef _WIN32
  const char *base = path;
  for (const char *p = path; *p; p++) {
    if (*p == '\\' || *p == '/') {
      base = p + 1;
    }
  }
#else
  const char *base = strrchr(path, '/');
  base = base ? base + 1 : path;
#endif
  snprintf(dst, cap, "onnx:%s", base);
}

static void copy_behavior_tag(const char *path) {
  copy_onnx_path_tag(g_beh_ver_tag, sizeof(g_beh_ver_tag), path);
}

static void copy_static_tag(const char *path) {
  copy_onnx_path_tag(g_static_ver_tag, sizeof(g_static_ver_tag), path);
}

static EdrError ensure_ort_env(void) {
  if (g_ort && g_env && g_mem && g_alloc) {
    return EDR_OK;
  }
  g_ort = OrtGetApiBase()->GetApi(ORT_API_VERSION);
  if (!g_ort) {
    fprintf(stderr, "[ave/onnx] ORT API 版本不匹配\n");
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  OrtStatus *st = g_ort->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "edr_ave", &g_env);
  if (st) {
    fprintf(stderr, "[ave/onnx] CreateEnv: %s\n", g_ort->GetErrorMessage(st));
    g_ort->ReleaseStatus(st);
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  st = g_ort->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault, &g_mem);
  if (st) {
    g_ort->ReleaseStatus(st);
    release_ort_full();
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  st = g_ort->GetAllocatorWithDefaultOptions(&g_alloc);
  if (st) {
    g_ort->ReleaseStatus(st);
    release_ort_full();
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  return EDR_OK;
}

static EdrError parse_input_shape(OrtSession *sess, int64_t def_dyn, int *out_ndim, int64_t *out_shape,
                                  int64_t *out_nelem) {
  OrtTypeInfo *ti = NULL;
  OrtStatus *st = g_ort->SessionGetInputTypeInfo(sess, 0, &ti);
  if (st || !ti) {
    if (st) {
      g_ort->ReleaseStatus(st);
    }
    if (ti) {
      g_ort->ReleaseTypeInfo(ti);
    }
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  const OrtTensorTypeAndShapeInfo *ts = NULL;
  st = g_ort->CastTypeInfoToTensorInfo(ti, &ts);
  if (st || !ts) {
    if (st) {
      g_ort->ReleaseStatus(st);
    }
    g_ort->ReleaseTypeInfo(ti);
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  size_t dimc = 0;
  st = g_ort->GetDimensionsCount(ts, &dimc);
  if (st || dimc == 0u || dimc > 4u) {
    if (st) {
      g_ort->ReleaseStatus(st);
    }
    g_ort->ReleaseTypeInfo(ti);
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  int64_t dims[4];
  st = g_ort->GetDimensions(ts, dims, dimc);
  g_ort->ReleaseTypeInfo(ti);
  if (st) {
    g_ort->ReleaseStatus(st);
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  *out_ndim = (int)dimc;
  int64_t nelem = 1;
  for (size_t i = 0; i < dimc; i++) {
    int64_t d = dims[i];
    if (d <= 0 || d == -1) {
      d = def_dyn;
    }
    if (i < 4u) {
      out_shape[i] = d;
    }
    nelem *= d;
  }
  /* 训练导出的 static 大图乘积可达数 M；上限与 EDR_AVE_STATIC_INPUT_NELEM_MAX 一致 */
  if (nelem <= 0 || nelem > EDR_AVE_STATIC_INPUT_NELEM_MAX) {
    fprintf(stderr, "[ave/onnx] 输入元素数异常 %lld\n", (long long)nelem);
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  *out_nelem = nelem;
  return EDR_OK;
}

static int64_t env_behavior_seq_len(void) {
  const char *e = getenv("EDR_AVE_BEH_SEQ_LEN");
  if (e && e[0]) {
    char *end = NULL;
    long v = strtol(e, &end, 10);
    if (end != e && v > 0 && v <= 512) {
      return (int64_t)v;
    }
  }
  return 128;
}

/**
 * behavior 输入常为 (batch, seq, feat) 含动态维；不能用单一 def_dyn 替代所有 -1。
 */
static EdrError refine_behavior_input_dims(OrtSession *sess) {
  OrtTypeInfo *ti = NULL;
  OrtStatus *st = g_ort->SessionGetInputTypeInfo(sess, 0, &ti);
  if (st || !ti) {
    if (st) {
      g_ort->ReleaseStatus(st);
    }
    if (ti) {
      g_ort->ReleaseTypeInfo(ti);
    }
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  const OrtTensorTypeAndShapeInfo *ts = NULL;
  st = g_ort->CastTypeInfoToTensorInfo(ti, &ts);
  if (st || !ts) {
    if (st) {
      g_ort->ReleaseStatus(st);
    }
    g_ort->ReleaseTypeInfo(ti);
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  size_t dimc = 0;
  st = g_ort->GetDimensionsCount(ts, &dimc);
  if (st || dimc == 0u || dimc > 4u) {
    if (st) {
      g_ort->ReleaseStatus(st);
    }
    g_ort->ReleaseTypeInfo(ti);
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  int64_t dims[4];
  st = g_ort->GetDimensions(ts, dims, dimc);
  g_ort->ReleaseTypeInfo(ti);
  if (st) {
    g_ort->ReleaseStatus(st);
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  const int64_t seq_def = env_behavior_seq_len();
  const int64_t feat_def = env_default_behavior_len();
  int64_t nelem = 1;
  for (size_t i = 0; i < dimc; i++) {
    int64_t d = dims[i];
    if (d <= 0 || d == -1) {
      if (dimc == 3u) {
        if (i == 0u) {
          d = 1;
        } else if (i == 1u) {
          d = seq_def;
        } else {
          d = feat_def;
        }
      } else if (dimc == 2u) {
        d = (i == 0u) ? seq_def : feat_def;
      } else if (dimc == 1u) {
        /* 《11》§6.1：单轴动态 [-1] 视为展平的 (1×seq×feat)，与 PidHistory 8192 对齐 */
        d = seq_def * feat_def;
      } else {
        d = feat_def;
      }
    }
    g_beh_in_shape[i] = d;
    nelem *= d;
  }
  g_beh_in_ndim = (int)dimc;
  for (size_t i = dimc; i < 4u; i++) {
    g_beh_in_shape[i] = 0;
  }
  if (nelem <= 0 || nelem > 1024 * 1024) {
    fprintf(stderr, "[ave/onnx] behavior 输入元素数异常 %lld\n", (long long)nelem);
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  g_beh_in_nelem = nelem;
  return EDR_OK;
}

static EdrError create_session_from_path(const char *onnx_path, const EdrConfig *cfg, int64_t def_dyn,
                                         OrtSession **out_sess, char **out_in_name, char **out_out_name,
                                         int *out_in_ndim, int64_t *out_in_shape, int64_t *out_in_nelem) {
  OrtSessionOptions *opt = NULL;
  OrtStatus *st = g_ort->CreateSessionOptions(&opt);
  if (st) {
    g_ort->ReleaseStatus(st);
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  int th = (cfg && cfg->ave.scan_threads > 0) ? cfg->ave.scan_threads : 1;
  
  // 性能优化：启用图优化和执行优化
  g_ort->SetIntraOpNumThreads(opt, th);
  g_ort->SetInterOpNumThreads(opt, 1);  // 小模型单线程更好
  
  // 设置图优化级别
  g_ort->SetSessionGraphOptimizationLevel(opt, ORT_ENABLE_EXTENDED);
  
  // 设置执行模式为顺序执行（对于小模型更快）
  g_ort->SetSessionExecutionMode(opt, ORT_SEQUENTIAL);

#ifdef _WIN32
  {
    wchar_t wpath[2048];
    int n = MultiByteToWideChar(CP_UTF8, 0, onnx_path, -1, wpath, (int)(sizeof(wpath) / sizeof(wpath[0])));
    if (n <= 0) {
      g_ort->ReleaseSessionOptions(opt);
      return EDR_ERR_AVE_LOAD_FAILED;
    }
    st = g_ort->CreateSession(g_env, wpath, opt, out_sess);
  }
#else
  st = g_ort->CreateSession(g_env, onnx_path, opt, out_sess);
#endif
  g_ort->ReleaseSessionOptions(opt);
  if (st) {
    fprintf(stderr, "[ave/onnx] CreateSession: %s\n", g_ort->GetErrorMessage(st));
    g_ort->ReleaseStatus(st);
    return EDR_ERR_AVE_LOAD_FAILED;
  }

  st = g_ort->SessionGetInputName(*out_sess, 0, g_alloc, out_in_name);
  if (st) {
    g_ort->ReleaseStatus(st);
    g_ort->ReleaseSession(*out_sess);
    *out_sess = NULL;
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  size_t n_out = 0;
  st = g_ort->SessionGetOutputCount(*out_sess, &n_out);
  if (st || n_out == 0u) {
    if (st) {
      g_ort->ReleaseStatus(st);
    }
    ort_free_str(*out_in_name);
    *out_in_name = NULL;
    g_ort->ReleaseSession(*out_sess);
    *out_sess = NULL;
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  st = g_ort->SessionGetOutputName(*out_sess, 0, g_alloc, out_out_name);
  if (st) {
    g_ort->ReleaseStatus(st);
    ort_free_str(*out_in_name);
    *out_in_name = NULL;
    g_ort->ReleaseSession(*out_sess);
    *out_sess = NULL;
    return EDR_ERR_AVE_LOAD_FAILED;
  }

  EdrError pe = parse_input_shape(*out_sess, def_dyn, out_in_ndim, out_in_shape, out_in_nelem);
  if (pe != EDR_OK) {
    ort_free_str(*out_in_name);
    *out_in_name = NULL;
    ort_free_str(*out_out_name);
    *out_out_name = NULL;
    g_ort->ReleaseSession(*out_sess);
    *out_sess = NULL;
    return pe;
  }
  return EDR_OK;
}

static int str_contains_ci(const char *haystack, const char *needle) {
  char h[384];
  char n[96];
  size_t i;
  for (i = 0; i < sizeof(h) - 1u && haystack[i]; i++) {
    h[i] = (char)tolower((unsigned char)haystack[i]);
  }
  h[i] = '\0';
  for (i = 0; i < sizeof(n) - 1u && needle[i]; i++) {
    n[i] = (char)tolower((unsigned char)needle[i]);
  }
  n[i] = '\0';
  return strstr(h, n) != NULL;
}

static void bind_static_spec_outputs(OrtSession *sess) {
  ort_free_str(g_out_spec_verdict);
  g_out_spec_verdict = NULL;
  ort_free_str(g_out_spec_family);
  g_out_spec_family = NULL;
  ort_free_str(g_out_spec_packer);
  g_out_spec_packer = NULL;
  g_static_spec_triple = 0;
  if (!g_ort || !sess) {
    return;
  }
  size_t n_out = 0;
  OrtStatus *st = g_ort->SessionGetOutputCount(sess, &n_out);
  if (st) {
    g_ort->ReleaseStatus(st);
    return;
  }
  if (n_out < 3u) {
    return;
  }
  for (size_t i = 0; i < n_out; i++) {
    char *nm = NULL;
    st = g_ort->SessionGetOutputName(sess, i, g_alloc, &nm);
    if (st || !nm) {
      if (st) {
        g_ort->ReleaseStatus(st);
      }
      continue;
    }
    if (!g_out_spec_verdict && str_contains_ci(nm, "verdict")) {
      g_out_spec_verdict = nm;
      continue;
    }
    if (!g_out_spec_family && str_contains_ci(nm, "family")) {
      g_out_spec_family = nm;
      continue;
    }
    if (!g_out_spec_packer && str_contains_ci(nm, "packer")) {
      g_out_spec_packer = nm;
      continue;
    }
    ort_free_str(nm);
  }
  if (g_out_spec_verdict && g_out_spec_family && g_out_spec_packer) {
    g_static_spec_triple = 1;
    EDR_LOGV("[ave/onnx] static triple outputs (spec 7.2): %s / %s / %s\n", g_out_spec_verdict,
            g_out_spec_family, g_out_spec_packer);
  }
}

/** 绑定 anomaly_score / tactic_probs（与设计 §6.2 一致）；单输出时仅 anomaly。 */
static void bind_behavior_outputs(OrtSession *sess) {
  ort_free_str(g_beh_out_tactic_name);
  g_beh_out_tactic_name = NULL;
  g_beh_dual_out = 0;
  if (!g_ort || !sess) {
    return;
  }
  size_t n_out = 0;
  OrtStatus *st = g_ort->SessionGetOutputCount(sess, &n_out);
  if (st) {
    g_ort->ReleaseStatus(st);
    return;
  }
  char *anomaly_nm = NULL;
  char *tactic_nm = NULL;
  for (size_t i = 0; i < n_out; i++) {
    char *nm = NULL;
    st = g_ort->SessionGetOutputName(sess, i, g_alloc, &nm);
    if (st || !nm) {
      if (st) {
        g_ort->ReleaseStatus(st);
      }
      continue;
    }
    if (str_contains_ci(nm, "tactic")) {
      if (!tactic_nm) {
        tactic_nm = nm;
      } else {
        ort_free_str(nm);
      }
      continue;
    }
    if (str_contains_ci(nm, "anomaly") || str_contains_ci(nm, "anomaly_score")) {
      if (!anomaly_nm) {
        anomaly_nm = nm;
      } else {
        ort_free_str(nm);
      }
      continue;
    }
    ort_free_str(nm);
  }
  if (!anomaly_nm && n_out >= 1u) {
    st = g_ort->SessionGetOutputName(sess, 0, g_alloc, &anomaly_nm);
    if (st) {
      g_ort->ReleaseStatus(st);
      anomaly_nm = NULL;
    }
  }
  if (!tactic_nm && n_out >= 2u) {
    st = g_ort->SessionGetOutputName(sess, 1, g_alloc, &tactic_nm);
    if (st) {
      g_ort->ReleaseStatus(st);
      tactic_nm = NULL;
    }
  }
  if (anomaly_nm) {
    ort_free_str(g_beh_out_name);
    g_beh_out_name = anomaly_nm;
  }
  if (tactic_nm) {
    g_beh_out_tactic_name = tactic_nm;
    g_beh_dual_out = 1;
  }
}

EdrError edr_onnx_runtime_load(const char *onnx_path, const EdrConfig *cfg) {
  (void)cfg;
  release_file_session();
  if (!onnx_path || !onnx_path[0]) {
    return EDR_OK;
  }
  const int64_t def_len = env_default_static_len();
  EdrError ee = ensure_ort_env();
  if (ee != EDR_OK) {
    return ee;
  }
  EdrError ce = create_session_from_path(onnx_path, cfg, def_len, &g_session, &g_in_name, &g_out_name,
                                         &g_in_ndim, g_in_shape, &g_in_nelem);
  if (ce != EDR_OK) {
    return ce;
  }
  bind_static_spec_outputs(g_session);
  EDR_LOGV("[ave/onnx] static ONNX loaded path=%s ndim=%d nelem=%lld triple=%d\n", onnx_path, g_in_ndim,
          (long long)g_in_nelem, g_static_spec_triple);
  snprintf(g_static_model_path, sizeof(g_static_model_path), "%s", onnx_path);
  copy_static_tag(onnx_path);
  
  // 初始化内存池 - 性能优化
  if (g_in_nelem > 0) {
    s_static_input_buf = (float *)calloc((size_t)g_in_nelem, sizeof(float));
    if (!s_static_input_buf) {
      EDR_LOGV("[ave/onnx] failed to alloc static input buf, will use per-call alloc\n");
    } else {
      EDR_LOGV("[ave/onnx] static input buf pool initialized, nelem=%lld\n", (long long)g_in_nelem);
    }
  }
  
  g_ready = 1;
  return EDR_OK;
}

EdrError edr_onnx_behavior_load(const char *behavior_onnx_path, const EdrConfig *cfg) {
  release_behavior_session();
  if (!behavior_onnx_path || !behavior_onnx_path[0]) {
    return EDR_OK;
  }
  const int64_t def_len = env_default_behavior_len();
  EdrError ee = ensure_ort_env();
  if (ee != EDR_OK) {
    return ee;
  }
  EdrError ce = create_session_from_path(behavior_onnx_path, cfg, def_len, &g_beh_session, &g_beh_in_name,
                                         &g_beh_out_name, &g_beh_in_ndim, g_beh_in_shape, &g_beh_in_nelem);
  if (ce != EDR_OK) {
    return ce;
  }
  EdrError rb = refine_behavior_input_dims(g_beh_session);
  if (rb != EDR_OK) {
    ort_free_str(g_beh_in_name);
    g_beh_in_name = NULL;
    ort_free_str(g_beh_out_name);
    g_beh_out_name = NULL;
    ort_free_str(g_beh_out_tactic_name);
    g_beh_out_tactic_name = NULL;
    g_beh_dual_out = 0;
    if (g_ort && g_beh_session) {
      g_ort->ReleaseSession(g_beh_session);
      g_beh_session = NULL;
    }
    g_beh_ready = 0;
    g_beh_in_ndim = 0;
    g_beh_in_nelem = 0;
    return rb;
  }
  bind_behavior_outputs(g_beh_session);
  copy_behavior_tag(behavior_onnx_path);
  snprintf(g_beh_model_path, sizeof(g_beh_model_path), "%s", behavior_onnx_path);
  EDR_LOGV("[ave/onnx] behavior ONNX loaded path=%s ndim=%d nelem=%lld dual_tactic=%d\n", behavior_onnx_path,
          g_beh_in_ndim, (long long)g_beh_in_nelem, g_beh_dual_out);
  
  // 初始化内存池 - 性能优化
  if (g_beh_in_nelem > 0) {
    s_behavior_input_buf = (float *)malloc((size_t)g_beh_in_nelem * sizeof(float));
    if (!s_behavior_input_buf) {
      EDR_LOGV("[ave/onnx] failed to alloc behavior input buf, will use per-call alloc\n");
    } else {
      EDR_LOGV("[ave/onnx] behavior input buf pool initialized, nelem=%lld\n", (long long)g_beh_in_nelem);
    }
  }
  
  g_beh_ready = 1;
  return EDR_OK;
}

void edr_onnx_runtime_cleanup(void) { release_ort_full(); }

int edr_onnx_runtime_ready(void) { return g_ready; }

int edr_onnx_behavior_ready(void) { return g_beh_ready; }

size_t edr_onnx_behavior_input_nelem(void) {
  return g_beh_ready && g_beh_in_nelem > 0 ? (size_t)g_beh_in_nelem : 0u;
}

size_t edr_onnx_behavior_input_seq_len(void) {
  if (!g_beh_ready || g_beh_in_nelem <= 0) {
    return 1u;
  }
  if (g_beh_in_ndim == 3) {
    return (size_t)g_beh_in_shape[1];
  }
  if (g_beh_in_ndim == 2) {
    return (size_t)g_beh_in_shape[0];
  }
  if (g_beh_in_ndim == 1) {
    const int64_t feat = env_default_behavior_len();
    if (feat > 0 && g_beh_in_nelem % feat == 0) {
      int64_t q = g_beh_in_nelem / feat;
      if (q >= 1 && q <= 512) {
        return (size_t)q;
      }
    }
  }
  return 1u;
}

void edr_onnx_behavior_model_version(char *buf, size_t cap) {
  if (!buf || cap == 0u) {
    return;
  }
  if (g_beh_ready && g_beh_ver_tag[0]) {
    snprintf(buf, cap, "%s", g_beh_ver_tag);
  } else {
    snprintf(buf, cap, "heuristic_v1");
  }
}

void edr_onnx_static_model_version(char *buf, size_t cap) {
  if (!buf || cap == 0u) {
    return;
  }
  if (g_ready && g_static_ver_tag[0]) {
    snprintf(buf, cap, "%s", g_static_ver_tag);
  } else {
    snprintf(buf, cap, "not_loaded");
  }
}

static size_t fill_input_from_file(const char *path, float *buf, int64_t nfloat) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  uint8_t *raw = (uint8_t *)calloc(1u, (size_t)nfloat);
  if (!raw) {
    fclose(f);
    return 0;
  }
  size_t nr = fread(raw, 1u, (size_t)nfloat, f);
  fclose(f);
  for (int64_t i = 0; i < nfloat; i++) {
    buf[i] = (i < (int64_t)nr) ? (float)raw[i] / 255.0f : 0.0f;
  }
  free(raw);
  return nr;
}

static int argmax_f(const float *v, size_t n, float *out_max) {
  if (n == 0u) {
    return -1;
  }
  int bi = 0;
  float m = v[0];
  for (size_t i = 1; i < n; i++) {
    if (v[i] > m) {
      m = v[i];
      bi = (int)i;
    }
  }
  *out_max = m;
  return bi;
}

static EdrError copy_ort_output_floats(OrtValue *out_val, float *dst, size_t expect) {
  float *out_data = NULL;
  OrtStatus *st = g_ort->GetTensorMutableData(out_val, (void **)&out_data);
  if (st || !out_data) {
    if (st) {
      g_ort->ReleaseStatus(st);
    }
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  OrtTensorTypeAndShapeInfo *ots = NULL;
  st = g_ort->GetTensorTypeAndShape(out_val, &ots);
  size_t elem = 0;
  if (!st && ots) {
    st = g_ort->GetTensorShapeElementCount(ots, &elem);
    g_ort->ReleaseTensorTypeAndShapeInfo(ots);
  }
  if (st) {
    g_ort->ReleaseStatus(st);
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  if (elem < expect) {
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  memcpy(dst, out_data, expect * sizeof(float));
  return EDR_OK;
}

EdrError edr_onnx_infer_file(const EdrConfig *cfg, const char *path, EdrAveInferResult *out) {
  (void)cfg;
  if (!g_ready || !g_ort || !g_session || !path || !path[0] || !out) {
    return EDR_ERR_INVALID_ARG;
  }
  memset(out, 0, sizeof(*out));

  int64_t n = g_in_nelem;
  
  // 使用内存池或按需分配
  float *buf = s_static_input_buf;
  int need_free = 0;
  if (!buf) {
    buf = (float *)calloc((size_t)n, sizeof(float));
    if (!buf) {
      return EDR_ERR_INTERNAL;
    }
    need_free = 1;
  } else {
    memset(buf, 0, (size_t)n * sizeof(float));
  }

  int use_lite512 = (n == 512);
  {
    const char *leg = getenv("EDR_AVE_STATIC_LEGACY512");
    if (leg && leg[0] == '1') {
      use_lite512 = 0;
    }
  }
  size_t nbytes = 0;
  if (use_lite512) {
    if (edr_ave_static_features_lite_512(path, buf) != 0) {
      if (need_free) {
        free(buf);
      }
      return EDR_ERR_INTERNAL;
    }
    nbytes = (size_t)n;
  } else {
    nbytes = fill_input_from_file(path, buf, n);
  }

  OrtValue *in_val = NULL;
  OrtStatus *st = g_ort->CreateTensorWithDataAsOrtValue(
      g_mem, buf, (size_t)n * sizeof(float), g_in_shape, (size_t)g_in_ndim,
      ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &in_val);
  if (st) {
    fprintf(stderr, "[ave/onnx] CreateTensor: %s\n", g_ort->GetErrorMessage(st));
    g_ort->ReleaseStatus(st);
    if (need_free) {
      free(buf);
    }
    return EDR_ERR_AVE_LOAD_FAILED;
  }

  const char *in_names[] = {g_in_name};

  if (g_static_spec_triple && g_out_spec_verdict && g_out_spec_family && g_out_spec_packer) {
    const char *onames[] = {g_out_spec_verdict, g_out_spec_family, g_out_spec_packer};
    OrtValue *outs[3] = {NULL, NULL, NULL};
    st = g_ort->Run(g_session, NULL, in_names, (const OrtValue *const *)&in_val, 1u, onames, 3u, outs);
    g_ort->ReleaseValue(in_val);
    if (need_free) {
      free(buf);
    }
    if (st) {
      fprintf(stderr, "[ave/onnx] Run triple: %s\n", g_ort->GetErrorMessage(st));
      g_ort->ReleaseStatus(st);
      return EDR_ERR_AVE_LOAD_FAILED;
    }
    EdrError c1 = copy_ort_output_floats(outs[0], out->verdict_probs, 4u);
    EdrError c2 = copy_ort_output_floats(outs[1], out->family_probs, 32u);
    EdrError c3 = copy_ort_output_floats(outs[2], out->packer_probs, 8u);
    g_ort->ReleaseValue(outs[0]);
    g_ort->ReleaseValue(outs[1]);
    g_ort->ReleaseValue(outs[2]);
    if (c1 != EDR_OK || c2 != EDR_OK || c3 != EDR_OK) {
      return EDR_ERR_AVE_LOAD_FAILED;
    }
    out->onnx_layout = 1;
    float mx = 0.f;
    int vi = argmax_f(out->verdict_probs, 4u, &mx);
    out->label = vi;
    out->score = mx;
    snprintf(out->detail, sizeof(out->detail), "static_onnx triple feat=%zu", nbytes);
    return EDR_OK;
  }

  const char *out_names[] = {g_out_name};
  OrtValue *out_val = NULL;
  st = g_ort->Run(g_session, NULL, in_names, (const OrtValue *const *)&in_val, 1u, out_names, 1u, &out_val);
  g_ort->ReleaseValue(in_val);
  if (need_free) {
    free(buf);
  }
  if (st) {
    fprintf(stderr, "[ave/onnx] Run: %s\n", g_ort->GetErrorMessage(st));
    g_ort->ReleaseStatus(st);
    return EDR_ERR_AVE_LOAD_FAILED;
  }

  float *out_data = NULL;
  st = g_ort->GetTensorMutableData(out_val, (void **)&out_data);
  if (st || !out_data) {
    if (st) {
      g_ort->ReleaseStatus(st);
    }
    g_ort->ReleaseValue(out_val);
    return EDR_ERR_AVE_LOAD_FAILED;
  }

  OrtTensorTypeAndShapeInfo *ots = NULL;
  st = g_ort->GetTensorTypeAndShape(out_val, &ots);
  size_t elem = 0;
  if (!st && ots) {
    st = g_ort->GetTensorShapeElementCount(ots, &elem);
    g_ort->ReleaseTensorTypeAndShapeInfo(ots);
  }
  if (st) {
    g_ort->ReleaseStatus(st);
    g_ort->ReleaseValue(out_val);
    return EDR_ERR_AVE_LOAD_FAILED;
  }

  float mx = 0.0f;
  int label = -1;
  if (elem == 1u) {
    label = 0;
    mx = out_data[0];
  } else {
    label = argmax_f(out_data, elem, &mx);
  }
  out->onnx_layout = 0;
  out->label = label;
  out->score = mx;
  snprintf(out->detail, sizeof(out->detail), "onnx bytes=%zu logits", nbytes);
  g_ort->ReleaseValue(out_val);
  return EDR_OK;
}

static void copy_tactic_probs_from_tensor(OrtValue *tval, float *tactic_probs) {
  if (!tactic_probs || !g_ort || !tval) {
    return;
  }
  memset(tactic_probs, 0, 14u * sizeof(float));
  float *td = NULL;
  OrtStatus *st = g_ort->GetTensorMutableData(tval, (void **)&td);
  if (st || !td) {
    if (st) {
      g_ort->ReleaseStatus(st);
    }
    return;
  }
  OrtTensorTypeAndShapeInfo *ots = NULL;
  st = g_ort->GetTensorTypeAndShape(tval, &ots);
  size_t elem = 0;
  if (!st && ots) {
    st = g_ort->GetTensorShapeElementCount(ots, &elem);
    g_ort->ReleaseTensorTypeAndShapeInfo(ots);
  }
  if (st) {
    g_ort->ReleaseStatus(st);
    return;
  }
  size_t n = elem < 14u ? elem : 14u;
  for (size_t i = 0; i < n; i++) {
    tactic_probs[i] = td[i];
  }
}

EdrError edr_onnx_behavior_infer(const float *feature, size_t n_float, float *out_score,
                                 float *tactic_probs) {
  if (!g_beh_ready || !g_ort || !g_beh_session || !feature || !out_score) {
    return EDR_ERR_INVALID_ARG;
  }
  if (n_float != (size_t)g_beh_in_nelem || g_beh_in_nelem <= 0) {
    return EDR_ERR_INVALID_ARG;
  }
  if (tactic_probs && !g_beh_dual_out) {
    memset(tactic_probs, 0, 14u * sizeof(float));
  }

  // 使用内存池或按需分配
  float *buf = s_behavior_input_buf;
  int need_free = 0;
  if (!buf) {
    buf = (float *)malloc((size_t)g_beh_in_nelem * sizeof(float));
    if (!buf) {
      return EDR_ERR_INTERNAL;
    }
    need_free = 1;
  }
  memcpy(buf, feature, (size_t)g_beh_in_nelem * sizeof(float));

  OrtValue *in_val = NULL;
  OrtStatus *st = g_ort->CreateTensorWithDataAsOrtValue(
      g_mem, buf, (size_t)g_beh_in_nelem * sizeof(float), g_beh_in_shape, (size_t)g_beh_in_ndim,
      ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &in_val);
  if (st) {
    fprintf(stderr, "[ave/onnx] behavior CreateTensor: %s\n", g_ort->GetErrorMessage(st));
    g_ort->ReleaseStatus(st);
    if (need_free) {
      free(buf);
    }
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  const char *in_names[] = {g_beh_in_name};
  const char *out_names_single[] = {g_beh_out_name};
  const char *out_names_dual[] = {g_beh_out_name, g_beh_out_tactic_name};
  OrtValue *out_val = NULL;
  OrtValue *out_tac = NULL;
  if (g_beh_dual_out && g_beh_out_tactic_name) {
    OrtValue *outs[2] = {NULL, NULL};
    st = g_ort->Run(g_beh_session, NULL, in_names, (const OrtValue *const *)&in_val, 1u, out_names_dual,
                    2u, outs);
    g_ort->ReleaseValue(in_val);
    if (need_free) {
      free(buf);
    }
    if (st) {
      fprintf(stderr, "[ave/onnx] behavior Run: %s\n", g_ort->GetErrorMessage(st));
      g_ort->ReleaseStatus(st);
      return EDR_ERR_AVE_LOAD_FAILED;
    }
    out_val = outs[0];
    out_tac = outs[1];
  } else {
    st = g_ort->Run(g_beh_session, NULL, in_names, (const OrtValue *const *)&in_val, 1u, out_names_single,
                    1u, &out_val);
    g_ort->ReleaseValue(in_val);
    if (need_free) {
      free(buf);
    }
    if (st) {
      fprintf(stderr, "[ave/onnx] behavior Run: %s\n", g_ort->GetErrorMessage(st));
      g_ort->ReleaseStatus(st);
      return EDR_ERR_AVE_LOAD_FAILED;
    }
  }
  float *out_data = NULL;
  st = g_ort->GetTensorMutableData(out_val, (void **)&out_data);
  if (st || !out_data) {
    if (st) {
      g_ort->ReleaseStatus(st);
    }
    g_ort->ReleaseValue(out_val);
    if (out_tac) {
      g_ort->ReleaseValue(out_tac);
    }
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  OrtTensorTypeAndShapeInfo *ots = NULL;
  st = g_ort->GetTensorTypeAndShape(out_val, &ots);
  size_t elem = 0;
  if (!st && ots) {
    st = g_ort->GetTensorShapeElementCount(ots, &elem);
    g_ort->ReleaseTensorTypeAndShapeInfo(ots);
  }
  if (st) {
    g_ort->ReleaseStatus(st);
    g_ort->ReleaseValue(out_val);
    if (out_tac) {
      g_ort->ReleaseValue(out_tac);
    }
    return EDR_ERR_AVE_LOAD_FAILED;
  }
  if (elem == 1u) {
    *out_score = out_data[0];
  } else {
    float mx = 0.f;
    (void)argmax_f(out_data, elem, &mx);
    *out_score = mx;
  }
  g_ort->ReleaseValue(out_val);
  if (out_tac) {
    if (tactic_probs) {
      copy_tactic_probs_from_tensor(out_tac, tactic_probs);
    }
    g_ort->ReleaseValue(out_tac);
  } else if (tactic_probs) {
    memset(tactic_probs, 0, 14u * sizeof(float));
  }
  return EDR_OK;
}

#endif
