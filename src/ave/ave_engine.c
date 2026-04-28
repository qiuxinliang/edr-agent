/* §5 AV Engine — 模型目录、扩展名过滤、文件指纹 */

#include "edr/ave.h"
#include "edr/edr_log.h"
#include "edr/sha256.h"
#include "ave_onnx_infer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <string.h>
#define strcasecmp _stricmp
#include <windows.h>
#else
#include <dirent.h>
#include <strings.h>
#endif

#include <stdint.h>

static int s_ready;
static int s_n_model;
static int s_n_files;

static int has_model_suffix(const char *name) {
  static const char *suf[] = {".onnx", ".tflite", ".pt", ".pth", ".model", ".bin", ".engine", ".mlc",
                             NULL};
  size_t ln = strlen(name);
  for (int i = 0; suf[i]; i++) {
    size_t sl = strlen(suf[i]);
    if (ln > sl && strcasecmp(name + ln - sl, suf[i]) == 0) {
      return 1;
    }
  }
  return 0;
}

static void scan_dir(const char *dir, int *out_models, int *out_all) {
  *out_models = 0;
  *out_all = 0;
#ifdef _WIN32
  char pat[1200];
  snprintf(pat, sizeof(pat), "%s\\*", dir);
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pat, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    return;
  }
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      continue;
    }
    (*out_all)++;
    if (has_model_suffix(fd.cFileName)) {
      (*out_models)++;
    }
  } while (FindNextFileA(h, &fd));
  FindClose(h);
#else
  DIR *d = opendir(dir);
  if (!d) {
    return;
  }
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.') {
      continue;
    }
    (*out_all)++;
    if (has_model_suffix(e->d_name)) {
      (*out_models)++;
    }
  }
  closedir(d);
#endif
}

static int is_behavior_onnx_leaf(const char *name) {
  if (!name) {
    return 0;
  }
  return strcasecmp(name, "behavior.onnx") == 0;
}

/** 在 dir 下找首个非 behavior.onnx 的 `.onnx`（静态模型），完整路径写入 out（成功返回 1） */
static int find_first_onnx_excluding_behavior(const char *dir, char *out, size_t cap) {
  if (!dir || !out || cap < 8u) {
    return 0;
  }
#ifdef _WIN32
  char pat[1200];
  snprintf(pat, sizeof(pat), "%s\\*", dir);
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pat, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    return 0;
  }
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      continue;
    }
    size_t nl = strlen(fd.cFileName);
    if (nl > 5u && strcasecmp(fd.cFileName + nl - 5u, ".onnx") == 0 && !is_behavior_onnx_leaf(fd.cFileName)) {
      snprintf(out, cap, "%s\\%s", dir, fd.cFileName);
      FindClose(h);
      return 1;
    }
  } while (FindNextFileA(h, &fd));
  FindClose(h);
#else
  DIR *d = opendir(dir);
  if (!d) {
    return 0;
  }
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.') {
      continue;
    }
    size_t nl = strlen(e->d_name);
    if (nl > 5u && strcasecmp(e->d_name + nl - 5u, ".onnx") == 0 && !is_behavior_onnx_leaf(e->d_name)) {
      snprintf(out, cap, "%s/%s", dir, e->d_name);
      closedir(d);
      return 1;
    }
  }
  closedir(d);
#endif
  return 0;
}

static int behavior_onnx_exists(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  fclose(f);
  return 1;
}

/** `model_dir/behavior.onnx` 存在则写入 out（成功返回 1） */
static int find_behavior_onnx_path(const char *dir, char *out, size_t cap) {
  if (!dir || !out || cap < 16u) {
    return 0;
  }
#ifdef _WIN32
  snprintf(out, cap, "%s\\behavior.onnx", dir);
#else
  snprintf(out, cap, "%s/behavior.onnx", dir);
#endif
  return behavior_onnx_exists(out) ? 1 : 0;
}

int edr_ave_file_fingerprint(const char *path, char *out_hex, size_t cap) {
  if (!path || !path[0] || !out_hex || cap < 65u) {
    return -1;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  EdrSha256Ctx ctx;
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  uint8_t buf[4096];
  edr_sha256_init(&ctx);
  for (;;) {
    size_t n = fread(buf, 1, sizeof(buf), f);
    if (n > 0u) {
      edr_sha256_update(&ctx, buf, n);
    }
    if (n < sizeof(buf)) {
      if (ferror(f)) {
        fclose(f);
        return -1;
      }
      break;
    }
  }
  fclose(f);
  edr_sha256_final(&ctx, digest);
  static const char *hx = "0123456789abcdef";
  for (size_t i = 0; i < EDR_SHA256_DIGEST_LEN; i++) {
    out_hex[i * 2u] = hx[digest[i] >> 4];
    out_hex[i * 2u + 1u] = hx[digest[i] & 0x0f];
  }
  out_hex[64] = '\0';
  return 0;
}

EdrError edr_ave_init(const EdrConfig *cfg) {
  if (!cfg) {
    return EDR_ERR_INVALID_ARG;
  }
  const char *en = getenv("EDR_AVE_ENABLED");
  if (en && en[0] == '1') {
    /* 显式启用 */
  } else if (!cfg->ave.enabled && (!en || en[0] != '1')) {
    EDR_LOGV("%s", "[ave] disabled by default, set EDR_AVE_ENABLED=1 to enable\n");
    return EDR_OK;
  }
  s_ready = 0;
  s_n_model = 0;
  s_n_files = 0;
  const char *dir = cfg->ave.model_dir;
  if (!dir || !dir[0]) {
    EDR_LOGV("%s", "[ave] model_dir empty, skip AVE scan init\n");
    return EDR_OK;
  }
  int n_model = 0, n_all = 0;
  scan_dir(dir, &n_model, &n_all);
  s_n_model = n_model;
  s_n_files = n_all;
  EDR_LOGV("[ave] model_dir=%s onnx_files=%d total_files=%d sensitivity=%s threads=%d\n", dir, n_model,
           n_all, cfg->ave.sensitivity, cfg->ave.scan_threads);
  s_ready = n_model > 0 ? 1 : 0;

  char onnx_path[2048];
  if (find_first_onnx_excluding_behavior(dir, onnx_path, sizeof(onnx_path))) {
    EdrError oe = edr_onnx_runtime_load(onnx_path, cfg);
    if (oe != EDR_OK) {
      EDR_LOGE("[ave] ONNX Runtime load failed (%d); inference falls back to dry-run / NOT_IMPL\n",
               (int)oe);
    }
  } else {
    (void)edr_onnx_runtime_load(NULL, cfg);
  }
  char beh_path[2048];
  if (find_behavior_onnx_path(dir, beh_path, sizeof(beh_path))) {
    EdrError be = edr_onnx_behavior_load(beh_path, cfg);
    if (be != EDR_OK) {
      EDR_LOGE("[ave] behavior.onnx load failed (%d); behavior score uses heuristics\n", (int)be);
    }
  } else {
    (void)edr_onnx_behavior_load(NULL, cfg);
  }
  return EDR_OK;
}

EdrError edr_ave_reload_models(const EdrConfig *cfg) {
  if (!cfg) {
    return EDR_ERR_INVALID_ARG;
  }
  const char *dir = cfg->ave.model_dir;
  if (!dir || !dir[0]) {
    return EDR_OK;
  }
  char onnx_path[2048];
  if (find_first_onnx_excluding_behavior(dir, onnx_path, sizeof(onnx_path))) {
    EdrError oe = edr_onnx_runtime_load(onnx_path, cfg);
    if (oe != EDR_OK) {
      EDR_LOGE("[ave] reload static ONNX failed (%d)\n", (int)oe);
    }
  } else {
    (void)edr_onnx_runtime_load(NULL, cfg);
  }
  char beh_path[2048];
  if (find_behavior_onnx_path(dir, beh_path, sizeof(beh_path))) {
    EdrError be = edr_onnx_behavior_load(beh_path, cfg);
    if (be != EDR_OK) {
      EDR_LOGE("[ave] reload behavior.onnx failed (%d)\n", (int)be);
    }
  } else {
    (void)edr_onnx_behavior_load(NULL, cfg);
  }
  return EDR_OK;
}

void edr_ave_shutdown(void) {
  edr_onnx_runtime_cleanup();
  s_ready = 0;
  s_n_model = 0;
  s_n_files = 0;
}

void edr_ave_get_scan_counts(int *out_model_files, int *out_non_dir_files, int *out_ready_flag) {
  if (out_model_files) {
    *out_model_files = s_n_model;
  }
  if (out_non_dir_files) {
    *out_non_dir_files = s_n_files;
  }
  if (out_ready_flag) {
    *out_ready_flag = s_ready;
  }
}

EdrError edr_ave_infer_file(const EdrConfig *cfg, const char *path, EdrAveInferResult *out) {
  (void)cfg;
  if (!path || !path[0] || !out) {
    return EDR_ERR_INVALID_ARG;
  }
  memset(out, 0, sizeof(*out));
  const char *dry = getenv("EDR_AVE_INFER_DRY_RUN");
  if (dry && dry[0] == '1') {
    out->label = -1;
    out->score = 0.01f;
    snprintf(out->detail, sizeof(out->detail), "dry_run no_backend");
    return EDR_OK;
  }
  if (edr_onnx_runtime_ready()) {
    return edr_onnx_infer_file(cfg, path, out);
  }
  EDR_LOGE("%s",
           "[ave] infer not implemented (set EDR_AVE_INFER_DRY_RUN=1 for dev; production: "
           "CMake -DEDR_WITH_ONNXRUNTIME=ON and install ONNX Runtime)\n");
  return EDR_ERR_NOT_IMPL;
}
