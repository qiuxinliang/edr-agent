#ifndef EDR_AVE_H
#define EDR_AVE_H

#include "edr/config.h"
#include "edr/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/** §5 AV Engine：扫描模型目录就绪检查（深度扫描接口后续扩展） */
EdrError edr_ave_init(const EdrConfig *cfg);
void edr_ave_shutdown(void);
/** 自 `model_dir` 重新加载 static / behavior ONNX（与 `edr_ave_init` 中加载逻辑一致） */
EdrError edr_ave_reload_models(const EdrConfig *cfg);
/** 清空 static ONNX 推理 LRU（`AVE_SyncFromEdrConfig` / `AVE_ApplyHotfix` / `AVE_UpdateModel` 成功重载后调用） */
void edr_ave_infer_cache_clear(void);

/** 最近一次 init 时模型目录扫描结果（供 gRPC ave_status 指令） */
void edr_ave_get_scan_counts(int *out_model_files, int *out_non_dir_files, int *out_ready_flag);

/**
 * 读取文件前 256 字节的 FNV-1a 指纹写入 out_hex（cap≥17）。
 * 返回 0 成功，-1 失败。
 */
int edr_ave_file_fingerprint(const char *path, char *out_hex, size_t cap);

/** 单文件推理结果（在线检测扩展点） */
typedef struct EdrAveInferResult {
  int label;
  float score;
  char detail[128];
  /**
   * **0**：单输出 legacy（字节填充 / 单 logit 或 argmax）。
   * **1**：《static_onnx 设计规范》§7.2 三输出：`verdict_probs`/`family_probs`/`packer_probs` 有效。
   */
  int onnx_layout;
  float verdict_probs[4];
  float family_probs[32];
  float packer_probs[8];
} EdrAveInferResult;

/**
 * 对 path 做一次推理：已用 CMake **`-DEDR_WITH_ONNXRUNTIME=ON`** 链接 ONNX Runtime 且 **`ave.model_dir`** 下存在 **`.onnx`** 时走真推理；否则返回 **EDR_ERR_NOT_IMPL**。
 * 设置 **`EDR_AVE_INFER_DRY_RUN=1`** 时跳过真实推理，返回 **EDR_OK** 与占位 score（用于集成测试/联调）。
 */
EdrError edr_ave_infer_file(const EdrConfig *cfg, const char *path, EdrAveInferResult *out);

#ifdef __cplusplus
}
#endif

#endif
