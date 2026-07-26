#ifndef EDR_AVE_ONNX_INFER_H
#define EDR_AVE_ONNX_INFER_H

#include <stddef.h>

#include "edr/error.h"

#ifdef __cplusplus
extern "C" {
#endif

struct EdrConfig;
struct EdrAveInferResult;

/** 是否已成功加载 ONNX 会话（仅 EDR_HAVE_ONNXRUNTIME 且加载成功时为真） */
int edr_onnx_runtime_ready(void);

/** 加载首个 .onnx（路径可为 NULL 表示卸载） */
EdrError edr_onnx_runtime_load(const char *onnx_path, const struct EdrConfig *cfg);

void edr_onnx_runtime_cleanup(void);

/** 真推理入口；未就绪时返回 EDR_ERR_INVALID_ARG */
EdrError edr_onnx_infer_file(const struct EdrConfig *cfg, const char *path, struct EdrAveInferResult *out);

/** Legacy endpoint behavior.onnx hook; product builds keep it unloaded and use server-side evaluation. */
EdrError edr_onnx_behavior_load(const char *behavior_onnx_path, const struct EdrConfig *cfg);
int edr_onnx_behavior_ready(void);
/**
 * 特征长度须与模型首输入元素数一致（见 edr_onnx_behavior_input_nelem）。
 * tactic_probs：可为 NULL；非 NULL 且模型含第二输出（如 tactic_probs）时写入 14 维，否则填 0。
 */
EdrError edr_onnx_behavior_infer(const float *feature, size_t n_float, float *out_score,
                                 float *tactic_probs);
size_t edr_onnx_behavior_input_nelem(void);
/** 序列输入的时间步数（§6.1）；平面向量模型为 1。 */
size_t edr_onnx_behavior_input_seq_len(void);
/** 供 AVE_GetStatus：product builds normally return `not_loaded`. */
void edr_onnx_behavior_model_version(char *buf, size_t cap);
/** 供 AVE_GetStatus：static 会话已加载时为 `onnx:<文件名>`，否则 `not_loaded`（stub 无 ORT 时同逻辑基于配置路径） */
void edr_onnx_static_model_version(char *buf, size_t cap);

/**
 * Legacy compatibility: export current behavior.onnx bytes only when endpoint behavior ONNX is explicitly enabled.
 * `buf == NULL`：仅查询，`*size_io` 置为文件字节数。
 * `buf != NULL`：`*size_io` 为缓冲容量；成功时回写实际字节数；不足时回写所需字节数。
 * @return 0 成功；1 无已加载路径；2 缓冲不足；3 读失败；-1 `size_io == NULL`
 */
int edr_onnx_behavior_export_weights(void *buf, size_t *size_io);

/** 导出当前 static.onnx 磁盘字节；返回值语义同 behavior export helper */
int edr_onnx_static_export_weights(void *buf, size_t *size_io);

/**
 * 已加载的 **behavior.onnx** 磁盘路径；product builds normally return **NULL**。
 */
const char *edr_onnx_behavior_loaded_path(void);

/**
 * Legacy compatibility: trainable tensor export for historical behavior.onnx research builds.
 * Product builds return 1 / not implemented.
 * `out_floats == NULL`：`*out_nelem_io` ← 所需 float 元素数；`manifest_json` 可写切片元数据（JSON）。
 * `out_floats != NULL`：调用前将 `*out_nelem_io` 设为缓冲可容下的元素数；成功时回写实际元素数。
 * @return 0 成功；1 无模型路径；2 缓冲不足；3 读文件或解析失败；-1 参数非法
 */
int edr_onnx_behavior_export_fl_trainable_floats(float *out_floats, size_t *out_nelem_io, char *manifest_json,
                                                 size_t manifest_cap);

#ifdef __cplusplus
}
#endif

#endif
