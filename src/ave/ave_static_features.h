#ifndef EDR_AVE_STATIC_FEATURES_H
#define EDR_AVE_STATIC_FEATURES_H

#include <stddef.h>

/**
 * 《static_onnx 设计规范》§7.2：模型输入为 512 维 float、L2 归一化。
 * 端侧在完整 EMBER+PCA 未就绪前，使用 **lite** 管线：256 维字节直方图（L1 归一化）
 * + 256 维分块 Shannon 熵，再整体 **L2 归一化**，与训练侧「features」张量形状一致。
 *
 * 返回 0 成功；-1 读文件失败。
 */
int edr_ave_static_features_lite_512(const char *path, float *out512);

#endif
