#ifndef FL_FROZEN_LAYERS_H
#define FL_FROZEN_LAYERS_H

#include "edr/fl_trainer.h"

#include <stddef.h>

/**
 * T-015：当前为 **特征均值** 联邦路径时，512/256 维向量无法按 ONNX 逻辑名逐层切片；
 * 保留钩子供未来 LibTorch 全图反向或张量级梯度使用。
 */
void fl_frozen_layers_apply_feature_delta(const FLTConfig *cfg, float *delta, size_t dim);

/** 首次 FLT_Init 后打印一次 frozen 配置（stderr）。 */
void fl_frozen_layers_log_once(const FLTConfig *cfg);

/**
 * 生成 HTTP JSON 后缀：`,"frozen_layer_names":["a","b"]`（按 model_target 选表）。
 * 返回写入字节数；0 表示无后缀或 cfg 为空。
 */
int fl_frozen_http_json_suffix(const FLTConfig *cfg, char *buf, size_t cap);

#endif
