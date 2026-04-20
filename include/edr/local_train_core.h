/**
 * C4：本地训练核心；可选 LibTorch（`EDR_WITH_LIBTORCH=ON`）对特征矩阵求均值。
 */
#ifndef EDR_LOCAL_TRAIN_CORE_H
#define EDR_LOCAL_TRAIN_CORE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int fl_local_train_mean_feature_delta(float *delta_out, size_t dim, size_t max_samples);

#ifdef __cplusplus
}
#endif

#endif
