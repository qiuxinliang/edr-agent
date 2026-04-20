#ifndef EDR_FL_DP_H
#define EDR_FL_DP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void fl_dp_clip_l2(float *vec, size_t n, float max_norm);
/** Laplace 噪声；`scale` 通常取 `dp_clip_norm / epsilon` 量级（由调用方计算） */
void fl_dp_add_laplace(float *vec, size_t n, float scale, uint64_t *rng_state);

#ifdef __cplusplus
}
#endif

#endif
