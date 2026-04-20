/**
 * FL 特征查找回调：由 `fl_trainer` 在 `FLT_Init` 时注册，`AVE_ExportFeatureVector(Ex)` 优先调用。
 * 未注册或回调返回非 0 时，回退为全零向量（与 C0 兼容）。
 */
#ifndef EDR_FL_FEATURE_PROVIDER_H
#define EDR_FL_FEATURE_PROVIDER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 与 `AVE_ExportFeatureVectorEx` 的 `target` 参数一致 */
#define EDR_FL_TARGET_STATIC 0
#define EDR_FL_TARGET_BEHAVIOR 1

/**
 * 返回值：0 表示已写入 `out`；非 0 表示未命中（AVE 侧可映射为 `AVE_ERR_FL_SAMPLE_NOT_FOUND`）。
 */
typedef int (*EdrFLFeatureLookupFn)(const char *sha256_64hex, float *out, size_t dim, int target,
                                    void *user);

void edr_fl_register_feature_lookup(EdrFLFeatureLookupFn fn, void *user);
void edr_fl_unregister_feature_lookup(void);

/**
 * 供 `ave_sdk` 内部调用：无注册时返回 -1；否则透传回调返回值（0=命中，1=未命中，其它=未命中）。
 */
int edr_fl_feature_lookup_dispatch(const char *sha256_64hex, float *out, size_t dim, int target);

#ifdef __cplusplus
}
#endif

#endif
