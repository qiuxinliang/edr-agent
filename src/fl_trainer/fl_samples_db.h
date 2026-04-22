#ifndef EDR_FL_SAMPLES_DB_H
#define EDR_FL_SAMPLES_DB_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int fl_samples_db_open(const char *path);
void fl_samples_db_close(void);

/** 枚举 `model_target` 为 `static` 的样本 SHA256（调用方提供 `char sha256[65]` 缓冲区数组） */
int fl_samples_db_list_static_sha256(char *out_sha256_rows, size_t row_stride, size_t max_rows,
                                     size_t *out_count);

/**
 * 读取特征到 `out`（长度 `dim`）；维度与 BLOB 不符则返回 1（未命中）。
 * 返回值：0 成功；1 未找到/维度不匹配；其它为错误码。
 */
int fl_samples_db_read_feature(const char *sha256_64hex, float *out, size_t dim);

void fl_samples_db_register_ave_bridge(void);
void fl_samples_db_unregister_ave_bridge(void);

#ifdef __cplusplus
}
#endif

#endif
