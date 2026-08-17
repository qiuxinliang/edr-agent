#ifndef EDR_AVE_H
#define EDR_AVE_H

#include "edr/config.h"
#include "edr/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/** AV Engine initialization for rule, allow-list, and behavior heuristics. */
EdrError edr_ave_init(const EdrConfig *cfg);
void edr_ave_shutdown(void);

/** Kept for the ave_status command ABI; model execution is no longer shipped. */
void edr_ave_get_scan_counts(int *out_model_files, int *out_non_dir_files, int *out_ready_flag);

/** 读取文件 SHA256 指纹；缓冲区小于 65 字节时写入偶数字节 hex 前缀（cap≥17）。返回 0 成功，-1 失败。 */
int edr_ave_file_fingerprint(const char *path, char *out_hex, size_t cap);

#ifdef __cplusplus
}
#endif

#endif
