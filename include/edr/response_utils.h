/**
 * response/ 公共工具 — 取证文件复制、目录创建、TAR 打包、参数拆分、Hook 执行。
 */
#ifndef EDR_RESPONSE_UTILS_H
#define EDR_RESPONSE_UTILS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int response_forensic_copy_one_file(const char *src, const char *dst);
void response_forensic_copy_lines(const char *jobdir, const uint8_t *pl, size_t len);
void response_sanitize_job_name(const char *src, char *dst, size_t cap);
int response_mkdir_p(const char *path);
int response_make_tar_bundle(const char *dir, const char *bundle_path);
int response_split_args(char *buf, char *argv[], size_t argv_cap);
int response_run_hook_no_shell(const char *hook_cmdline);

#ifdef __cplusplus
}
#endif

#endif