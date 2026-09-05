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
/* Build the exact request/artifact arguments for an external collector.
 * A nonzero return clears every output; callers must not execute a partially
 * formatted action. */
int response_forensic_build_collector_paths(const char *outdir, char separator,
                                            const char *scope, const char *job,
                                            long long timestamp, const char *artifact_ext,
                                            char *reqpath, size_t reqpath_cap,
                                            char *artifact, size_t artifact_cap,
                                            char *extra_args, size_t extra_args_cap);
/* Bounds/integrity failures must not fall back to another forensic action. */
int response_forensic_external_failure_must_not_fallback(int collector_rc);
/* Only a structured, non-contradictory OS-effect receipt is success. */
int response_isolation_status_verified(const char *json, int expect_isolated);
typedef struct EdrResponseFileSecurity {
  char dacl[8192];
  uint32_t attributes;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
} EdrResponseFileSecurity;
int response_file_security_snapshot(const char *path, EdrResponseFileSecurity *out);
int response_file_security_lock(const char *path, int directory);
int response_file_security_restore(const char *path, const EdrResponseFileSecurity *saved);
int response_mkdir_p(const char *path);
int response_make_tar_bundle(const char *dir, const char *bundle_path);
int response_split_args(char *buf, char *argv[], size_t argv_cap);
int response_run_hook_no_shell(const char *hook_cmdline);

#ifdef __cplusplus
}
#endif

#endif
