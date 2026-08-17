/**
 * 非 Windows：§08 签名白名单 Stage0 不适用。
 */

#include "ave_sign_whitelist.h"

#include "edr/config.h"

int edr_ave_sign_stage0(const struct EdrConfig *cfg, const char *path, const char file_sha256_hex[65],
                        AVEScanResult *res, int *skip_remaining_checks_out) {
  (void)cfg;
  (void)path;
  (void)file_sha256_hex; /* 预留：sign_cache 按文件哈希 */
  (void)res;
  if (skip_remaining_checks_out) {
    *skip_remaining_checks_out = 0;
  }
  return 0;
}
