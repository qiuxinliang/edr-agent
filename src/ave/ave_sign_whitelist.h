/**
 * §08 签名白名单 Stage0 — 仅供 ave_sdk 内部使用。
 */
#ifndef EDR_AVE_SIGN_WHITELIST_H
#define EDR_AVE_SIGN_WHITELIST_H

#include "edr/ave_sdk.h"

struct EdrConfig;

/**
 * @param onnx_boost_out 黑名单命中时对 ONNX 置信度的增量（§08，默认 0.30）
 * @param skip_onnx_out  1：L1 放行，跳过 ONNX
 * @return 0
 */
int edr_ave_sign_stage0(const struct EdrConfig *cfg, const char *path, const char file_sha256_hex[65],
                        AVEScanResult *res, int *skip_onnx_out, float *onnx_boost_out);

#ifdef _WIN32
#include <wchar.h>
/**
 * 独立 Authenticode 校验（供 `AVE_VerifySignature`）；与 Stage0 共享吊销策略。
 * @return AVE_OK / AVE_ERR_INVALID_PARAM
 */
int edr_ave_verify_signature_file(const struct EdrConfig *cfg, const wchar_t *file_path,
                                    SignatureVerifyResult *sig_result_out, TrustLevel *trust_level_out,
                                    char *vendor_id_out, char *vendor_name_out);
#endif

#endif
