#ifndef EDR_FL_CRYPTO_H
#define EDR_FL_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 设置协调方 P-256 公钥（SEC1 压缩或解压），供 **FL3**（ECDH+HKDF+AES-GCM）封装；`len==0` 清除。
 * 在 `FLT_Init` / `fl_round_set_config` 内调用。
 */
void fl_crypto_set_coordinator_pubkey(const uint8_t *pub, size_t pub_len);

/**
 * C6：将明文梯度封装为可上传字节。
 * - 默认：`FLSTUB1` + 明文（开发）。
 * - `EDR_FL_CRYPTO_OPENSSL=1` 且已 `fl_crypto_set_coordinator_pubkey`：**FL3**（ECDH P-256 + HKDF-SHA256 + AES-256-GCM，无密钥附尾）。
 * - `EDR_FL_CRYPTO_OPENSSL=1` 且无公钥：失败（`-4`），除非 `EDR_FL_CRYPTO_ALLOW_INSECURE_FL2=1` 使用已废弃的 FL2。
 */
int fl_crypto_seal_gradient(const uint8_t *plain, size_t plain_len, uint8_t *out, size_t out_cap,
                            size_t *out_len);

/** 验证并解密；`FLSTUB1` 明文；旧 FL2；**FL3** 在端上无法解密（无临时私钥），返回 `-5` */
int fl_crypto_open_gradient(const uint8_t *blob, size_t blob_len, uint8_t *plain_out, size_t plain_cap,
                            size_t *plain_len);

/**
 * 协调端：用 P-256 **私钥**（32 字节 big-endian 标量）解密 **FL3** blob。
 * 需 `EDR_HAVE_OPENSSL_FL`。成功返回 `0`；`plain_out==NULL` 时仅写入所需明文长度（与密文等长）。
 * `-1` 参数/格式；`-2` 输出缓冲区不足；`-3` 解密或认证失败。
 */
int fl_crypto_coordinator_open_fl3(const uint8_t *coord_priv, size_t coord_priv_len, const uint8_t *blob,
                                   size_t blob_len, uint8_t *plain_out, size_t plain_cap, size_t *plain_len);

#ifdef __cplusplus
}
#endif

#endif
