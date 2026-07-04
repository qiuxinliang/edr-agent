/**
 * P0 规则文件解密（EDR1 格式）。
 * 仅依赖 OpenSSL/LibreSSL；无 OpenSSL 时 fallback 为返回 0（不识别加密格式），调用方可回退到纯文本 JSON。
 */
#ifndef EDR_P0_RULE_ENCRYPT_H
#define EDR_P0_RULE_ENCRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDR_P0_ENCRYPT_MAGIC "EDR1"
#define EDR_P0_ENCRYPT_MAGIC_LEN 4u
#define EDR_P0_ENCRYPT_NONCE_LEN 12u
#define EDR_P0_ENCRYPT_TAG_LEN 16u
#define EDR_P0_ENCRYPT_OVERHEAD (EDR_P0_ENCRYPT_MAGIC_LEN + EDR_P0_ENCRYPT_NONCE_LEN + EDR_P0_ENCRYPT_TAG_LEN)

/**
 * 判断字节序列是否以 EDR1 魔数开头。
 */
int edr_p0_encrypt_is_edr1(const uint8_t *data, size_t data_len);

/**
 * 解密 EDR1 格式的规则数据。
 * @param in       输入字节（含完整 MAGIC+NONCE+CIPHERTEXT+TAG）
 * @param in_len   输入长度
 * @param out      输出缓冲区（解密后的纯文本 JSON），调用方负责 free()
 * @param out_len  输出长度（解密后的实际长度）
 * @return 0 成功，-1 参数无效，-2 缓冲区/长度，-3 解密或认证失败，-4 未编译加密支持
 */
int edr_p0_encrypt_decrypt_edr1(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
