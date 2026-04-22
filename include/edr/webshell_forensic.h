#ifndef EDR_WEBSHELL_FORENSIC_H
#define EDR_WEBSHELL_FORENSIC_H

#include <stddef.h>
#include <stdint.h>

/**
 * 生成轻量 alert_id（时间戳 + 递增计数，适配本地幂等键）。
 */
void edr_webshell_make_alert_id(char *out, size_t cap);

/**
 * 计算文件指纹（FNV-1a 全文件），16 hex chars + '\0'。
 * 成功返回 0，失败返回 -1。
 */
int edr_webshell_file_fingerprint(const char *path, char *out_hex, size_t cap);

/**
 * 将样本按 webshell/{tenant}/{date}/{alert_id}/{filename} 规范复制到本地取证目录。
 * out_object_key 返回对象键（webshell/...），out_local_path 返回本地绝对路径。
 * 成功返回 1，失败返回 0。
 */
int edr_webshell_stage_file(const char *src_path, const char *forensic_root, const char *tenant_id,
                            const char *alert_id, char *out_object_key, size_t out_object_key_cap,
                            char *out_local_path, size_t out_local_path_cap);

#endif
