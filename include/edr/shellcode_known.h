#ifndef EDR_SHELLCODE_KNOWN_H
#define EDR_SHELLCODE_KNOWN_H

#include "edr/proto_parse.h"

#include <stddef.h>
#include <stdint.h>

/**
 * 初始化已知漏洞规则库。rules_dir 为空时仅使用内置匹配器。
 * 返回 0 表示可继续（包括降级到内置匹配器），负值表示内部错误。
 */
int edr_shellcode_known_init(const char *rules_dir);

/** 释放已知漏洞规则库资源。 */
void edr_shellcode_known_shutdown(void);

/**
 * 周期性重新编译 `rules_dir` 下的 YARA 规则（`interval_s` 为 0 时不调用）。
 * 与 `edr_shellcode_known_init` 使用同一目录；在 WinDivert 捕获线程内调用。
 */
void edr_shellcode_known_reload_periodic(const char *rules_dir, uint32_t interval_s);

/**
 * §17.5.3 已知漏洞特征库（YARA 语义）
 * 在给定协议载荷区内做已知漏洞字节特征匹配。
 *
 * 返回值：
 *  - 1: 命中，rule_name_out 写入规则名
 *  - 0: 未命中
 */
int edr_shellcode_match_known_exploit(const uint8_t *data, uint32_t len, EdrProtoKind kind,
                                      char *rule_name_out, size_t rule_name_cap);

#endif
