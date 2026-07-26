#ifndef EDR_SHELLCODE_KNOWN_H
#define EDR_SHELLCODE_KNOWN_H

#include "edr/proto_parse.h"

#include <stddef.h>
#include <stdint.h>

typedef struct EdrShellcodeRulesStatus {
  char source[32];
  char version[96];
  char last_error[160];
  uint32_t files_loaded;
  uint64_t last_reload_unix_s;
  int yara_enabled;
  uint32_t gray_percent;
  int rollback_available;
  int rollback_active;
  char rollback_version[96];
  uint64_t matches_total;
  uint64_t yara_matches;
  uint64_t builtin_matches;
  uint64_t gray_shadow_matches;
  char last_match_rule[96];
  char last_match_source[32];
} EdrShellcodeRulesStatus;

typedef struct EdrShellcodeExploitAttribution {
  char candidate_cve[64];
  char family[96];
  char product[96];
  char vector[48];
  char confidence[24];
  char source[32];
  char evidence_basis[160];
} EdrShellcodeExploitAttribution;

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

/** 获取当前规则库运营状态，用于 engine_health 上报和运维中心展示。 */
void edr_shellcode_known_get_status(EdrShellcodeRulesStatus *out);

/**
 * §17.5.3 已知漏洞特征库（YARA 语义）
 * 在给定协议载荷区内做已知漏洞字节特征匹配。
 *
 * 返回值：
 *  - 1: 命中，rule_name_out 写入规则名
 *  - 0: 未命中
 */
int edr_shellcode_match_known_exploit_ex(const uint8_t *data, uint32_t len, EdrProtoKind kind,
                                         char *rule_name_out, size_t rule_name_cap,
                                         EdrShellcodeExploitAttribution *attrib_out);

int edr_shellcode_match_known_exploit(const uint8_t *data, uint32_t len, EdrProtoKind kind,
                                      char *rule_name_out, size_t rule_name_cap);

#endif
