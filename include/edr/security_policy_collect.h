/* §19.3.3 P1：攻击面快照内 securityPolicy（及顶层 firewall 粗字段）采集 */

#ifndef EDR_SECURITY_POLICY_COLLECT_H
#define EDR_SECURITY_POLICY_COLLECT_H

#include <stdio.h>
#include <stdint.h>

struct EdrConfig;

/** 采集结果：未知项用 *_known==0 表示，写入 JSON 时用 null 或省略 */
typedef struct {
  int top_fw_enabled_known;
  int top_fw_enabled;
  char top_fw_profile[192];
  int top_rule_count_known;
  int top_rule_count;

  int sp_fw_enabled_known;
  int sp_fw_enabled;
  char sp_default_inbound[24];
  char sp_default_outbound[24];
  int sp_in_allow_known;
  uint32_t sp_in_allow;
  int sp_in_block_known;
  uint32_t sp_in_block;
  int sp_out_allow_known;
  uint32_t sp_out_allow;
  int sp_out_block_known;
  uint32_t sp_out_block;

  int os_uac_known;
  int os_uac;
  int os_dep_known;
  int os_dep;
  int os_aslr_known;
  int os_aslr;
  int os_smb_sign_known;
  int os_smb_sign;
  int os_smbv1_known;
  int os_smbv1;
  int os_rdp_nla_known;
  int os_rdp_nla;
  int os_secure_boot_known;
  int os_secure_boot;
  char os_patch[160];

  /** Windows：入站 Allow 且 LocalPort 命中高危列表的端口摘要（如 `445/tcp`），最多 16 条 */
  int sp_hr_allow_ports_count;
  char sp_hr_allow_ports[16][24];
} EdrSecurityPolicySnap;

void edr_security_policy_snap_collect(const struct EdrConfig *cfg, EdrSecurityPolicySnap *out);

/**
 * 写入 `securityPolicy` 对象：`edrPolicy` 来自 `EdrConfig`；`firewall`/`osSecurity` 来自快照。
 * `cfg` 可为 NULL，此时省略 `edrPolicy` 键。
 */
void edr_security_policy_snap_write_policy_object(FILE *f, const struct EdrConfig *cfg,
                                                  const EdrSecurityPolicySnap *s);

#endif
