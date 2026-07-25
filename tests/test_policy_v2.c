#include "edr/policy_v2.h"

#include <assert.h>
#include <string.h>

int main(void) {
  EdrConfig cfg;
  EdrConfig remote;
  memset(&cfg, 0, sizeof(cfg));
  memset(&remote, 0, sizeof(remote));
  cfg.policy_v2.credential_mode = EDR_POLICY_MODE_OFF;
  cfg.policy_v2.lateral_mode = EDR_POLICY_MODE_OBSERVE;
  cfg.policy_v2.script_mode = EDR_POLICY_MODE_ALERT;
  cfg.policy_v2.webshell_mode = EDR_POLICY_MODE_BLOCK;
  cfg.policy_v2.impact_mode = EDR_POLICY_MODE_ALERT;
  cfg.policy_v2.ransomware_behavior = true;
  cfg.policy_v2.ransomware_mass_write = true;
  cfg.policy_v2.ransomware_vss = true;
  cfg.policy_v2.ransomware_spread = true;
  cfg.policy_v2.ransomware_honey = true;
  cfg.policy_v2.ransomware_forensic = true;
  edr_policy_v2_configure(&cfg);
  assert(!edr_policy_v2_alert_allowed("T1003", "{}"));
  assert(!edr_policy_v2_alert_allowed("T1021", "{}"));
  assert(edr_policy_v2_alert_allowed("T1059.001", "{}"));
  assert(edr_policy_v2_mode_for_alert("T1059.001", "{}") == EDR_POLICY_MODE_ALERT);
  assert(edr_policy_v2_mode_for_alert("T1505.003", "{}") == EDR_POLICY_MODE_BLOCK);
  assert(edr_policy_v2_mode_for_alert("", "{\"rule_id\":\"unknown\"}") == EDR_POLICY_MODE_ALERT);
  assert(edr_policy_v2_alert_allowed("T1505.003", "{\"rule_id\":\"webshell\"}"));
  assert(edr_policy_v2_alert_allowed("", "{\"rule_id\":\"unknown\"}"));
  assert(edr_policy_v2_ransomware_enabled("mass_write"));
  assert(edr_policy_v2_ransomware_enabled("forensic"));

  remote = cfg;
  remote.policy_v2.credential_mode = EDR_POLICY_MODE_ALERT;
  remote.policy_v2.ransomware_forensic = false;
  assert(edr_policy_v2_apply_remote(&cfg, &remote) == 1);
  assert(edr_policy_v2_alert_allowed("T1003", "{}"));
  assert(!edr_policy_v2_ransomware_enabled("forensic"));
  assert(edr_policy_v2_apply_remote(&cfg, &remote) == 0);
  return 0;
}
