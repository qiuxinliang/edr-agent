#include "edr/policy_v2.h"

#include <ctype.h>
#include <string.h>

enum PolicyCategory {
  CAT_CREDENTIAL = 0,
  CAT_LATERAL,
  CAT_PRIVILEGE,
  CAT_EVASION,
  CAT_PERSISTENCE,
  CAT_SCRIPT,
  CAT_WEBSHELL,
  CAT_EXFIL,
  CAT_IMPACT,
  CAT_COUNT,
  CAT_UNKNOWN = -1
};

static volatile int s_modes[CAT_COUNT] = {2, 2, 2, 2, 2, 2, 2, 2, 2};
static volatile int s_ransomware_behavior = 1;
static volatile int s_ransomware_mass_write = 1;
static volatile int s_ransomware_vss = 1;
static volatile int s_ransomware_spread = 1;
static volatile int s_ransomware_honey = 1;
static volatile int s_ransomware_forensic = 1;

static int contains_ci(const char *haystack, const char *needle) {
  size_t n;
  if (!haystack || !needle || !needle[0]) return 0;
  n = strlen(needle);
  for (const char *p = haystack; *p; ++p) {
    size_t i = 0;
    while (i < n && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) ++i;
    if (i == n) return 1;
  }
  return 0;
}

static int category_from_name(const char *category) {
  static const char *names[CAT_COUNT] = {"credential", "lateral", "privilege", "evasion", "persistence", "script", "webshell", "exfil", "impact"};
  if (!category) return CAT_UNKNOWN;
  for (int i = 0; i < CAT_COUNT; ++i) if (strcmp(category, names[i]) == 0) return i;
  return CAT_UNKNOWN;
}

static int category_from_alert(const char *tactics, const char *subject) {
  const char *text = tactics ? tactics : "";
  if (contains_ci(text, "T1505.003") || contains_ci(subject, "webshell")) return CAT_WEBSHELL;
  if (contains_ci(text, "T1003") || contains_ci(text, "T1555") || contains_ci(text, "T1558") || contains_ci(subject, "credential")) return CAT_CREDENTIAL;
  if (contains_ci(text, "T1021") || contains_ci(text, "T1210") || contains_ci(text, "T1570") || contains_ci(subject, "lateral")) return CAT_LATERAL;
  if (contains_ci(text, "T1068") || contains_ci(text, "T1134") || contains_ci(text, "T1548") || contains_ci(subject, "privilege")) return CAT_PRIVILEGE;
  if (contains_ci(text, "T1562") || contains_ci(text, "T1070") || contains_ci(text, "T1027") || contains_ci(subject, "evasion")) return CAT_EVASION;
  if (contains_ci(text, "T1547") || contains_ci(text, "T1543") || contains_ci(text, "T1053") || contains_ci(text, "T1546") || contains_ci(subject, "persistence")) return CAT_PERSISTENCE;
  if (contains_ci(text, "T1059") || contains_ci(text, "T1218") || contains_ci(subject, "script")) return CAT_SCRIPT;
  if (contains_ci(text, "T1041") || contains_ci(text, "T1048") || contains_ci(text, "T1567") || contains_ci(subject, "exfil")) return CAT_EXFIL;
  if (contains_ci(text, "T1486") || contains_ci(text, "T1490") || contains_ci(text, "T1485") || contains_ci(subject, "ransom")) return CAT_IMPACT;
  return CAT_UNKNOWN;
}

void edr_policy_v2_configure(const EdrConfig *cfg) {
  if (!cfg) return;
  s_modes[CAT_CREDENTIAL] = cfg->policy_v2.credential_mode;
  s_modes[CAT_LATERAL] = cfg->policy_v2.lateral_mode;
  s_modes[CAT_PRIVILEGE] = cfg->policy_v2.privilege_mode;
  s_modes[CAT_EVASION] = cfg->policy_v2.evasion_mode;
  s_modes[CAT_PERSISTENCE] = cfg->policy_v2.persistence_mode;
  s_modes[CAT_SCRIPT] = cfg->policy_v2.script_mode;
  s_modes[CAT_WEBSHELL] = cfg->policy_v2.webshell_mode;
  s_modes[CAT_EXFIL] = cfg->policy_v2.exfil_mode;
  s_modes[CAT_IMPACT] = cfg->policy_v2.impact_mode;
  s_ransomware_behavior = cfg->policy_v2.ransomware_behavior ? 1 : 0;
  s_ransomware_mass_write = cfg->policy_v2.ransomware_mass_write ? 1 : 0;
  s_ransomware_vss = cfg->policy_v2.ransomware_vss ? 1 : 0;
  s_ransomware_spread = cfg->policy_v2.ransomware_spread ? 1 : 0;
  s_ransomware_honey = cfg->policy_v2.ransomware_honey ? 1 : 0;
  s_ransomware_forensic = cfg->policy_v2.ransomware_forensic ? 1 : 0;
}

int edr_policy_v2_apply_remote(EdrConfig *current, const EdrConfig *remote) {
  if (!current || !remote) return 0;
  int changed = memcmp(&current->policy_v2, &remote->policy_v2, sizeof(current->policy_v2)) != 0;
  current->policy_v2 = remote->policy_v2;
  edr_policy_v2_configure(current);
  return changed;
}

int edr_policy_v2_alert_allowed(const char *triggered_tactics, const char *subject_json) {
  int category = category_from_alert(triggered_tactics, subject_json);
  if (category == CAT_UNKNOWN) return 1;
  return s_modes[category] >= EDR_POLICY_MODE_ALERT;
}

int edr_policy_v2_mode_for_category(const char *category) {
  int id = category_from_name(category);
  return id == CAT_UNKNOWN ? EDR_POLICY_MODE_ALERT : s_modes[id];
}

int edr_policy_v2_mode_for_alert(const char *triggered_tactics, const char *subject_json) {
  int category = category_from_alert(triggered_tactics, subject_json);
  return category == CAT_UNKNOWN ? EDR_POLICY_MODE_ALERT : s_modes[category];
}

int edr_policy_v2_ransomware_enabled(const char *control) {
  if (!control) return 0;
  if (strcmp(control, "behavior") == 0) return s_ransomware_behavior;
  if (strcmp(control, "mass_write") == 0) return s_ransomware_mass_write;
  if (strcmp(control, "vss") == 0) return s_ransomware_vss;
  if (strcmp(control, "spread") == 0) return s_ransomware_spread;
  if (strcmp(control, "honey") == 0) return s_ransomware_honey;
  if (strcmp(control, "forensic") == 0) return s_ransomware_forensic;
  return 0;
}
