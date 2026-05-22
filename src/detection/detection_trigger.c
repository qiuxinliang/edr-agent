#include "edr/detection_trigger.h"

#include "edr/resource.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int contains_icase(const char *hay, const char *needle);

static int streq_ci(const char *a, const char *b) {
  if (!a || !b) return 0;
  while (*a && *b) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

static int env_is_on(const char *name) {
  const char *v = getenv(name);
  if (!v || !v[0]) return 0;
  if (strcmp(v, "1") == 0) return 1;
  return streq_ci(v, "true") || streq_ci(v, "yes") || streq_ci(v, "on");
}

static int contains_icase(const char *hay, const char *needle) {
  if (!hay || !needle || !needle[0]) return 0;
  size_t nl = strlen(needle);
  for (const char *p = hay; *p; p++) {
    size_t i = 0;
    while (i < nl && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == nl) return 1;
  }
  return 0;
}

static int process_is_any(const EdrBehaviorRecord *br, const char *names_csv) {
  if (!br || !names_csv || !names_csv[0]) return 0;
  const char *process_name = br->process_name;
  for (const char *p = br->process_name; p && *p; p++) {
    if (*p == '/' || *p == '\\') process_name = p + 1;
  }
  char buf[512];
  snprintf(buf, sizeof(buf), "%s", names_csv);
  char *p = buf;
  while (p && *p) {
    char *comma = strchr(p, ',');
    if (comma) *comma++ = '\0';
    while (*p == ' ' || *p == '\t') p++;
    char *end = p + strlen(p);
    while (end > p && (end[-1] == ' ' || end[-1] == '\t')) {
      *--end = '\0';
    }
    if (*p && streq_ci(process_name, p)) return 1;
    p = comma;
  }
  return 0;
}

static int is_lolbin_remote(const EdrBehaviorRecord *br) {
  if (!br) return 0;
  const int lolbin = process_is_any(br, "regsvr32.exe,mshta.exe,rundll32.exe,powershell.exe,pwsh.exe,wscript.exe,cscript.exe");
  if (!lolbin) return 0;
  if (contains_icase(br->cmdline, "http://") || contains_icase(br->cmdline, "https://")) return 1;
  if (contains_icase(br->cmdline, "scrobj.dll") || contains_icase(br->cmdline, "downloadstring")) return 1;
  if (contains_icase(br->cmdline, "iex ") || contains_icase(br->cmdline, " -enc") ||
      contains_icase(br->cmdline, " -encodedcommand")) {
    return 1;
  }
  return 0;
}

static int is_high_value_service(const EdrBehaviorRecord *br) {
  return process_is_any(br, "lsass.exe,svchost.exe,services.exe,w3wp.exe,nginx,apache,httpd,php-fpm,java,sqlservr.exe,mysqld,postgres,redis-server");
}

static int pmfe_alert_trigger_allowed(const EdrConfig *cfg) {
  if (env_is_on("EDR_PMFE_ETW_AUTO")) return 1;
  if (!cfg) return 0;
  return cfg->detection.pmfe_mode == 2 || cfg->detection.pmfe_mode == -1;
}

static int pmfe_budget_allow(const EdrConfig *cfg, uint32_t pid) {
  static time_t s_minute_start;
  static unsigned s_minute_count;
  static uint32_t s_last_pid;
  static time_t s_last_pid_at;
  unsigned cap = 3u;
  if (cfg && cfg->resource_limit.pmfe_scans_per_min > 0u) {
    cap = cfg->resource_limit.pmfe_scans_per_min;
  }
  time_t now = time(NULL);
  if (s_minute_start == 0 || now - s_minute_start >= 60) {
    s_minute_start = now;
    s_minute_count = 0;
  }
  if (s_minute_count >= cap) return 0;
  if (pid != 0 && pid == s_last_pid && now - s_last_pid_at < 600) return 0;
  s_minute_count++;
  s_last_pid = pid;
  s_last_pid_at = now;
  return 1;
}

void edr_detection_decision_init(EdrDetectionDecision *out) {
  if (!out) return;
  memset(out, 0, sizeof(*out));
}

bool edr_detection_trigger_evaluate(const EdrConfig *cfg,
                                    const EdrEventSlot *slot,
                                    const EdrBehaviorRecord *br,
                                    EdrDetectionDecision *out) {
  if (!slot || !br || !out) return false;
  edr_detection_decision_init(out);
  if (!pmfe_alert_trigger_allowed(cfg)) return false;

  const char *reason = NULL;
  if (br->type == EDR_EVENT_PROTOCOL_SHELLCODE) {
    reason = "protocol_shellcode";
  } else if (br->type == EDR_EVENT_WEBSHELL_DETECTED) {
    reason = "webshell_detected";
  } else if (is_lolbin_remote(br)) {
    reason = "lolbin_remote_payload";
  } else if (slot->priority == 0u && is_high_value_service(br)) {
    reason = "high_value_service_alert";
  }

  if (!reason) return false;
  if (br->pid == 0u && br->type != EDR_EVENT_PROTOCOL_SHELLCODE) return false;
  if (edr_resource_preprocess_throttle_active() && slot->priority != 0u &&
      br->type != EDR_EVENT_PROTOCOL_SHELLCODE && br->type != EDR_EVENT_WEBSHELL_DETECTED) {
    return false;
  }
  if (br->pid != 0u && !pmfe_budget_allow(cfg, br->pid)) return false;

  out->recommend_pmfe = true;
  out->pmfe_pid = br->pid;
  out->pmfe_priority = slot->priority == 0u ? 0u : 1u;
  out->recommend_minidump = false;
  snprintf(out->pmfe_reason, sizeof(out->pmfe_reason), "%s", reason);
  return true;
}
