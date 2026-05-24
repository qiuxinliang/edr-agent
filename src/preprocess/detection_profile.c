#include "edr/detection_profile.h"

#include "edr/detection_decision.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int eq_ci(const char *a, const char *b) {
  if (!a || !b) {
    return 0;
  }
  while (*a && *b) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
      return 0;
    }
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

static int has_ci(const char *hay, const char *needle) {
  if (!needle || !needle[0]) {
    return 1;
  }
  if (!hay) {
    hay = "";
  }
  for (; *hay; hay++) {
    const char *a = hay;
    const char *b = needle;
    while (*a && *b && tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
      a++;
      b++;
    }
    if (!*b) {
      return 1;
    }
  }
  return 0;
}

static int has_stream_forensic_pattern(const EdrBehaviorRecord *r) {
  const char *s = r && r->cmdline[0] ? r->cmdline : (r ? r->script_snippet : "");
  return has_ci(s, ".sct") || has_ci(s, "scrobj.dll") || has_ci(s, "downloadstring") ||
         has_ci(s, "invoke-webrequest") || has_ci(s, "-encodedcommand") || has_ci(s, "frombase64string");
}

static int has_script_sensor_pattern(const EdrBehaviorRecord *r) {
  const char *s = r && r->script_snippet[0] ? r->script_snippet : (r ? r->cmdline : "");
  return (r && (r->type == EDR_EVENT_SCRIPT_POWERSHELL || r->type == EDR_EVENT_SCRIPT_WMI ||
                r->type == EDR_EVENT_SCRIPT_BASH || r->type == EDR_EVENT_SCRIPT_PYTHON)) ||
         has_ci(s, "sensor=amsi") || has_ci(s, "sensor=scriptblock") || has_ci(s, "sensor=etw") ||
         has_ci(s, "provider=Microsoft-Antimalware-Scan-Interface") ||
         has_ci(s, "amsiutils") || has_ci(s, "amsiinitfailed") || has_ci(s, "downloadstring") ||
         has_ci(s, "invoke-expression") || has_ci(s, "frombase64string") ||
         has_ci(s, "amsi_content=") || has_ci(s, "amsi_result=") ||
         has_ci(s, "script_content=") || has_ci(s, "script_text=");
}

static int has_tls_anomaly_pattern(const EdrBehaviorRecord *r) {
  const char *s = r ? r->script_snippet : "";
  return r && (r->type == EDR_EVENT_NET_TLS_HANDSHAKE || r->cert_revoked_ancestor || has_ci(s, "ja3_rare=1") ||
               has_ci(s, "sni_suspicious=1") || has_ci(s, "sni_mismatch=1") ||
               has_ci(s, "cert_self_signed=1") || has_ci(s, "cert_expired=1") ||
               has_ci(s, "cert_mismatch=1") || has_ci(s, "cert_revoked=1") ||
               has_ci(s, "cert_chain_anomaly=1") || has_ci(s, "cert_untrusted=1") ||
               has_ci(s, "ja3_hash=") || has_ci(s, "ja3_fingerprint=") || has_ci(s, "tls_sni="));
}

static int has_ransom_or_webshell_semantic_pattern(const EdrBehaviorRecord *r) {
  const char *s = r && r->script_snippet[0] ? r->script_snippet : (r ? r->cmdline : "");
  return r && (has_ci(s, "ransom_counter=1") || has_ci(s, "mass_rename=1") ||
               has_ci(s, "extension_burst=1") || has_ci(s, "rename_burst=1") ||
               has_ci(s, "shadowcopy_delete=1") || has_ci(s, "ast=webshell") ||
               has_ci(s, "token=webshell") || has_ci(s, "ast_score=") ||
               has_ci(s, "token_score=") || has_ci(s, "semantic_score=") ||
               has_ci(s, "ast_tokens=") || has_ci(s, "token_features="));
}

static int has_memory_or_credential_pattern(const EdrBehaviorRecord *r) {
  const char *s = r && r->cmdline[0] ? r->cmdline : (r ? r->script_snippet : "");
  return has_ci(s, "lsass") || has_ci(s, "comsvcs.dll") || has_ci(s, "minidump") ||
         has_ci(s, "sekurlsa::logonpasswords") || has_ci(s, "invoke-mimikatz") ||
         has_ci(s, "nanodump") || has_ci(s, "procdump");
}

static int has_persistence_pattern(const EdrBehaviorRecord *r) {
  const char *s = r && r->cmdline[0] ? r->cmdline : (r ? r->script_snippet : "");
  const char *k = r ? r->reg_key_path : "";
  if (!r) {
    return 0;
  }
  return r->type == EDR_EVENT_SERVICE_CREATE || r->type == EDR_EVENT_SCHEDULED_TASK_CREATE ||
         r->type == EDR_EVENT_DRIVER_LOAD || has_ci(k, "\\currentversion\\run") ||
         has_ci(k, "\\currentversion\\runonce") || has_ci(k, "\\services\\") ||
         has_ci(k, "\\winlogon") || has_ci(k, "\\image file execution options\\") ||
         has_ci(s, "persistence_change_indicator") || has_ci(s, "schtasks /create") ||
         has_ci(s, "sc create") || has_ci(s, "new-service");
}

static int has_silverfox_pattern(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  const char *fields[] = {
      r->process_name,    r->exe_path,       r->cmdline,        r->file_path,
      r->reg_key_path,    r->reg_value_name, r->reg_value_data, r->script_snippet,
  };
  int setup64_seen = 0;
  int silverfox_path_seen = 0;
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    const char *s = fields[i] ? fields[i] : "";
    if (has_ci(s, "\\public\\501\\") || has_ci(s, "\\programdata\\golden\\")) {
      silverfox_path_seen = 1;
    }
    if (has_ci(s, "setup64.exe")) {
      setup64_seen = 1;
    }
    if (has_ci(s, "winos") || has_ci(s, "valleyrat") ||
        has_ci(s, "wsftprm.sys") || has_ci(s, "amsdk.sys") || has_ci(s, "wamsdk.sys") ||
        has_ci(s, "zam.exe") || has_ci(s, "zemana") || has_ci(s, "watchdog")) {
      return 1;
    }
  }
  if (setup64_seen && silverfox_path_seen) {
    return 1;
  }
  return 0;
}

static int is_memory_event(const EdrBehaviorRecord *r) {
  return r && (r->type == EDR_EVENT_PROCESS_INJECT || r->type == EDR_EVENT_THREAD_CREATE_REMOTE);
}

static void add_reason(char *dst, size_t cap, const char *s) {
  if (!dst || cap == 0u || !s || !s[0]) {
    return;
  }
  size_t l = strlen(dst);
  if (l > 0u && l + 1u < cap) {
    dst[l++] = ',';
    dst[l] = '\0';
  }
  if (l + 1u < cap) {
    snprintf(dst + l, cap - l, "%s", s);
  }
}

static int env_bool(const char *name, int fallback) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return fallback;
  }
  if (v[0] == '1' || eq_ci(v, "true") || eq_ci(v, "yes") || eq_ci(v, "on")) {
    return 1;
  }
  if (v[0] == '0' || eq_ci(v, "false") || eq_ci(v, "no") || eq_ci(v, "off")) {
    return 0;
  }
  return fallback;
}

static float env_float(const char *name, float fallback, float lo, float hi) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return fallback;
  }
  float f = (float)strtod(v, NULL);
  if (f < lo) {
    f = lo;
  }
  if (f > hi) {
    f = hi;
  }
  return f;
}

void edr_detection_profile_load(EdrDetectionProfile *out) {
  if (!out) {
    return;
  }
  memset(out, 0, sizeof(*out));
  snprintf(out->name, sizeof(out->name), "%s", "balanced");
  out->pmfe_auto_enabled = 1u;
  out->minidump_enabled = 1u;
  out->pmfe_confidence_threshold = 0.86f;
  out->minidump_confidence_threshold = 0.93f;

  const char *p = getenv("EDR_DETECTION_PROFILE");
  if (p && p[0]) {
    snprintf(out->name, sizeof(out->name), "%s", p);
    if (eq_ci(p, "server")) {
      out->server_asset = 1u;
      out->pmfe_confidence_threshold = 0.80f;
    } else if (eq_ci(p, "high_value") || eq_ci(p, "high-value")) {
      out->server_asset = 1u;
      out->high_value_asset = 1u;
      out->pmfe_confidence_threshold = 0.74f;
      out->minidump_confidence_threshold = 0.90f;
    } else if (eq_ci(p, "aggressive")) {
      out->server_asset = 1u;
      out->high_value_asset = 1u;
      out->aggressive = 1u;
      out->pmfe_confidence_threshold = 0.70f;
      out->minidump_confidence_threshold = 0.88f;
    } else if (eq_ci(p, "workstation")) {
      out->pmfe_confidence_threshold = 0.88f;
      out->minidump_confidence_threshold = 0.94f;
    }
  }

  out->pmfe_auto_enabled = (uint8_t)env_bool("EDR_DETECTION_PMFE_AUTO", out->pmfe_auto_enabled);
  out->minidump_enabled = (uint8_t)env_bool("EDR_DETECTION_MINIDUMP", out->minidump_enabled);
  out->pmfe_confidence_threshold =
      env_float("EDR_DETECTION_PMFE_THRESHOLD", out->pmfe_confidence_threshold, 0.50f, 0.99f);
  out->minidump_confidence_threshold =
      env_float("EDR_DETECTION_MINIDUMP_THRESHOLD", out->minidump_confidence_threshold, 0.70f, 0.99f);
}

void edr_detection_trigger_evaluate(const EdrBehaviorRecord *r, const EdrDetectionDecision *d,
                                    EdrDetectionTrigger *out) {
  if (!out) {
    return;
  }
  memset(out, 0, sizeof(*out));
  EdrDetectionProfile p;
  edr_detection_profile_load(&p);
  snprintf(out->profile_name, sizeof(out->profile_name), "%s", p.name);
  if (!r || !d || d->suppress || d->drop) {
    add_reason(out->reason, sizeof(out->reason), "suppressed_or_invalid");
    return;
  }

  if (r->file_path[0] || r->exe_path[0]) {
    out->targeted_files = 1u;
  }
  if (d->has_remote || r->dns_query[0] || r->net_dst[0]) {
    out->ioc_lookup = 1u;
  }

  if (p.pmfe_auto_enabled) {
    if (r->type == EDR_EVENT_PMFE_SCAN_RESULT) {
      add_reason(out->reason, sizeof(out->reason), "pmfe_result_feedback");
    } else if (r->type == EDR_EVENT_PROTOCOL_SHELLCODE) {
      out->pmfe_scan = 1u;
      add_reason(out->reason, sizeof(out->reason), "shellcode_high_signal");
    } else if (r->type == EDR_EVENT_WEBSHELL_DETECTED) {
      out->pmfe_scan = 1u;
      add_reason(out->reason, sizeof(out->reason), "webshell_high_signal");
    } else if (is_memory_event(r)) {
      out->pmfe_scan = 1u;
      add_reason(out->reason, sizeof(out->reason), "memory_event_high_signal");
    } else if (d->confidence >= 0.70f && has_silverfox_pattern(r)) {
      out->pmfe_scan = 1u;
      out->targeted_files = 1u;
      out->ioc_lookup = 1u;
      add_reason(out->reason, sizeof(out->reason), "silverfox_attack_chain_review");
    } else if (d->confidence >= 0.70f && has_script_sensor_pattern(r)) {
      out->pmfe_scan = 1u;
      add_reason(out->reason, sizeof(out->reason), "script_sensor_high_signal");
    } else if (d->confidence >= 0.70f && has_tls_anomaly_pattern(r)) {
      out->ioc_lookup = 1u;
      add_reason(out->reason, sizeof(out->reason), "tls_ioc_certificate_review");
    } else if (d->confidence >= 0.55f && has_ransom_or_webshell_semantic_pattern(r)) {
      out->pmfe_scan = 1u;
      add_reason(out->reason, sizeof(out->reason), "semantic_behavior_high_signal");
    } else if (d->confidence >= 0.55f && has_memory_or_credential_pattern(r)) {
      out->pmfe_scan = 1u;
      add_reason(out->reason, sizeof(out->reason), "credential_memory_combo");
    } else if (d->confidence >= 0.55f && has_persistence_pattern(r)) {
      out->targeted_files = 1u;
      add_reason(out->reason, sizeof(out->reason), "persistence_change_review");
    } else if (d->context_correlated && d->confidence >= 0.55f) {
      out->pmfe_scan = 1u;
      add_reason(out->reason, sizeof(out->reason), "process_context_high_signal");
    } else if (d->confidence >= 0.70f && d->has_remote && has_stream_forensic_pattern(r)) {
      out->pmfe_scan = 1u;
      add_reason(out->reason, sizeof(out->reason), "stream_forensic_combo");
    } else if (d->confidence >= p.pmfe_confidence_threshold &&
               (d->has_remote || d->suspicious_parent || r->cert_revoked_ancestor)) {
      out->pmfe_scan = 1u;
      add_reason(out->reason, sizeof(out->reason), "high_confidence_behavior");
    }
  } else {
    add_reason(out->reason, sizeof(out->reason), "pmfe_auto_disabled");
  }

  if (p.minidump_enabled && d->confidence >= p.minidump_confidence_threshold &&
      (r->type == EDR_EVENT_PMFE_SCAN_RESULT || is_memory_event(r) ||
       has_memory_or_credential_pattern(r) || r->cert_revoked_ancestor)) {
    out->single_process_minidump = 1u;
    add_reason(out->reason, sizeof(out->reason), "minidump_multi_source_high_confidence");
  }

  if (!out->reason[0]) {
    add_reason(out->reason, sizeof(out->reason), "no_heavy_trigger");
  }
}

int edr_detection_trigger_should_auto_pmfe(const EdrBehaviorRecord *r, const EdrDetectionDecision *d) {
  EdrDetectionTrigger t;
  edr_detection_trigger_evaluate(r, d, &t);
  return t.pmfe_scan ? 1 : 0;
}
