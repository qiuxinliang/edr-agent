#include "edr/ave_cross_engine_feed.h"

#include "edr/ave_sdk.h"
#include "edr/policy_v2.h"
#include "edr/types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int mz_hits_from_detail_text(const char *s) {
  if (!s || !s[0]) {
    return 0;
  }
  const char *p = strstr(s, "mz_hits=");
  if (!p) {
    return 0;
  }
  return (int)strtol(p + 8, NULL, 10);
}

static uint8_t pmfe_pe_found_from_record(const EdrBehaviorRecord *br) {
  if (edr_ave_cross_engine_pmfe_snapshot_pe_hint(br->pmfe_snapshot)) {
    return 1u;
  }
  if (mz_hits_from_detail_text(br->cmdline) >= 1) {
    return 1u;
  }
  if (mz_hits_from_detail_text(br->script_snippet) >= 1) {
    return 1u;
  }
  return 0u;
}

static int ace_str_has_ci(const char *hay, const char *needle) {
  if (!hay || !needle || !needle[0]) {
    return 0;
  }
  size_t n = strlen(needle);
  for (const char *p = hay; *p; ++p) {
    size_t i = 0;
    while (i < n && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == n) {
      return 1;
    }
  }
  return 0;
}

static float script_score_from_record(const EdrBehaviorRecord *br) {
  if (!br) {
    return 0.f;
  }
  const char *fields[] = {br->powershell_script_block, br->script_snippet, br->cmdline, NULL};
  float s = 0.f;
  for (const char **p = fields; *p; ++p) {
    const char *v = *p;
    if (!v || !v[0]) continue;
    if (ace_str_has_ci(v, "FromBase64String") || ace_str_has_ci(v, "DownloadString") ||
        ace_str_has_ci(v, "IEX") || ace_str_has_ci(v, "Invoke-Expression")) {
      s += 0.35f;
    }
    if (ace_str_has_ci(v, "VirtualAlloc") || ace_str_has_ci(v, "WriteProcessMemory") ||
        ace_str_has_ci(v, "CreateRemoteThread") || ace_str_has_ci(v, "Reflection.Assembly")) {
      s += 0.35f;
    }
    if (ace_str_has_ci(v, "-enc") || ace_str_has_ci(v, "EncodedCommand") || ace_str_has_ci(v, "AmsiUtils")) {
      s += 0.25f;
    }
  }
  return s > 1.f ? 1.f : s;
}

static int ace_str_eq_ci(const char *a, const char *b) {
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

static int path_has_ransom_ext(const char *path) {
  const char *exts[] = {".locked", ".lockbit", ".encrypted", ".crypt", ".crypted", ".conti", ".ryuk",
                        ".blackcat", ".akira", ".8base", ".mallox", ".medusa", NULL};
  const char *base;
  const char *dot = NULL;
  if (!path || !path[0]) {
    return 0;
  }
  base = path;
  for (const char *p = path; *p; ++p) {
    if (*p == '\\' || *p == '/') {
      base = p + 1;
      dot = NULL;
    } else if (*p == '.') {
      dot = p;
    }
  }
  if (!dot || dot == base || dot[1] == '\0') {
    return 0;
  }
  for (const char **p = exts; *p; ++p) {
    if (ace_str_eq_ci(dot, *p)) {
      return 1;
    }
  }
  return 0;
}

static int env_int_clamped(const char *name, int fallback, int min_v, int max_v) {
  const char *e = getenv(name);
  int v = fallback;
  if (e && e[0]) {
    char *end = NULL;
    long n = strtol(e, &end, 10);
    if (end != e) {
      v = (int)n;
    }
  }
  if (v < min_v) {
    v = min_v;
  }
  if (v > max_v) {
    v = max_v;
  }
  return v;
}

static int record_feed_min_quality(void) {
  return env_int_clamped("EDR_AVE_RECORD_FEED_MIN_QUALITY", 60, 30, 100);
}

static int has_text(const char *s) {
  return s && s[0];
}

static int has_process_identity(const EdrBehaviorRecord *br) {
  return br && (has_text(br->process_name) || has_text(br->exe_path));
}

static int has_parent_context(const EdrBehaviorRecord *br) {
  return br && (br->ppid != 0u || has_text(br->parent_name) || has_text(br->parent_path) ||
                has_text(br->parent_cmdline));
}

static int ave_event_type_from_record(EdrEventType t, AVEEventType *out) {
  if (!out) {
    return 0;
  }
  switch (t) {
  case EDR_EVENT_PROCESS_CREATE:
    *out = AVE_EVT_PROCESS_CREATE;
    return 1;
  case EDR_EVENT_PROCESS_INJECT:
  case EDR_EVENT_THREAD_CREATE_REMOTE:
    *out = AVE_EVT_PROCESS_INJECT;
    return 1;
  case EDR_EVENT_DLL_LOAD:
  case EDR_EVENT_DRIVER_LOAD:
    *out = AVE_EVT_DLL_LOAD;
    return 1;
  case EDR_EVENT_FILE_CREATE:
  case EDR_EVENT_FILE_WRITE:
  case EDR_EVENT_FILE_DELETE:
  case EDR_EVENT_FILE_RENAME:
  case EDR_EVENT_FILE_PERMISSION_CHANGE:
    *out = AVE_EVT_FILE_WRITE;
    return 1;
  case EDR_EVENT_NET_CONNECT:
  case EDR_EVENT_NET_LISTEN:
    *out = AVE_EVT_NET_CONNECT;
    return 1;
  case EDR_EVENT_NET_DNS_QUERY:
    *out = AVE_EVT_NET_DNS;
    return 1;
  case EDR_EVENT_REG_CREATE_KEY:
  case EDR_EVENT_REG_SET_VALUE:
  case EDR_EVENT_REG_DELETE_KEY:
    *out = AVE_EVT_REG_WRITE;
    return 1;
  case EDR_EVENT_SCRIPT_POWERSHELL:
  case EDR_EVENT_SCRIPT_WMI:
    *out = AVE_EVT_PROCESS_CREATE;
    return 1;
  case EDR_EVENT_PROTOCOL_SHELLCODE:
    *out = AVE_EVT_SHELLCODE_SIGNAL;
    return 1;
  case EDR_EVENT_WEBSHELL_DETECTED:
    *out = AVE_EVT_WEBSHELL_SIGNAL;
    return 1;
  case EDR_EVENT_PMFE_SCAN_RESULT:
    *out = AVE_EVT_PMFE_RESULT;
    return 1;
  default:
    return 0;
  }
}

static int record_is_high_signal(const EdrBehaviorRecord *br, float script_score, int ransom_ext,
                                 int shadow_delete, int cert_anom) {
  if (!br) {
    return 0;
  }
  if (br->type == EDR_EVENT_PROTOCOL_SHELLCODE || br->type == EDR_EVENT_WEBSHELL_DETECTED ||
      br->type == EDR_EVENT_PMFE_SCAN_RESULT || br->type == EDR_EVENT_PROCESS_INJECT ||
      br->type == EDR_EVENT_THREAD_CREATE_REMOTE) {
    return 1;
  }
  return (script_score > 0.f || ransom_ext || shadow_delete || cert_anom ||
          br->cert_revoked_ancestor != 0u || br->priority == 0u);
}

static int ave_record_input_quality(const EdrBehaviorRecord *br, AVEEventType avt, int high_signal) {
  int q = 0;
  if (!br || br->pid == 0u) {
    return 0;
  }
  q += 20;
  if (has_process_identity(br)) {
    q += 20;
  }
  if (has_text(br->cmdline)) {
    q += 15;
  }
  if (has_parent_context(br)) {
    q += 10;
  }
  switch (avt) {
  case AVE_EVT_PROCESS_CREATE:
    if (has_text(br->exe_path) || has_text(br->process_name)) {
      q += 15;
    }
    if (has_text(br->cmdline) || has_text(br->powershell_script_block) || has_text(br->script_snippet)) {
      q += 20;
    }
    break;
  case AVE_EVT_FILE_WRITE:
  case AVE_EVT_FILE_EXECUTE:
  case AVE_EVT_DLL_LOAD:
    if (has_text(br->file_path) || has_text(br->exe_path)) {
      q += 30;
    }
    if (has_text(br->file_op) || br->file_target_has_motw) {
      q += 5;
    }
    break;
  case AVE_EVT_NET_CONNECT:
    if (has_text(br->net_dst) || br->net_dport != 0u) {
      q += 30;
    }
    if (has_text(br->network_aux_path)) {
      q += 5;
    }
    break;
  case AVE_EVT_NET_DNS:
    if (has_text(br->dns_query)) {
      q += 35;
    }
    break;
  case AVE_EVT_REG_WRITE:
    if (has_text(br->reg_key_path)) {
      q += 30;
    }
    if (has_text(br->reg_op) || has_text(br->reg_value_name)) {
      q += 5;
    }
    break;
  case AVE_EVT_PROCESS_INJECT:
  case AVE_EVT_MEM_ALLOC_EXEC:
  case AVE_EVT_LSASS_ACCESS:
  case AVE_EVT_SHELLCODE_SIGNAL:
  case AVE_EVT_WEBSHELL_SIGNAL:
  case AVE_EVT_PMFE_RESULT:
    if (has_text(br->detection_context) || has_text(br->pmfe_snapshot) ||
        has_text(br->script_snippet) || has_text(br->cmdline)) {
      q += 35;
    }
    break;
  default:
    break;
  }
  if (high_signal) {
    q += 15;
  }
  if (!has_process_identity(br) && avt != AVE_EVT_SHELLCODE_SIGNAL && avt != AVE_EVT_WEBSHELL_SIGNAL &&
      avt != AVE_EVT_PMFE_RESULT && avt != AVE_EVT_PROCESS_INJECT && avt != AVE_EVT_MEM_ALLOC_EXEC &&
      avt != AVE_EVT_LSASS_ACCESS) {
    q = q > 50 ? 50 : q;
  }
  return q > 100 ? 100 : q;
}

void edr_ave_cross_engine_feed_from_record(const EdrBehaviorRecord *br) {
  const char *eo = getenv("EDR_AVE_CROSS_ENGINE_FEED");
  if (eo && eo[0] == '0') {
    return;
  }
  if (!br || br->pid == 0u) {
    return;
  }
  float script_score = script_score_from_record(br);
  int ransom_ext = edr_policy_v2_ransomware_enabled("mass_write") && path_has_ransom_ext(br->file_path);
  int shadow_delete = edr_policy_v2_ransomware_enabled("vss") &&
                      ((ace_str_has_ci(br->cmdline, "vssadmin") && ace_str_has_ci(br->cmdline, "delete") && ace_str_has_ci(br->cmdline, "shadows")) ||
                      (ace_str_has_ci(br->cmdline, "wmic") && ace_str_has_ci(br->cmdline, "shadowcopy") && ace_str_has_ci(br->cmdline, "delete")));
  int cert_anom = br->cert_revoked_ancestor ? 1 : 0;
  AVEEventType avt;
  if (!ave_event_type_from_record(br->type, &avt)) {
    return;
  }
  int high_signal = record_is_high_signal(br, script_score, ransom_ext, shadow_delete, cert_anom);
  int q = ave_record_input_quality(br, avt, high_signal);
  if (q < record_feed_min_quality()) {
    return;
  }

  AVEBehaviorEvent ev;
  memset(&ev, 0, sizeof(ev));
  ev.pid = br->pid;
  ev.ppid = br->ppid;
  ev.event_type = avt;
  ev.cert_revoked_ancestor = br->cert_revoked_ancestor ? 1u : 0u;
  ev.cert_anomaly = br->cert_revoked_ancestor ? 1u : 0u;
  ev.tls_anomaly_score = br->cert_revoked_ancestor ? 0.8f : 0.f;
  ev.script_content_score = script_score;
  ev.script_block_present = (br->powershell_script_block[0] || br->script_snippet[0]) ? 1u : 0u;
  ev.amsi_content_present = ace_str_has_ci(br->script_snippet, "amsi") || ace_str_has_ci(br->powershell_script_block, "amsi");
  ev.suspicious_extension_burst = ransom_ext ? 1u : 0u;
  ev.shadow_copy_delete = shadow_delete ? 1u : 0u;
  ev.ransom_counter_score = (float)((ransom_ext ? 0.18 : 0.0) + (shadow_delete ? 0.25 : 0.0));
  if (ransom_ext && shadow_delete) ev.ransom_counter_score += 0.20f;
  if (ev.ransom_counter_score > 1.f) ev.ransom_counter_score = 1.f;
  ev.timestamp_ns = br->event_time_ns;
  snprintf(ev.process_name, sizeof(ev.process_name), "%s", br->process_name);
  snprintf(ev.process_path, sizeof(ev.process_path), "%s", br->exe_path);
  snprintf(ev.cmdline, sizeof(ev.cmdline), "%s", br->cmdline);
  if (br->priority <= 255u) {
    ev.severity_hint = (uint8_t)br->priority;
  }
  if (br->exe_path[0]) {
    snprintf(ev.target_path, sizeof(ev.target_path), "%s", br->exe_path);
  } else if (br->file_path[0]) {
    snprintf(ev.target_path, sizeof(ev.target_path), "%s", br->file_path);
  }
  if (br->net_dst[0]) {
    snprintf(ev.target_ip, sizeof(ev.target_ip), "%s", br->net_dst);
  }
  if (br->dns_query[0]) {
    snprintf(ev.target_domain, sizeof(ev.target_domain), "%s", br->dns_query);
  }
  if (br->net_dport != 0u) {
    ev.target_port = (uint16_t)(br->net_dport > 65535u ? 0u : br->net_dport);
  }

  float sc = edr_ave_cross_engine_parse_first_score(br->script_snippet, br->cmdline, NULL);
  float snap_ave = edr_ave_cross_engine_pmfe_snapshot_ave(br->pmfe_snapshot);

  switch (br->type) {
  case EDR_EVENT_PROTOCOL_SHELLCODE:
    ev.event_type = AVE_EVT_SHELLCODE_SIGNAL;
    ev.shellcode_score = sc;
    break;
  case EDR_EVENT_WEBSHELL_DETECTED:
    ev.event_type = AVE_EVT_WEBSHELL_SIGNAL;
    ev.webshell_score = sc;
    break;
  case EDR_EVENT_PMFE_SCAN_RESULT:
    {
      float conf = sc;
      if (conf <= 0.f) {
        conf = snap_ave;
      }
      ev.pmfe_confidence = conf;
      ev.pmfe_pe_found = pmfe_pe_found_from_record(br);
    }
    break;
  default:
    if (avt == AVE_EVT_FILE_WRITE && br->file_path[0]) {
      snprintf(ev.target_path, sizeof(ev.target_path), "%s", br->file_path);
    } else if (avt == AVE_EVT_REG_WRITE && br->reg_key_path[0]) {
      snprintf(ev.target_path, sizeof(ev.target_path), "%s", br->reg_key_path);
    } else if (avt == AVE_EVT_DLL_LOAD && br->file_path[0]) {
      snprintf(ev.target_path, sizeof(ev.target_path), "%s", br->file_path);
    } else if (script_score > 0.f && br->exe_path[0]) {
      snprintf(ev.target_path, sizeof(ev.target_path), "%s", br->exe_path);
    } else if (ransom_ext || shadow_delete) {
      if (br->file_path[0]) {
        snprintf(ev.target_path, sizeof(ev.target_path), "%s", br->file_path);
      }
    }
    break;
  }

  AVE_FeedEvent(&ev);
}
