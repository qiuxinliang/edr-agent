#include "edr/ave_cross_engine_feed.h"

#include "edr/ave_sdk.h"
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

static int path_has_ransom_ext(const char *path) {
  const char *exts[] = {".locked", ".lockbit", ".encrypted", ".crypt", ".crypted", ".conti", ".ryuk",
                        ".blackcat", ".akira", ".8base", ".mallox", ".medusa", NULL};
  for (const char **p = exts; path && *p; ++p) {
    if (ace_str_has_ci(path, *p)) {
      return 1;
    }
  }
  return 0;
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
  int ransom_ext = path_has_ransom_ext(br->file_path);
  int shadow_delete = ace_str_has_ci(br->cmdline, "vssadmin delete shadows") ||
                      ace_str_has_ci(br->cmdline, "wmic shadowcopy delete") ||
                      ace_str_has_ci(br->cmdline, "delete shadows");
  int cert_anom = br->cert_revoked_ancestor ? 1 : 0;
  if (br->type != EDR_EVENT_PROTOCOL_SHELLCODE && br->type != EDR_EVENT_WEBSHELL_DETECTED &&
      br->type != EDR_EVENT_PMFE_SCAN_RESULT && script_score <= 0.f && !ransom_ext && !shadow_delete && !cert_anom) {
    return;
  }

  AVEBehaviorEvent ev;
  memset(&ev, 0, sizeof(ev));
  ev.pid = br->pid;
  ev.ppid = br->ppid;
  ev.cert_revoked_ancestor = br->cert_revoked_ancestor ? 1u : 0u;
  ev.cert_anomaly = br->cert_revoked_ancestor ? 1u : 0u;
  ev.tls_anomaly_score = br->cert_revoked_ancestor ? 0.8f : 0.f;
  ev.script_content_score = script_score;
  ev.script_block_present = (br->powershell_script_block[0] || br->script_snippet[0]) ? 1u : 0u;
  ev.amsi_content_present = ace_str_has_ci(br->script_snippet, "amsi") || ace_str_has_ci(br->powershell_script_block, "amsi");
  ev.suspicious_extension_burst = ransom_ext ? 1u : 0u;
  ev.shadow_copy_delete = shadow_delete ? 1u : 0u;
  ev.ransom_counter_score = (float)((ransom_ext ? 0.45 : 0.0) + (shadow_delete ? 0.45 : 0.0));
  if (ev.ransom_counter_score > 1.f) ev.ransom_counter_score = 1.f;
  ev.timestamp_ns = br->event_time_ns;
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
    ev.event_type = AVE_EVT_PMFE_RESULT;
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
    if (script_score > 0.f) {
      ev.event_type = AVE_EVT_PROCESS_CREATE;
    } else if (ransom_ext || shadow_delete) {
      ev.event_type = AVE_EVT_FILE_WRITE;
      if (br->file_path[0]) {
        snprintf(ev.target_path, sizeof(ev.target_path), "%s", br->file_path);
      }
    } else {
      ev.event_type = AVE_EVT_NET_CONNECT;
    }
    break;
  }

  AVE_FeedEvent(&ev);
}
