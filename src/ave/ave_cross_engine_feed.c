#include "edr/ave_cross_engine_feed.h"

#include "edr/ave_sdk.h"
#include "edr/types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void edr_ave_cross_engine_feed_from_record(const EdrBehaviorRecord *br) {
  const char *eo = getenv("EDR_AVE_CROSS_ENGINE_FEED");
  if (eo && eo[0] == '0') {
    return;
  }
  if (!br || br->pid == 0u) {
    return;
  }
  if (br->type != EDR_EVENT_PROTOCOL_SHELLCODE && br->type != EDR_EVENT_WEBSHELL_DETECTED &&
      br->type != EDR_EVENT_PMFE_SCAN_RESULT) {
    return;
  }

  AVEBehaviorEvent ev;
  memset(&ev, 0, sizeof(ev));
  ev.pid = br->pid;
  ev.ppid = br->ppid;
  ev.cert_revoked_ancestor = br->cert_revoked_ancestor ? 1u : 0u;
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
    return;
  }

  AVE_FeedEvent(&ev);
}
