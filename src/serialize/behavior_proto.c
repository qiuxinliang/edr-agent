#include "edr/behavior_proto.h"

#include "edr/ave_sdk.h"
#include "edr/types.h"

#include "edr/v1/event.pb.h"
#include <pb_encode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void copy_str(char *dst, size_t cap, const char *src) {
  if (!dst || cap == 0) {
    return;
  }
  if (!src) {
    dst[0] = '\0';
    return;
  }
  snprintf(dst, cap, "%s", src);
}

/** `EdrEventType` → `AVEEventType`（《11》§4.1）；无对应时返回 -1 */
static int32_t edr_event_type_to_ave_event_type(EdrEventType t) {
  switch (t) {
  case EDR_EVENT_PROCESS_CREATE:
    return (int32_t)AVE_EVT_PROCESS_CREATE;
  case EDR_EVENT_PROCESS_INJECT:
  case EDR_EVENT_THREAD_CREATE_REMOTE:
    return (int32_t)AVE_EVT_PROCESS_INJECT;
  case EDR_EVENT_DLL_LOAD:
    return (int32_t)AVE_EVT_DLL_LOAD;
  case EDR_EVENT_FILE_CREATE:
  case EDR_EVENT_FILE_WRITE:
  case EDR_EVENT_FILE_DELETE:
  case EDR_EVENT_FILE_RENAME:
  case EDR_EVENT_FILE_PERMISSION_CHANGE:
    return (int32_t)AVE_EVT_FILE_WRITE;
  case EDR_EVENT_NET_CONNECT:
    return (int32_t)AVE_EVT_NET_CONNECT;
  case EDR_EVENT_NET_DNS_QUERY:
    return (int32_t)AVE_EVT_NET_DNS;
  case EDR_EVENT_REG_CREATE_KEY:
  case EDR_EVENT_REG_SET_VALUE:
  case EDR_EVENT_REG_DELETE_KEY:
    return (int32_t)AVE_EVT_REG_WRITE;
  case EDR_EVENT_AUTH_LOGIN:
  case EDR_EVENT_AUTH_LOGOUT:
  case EDR_EVENT_AUTH_FAILED:
  case EDR_EVENT_AUTH_PRIVILEGE_ESC:
    return (int32_t)AVE_EVT_AUTH_EVENT;
  case EDR_EVENT_PROTOCOL_SHELLCODE:
    return (int32_t)AVE_EVT_SHELLCODE_SIGNAL;
  case EDR_EVENT_WEBSHELL_DETECTED:
    return (int32_t)AVE_EVT_WEBSHELL_SIGNAL;
  case EDR_EVENT_PMFE_SCAN_RESULT:
    return (int32_t)AVE_EVT_PMFE_RESULT;
  default:
    return -1;
  }
}

static int pmfe_detail_i(const char *s, const char *key) {
  if (!s || !key || !key[0]) return 0;
  const char *p = strstr(s, key);
  if (!p) return 0;
  p += strlen(key);
  if (*p == '=') p++;
  return (int)strtol(p, NULL, 10);
}

static float pmfe_detail_f(const char *s, const char *key) {
  if (!s || !key || !key[0]) return 0.f;
  const char *p = strstr(s, key);
  if (!p) return 0.f;
  p += strlen(key);
  if (*p == '=') p++;
  return strtof(p, NULL);
}

static int pmfe_has_positive_json_number(const char *json, const char *key) {
  if (!json || !key || !key[0]) return 0;
  char pat[64];
  snprintf(pat, sizeof(pat), "\"%s\":", key);
  const char *p = strstr(json, pat);
  if (!p) return 0;
  p += strlen(pat);
  while (*p == ' ' || *p == '\t') p++;
  return strtof(p, NULL) > 0.f;
}

static void fill_pmfe_cross_engine_fields(edr_v1_BehaviorEvent *m, const EdrBehaviorRecord *r) {
  if (!m || !r || r->type != EDR_EVENT_PMFE_SCAN_RESULT) return;
  float ave = pmfe_detail_f(r->cmdline, "ave_max_score");
  float dns_best = pmfe_detail_f(r->cmdline, "dns_best");
  int stomp = pmfe_detail_i(r->cmdline, "stomp_suspicious");
  int mz = pmfe_detail_i(r->cmdline, "mz_hits");
  int elf = pmfe_detail_i(r->cmdline, "elf_hits");
  int dns_hits = pmfe_detail_i(r->cmdline, "dns_ascii_hits") + pmfe_detail_i(r->cmdline, "dns_utf16_hits") +
                 pmfe_detail_i(r->cmdline, "dns_wire_hits");
  if (r->pmfe_snapshot[0]) {
    if (pmfe_has_positive_json_number(r->pmfe_snapshot, "ave") && ave <= 0.f) {
      const char *p = strstr(r->pmfe_snapshot, "\"ave\":");
      ave = p ? strtof(p + 6, NULL) : ave;
    }
    if (pmfe_has_positive_json_number(r->pmfe_snapshot, "dns_best") && dns_best <= 0.f) {
      const char *p = strstr(r->pmfe_snapshot, "\"dns_best\":");
      dns_best = p ? strtof(p + 11, NULL) : dns_best;
    }
    stomp = stomp || pmfe_has_positive_json_number(r->pmfe_snapshot, "stomp");
    mz = mz || pmfe_has_positive_json_number(r->pmfe_snapshot, "mz");
    elf = elf || pmfe_has_positive_json_number(r->pmfe_snapshot, "elf");
    dns_hits = dns_hits || pmfe_has_positive_json_number(r->pmfe_snapshot, "dns");
  }
  float conf = 0.f;
  if (stomp) conf = 0.92f;
  if (dns_hits) conf = conf > 0.63f ? conf : 0.63f;
  if (dns_best > conf) conf = dns_best;
  if (ave > conf) conf = ave;
  if (conf > 1.f) conf = 1.f;
  m->has_ave_behavior_feed = true;
  m->ave_behavior_feed.pmfe_confidence = conf;
  m->ave_behavior_feed.pmfe_pe_found = (mz || elf || stomp) ? true : false;
  m->ave_behavior_feed.pmfe_dns_tunnel = (dns_hits || dns_best >= 0.30f) ? true : false;
}

static void fill_ave_behavior_feed(edr_v1_BehaviorEvent *m, const EdrBehaviorRecord *r) {
  m->has_ave_behavior_feed = false;
  memset(&m->ave_behavior_feed, 0, sizeof(m->ave_behavior_feed));

  int32_t avt = edr_event_type_to_ave_event_type(r->type);
  if (avt >= 0) {
    m->has_ave_behavior_feed = true;
    m->ave_behavior_feed.has_ave_event_type = true;
    m->ave_behavior_feed.ave_event_type = avt;
  }

  if (r->file_path[0]) {
    m->has_ave_behavior_feed = true;
    copy_str(m->ave_behavior_feed.target_path, sizeof(m->ave_behavior_feed.target_path), r->file_path);
    m->ave_behavior_feed.target_has_motw = (r->file_target_has_motw != 0u);
  }
  if (r->net_dst[0]) {
    m->has_ave_behavior_feed = true;
    copy_str(m->ave_behavior_feed.target_ip, sizeof(m->ave_behavior_feed.target_ip), r->net_dst);
    m->ave_behavior_feed.target_port = r->net_dport;
  }
  if (r->dns_query[0]) {
    m->has_ave_behavior_feed = true;
    copy_str(m->ave_behavior_feed.target_domain, sizeof(m->ave_behavior_feed.target_domain), r->dns_query);
  }
  if (r->reg_key_path[0]) {
    m->has_ave_behavior_feed = true;
    copy_str(m->ave_behavior_feed.target_path, sizeof(m->ave_behavior_feed.target_path), r->reg_key_path);
  }
  if (r->cert_revoked_ancestor != 0u) {
    m->has_ave_behavior_feed = true;
    m->ave_behavior_feed.cert_revoked_ancestor = true;
  }
  if (r->type == EDR_EVENT_PROTOCOL_SHELLCODE) {
    float score = pmfe_detail_f(r->script_snippet, "score");
    if (score > 0.f) {
      m->has_ave_behavior_feed = true;
      m->ave_behavior_feed.shellcode_score = score;
    }
  } else if (r->type == EDR_EVENT_WEBSHELL_DETECTED) {
    float score = pmfe_detail_f(r->script_snippet, "score");
    if (score > 0.f) {
      m->has_ave_behavior_feed = true;
      m->ave_behavior_feed.webshell_score = score;
    }
  }
  fill_pmfe_cross_engine_fields(m, r);
}

static void fill_oneof_detail(edr_v1_BehaviorEvent *m, const EdrBehaviorRecord *r) {
  m->which_detail = 0;
  memset(&m->detail, 0, sizeof(m->detail));

  if (r->dns_query[0]) {
    m->which_detail = edr_v1_BehaviorEvent_dns_tag;
    copy_str(m->detail.dns.query_name, sizeof(m->detail.dns.query_name), r->dns_query);
    return;
  }
  if (r->reg_key_path[0] || r->reg_value_name[0] || r->reg_value_data[0] || r->reg_op[0]) {
    m->which_detail = edr_v1_BehaviorEvent_registry_tag;
    copy_str(m->detail.registry.key_path, sizeof(m->detail.registry.key_path), r->reg_key_path);
    copy_str(m->detail.registry.value_name, sizeof(m->detail.registry.value_name), r->reg_value_name);
    copy_str(m->detail.registry.value_data, sizeof(m->detail.registry.value_data), r->reg_value_data);
    copy_str(m->detail.registry.operation, sizeof(m->detail.registry.operation), r->reg_op);
    return;
  }
  if (r->net_dst[0] || r->net_src[0]) {
    m->which_detail = edr_v1_BehaviorEvent_network_tag;
    copy_str(m->detail.network.src_ip, sizeof(m->detail.network.src_ip), r->net_src);
    m->detail.network.src_port = r->net_sport;
    copy_str(m->detail.network.dst_ip, sizeof(m->detail.network.dst_ip), r->net_dst);
    m->detail.network.dst_port = r->net_dport;
    copy_str(m->detail.network.protocol, sizeof(m->detail.network.protocol), r->net_proto);
    return;
  }
  if (r->file_path[0] || r->file_op[0]) {
    m->which_detail = edr_v1_BehaviorEvent_file_tag;
    copy_str(m->detail.file.operation, sizeof(m->detail.file.operation), r->file_op);
    copy_str(m->detail.file.target_path, sizeof(m->detail.file.target_path), r->file_path);
    m->detail.file.file_size = 0;
    m->detail.file.target_has_motw = (r->file_target_has_motw != 0u);
    return;
  }
  if (r->script_snippet[0]) {
    m->which_detail = edr_v1_BehaviorEvent_script_tag;
    copy_str(m->detail.script.snippet, sizeof(m->detail.script.snippet), r->script_snippet);
    return;
  }
  if (r->parent_name[0] || r->parent_path[0]) {
    m->which_detail = edr_v1_BehaviorEvent_process_tag;
    copy_str(m->detail.process.parent_name, sizeof(m->detail.process.parent_name),
             r->parent_name);
    copy_str(m->detail.process.parent_path, sizeof(m->detail.process.parent_path),
             r->parent_path);
    copy_str(m->detail.process.integrity_level, sizeof(m->detail.process.integrity_level),
             r->integrity_level);
    /* 取证增强字段：端侧已采集，补齐上报（服务端 pbwire 按字段号 4-10 接住落库）。 */
    copy_str(m->detail.process.parent_cmdline, sizeof(m->detail.process.parent_cmdline),
             r->parent_cmdline);
    copy_str(m->detail.process.current_directory, sizeof(m->detail.process.current_directory),
             r->current_directory);
    copy_str(m->detail.process.process_creation_time, sizeof(m->detail.process.process_creation_time),
             r->process_creation_time);
    m->detail.process.token_elevation = r->token_elevation;
    m->detail.process.grandparent_pid = r->grandparent_pid;
    copy_str(m->detail.process.grandparent_name, sizeof(m->detail.process.grandparent_name),
             r->grandparent_name);
    copy_str(m->detail.process.grandparent_path, sizeof(m->detail.process.grandparent_path),
             r->grandparent_path);
    return;
  }
}

size_t edr_behavior_record_encode_protobuf(const EdrBehaviorRecord *r, uint8_t *out,
                                           size_t out_cap) {
  if (!r || !out || out_cap < 16u) {
    return 0;
  }

  edr_v1_BehaviorEvent msg;
  memset(&msg, 0, sizeof(msg));

  copy_str(msg.event_id, sizeof(msg.event_id), r->event_id);
  copy_str(msg.endpoint_id, sizeof(msg.endpoint_id), r->endpoint_id);
  copy_str(msg.tenant_id, sizeof(msg.tenant_id), r->tenant_id);
  msg.type = (int32_t)r->type;
  msg.event_time_ns = r->event_time_ns;
  msg.pid = r->pid;
  msg.ppid = r->ppid;
  copy_str(msg.process_name, sizeof(msg.process_name), r->process_name);
  copy_str(msg.cmdline, sizeof(msg.cmdline), r->cmdline);
  copy_str(msg.exe_hash, sizeof(msg.exe_hash), r->exe_hash);
  copy_str(msg.exe_path, sizeof(msg.exe_path), r->exe_path);
  copy_str(msg.username, sizeof(msg.username), r->username);
  copy_str(msg.domain, sizeof(msg.domain), r->domain);
  copy_str(msg.user_sid, sizeof(msg.user_sid), r->user_sid);
  copy_str(msg.logon_id, sizeof(msg.logon_id), r->logon_id);
  copy_str(msg.creator_username, sizeof(msg.creator_username), r->creator_username);
  copy_str(msg.creator_domain, sizeof(msg.creator_domain), r->creator_domain);
  copy_str(msg.creator_sid, sizeof(msg.creator_sid), r->creator_sid);
  copy_str(msg.creator_logon_id, sizeof(msg.creator_logon_id), r->creator_logon_id);
  copy_str(msg.identity_source, sizeof(msg.identity_source), r->identity_source);
  copy_str(msg.identity_quality, sizeof(msg.identity_quality), r->identity_quality);
  msg.session_id = r->session_id;
  if (r->detection_context[0]) {
    copy_str(msg.ave_result_json, sizeof(msg.ave_result_json), r->detection_context);
  } else if (r->pmfe_snapshot[0]) {
    copy_str(msg.ave_result_json, sizeof(msg.ave_result_json), r->pmfe_snapshot);
  } else {
    copy_str(msg.ave_result_json, sizeof(msg.ave_result_json), "");
  }
  msg.priority = r->priority;

  fill_oneof_detail(&msg, r);
  fill_ave_behavior_feed(&msg, r);

  msg.mitre_ttps_count = 0;
  if (r->mitre_ttp_count > 0) {
    int n = r->mitre_ttp_count;
    if (n > 8) {
      n = 8;
    }
    msg.mitre_ttps_count = (pb_size_t)n;
    for (int i = 0; i < n; i++) {
      copy_str(msg.mitre_ttps[i], sizeof(msg.mitre_ttps[i]), r->mitre_ttps[i]);
    }
  }

  pb_ostream_t stream = pb_ostream_from_buffer(out, out_cap);
  if (!pb_encode(&stream, edr_v1_BehaviorEvent_fields, &msg)) {
    return 0;
  }
  return stream.bytes_written;
}

#ifdef EDR_HAVE_NANOPB
size_t edr_behavior_alert_encode_protobuf(const AVEBehaviorAlert *a, const char *endpoint_id,
                                          const char *tenant_id, uint8_t *out, size_t out_cap) {
  if (!a || !out || out_cap < edr_v1_BehaviorEvent_size) {
    return 0;
  }
  edr_v1_BehaviorEvent msg;
  memset(&msg, 0, sizeof(msg));

  snprintf(msg.event_id, sizeof(msg.event_id), "bahv_%lld_%u", (long long)a->timestamp_ns,
           (unsigned)a->pid);
  copy_str(msg.endpoint_id, sizeof(msg.endpoint_id), endpoint_id ? endpoint_id : "");
  copy_str(msg.tenant_id, sizeof(msg.tenant_id), tenant_id ? tenant_id : "");
  msg.type = (int32_t)EDR_EVENT_BEHAVIOR_ONNX_ALERT;
  msg.event_time_ns = a->timestamp_ns;
  msg.pid = a->pid;
  msg.ppid = a->ppid;
  copy_str(msg.process_name, sizeof(msg.process_name), a->process_name[0] ? a->process_name : "");
  copy_str(msg.cmdline, sizeof(msg.cmdline), a->cmdline[0] ? a->cmdline : "");
  copy_str(msg.exe_path, sizeof(msg.exe_path), a->process_path[0] ? a->process_path : "");
  msg.priority = 0u;

  msg.has_behavior_alert = true;
  msg.behavior_alert.anomaly_score = a->anomaly_score;
  msg.behavior_alert.tactic_probs_count = 14;
  for (int i = 0; i < 14; i++) {
    msg.behavior_alert.tactic_probs[i] = a->tactic_probs[i];
  }
  copy_str(msg.behavior_alert.triggered_tactics, sizeof(msg.behavior_alert.triggered_tactics),
           a->triggered_tactics[0] ? a->triggered_tactics : "");
  msg.behavior_alert.skip_ai_analysis = a->skip_ai_analysis;
  msg.behavior_alert.needs_l2_review = a->needs_l2_review;
  msg.behavior_alert.timestamp_ns = a->timestamp_ns;
  msg.behavior_alert.pid = a->pid;
  copy_str(msg.behavior_alert.process_name, sizeof(msg.behavior_alert.process_name),
           a->process_name[0] ? a->process_name : "");
  copy_str(msg.behavior_alert.process_path, sizeof(msg.behavior_alert.process_path),
           a->process_path[0] ? a->process_path : "");
  copy_str(msg.behavior_alert.related_iocs_json, sizeof(msg.behavior_alert.related_iocs_json),
           a->related_iocs_json[0] ? a->related_iocs_json : "");
  copy_str(msg.behavior_alert.user_subject_json, sizeof(msg.behavior_alert.user_subject_json),
           a->user_subject_json[0] ? a->user_subject_json : "");
  msg.behavior_alert.ppid = a->ppid;
  copy_str(msg.behavior_alert.cmdline, sizeof(msg.behavior_alert.cmdline),
           a->cmdline[0] ? a->cmdline : "");

  pb_ostream_t stream = pb_ostream_from_buffer(out, out_cap);
  if (!pb_encode(&stream, edr_v1_BehaviorEvent_fields, &msg)) {
    return 0;
  }
  return stream.bytes_written;
}
#else
size_t edr_behavior_alert_encode_protobuf(const AVEBehaviorAlert *a, const char *endpoint_id,
                                          const char *tenant_id, uint8_t *out, size_t out_cap) {
  (void)a;
  (void)endpoint_id;
  (void)tenant_id;
  (void)out;
  (void)out_cap;
  return 0;
}
#endif
