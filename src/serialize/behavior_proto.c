#include "edr/behavior_proto.h"

#include "edr/ave_sdk.h"
#include "edr/types.h"

#include "edr/v1/event.pb.h"
#include <pb_encode.h>

#include <stdio.h>
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
  case EDR_EVENT_FILE_READ:
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
  if (r->net_dst[0] || r->net_src[0] || r->network_aux_path[0]) {
    m->which_detail = edr_v1_BehaviorEvent_network_tag;
    copy_str(m->detail.network.src_ip, sizeof(m->detail.network.src_ip), r->net_src);
    m->detail.network.src_port = r->net_sport;
    copy_str(m->detail.network.dst_ip, sizeof(m->detail.network.dst_ip), r->net_dst);
    m->detail.network.dst_port = r->net_dport;
    copy_str(m->detail.network.protocol, sizeof(m->detail.network.protocol), r->net_proto);
    copy_str(m->detail.network.network_aux_path, sizeof(m->detail.network.network_aux_path),
             r->network_aux_path);
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
    copy_str(m->detail.process.integrity_level, sizeof(m->detail.process.integrity_level), "");
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
  msg.session_id = r->session_id;
  msg.process_chain_depth = r->process_chain_depth;
  if (r->pmfe_snapshot[0]) {
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
  copy_str(msg.process_name, sizeof(msg.process_name), a->process_name[0] ? a->process_name : "");
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
