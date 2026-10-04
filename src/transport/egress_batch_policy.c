#include "edr/egress_batch_policy.h"
#include "edr/ave_behavior_gates.h"
#include "edr/transport_sink.h"
#include "edr/types.h"
#include "edr/v1/event.pb.h"
#include "cJSON.h"
#include <pb_common.h>
#include <pb_decode.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef EDR_HAVE_LZ4
#include "lz4.h"
#endif

static int deny(char *reason, size_t cap, const char *value) {
  if (reason && cap) snprintf(reason, cap, "%s", value);
  return 0;
}
static uint32_t u32(const uint8_t *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8u |
      (uint32_t)p[2] << 16u | (uint32_t)p[3] << 24u;
}

/* nanopb normally skips unknown tags. An egress whitelist must instead reject
 * them, recursively, rather than transmitting opaque fields it cannot own. */
static int schema_known(pb_istream_t *stream, const pb_msgdesc_t *desc, unsigned depth) {
  uint32_t seen[128]; size_t count = 0; int oneof_seen = 0;
  if (depth > 12) return 0;
  while (stream->bytes_left) {
    pb_wire_type_t wire; uint32_t tag; bool eof; pb_field_iter_t field;
    if (!pb_decode_tag(stream, &wire, &tag, &eof) || eof ||
        !pb_field_iter_begin(&field, desc, NULL) || !pb_field_iter_find(&field, tag)) return 0;
    if (PB_HTYPE(field.type) == PB_HTYPE_ONEOF && oneof_seen++) return 0;
    if (PB_HTYPE(field.type) != PB_HTYPE_REPEATED) {
      for (size_t i = 0; i < count; i++) if (seen[i] == tag) return 0;
      if (count == sizeof(seen)/sizeof(seen[0])) return 0;
      seen[count++] = tag;
    }
    if (field.submsg_desc) {
      pb_istream_t sub;
      if (wire != PB_WT_STRING || !pb_make_string_substream(stream, &sub) ||
          !schema_known(&sub, field.submsg_desc, depth + 1u) ||
          !pb_close_string_substream(stream, &sub)) return 0;
    } else if (PB_LTYPE(field.type) == PB_LTYPE_STRING) {
      pb_istream_t sub; uint8_t chunk[256];
      if (wire != PB_WT_STRING || !pb_make_string_substream(stream,&sub)) return 0;
      while(sub.bytes_left) {
        size_t n=sub.bytes_left<sizeof(chunk)?sub.bytes_left:sizeof(chunk);
        if(!pb_read(&sub,chunk,n) || memchr(chunk,0,n)) return 0;
      }
      if(!pb_close_string_substream(stream,&sub)) return 0;
    } else if (!pb_skip_field(stream, wire)) return 0;
  }
  return 1;
}

static int json_unique(const cJSON *value, unsigned depth) {
  if (!value || depth > 12) return 0;
  const cJSON *a;
  cJSON_ArrayForEach(a, value) {
    if (cJSON_IsObject(value)) {
      if (!a->string) return 0;
      for (const cJSON *b = a->next; b; b = b->next)
        if (b->string && !strcmp(a->string, b->string)) return 0;
    }
    if ((cJSON_IsObject(a) || cJSON_IsArray(a)) && !json_unique(a, depth + 1u)) return 0;
  }
  return 1;
}
static cJSON *document(const char *text) {
  /* cJSON exposes C strings; escaped zero would hide a suffix from field
   * checks while the original wire still carries it. */
  for (const char *p=text; *p; p++) {
    if (*p!='\\') continue;
    p++;
    if (!*p) return NULL;
    if (*p=='u' && !strncmp(p+1,"0000",4)) return NULL;
  }
  cJSON *out = cJSON_ParseWithOpts(text, NULL, 1);
  if ((!cJSON_IsObject(out) && !cJSON_IsArray(out)) || !json_unique(out, 0)) { cJSON_Delete(out); return NULL; }
  return out;
}
static cJSON *object(const char *text) {
  cJSON *out=document(text);
  if (!cJSON_IsObject(out)) { cJSON_Delete(out); return NULL; }
  return out;
}
static const char *string(const cJSON *root, const char *key) {
  const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, key);
  return cJSON_IsString(v) && v->valuestring ? v->valuestring : "";
}
static int same(const cJSON *root, const char *key, const char *value) {
  const char *s = string(root, key);
  return s[0] && value && value[0] && !strcmp(s, value);
}
static int unit_signal(const cJSON *root, const char *key) {
  const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, key);
  return cJSON_IsNumber(v) && isfinite(v->valuedouble) &&
      v->valuedouble > 0 && v->valuedouble <= 1;
}
static int count_signal(const cJSON *root, const char *key) {
  const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, key);
  return cJSON_IsNumber(v) && isfinite(v->valuedouble) &&
      v->valuedouble > 0 && v->valuedouble <= UINT32_MAX && floor(v->valuedouble) == v->valuedouble;
}
static int equal_uint(const cJSON *root, const char *key, uint32_t n) {
  const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, key);
  return cJSON_IsNumber(v) && n && v->valuedouble == (double)n;
}
static int hash(const char *s) {
  if (strlen(s) != 64) return 0;
  for (size_t i=0; i<64; i++)
    if (!((s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f') ||
          (s[i]>='A' && s[i]<='F'))) return 0;
  return 1;
}
static int timestamp_equal(const cJSON *root, const char *key, int64_t timestamp) {
  char expected[32]; snprintf(expected,sizeof(expected),"%lld",(long long)timestamp);
  return same(root,key,expected);
}
static int basis_valid(const edr_v1_BehaviorEvent *ev, const cJSON *basis, const char *owner) {
  return same(basis,"schema","agent_detection_basis_v1") && same(basis,"owner",owner) &&
      cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(basis,"predicate_matched")) &&
      equal_uint(basis,"pid",ev->pid) && timestamp_equal(basis,"timestamp_ns",ev->event_time_ns);
}

/* JSON carried inside known protobuf strings is not an opaque extension
 * channel. Admit the current owner's declared members; retain unknown future
 * versions locally for compatibility review. Payloads are never rewritten. */
static int keys_allowed(const cJSON *root, const char *keys) {
  if (!cJSON_IsObject(root)) return 0;
  const cJSON *v;
  cJSON_ArrayForEach(v,root) {
    int known=0;
    for (const char *p=keys; *p;) {
      const char *end=strchr(p,'|'); size_t n=end?(size_t)(end-p):strlen(p);
      if (v->string && strlen(v->string)==n && !memcmp(v->string,p,n)) known=1;
      p=end?end+1:p+n;
    }
    if (!known) return 0;
  }
  return 1;
}
static int optional_keys(const cJSON *root,const char *key,const char *keys) {
  const cJSON *v=cJSON_GetObjectItemCaseSensitive(root,key);
  return !v || keys_allowed(v,keys);
}

static int dynamic_alert(const edr_v1_BehaviorEvent *ev, const cJSON *subject) {
  const cJSON *ctx = cJSON_GetObjectItemCaseSensitive(subject, "context");
  if (!keys_allowed(subject,"subject_type|rule_id|rules_bundle_version|rules_bundle_sha256|display_title|context|enforcement") ||
      !keys_allowed(ctx,"pid|ppid|process_name|process_path|canonical_image_path|process_start_key|process_creation_filetime_100ns|file_identity|cmdline|exe_hash|exe_path_hash|parent_name|parent_path|parent_cmdline|grandparent_pid|grandparent_name|username|process_chain_depth|endpoint_id|tenant_id|event_type|hostname|domain|user_sid|logon_id|creator_username|creator_domain|creator_sid|creator_logon_id|identity_source|identity_quality|source_event_id|current_directory|logon_time_ns|integrity_level|token_elevation|process_creation_time|parent_creation_time|child_pids|powershell_script_block|command_line_origin|encoded_command_type|registry_source|registry_attribution|registry_detail_status|registry_old_data|context_degraded|context_error") ||
      !optional_keys(subject,"enforcement","requested|attempted|succeeded|action|error_code|message")) return 0;
  /* A matched authenticated bundle, a real rule and the exact captured
   * source tuple are jointly required. Priority, score and display labels
   * play no role in establishing this identity. */
  return string(subject, "rule_id")[0] && string(subject, "rules_bundle_version")[0] &&
      hash(string(subject, "rules_bundle_sha256")) && cJSON_IsObject(ctx) &&
      same(ctx, "source_event_id", ev->event_id) && equal_uint(ctx, "pid", ev->pid) &&
      equal_uint(ctx, "event_type", (uint32_t)ev->type) &&
      same(ctx, "endpoint_id", ev->endpoint_id) && same(ctx, "tenant_id", ev->tenant_id);
}
static int engine_alert(const edr_v1_BehaviorEvent *ev, const cJSON *subject) {
  const cJSON *basis=cJSON_GetObjectItemCaseSensitive(subject,"evaluation_basis");
  const cJSON *ctx = cJSON_GetObjectItemCaseSensitive(subject, "detection_context");
  const cJSON *process = cJSON_GetObjectItemCaseSensitive(ctx, "process");
  const cJSON *signals = cJSON_GetObjectItemCaseSensitive(ctx, "engine_signals");
  const char *engine = string(ctx, "engine"), *rule = string(ctx, "rule_id");
  const cJSON *threshold=cJSON_GetObjectItemCaseSensitive(basis,"threshold");
  const cJSON *flags=cJSON_GetObjectItemCaseSensitive(basis,"behavior_flags");
  if (!keys_allowed(subject,"subject_type|evaluation_basis|detection_context") ||
      !keys_allowed(basis,"schema|owner|predicate_matched|threshold_met|pid|timestamp_ns|threshold|event_count|behavior_flags|last_event_type") ||
      !keys_allowed(ctx,"engine|rule_id|confidence|process|file|network|policy_version|engine_signals|suppression|recommended_forensics|context_degraded|projection_omissions|omission_source") ||
      !keys_allowed(process,"pid|name|path|parent_pid|cmdline") ||
      !keys_allowed(signals,"shellcode_score|webshell_score|pmfe_confidence|pmfe_dns_tunnel|pmfe_pe_found|script_content_score|tls_anomaly_score|ransom_counter_score|script_block_present|amsi_content_present|ja3_anomaly|sni_anomaly|cert_anomaly|suspicious_extension_burst|shadow_copy_delete|ioc_ip_hit|ioc_domain_hit|ioc_sha256_hit") ||
      !optional_keys(ctx,"file","path|sha256|signed|signature_status") ||
      !optional_keys(ctx,"network","remote_ip|remote_url|dst_port") ||
      !optional_keys(ctx,"suppression","applied|policy_version")) return 0;
  if (!basis_valid(ev,basis,"ave_behavior_pipeline") ||
      !cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(basis,"threshold_met")) ||
      !unit_signal(basis,"threshold") || !count_signal(basis,"event_count") ||
      fabs(threshold->valuedouble-(double)EDR_AVE_BEH_SCORE_HIGH)>0.000001 ||
      !cJSON_IsNumber(flags) || flags->valuedouble<0 || flags->valuedouble>UINT32_MAX ||
      floor(flags->valuedouble)!=flags->valuedouble ||
      ev->behavior_alert.anomaly_score+0.000001 < threshold->valuedouble ||
      !equal_uint(process, "pid", ev->pid) || !cJSON_IsObject(signals)) return 0;
  if (!((!strcmp(engine,"pmfe") && !strcmp(rule,"pmfe_signal")) ||
        (!strcmp(engine,"shellcode") && !strcmp(rule,"shellcode_signal")) ||
        (!strcmp(engine,"webshell") && !strcmp(rule,"webshell_signal")) ||
        (!strcmp(engine,"ave") && !strcmp(rule,"behavior_anomaly")))) return 0;
  /* AVE's current detector uses the accumulated behavior window. Capture the
   * actual predicate and contributing count at its owner, including alerts
   * without MITRE labels, rather than pretending engine hints are rule hits. */
  const cJSON *last=cJSON_GetObjectItemCaseSensitive(basis,"last_event_type");
  if (!cJSON_IsNumber(last) || last->valuedouble<0 || last->valuedouble>13 ||
      floor(last->valuedouble)!=last->valuedouble) return 0;
  return (!strcmp(engine,"pmfe") && last->valuedouble==13) ||
      (!strcmp(engine,"shellcode") && last->valuedouble==11) ||
      (!strcmp(engine,"webshell") && last->valuedouble==12) ||
      (!strcmp(engine,"ave") && last->valuedouble<=10);
}
/* Typed positive engine findings can be a detection source even without an
 * embedded BehaviorAlert. A follow-up ID alone cannot prove the original
 * alert association: legacy clean follow-ups remain local pending a durable
 * association owner, rather than authorizing arbitrary clean process data. */
static int standalone_engine(const edr_v1_BehaviorEvent *ev, const cJSON *ctx) {
  const cJSON *process=cJSON_GetObjectItemCaseSensitive(ctx,"process");
  const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence");
  const cJSON *signals=cJSON_GetObjectItemCaseSensitive(engine,"signals");
  if (!same(ctx,"rule_id","agent_decision_v1") || !equal_uint(process,"pid",ev->pid) ||
      !ev->event_id[0] || !ev->endpoint_id[0] || !ev->tenant_id[0] || ev->event_time_ns<=0) return 0;
  if (ev->type == EDR_EVENT_PMFE_SCAN_RESULT && same(engine,"schema","pmfe_result_v1") &&
      same(engine,"detector","pmfe")) {
    const char *status=string(engine,"status"), *verdict=string(engine,"verdict");
    if ((strcmp(status,"completed_clean") && strcmp(status,"completed_suspicious") &&
         strcmp(status,"partial") && strcmp(status,"failed")) ||
        (strcmp(verdict,"clean") && strcmp(verdict,"inconclusive") && strcmp(verdict,"suspicious"))) return 0;
    if ((!strcmp(status,"completed_clean") && strcmp(verdict,"clean")) ||
        (!strcmp(status,"completed_suspicious") && strcmp(verdict,"suspicious"))) return 0;
    if (strcmp(verdict,"suspicious")) return 0;
    static const char *const counts[]={"stomp_suspicious","dns_hits","memfd_exec","deleted_exec",
      "private_exec_image_hits","private_exec_thread_starts"};
    for (size_t i=0;i<sizeof(counts)/sizeof(counts[0]);i++) if(count_signal(signals,counts[i])) return 1;
    return unit_signal(signals,"ave_max_score") ||
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(signals,"injection_observed"));
  }
  const cJSON *detection=cJSON_GetObjectItemCaseSensitive(engine,"detection");
  if (ev->type == EDR_EVENT_PROTOCOL_SHELLCODE && same(engine,"schema","shellcode_result_v1")) {
    const cJSON *owner=cJSON_GetObjectItemCaseSensitive(engine,"owner");
    const cJSON *payload=cJSON_GetObjectItemCaseSensitive(engine,"payload");
    return equal_uint(owner,"pid",ev->pid) && string(engine,"alert_id")[0] &&
      string(detection,"detector")[0] && string(detection,"rule")[0] &&
      hash(string(payload,"sha256")) && unit_signal(detection,"score");
  }
  if (ev->type == EDR_EVENT_WEBSHELL_DETECTED && same(engine,"schema","webshell_result_v1")) {
    const cJSON *file=cJSON_GetObjectItemCaseSensitive(engine,"file");
    return string(detection,"detector")[0] && string(detection,"rule")[0] &&
      string(file,"path")[0] && hash(string(file,"sha256")) && unit_signal(detection,"score");
  }
  return 0;
}
static int correlation_alert(const edr_v1_BehaviorEvent *ev, const cJSON *subject) {
  const cJSON *basis=cJSON_GetObjectItemCaseSensitive(subject,"evaluation_basis");
  const cJSON *threshold=cJSON_GetObjectItemCaseSensitive(basis,"threshold");
  const cJSON *matched=cJSON_GetObjectItemCaseSensitive(basis,"matched_count");
  const cJSON *chain = cJSON_GetObjectItemCaseSensitive(subject, "evidence_chain"), *item;
  if (!keys_allowed(subject,"subject_type|rule_id|rules_bundle_version|display_title|evaluation_basis|window_ms|count|distinct|evidence_chain") ||
      !keys_allowed(basis,"schema|owner|predicate_matched|pid|timestamp_ns|kind|threshold|matched_count|window_ms|ordered")) return 0;
  if (!basis_valid(ev,basis,"correlation_engine") || !count_signal(basis,"threshold") ||
      !count_signal(basis,"matched_count") || matched->valuedouble<threshold->valuedouble ||
      (strcmp(string(basis,"kind"),"sequence") && strcmp(string(basis,"kind"),"threshold")) ||
      !string(subject,"rule_id")[0] || !string(subject,"rules_bundle_version")[0] ||
      !count_signal(subject,"window_ms") || !count_signal(subject,"count") ||
      !cJSON_IsArray(chain) || cJSON_GetArraySize(chain) < 1) return 0;
  int bound = 0;
  cJSON_ArrayForEach(item,chain) {
    if (!keys_allowed(item,"type|pid|event_time_ns|detail") || !count_signal(item,"type") || !count_signal(item,"pid") ||
        !string(item,"event_time_ns")[0]) return 0;
    if (equal_uint(item,"pid",ev->pid)) bound = 1;
  }
  return bound;
}
static int alert_valid(const edr_v1_BehaviorEvent *ev) {
  const edr_v1_BehaviorAlert *a = &ev->behavior_alert;
  if (!ev->has_behavior_alert || !ev->event_id[0] || !ev->endpoint_id[0] ||
      !ev->tenant_id[0] || !ev->pid || ev->event_time_ns <= 0 ||
      a->pid != ev->pid || a->timestamp_ns != ev->event_time_ns ||
      !isfinite(a->anomaly_score) || a->anomaly_score <= 0 || a->anomaly_score > 1 ||
      (!a->triggered_tactics[0] && !a->user_subject_json[0])) return 0;
  for (pb_size_t i=0;i<a->tactic_probs_count;i++)
    if (!isfinite(a->tactic_probs[i]) || a->tactic_probs[i]<0 || a->tactic_probs[i]>1) return 0;
  cJSON *subject = object(a->user_subject_json);
  const char *type = string(subject,"subject_type");
  if (a->related_iocs_json[0] && strcmp(type,"net_fanout")) {
    cJSON *iocs=document(a->related_iocs_json); const cJSON *item;
    int known=cJSON_IsArray(iocs) && cJSON_GetArraySize(iocs)<=3;
    cJSON_ArrayForEach(item,iocs) {
      const char *kind=string(item,"type");
      if (!keys_allowed(item,"type|value|source") || !same(item,"source","endpoint_ioc") ||
          !string(item,"value")[0] || (strcmp(kind,"ip") && strcmp(kind,"domain") && strcmp(kind,"sha256"))) known=0;
    }
    cJSON_Delete(iocs);
    if (!known) { cJSON_Delete(subject); return 0; }
  }
  int allowed = (!strcmp(type,"edr_dynamic_rule") && dynamic_alert(ev,subject)) ||
      (!strcmp(type,"detection_context") && engine_alert(ev,subject)) ||
      (!strcmp(type,"edr_correlation") && correlation_alert(ev,subject));
  cJSON_Delete(subject);
  if (allowed) return 1;
  subject = object(a->user_subject_json);
  const cJSON *basis=cJSON_GetObjectItemCaseSensitive(subject,"evaluation_basis");
  const cJSON *threshold=cJSON_GetObjectItemCaseSensitive(basis,"threshold");
  const cJSON *distinct=cJSON_GetObjectItemCaseSensitive(basis,"distinct_ips");
  cJSON *fanout = object(a->related_iocs_json);
  allowed = same(subject,"subject_type","net_fanout") &&
      keys_allowed(subject,"subject_type|evaluation_basis") &&
      keys_allowed(basis,"schema|owner|predicate_matched|pid|timestamp_ns|threshold|distinct_ips|window_s|dport|source_event_id") &&
      keys_allowed(fanout,"detector|dport|distinct_ips|window_s") &&
      basis_valid(ev,basis,"net_fanout_detector") &&
      count_signal(basis,"threshold") && count_signal(basis,"distinct_ips") &&
      distinct->valuedouble>=threshold->valuedouble && string(basis,"source_event_id")[0] &&
      same(fanout,"detector","net_fanout") && count_signal(fanout,"dport") &&
      cJSON_GetObjectItemCaseSensitive(fanout,"dport")->valuedouble<=65535 &&
      count_signal(fanout,"window_s") && count_signal(fanout,"distinct_ips") &&
      cJSON_GetObjectItemCaseSensitive(fanout,"distinct_ips")->valuedouble==distinct->valuedouble &&
      equal_uint(basis,"dport",(uint32_t)cJSON_GetObjectItemCaseSensitive(fanout,"dport")->valuedouble) &&
      equal_uint(basis,"window_s",(uint32_t)cJSON_GetObjectItemCaseSensitive(fanout,"window_s")->valuedouble);
  cJSON_Delete(subject);
  cJSON_Delete(fanout);
  return allowed;
}

int edr_egress_frame_validate(const uint8_t *frame, size_t len, char *reason, size_t cap) {
  if (!frame || !len || len > EDR_EGRESS_FRAME_MAX) return deny(reason,cap,"frame_size_invalid");
  pb_istream_t stream = pb_istream_from_buffer(frame,len);
  if (!schema_known(&stream,edr_v1_BehaviorEvent_fields,0)) return deny(reason,cap,"unknown_or_invalid_event_schema");
  edr_v1_BehaviorEvent *ev = calloc(1,sizeof(*ev));
  if (!ev) return deny(reason,cap,"egress_validation_allocation_failed");
  stream = pb_istream_from_buffer(frame,len);
  if (!pb_decode(&stream,edr_v1_BehaviorEvent_fields,ev)) {
    free(ev); return deny(reason,cap,"event_decode_failed");
  }
  switch ((EdrEventType)ev->type) {
    case EDR_EVENT_PROCESS_CREATE: case EDR_EVENT_PROCESS_TERMINATE:
    case EDR_EVENT_PROCESS_INJECT: case EDR_EVENT_DLL_LOAD: case EDR_EVENT_THREAD_CREATE_REMOTE:
    case EDR_EVENT_FILE_READ: case EDR_EVENT_FILE_CREATE: case EDR_EVENT_FILE_WRITE:
    case EDR_EVENT_FILE_DELETE: case EDR_EVENT_FILE_RENAME: case EDR_EVENT_FILE_PERMISSION_CHANGE:
    case EDR_EVENT_NET_CONNECT: case EDR_EVENT_NET_LISTEN: case EDR_EVENT_NET_DNS_QUERY:
    case EDR_EVENT_NET_TLS_HANDSHAKE: case EDR_EVENT_REG_CREATE_KEY: case EDR_EVENT_REG_SET_VALUE:
    case EDR_EVENT_REG_DELETE_KEY: case EDR_EVENT_SCRIPT_POWERSHELL: case EDR_EVENT_SCRIPT_BASH:
    case EDR_EVENT_SCRIPT_PYTHON: case EDR_EVENT_SCRIPT_WMI: case EDR_EVENT_AUTH_LOGIN:
    case EDR_EVENT_AUTH_LOGOUT: case EDR_EVENT_AUTH_FAILED: case EDR_EVENT_AUTH_PRIVILEGE_ESC:
    case EDR_EVENT_SERVICE_CREATE: case EDR_EVENT_SCHEDULED_TASK_CREATE: case EDR_EVENT_DRIVER_LOAD:
    case EDR_EVENT_PROTOCOL_SHELLCODE: case EDR_EVENT_WEBSHELL_DETECTED:
    case EDR_EVENT_FIREWALL_RULE_CHANGE: case EDR_EVENT_PMFE_SCAN_RESULT:
    case EDR_EVENT_BEHAVIOR_ONNX_ALERT: break;
    default: free(ev); return deny(reason,cap,"event_purpose_unknown");
  }
  cJSON *ctx = object(ev->ave_result_json);
  if (ev->ave_result_json[0] && !ctx) {
    free(ev); return deny(reason,cap,"detection_context_invalid");
  }
  int source_only = !strcmp(string(ctx,"p0_disposition"),"NOT_EVALUABLE");
  if (ctx && !source_only && !keys_allowed(ctx,"engine|event_type|rule_id|confidence|suppressed|reason|event_quality|process|file|network|registry|signals|ransom_control|suppression|detection_profile|detection_trigger|engine_evidence|recommended_forensics|evidence|evidence_complete|omitted_fields|omission_sources|invalid_fields|projection_limited|schema|context_error")) {
    cJSON_Delete(ctx); free(ev); return deny(reason,cap,"detection_context_fields_unknown");
  }
  int valid = !source_only && (alert_valid(ev) || standalone_engine(ev,ctx));
  cJSON_Delete(ctx);
  free(ev);
  if (!valid) return deny(reason,cap,source_only ? "source_only_requires_local_owner_v3" : "alert_provenance_unavailable");
  if (reason && cap) snprintf(reason,cap,"validated_alert");
  return 1;
}

int edr_egress_batch_validate(const uint8_t *header, size_t header_len,
    const uint8_t *payload, size_t len, char *reason, size_t cap) {
  if (!header || header_len != 12 || !payload || !len || len > EDR_EGRESS_BATCH_MAX)
    return deny(reason,cap,"batch_size_invalid");
  uint32_t magic = u32(header), frames=u32(header+4), raw_len=u32(header+8);
  if (!frames || frames>EDR_EGRESS_FRAME_COUNT_MAX || !raw_len || raw_len>EDR_EGRESS_BATCH_MAX)
    return deny(reason,cap,"batch_limits_invalid");
  uint8_t *raw = NULL; const uint8_t *data = payload;
  if (magic == EDR_TRANSPORT_BATCH_MAGIC_RAW) {
    if (raw_len != len) return deny(reason,cap,"batch_length_mismatch");
  } else if (magic == EDR_TRANSPORT_BATCH_MAGIC_LZ4) {
#ifdef EDR_HAVE_LZ4
    raw = malloc(raw_len);
    if (!raw) return deny(reason,cap,"egress_validation_allocation_failed");
    int decoded = LZ4_decompress_safe((const char *)payload,(char *)raw,(int)len,(int)raw_len);
    if (decoded != (int)raw_len) { free(raw); return deny(reason,cap,"compressed_batch_invalid"); }
    data = raw;
#else
    return deny(reason,cap,"compressed_batch_decoder_unavailable");
#endif
  } else return deny(reason,cap,"unknown_batch_format");
  size_t offset = 0;
  for (uint32_t i=0; i<frames; i++) {
    if (raw_len-offset < 4) { free(raw); return deny(reason,cap,"frame_count_mismatch"); }
    uint32_t frame_len=u32(data+offset); offset += 4;
    if (frame_len>raw_len-offset) { free(raw); return deny(reason,cap,"frame_length_invalid"); }
    if (!edr_egress_frame_validate(data+offset,frame_len,reason,cap)) { free(raw); return 0; }
    offset += frame_len;
  }
  free(raw);
  if (offset != raw_len) return deny(reason,cap,"batch_trailing_bytes");
  if (reason && cap) snprintf(reason,cap,"validated_alert_batch");
  return 1;
}
