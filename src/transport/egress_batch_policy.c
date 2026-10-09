#include "edr/egress_batch_policy.h"
#include "edr/ave_behavior_gates.h"
#include "edr/p0_terminal_identity.h"
#include "edr/transport_sink.h"
#include "edr/types.h"
#include "edr/evidence_projection.h"
#include "edr/parent_pid.h"
#include "edr/v1/event.pb.h"
#include "cJSON.h"
#include <pb_common.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
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
static void put_u32(uint8_t *p, uint32_t value) {
  for (unsigned i=0; i<4; i++) p[i]=(uint8_t)(value>>(8u*i));
}
static _Atomic(EdrEgressPmfeAssociationValidator) pmfe_validator;
static _Atomic(void*) pmfe_validator_user;
static _Atomic(EdrEgressPmfeReceiptHandler) pmfe_receipt_handler;
static _Atomic(void*) pmfe_receipt_user;
static _Atomic(EdrEgressPmfeReceiptHandler) pmfe_queue_removed_handler;
static _Atomic(void*) pmfe_queue_removed_user;
static _Atomic(EdrEgressP0PairValidator) p0_pair_validator;
static _Atomic(void*) p0_pair_user;
static _Atomic(EdrEgressRuleProjectionValidator) rule_projection_validator;
static _Atomic(void*) rule_projection_user;
void edr_egress_set_rule_projection_validator(EdrEgressRuleProjectionValidator validator,void *user) {
  if (!validator) { atomic_store_explicit(&rule_projection_validator,NULL,memory_order_release);return; }
  atomic_store_explicit(&rule_projection_user,user,memory_order_relaxed);
  atomic_store_explicit(&rule_projection_validator,validator,memory_order_release);
}
void edr_egress_set_pmfe_association_validator(
    EdrEgressPmfeAssociationValidator validator, void *user) {
  if (!validator) { atomic_store_explicit(&pmfe_validator,NULL,memory_order_release); return; }
  atomic_store_explicit(&pmfe_validator_user,user,memory_order_relaxed);
  atomic_store_explicit(&pmfe_validator,validator,memory_order_release);
}
void edr_egress_set_pmfe_receipt_handler(EdrEgressPmfeReceiptHandler handler,void *user) {
  if (!handler) { atomic_store_explicit(&pmfe_receipt_handler,NULL,memory_order_release); return; }
  atomic_store_explicit(&pmfe_receipt_user,user,memory_order_relaxed);
  atomic_store_explicit(&pmfe_receipt_handler,handler,memory_order_release);
}
void edr_egress_set_pmfe_queue_removed_handler(EdrEgressPmfeReceiptHandler handler,void *user) {
  if (!handler) { atomic_store_explicit(&pmfe_queue_removed_handler,NULL,memory_order_release); return; }
  atomic_store_explicit(&pmfe_queue_removed_user,user,memory_order_relaxed);
  atomic_store_explicit(&pmfe_queue_removed_handler,handler,memory_order_release);
}
void edr_egress_set_p0_pair_validator(EdrEgressP0PairValidator validator,void *user) {
  if (!validator) { atomic_store_explicit(&p0_pair_validator,NULL,memory_order_release); return; }
  atomic_store_explicit(&p0_pair_user,user,memory_order_relaxed);
  atomic_store_explicit(&p0_pair_validator,validator,memory_order_release);
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

/* These are purpose masks, shared by the producer projection and the final
 * immutable-byte gate. Every JSON leaf has a scalar type and a bound. Actor
 * display/command/parent facts already have typed protobuf owners and are
 * omitted from duplicate JSON; generation/file identity remain for the
 * current response consumer. Unknown nested members cannot hide raw events. */
typedef enum { JS_STRING, JS_BOOL, JS_UINT, JS_U64, JS_UNIT, JS_ENTROPY,
  JS_DECIMAL, JS_NULL_DECIMAL, JS_OBJECT, JS_OBJECT_ARRAY, JS_STRING_ARRAY } JsonKind;
typedef struct JsonField {
  const char *key; JsonKind kind; size_t bound;
  const struct JsonField *children; const char *values;
} JsonField;
#define S(k,n) {k,JS_STRING,n,NULL,NULL}
#define E(k,n,v) {k,JS_STRING,n,NULL,v}
#define B(k) {k,JS_BOOL,0,NULL,NULL}
#define U(k) {k,JS_UINT,UINT32_MAX,NULL,NULL}
#define P(k) {k,JS_UINT,65535,NULL,NULL}
#define F(k) {k,JS_UNIT,0,NULL,NULL}
#define D(k) {k,JS_DECIMAL,0,NULL,NULL}
#define ND(k) {k,JS_NULL_DECIMAL,0,NULL,NULL}
#define O(k,c) {k,JS_OBJECT,0,c,NULL}
#define A(k,n,c) {k,JS_OBJECT_ARRAY,n,c,NULL}
#define L(k,n,v) {k,JS_STRING_ARRAY,n,NULL,v}
#define END {NULL,JS_STRING,0,NULL,NULL}
#define DYNAMIC_CORE_FIELDS \
  U("pid"),U("event_type"),S("source_event_id",255),S("endpoint_id",255),S("tenant_id",255), \
  S("process_path",4096),S("canonical_image_path",4096), \
  ND("process_start_key"),ND("process_creation_filetime_100ns"),S("file_identity",255), \
  S("exe_path_hash",128),S("powershell_script_block",1024),S("command_line_origin",96), \
  S("encoded_command_type",64),S("registry_source",48),S("registry_attribution",32), \
  S("registry_detail_status",48),S("registry_old_data",1024),B("context_degraded"),S("context_error",128)
static const JsonField dynamic_context_fields[]={DYNAMIC_CORE_FIELDS,END};
/* The current paired P0 journal assigns its immutable wire/ACK identity before
 * sending. Its declared scalar source snapshot is retained only when the
 * entire exact terminal commitment is proven below. This is not a generic
 * JSON exception, and never applies to ordinary/source-only records. */
static const JsonField p0_journal_subject_context_fields[]={DYNAMIC_CORE_FIELDS,
  U("ppid"),S("process_name",256),S("cmdline",1024),S("exe_hash",128),
  S("parent_name",256),S("parent_path",4096),S("parent_cmdline",1024),
  U("grandparent_pid"),S("grandparent_name",256),S("username",256),U("process_chain_depth"),
  S("hostname",255),S("domain",256),S("user_sid",256),S("logon_id",64),
  S("creator_username",256),S("creator_domain",256),S("creator_sid",256),S("creator_logon_id",64),
  S("identity_source",32),S("identity_quality",32),S("current_directory",4096),
  {"logon_time_ns",JS_U64,0,NULL,NULL},S("integrity_level",64),U("token_elevation"),
  S("process_creation_time",64),S("parent_creation_time",64),S("child_pids",512),END};
#undef DYNAMIC_CORE_FIELDS
static const JsonField enforcement_fields[]={B("requested"),B("attempted"),B("succeeded"),
  S("action",64),U("error_code"),END};
static const JsonField dynamic_fields[]={E("subject_type",32,"edr_dynamic_rule"),
  S("rule_id",128),S("rules_bundle_version",255),S("rules_bundle_sha256",64),
  S("display_title",384),O("context",dynamic_context_fields),O("enforcement",enforcement_fields),END};
static const JsonField p0_journal_enforcement_fields[]={B("requested"),B("attempted"),B("succeeded"),
  S("action",64),U("error_code"),S("message",160),END};
/* New v2 terminals use the finite rule evidence context; legacy v0
 * journal frames retain their original closed schema and exact ownership. */
static const JsonField p0_projected_subject_fields[]={E("subject_type",32,"edr_dynamic_rule"),
  S("rule_id",128),S("rules_bundle_version",255),S("rules_bundle_sha256",64),S("display_title",384),
  O("context",dynamic_context_fields),O("enforcement",p0_journal_enforcement_fields),END};
static const JsonField p0_journal_subject_fields[]={E("subject_type",32,"edr_dynamic_rule"),
  S("rule_id",128),S("rules_bundle_version",255),S("rules_bundle_sha256",64),S("display_title",384),
  O("context",p0_journal_subject_context_fields),O("enforcement",p0_journal_enforcement_fields),END};
static const JsonField ave_basis_fields[]={E("schema",64,"agent_detection_basis_v1"),
  E("owner",48,"ave_behavior_pipeline"),B("predicate_matched"),B("tactic_probs_computed"),B("threshold_met"),
  U("pid"),D("timestamp_ns"),F("threshold"),U("event_count"),U("behavior_flags"),
  {"last_event_type",JS_UINT,13,NULL,NULL},END};
static const JsonField actor_json_fields[]={U("pid"),U("parent_pid"),END};
static const JsonField ave_signal_fields[]={F("shellcode_score"),F("webshell_score"),
  F("pmfe_confidence"),F("pmfe_dns_tunnel"),B("pmfe_pe_found"),F("script_content_score"),
  F("tls_anomaly_score"),F("ransom_counter_score"),B("script_block_present"),
  B("amsi_content_present"),B("ja3_anomaly"),B("sni_anomaly"),B("cert_anomaly"),
  B("suspicious_extension_burst"),B("shadow_copy_delete"),B("ioc_ip_hit"),
  B("ioc_domain_hit"),B("ioc_sha256_hit"),END};
static const JsonField file_json_fields[]={S("path",32768),S("sha256",64),B("signed"),
  E("signature_status",32,"unknown|signed|unsigned|valid|invalid|untrusted|revoked"),END};
/* remote_url is the SDK's captured target_domain[256] fact, including its
 * bounded diagnostic value. Do not reject a real alert at its ABI boundary. */
static const JsonField network_json_fields[]={S("remote_ip",64),S("remote_url",255),P("dst_port"),END};
static const JsonField suppression_fields[]={B("applied"),S("policy_version",128),END};
#define FORENSICS "process_tree|timeline_window|targeted_files|pmfe_scan|single_process_minidump_if_needed"
static const JsonField ave_context_fields[]={E("engine",32,"ave|pmfe|shellcode|webshell"),
  E("rule_id",64,"behavior_anomaly|pmfe_signal|shellcode_signal|webshell_signal"),F("confidence"),
  O("process",actor_json_fields),O("file",file_json_fields),O("network",network_json_fields),
  S("policy_version",128),O("engine_signals",ave_signal_fields),O("suppression",suppression_fields),
  L("recommended_forensics",5,FORENSICS),B("context_degraded"),
  L("projection_omissions",3,"process.name|process.path|process.cmdline"),
  E("omission_source",32,"behavior_alert_fields"),END};
static const JsonField ave_fields[]={E("subject_type",32,"detection_context"),
  O("evaluation_basis",ave_basis_fields),O("detection_context",ave_context_fields),END};
static const JsonField correlation_basis_fields[]={E("schema",64,"agent_detection_basis_v1"),
  E("owner",48,"correlation_engine"),B("tactic_probs_computed"),B("predicate_matched"),U("pid"),D("timestamp_ns"),
  E("kind",16,"sequence|threshold"),U("threshold"),U("matched_count"),U("window_ms"),B("ordered"),END};
static const JsonField chain_fields[]={U("type"),U("pid"),D("event_time_ns"),S("detail",80),END};
static const JsonField correlation_fields[]={E("subject_type",32,"edr_correlation"),
  S("rule_id",128),S("rules_bundle_version",255),S("display_title",384),
  O("evaluation_basis",correlation_basis_fields),U("window_ms"),U("count"),U("distinct"),
  A("evidence_chain",32,chain_fields),END};
static const JsonField fanout_basis_fields[]={E("schema",64,"agent_detection_basis_v1"),
  E("owner",48,"net_fanout_detector"),B("tactic_probs_computed"),B("predicate_matched"),U("pid"),D("timestamp_ns"),
  U("threshold"),U("distinct_ips"),U("window_s"),P("dport"),S("source_event_id",255),END};
static const JsonField fanout_fields[]={E("subject_type",32,"net_fanout"),
  O("evaluation_basis",fanout_basis_fields),END};
static const JsonField fanout_ioc_fields[]={E("detector",32,"net_fanout"),P("dport"),
  U("distinct_ips"),U("window_s"),END};
static const JsonField ioc_fields[]={E("type",16,"ip|domain|sha256"),S("value",253),
  E("source",32,"endpoint_ioc"),END};
static const JsonField standalone_actor_fields[]={U("pid"),END};
static const JsonField linux_syscall_fields[]={S("name",64),S("sensor",64),B("success"),
  S("result",24),U("target_pid"),END};
static const JsonField pmfe_signal_fields[]={U("stomp_suspicious"),U("mz_hits"),U("elf_hits"),
  U("dns_hits"),F("dns_best"),F("ave_max_score"),{"entropy_max",JS_ENTROPY,0,NULL,NULL},
  U("regions_scanned"),U("private_exec"),U("memfd_exec"),U("deleted_exec"),U("thread_start_matches"),
  U("read_failures"),B("injection_observed"),S("module_consistency",64),
  U("private_exec_image_hits"),U("private_exec_thread_starts"),S("module_integrity_scope",32),
  S("injection_status",32),END};
static const JsonField pmfe_fields[]={E("schema",64,"pmfe_result_v1"),
  S("source_alert_id",64),B("followup_only"),
  E("status",32,"completed_clean|completed_suspicious|partial|failed"),
  E("verdict",16,"clean|inconclusive|suspicious"),E("detector",32,"pmfe"),
  O("signals",pmfe_signal_fields),O("linux_syscall",linux_syscall_fields),END};
static const JsonField shellcode_detection_fields[]={S("detector",48),S("rule",128),F("score"),S("mitre",32),END};
static const JsonField shellcode_flow_fields[]={S("src",64),P("spt"),S("dst",64),P("dpt"),S("proto",48),END};
static const JsonField shellcode_payload_fields[]={S("sha256",64),END};
static const JsonField pmfe_followup_fields[]={B("recommended"),S("trigger",48),S("status",32),END};
static const JsonField vulnerability_fields[]={E("schema",64,"shellcode_vulnerability_attribution_v1"),
  S("candidate_cve",64),S("family",96),S("product",96),S("vector",48),
  S("confidence",24),S("source",32),L("evidence_basis",8,
  "known_rule_name|protocol_region|safe_signature_metadata|explicit_cve_token|rule_name_cve|signature_metadata|protocol_observation"),END};
static const JsonField shellcode_fields[]={E("schema",64,"shellcode_result_v1"),S("alert_id",64),
  O("flow",shellcode_flow_fields),O("owner",standalone_actor_fields),
  O("detection",shellcode_detection_fields),O("payload",shellcode_payload_fields),
  O("pmfe_followup",pmfe_followup_fields),O("vulnerability_attribution",vulnerability_fields),
  O("linux_syscall",linux_syscall_fields),END};
static const JsonField webshell_detection_fields[]={S("detector",48),S("rule",128),F("score"),
  F("ast_score"),F("token_score"),END};
static const JsonField webshell_file_fields[]={S("path",32768),S("sha256",64),END};
/* This detector establishes a file finding, not an observed HTTP request.
 * A service identifier helps attribution; arbitrary URL queries/userinfo are
 * not necessary evidence for that finding and remain in the local record. */
static const JsonField webshell_http_fields[]={S("service",96),END};
static const JsonField webshell_fields[]={E("schema",64,"webshell_result_v1"),
  O("file",webshell_file_fields),O("http",webshell_http_fields),
  O("detection",webshell_detection_fields),O("linux_syscall",linux_syscall_fields),END};
static const JsonField standalone_pmfe_context[]={E("rule_id",64,"agent_decision_v1"),
  O("process",standalone_actor_fields),O("engine_evidence",pmfe_fields),END};
static const JsonField standalone_shellcode_context[]={E("rule_id",64,"agent_decision_v1"),
  O("process",standalone_actor_fields),O("engine_evidence",shellcode_fields),END};
static const JsonField standalone_webshell_context[]={E("rule_id",64,"agent_decision_v1"),
  O("process",standalone_actor_fields),O("engine_evidence",webshell_fields),END};
static const JsonField p0_artifact_fields[]={S("source",96),S("quality",64),S("reason",160),END};
static const JsonField p0_hash_fields[]={S("value",96),S("source",96),S("quality",64),S("reason",160),END};
static const JsonField p0_signature_fields[]={S("status",64),S("source",96),S("signer",1024),
  S("thumbprint",192),S("revocation",64),S("quality",64),S("reason",160),END};
static const JsonField p0_evidence_fields[]={O("artifact",p0_artifact_fields),S("file_identity",128),
  O("hash",p0_hash_fields),O("signature",p0_signature_fields),B("omitted"),S("reason",160),END};
static const JsonField p0_terminal_process_fields[]={S("generation_key",32),
  {"creation_filetime_100ns",JS_U64,0,NULL,NULL},S("canonical_image_path",4096),
  S("file_identity",128),B("file_identity_available"),END};
static const JsonField p0_terminal_fields[]={E("phase",16,"intent|result"),S("terminal_key",80),
  S("rule_id",128),S("rules_bundle_version",255),S("rules_bundle_sha256",64),
  S("source_event_key",48),S("source_event_id",48),U("process_pid"),B("requested"),
  S("planned_action",64),O("process",p0_terminal_process_fields),B("attempted"),B("succeeded"),
  S("action",64),U("error_code"),S("message",160),END};
static const JsonField p0_terminal_context_fields[]={O("evidence",p0_evidence_fields),
  O("enforcement_terminal",p0_terminal_fields),END};
#undef S
#undef E
#undef B
#undef U
#undef P
#undef F
#undef D
#undef ND
#undef O
#undef A
#undef L
#undef END

static int enum_value(const char *s,const char *choices) {
  if (!choices) return 1;
  for (const char *p=choices; *p;) {
    const char *end=strchr(p,'|'); size_t n=end?(size_t)(end-p):strlen(p);
    if (strlen(s)==n && !memcmp(p,s,n)) return 1;
    p=end?end+1:p+n;
  }
  return 0;
}
static int decimal_value(const cJSON *v) {
  if (!cJSON_IsString(v) || !v->valuestring || !v->valuestring[0]) return 0;
  uint64_t n=0;
  for (const char *p=v->valuestring; *p; p++) {
    if (*p<'0' || *p>'9' || n>(UINT64_MAX-(uint64_t)(*p-'0'))/10u) return 0;
    n=n*10u+(uint64_t)(*p-'0');
  }
  return n>0 && strlen(v->valuestring)<=20 && v->valuestring[0]!='0';
}
static int json_fields(cJSON *root,const JsonField *fields,int project,unsigned depth) {
  if (!cJSON_IsObject(root) || depth>12) return 0;
  for (cJSON *v=root->child,*next; v; v=next) {
    next=v->next; const JsonField *f=fields;
    while (f->key && (!v->string || strcmp(f->key,v->string))) f++;
    if (!f->key) {
      if (!project) return 0;
      cJSON_Delete(cJSON_DetachItemViaPointer(root,v)); continue;
    }
    int valid=0;
    switch (f->kind) {
      case JS_STRING: valid=cJSON_IsString(v) && v->valuestring &&
        strlen(v->valuestring)<=f->bound && enum_value(v->valuestring,f->values); break;
      case JS_BOOL: valid=cJSON_IsBool(v); break;
      case JS_UINT: valid=cJSON_IsNumber(v) && isfinite(v->valuedouble) &&
        v->valuedouble>=0 && v->valuedouble<=(double)f->bound && floor(v->valuedouble)==v->valuedouble; break;
      case JS_U64: valid=cJSON_IsNumber(v) && isfinite(v->valuedouble) &&
        v->valuedouble>=0 && v->valuedouble<=(double)UINT64_MAX && floor(v->valuedouble)==v->valuedouble; break;
      case JS_UNIT: case JS_ENTROPY: valid=cJSON_IsNumber(v) && isfinite(v->valuedouble) &&
        v->valuedouble>=0 && v->valuedouble<=(f->kind==JS_UNIT?1.0:8.0); break;
      case JS_DECIMAL: valid=decimal_value(v); break;
      case JS_NULL_DECIMAL: valid=cJSON_IsNull(v)||decimal_value(v); break;
      case JS_OBJECT: valid=json_fields(v,f->children,project,depth+1); break;
      case JS_OBJECT_ARRAY:
        valid=cJSON_IsArray(v) && (size_t)cJSON_GetArraySize(v)<=f->bound;
        for (cJSON *item=v->child; valid && item; item=item->next)
          valid=json_fields(item,f->children,project,depth+1);
        break;
      case JS_STRING_ARRAY:
        valid=cJSON_IsArray(v) && (size_t)cJSON_GetArraySize(v)<=f->bound;
        for (cJSON *item=v->child; valid && item; item=item->next)
          valid=cJSON_IsString(item) && item->valuestring && strlen(item->valuestring)<=96 &&
            enum_value(item->valuestring,f->values);
        break;
    }
    if (!valid) return 0;
  }
  return 1;
}
static const JsonField *subject_fields(const cJSON *subject) {
  const char *type=string(subject,"subject_type");
  if (!strcmp(type,"edr_dynamic_rule")) return dynamic_fields;
  if (!strcmp(type,"detection_context")) return ave_fields;
  if (!strcmp(type,"edr_correlation")) return correlation_fields;
  if (!strcmp(type,"net_fanout")) return fanout_fields;
  return NULL;
}
static const JsonField *standalone_fields(const edr_v1_BehaviorEvent *ev,const cJSON *ctx) {
  const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence");
  if (!same(ctx,"rule_id","agent_decision_v1")) return NULL;
  if (ev->type==EDR_EVENT_PMFE_SCAN_RESULT && same(engine,"schema","pmfe_result_v1"))
    return standalone_pmfe_context;
  if (ev->type==EDR_EVENT_PROTOCOL_SHELLCODE && same(engine,"schema","shellcode_result_v1"))
    return standalone_shellcode_context;
  if (ev->type==EDR_EVENT_WEBSHELL_DETECTED && same(engine,"schema","webshell_result_v1"))
    return standalone_webshell_context;
  return NULL;
}
static int ioc_json_fields(cJSON *root,int fanout,int project) {
  if (fanout) return json_fields(root,fanout_ioc_fields,project,0);
  if (!cJSON_IsArray(root) || cJSON_GetArraySize(root)>3) return 0;
  for (cJSON *item=root->child; item; item=item->next)
    if (!json_fields(item,ioc_fields,project,0) ||
        (!strcmp(string(item,"type"),"sha256") && !hash(string(item,"value")))) return 0;
  return 1;
}

static int dynamic_alert(const edr_v1_BehaviorEvent *ev, const cJSON *subject) {
  const cJSON *ctx = cJSON_GetObjectItemCaseSensitive(subject, "context");
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
  const cJSON *parent = cJSON_GetObjectItemCaseSensitive(process, "parent_pid");
  if (ev->evidence_projection_version == EDR_EVIDENCE_PROJECTION_VERSION && parent &&
      (!cJSON_IsNumber(parent) || parent->valuedouble < 0 || parent->valuedouble > UINT32_MAX ||
       floor(parent->valuedouble) != parent->valuedouble ||
        parent->valuedouble != ev->ppid)) return 0;
  const char *engine = string(ctx, "engine"), *rule = string(ctx, "rule_id");
  const cJSON *threshold=cJSON_GetObjectItemCaseSensitive(basis,"threshold");
  const cJSON *flags=cJSON_GetObjectItemCaseSensitive(basis,"behavior_flags");
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
static int pmfe_status_coherent(const cJSON *engine) {
  const char *status=string(engine,"status"),*verdict=string(engine,"verdict");
  return (!strcmp(status,"completed_clean") && !strcmp(verdict,"clean")) ||
    ((!strcmp(status,"failed") || !strcmp(status,"partial")) && !strcmp(verdict,"inconclusive")) ||
    ((!strcmp(status,"completed_suspicious") || !strcmp(status,"partial")) && !strcmp(verdict,"suspicious"));
}
static int pmfe_independent_positive(const cJSON *engine) {
  if (!pmfe_status_coherent(engine) || strcmp(string(engine,"verdict"),"suspicious")) return 0;
  const cJSON *signals=cJSON_GetObjectItemCaseSensitive(engine,"signals");
  static const char *const counts[]={"stomp_suspicious","dns_hits","memfd_exec","deleted_exec",
    "private_exec_image_hits","private_exec_thread_starts"};
  for (size_t i=0;i<sizeof(counts)/sizeof(counts[0]);i++) if(count_signal(signals,counts[i])) return 1;
  return unit_signal(signals,"ave_max_score") ||
    cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(signals,"injection_observed"));
}
/* Typed positive engine findings can be a detection source even without an
 * embedded BehaviorAlert. A follow-up ID alone cannot prove the original
 * alert association: legacy clean follow-ups remain local pending a durable
 * association owner, rather than authorizing arbitrary clean process data. */
static int standalone_engine(const edr_v1_BehaviorEvent *ev, const cJSON *ctx,
    const uint8_t *frame,size_t frame_len) {
  const cJSON *process=cJSON_GetObjectItemCaseSensitive(ctx,"process");
  const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence");
  if (!same(ctx,"rule_id","agent_decision_v1") || !equal_uint(process,"pid",ev->pid) ||
      !ev->event_id[0] || !ev->endpoint_id[0] || !ev->tenant_id[0] || ev->event_time_ns<=0) return 0;
  if (ev->type == EDR_EVENT_PMFE_SCAN_RESULT && same(engine,"schema","pmfe_result_v1") &&
      same(engine,"detector","pmfe")) {
    const char *status=string(engine,"status"), *verdict=string(engine,"verdict");
    if (!pmfe_status_coherent(engine)) return 0;
    if (pmfe_independent_positive(engine)) return 1;
    {
      EdrEgressPmfeAssociationValidator validator=atomic_load_explicit(&pmfe_validator,memory_order_acquire);
      void *user=atomic_load_explicit(&pmfe_validator_user,memory_order_relaxed);
      return frame && frame_len && validator && ev->pid &&
        ev->process_start_key && ev->process_creation_filetime_100ns &&
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(engine,"followup_only")) &&
        string(engine,"source_alert_id")[0] &&
        validator(string(engine,"source_alert_id"),ev->endpoint_id,ev->tenant_id,
          ev->event_id,ev->pid,ev->process_start_key,ev->process_creation_filetime_100ns,
          ev->event_time_ns,status,verdict,frame,frame_len,user)==1;
    }
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
  if (!basis_valid(ev,basis,"correlation_engine") || !count_signal(basis,"threshold") ||
      !count_signal(basis,"matched_count") || matched->valuedouble<threshold->valuedouble ||
      (strcmp(string(basis,"kind"),"sequence") && strcmp(string(basis,"kind"),"threshold")) ||
      !string(subject,"rule_id")[0] || !string(subject,"rules_bundle_version")[0] ||
      !count_signal(subject,"window_ms") || !count_signal(subject,"count") ||
      !cJSON_IsArray(chain) || cJSON_GetArraySize(chain) < 1) return 0;
  int bound = 0;
  cJSON_ArrayForEach(item,chain) {
    if (!count_signal(item,"type") || !count_signal(item,"pid") ||
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

static void project_supplemental_identity(edr_v1_BehaviorEvent *ev) {
  ev->session_id=0;
  ev->domain[0]=ev->user_sid[0]=ev->logon_id[0]=0;
  ev->creator_username[0]=ev->creator_domain[0]=ev->creator_sid[0]=ev->creator_logon_id[0]=0;
  ev->identity_source[0]=ev->identity_quality[0]=0;
}
/* These are finite purpose profiles, not authorization inferred from a field
 * name. Dynamic masks originate in the held IR snapshot; the final byte gate
 * enforces that contract independently of the currently active rule bundle. */
static int operation_evidence_valid(const edr_v1_BehaviorEvent *ev) {
  if (!(ev->required_evidence_fields & EDR_EVIDENCE_OPERATION)) return !ev->operation_evidence_json[0];
  if (ev->required_evidence_fields & (EDR_EVIDENCE_COMMAND|EDR_EVIDENCE_SCRIPT)) return 0;
  if (!strcmp(ev->operation_evidence_json,"{\"kind\":\"credential_db_decrypt\",\"object_bound\":true,\"unprotect\":true}"))
    return (ev->required_evidence_fields & EDR_EVIDENCE_FILE)!=0;
  if (!strcmp(ev->operation_evidence_json,"{\"kind\":\"remote_hash_auth\",\"object_bound\":true,\"hash_argument_present\":true}"))
    return (ev->required_evidence_fields & EDR_EVIDENCE_NETWORK)!=0;
  if (!strcmp(ev->operation_evidence_json,"{\"kind\":\"credential_tool_attempt\"}"))
    return ev->type==EDR_EVENT_PROCESS_CREATE &&
        (ev->required_evidence_fields & ~EDR_EVIDENCE_USER)==EDR_EVIDENCE_OPERATION;
  return 0;
}
static int dynamic_context_purpose(cJSON *subject,uint64_t mask,int project) {
  cJSON *ctx=cJSON_GetObjectItemCaseSensitive(subject,"context");
  static const struct {const char *name;uint64_t purpose;} conditional[]={
    {"powershell_script_block",EDR_EVIDENCE_SCRIPT},
    {"command_line_origin",EDR_EVIDENCE_COMMAND|EDR_EVIDENCE_SCRIPT},
    {"encoded_command_type",EDR_EVIDENCE_COMMAND|EDR_EVIDENCE_SCRIPT},
    {"registry_source",EDR_EVIDENCE_REGISTRY},
    {"registry_attribution",EDR_EVIDENCE_REGISTRY},
    {"registry_detail_status",EDR_EVIDENCE_REGISTRY},
    {"registry_old_data",0} /* no current IR predicate consumes previous data */
  };
  for (size_t i=0;i<sizeof(conditional)/sizeof(conditional[0]);i++)
    if (!(mask&conditional[i].purpose) && cJSON_GetObjectItemCaseSensitive(ctx,conditional[i].name)) {
      if (!project) return 0;
      cJSON_DeleteItemFromObjectCaseSensitive(ctx,conditional[i].name);
    }
  return 1;
}
/* Native target identity owners, not arbitrary display labels. This content
 * purpose check never substitutes for rule authority or exact frame ownership. */
static int target_identity_qualified(const edr_v1_BehaviorEvent *ev) {
  if (!ev->username[0]) return 0;
  if (!strcmp(ev->identity_source,"target_4688") && !strcmp(ev->identity_quality,"target_4688")) return 1;
  if (strcmp(ev->identity_quality,"token_sid")) return 0;
  static const char *sources[]={"kernel_process_token","token_query","token_cache",
    "token_query_4688_validated","token_cache_4688_validated"};
  for (size_t i=0;i<sizeof(sources)/sizeof(sources[0]);i++)
    if (!strcmp(ev->identity_source,sources[i])) return 1;
  return 0;
}
static int projected_version(uint32_t version) {
  return version == EDR_EVIDENCE_PROJECTION_VERSION ||
      version == EDR_EVIDENCE_PROJECTION_LEGACY_VERSION;
}
static int parent_pid_fields_valid(const edr_v1_BehaviorEvent *ev) {
  if (ev->evidence_projection_version == EDR_EVIDENCE_PROJECTION_LEGACY_VERSION)
    return !ev->has_parent_pid_state;
  if (!ev->has_parent_pid_state) return 0;
  /* A purpose authorizes available evidence; it is not a detection predicate.
   * An unavailable/conflicting edge may carry diagnostics, never borrowed
   * parent text or ancestry. This v3 check does not alter frozen v2 fields. */
  if (ev->parent_pid_state != EDR_PARENT_PID_KNOWN &&
      (ev->parent_name[0] || ev->parent_path[0] || ev->process_chain_depth ||
       ev->process_context.has_parent_name || ev->process_context.parent_name[0] ||
       ev->process_context.has_parent_path || ev->process_context.parent_path[0] ||
       ev->process_context.has_parent_cmdline || ev->process_context.parent_cmdline[0] ||
       ev->process_context.has_grandparent_pid || ev->process_context.grandparent_pid ||
       ev->process_context.has_grandparent_name || ev->process_context.grandparent_name[0] ||
       ev->process_context.has_grandparent_path || ev->process_context.grandparent_path[0] ||
       (ev->which_detail == edr_v1_BehaviorEvent_process_tag &&
        (ev->detail.process.parent_name[0] || ev->detail.process.parent_path[0] ||
         ev->detail.process.parent_cmdline[0] || ev->detail.process.grandparent_pid ||
         ev->detail.process.grandparent_name[0] || ev->detail.process.grandparent_path[0])))) return 0;
  switch (ev->parent_pid_state) {
    case EDR_PARENT_PID_KNOWN: return ev->ppid != 0;
    case EDR_PARENT_PID_UNKNOWN:
    case EDR_PARENT_PID_EXPLICIT_ZERO:
    case EDR_PARENT_PID_INVALID: return ev->ppid == 0;
    case EDR_PARENT_PID_CONFLICT: return 1;
    default: return 0;
  }
}
static void project_evidence_fields(edr_v1_BehaviorEvent *ev) {
  uint64_t mask=ev->required_evidence_fields;
  char identity_source[sizeof(ev->identity_source)],identity_quality[sizeof(ev->identity_quality)];
  memcpy(identity_source,ev->identity_source,sizeof(identity_source));
  memcpy(identity_quality,ev->identity_quality,sizeof(identity_quality));
  int keep_user=(mask & EDR_EVIDENCE_USER) && target_identity_qualified(ev);
  project_supplemental_identity(ev);
  if (!keep_user) ev->username[0]=0;
  else {
    memcpy(ev->identity_source,identity_source,sizeof(identity_source));
    memcpy(ev->identity_quality,identity_quality,sizeof(identity_quality));
  }
  if (!(mask & EDR_EVIDENCE_COMMAND)) ev->cmdline[0]=0;
  if (!(mask & EDR_EVIDENCE_CHAIN_DEPTH)) ev->process_chain_depth=0;
  ev->parent_name[0]=ev->parent_path[0]=0;
  edr_v1_ProcessContext *c=&ev->process_context;
  ev->has_process_context=true; /* Authoritative even when intentionally empty. */
  if (!(mask & EDR_EVIDENCE_PARENT_NAME)) {c->has_parent_name=false;c->parent_name[0]=0;}
  if (!(mask & EDR_EVIDENCE_PARENT_PATH)) {c->has_parent_path=false;c->parent_path[0]=0;}
  if (!(mask & EDR_EVIDENCE_PARENT_COMMAND)) {c->has_parent_cmdline=false;c->parent_cmdline[0]=0;}
  if (!(mask & EDR_EVIDENCE_TOKEN)) {c->has_integrity_level=false;c->integrity_level[0]=0;c->has_token_elevation=false;c->token_elevation=0;}
  c->has_current_directory=false;c->current_directory[0]=0;
  c->has_process_creation_time=false;c->process_creation_time[0]=0;
  c->has_grandparent_pid=false;c->grandparent_pid=0;
  c->has_grandparent_name=false;c->grandparent_name[0]=0;
  c->has_grandparent_path=false;c->grandparent_path[0]=0;
  if (!(mask & (EDR_EVIDENCE_PARENT_NAME|EDR_EVIDENCE_PARENT_PATH|EDR_EVIDENCE_PARENT_COMMAND|EDR_EVIDENCE_CHAIN_DEPTH))) {
    if (ev->evidence_projection_version == EDR_EVIDENCE_PROJECTION_LEGACY_VERSION) {
      ev->ppid=0;
      ev->parent_resolution_status[0]=ev->parent_resolution_source[0]=ev->parent_creation_time[0]=0;
    }
    /* v3 collection diagnostics are independent of optional parent text.
     * Preserve only captured values; absence and invalid/conflicting parent
     * states never acquire a creation identity or a successful resolution. */
  }
  int keep=(ev->which_detail==edr_v1_BehaviorEvent_file_tag && (mask&EDR_EVIDENCE_FILE)) ||
    (ev->which_detail==edr_v1_BehaviorEvent_network_tag && (mask&EDR_EVIDENCE_NETWORK)) ||
    (ev->which_detail==edr_v1_BehaviorEvent_registry_tag && (mask&EDR_EVIDENCE_REGISTRY)) ||
    (ev->which_detail==edr_v1_BehaviorEvent_script_tag && (mask&EDR_EVIDENCE_SCRIPT)) ||
    (ev->which_detail==edr_v1_BehaviorEvent_dns_tag && (mask&EDR_EVIDENCE_NETWORK));
  if (!keep) {ev->which_detail=0;memset(&ev->detail,0,sizeof(ev->detail));}
  if (ev->which_detail==edr_v1_BehaviorEvent_file_tag) {
    ev->detail.file.file_size=0;ev->detail.file.target_has_motw=false;
  }
  if (ev->which_detail==edr_v1_BehaviorEvent_registry_tag && !(mask&EDR_EVIDENCE_REGISTRY_DATA))
    ev->detail.registry.value_data[0]=0;
  if (ev->which_detail==edr_v1_BehaviorEvent_network_tag) {
    ev->detail.network.src_ip[0]=0;ev->detail.network.src_port=0;
    if (!(mask&EDR_EVIDENCE_NETWORK_AUX)) ev->detail.network.network_aux_path[0]=0;
  }
  if (ev->has_behavior_alert) {
    ev->behavior_alert.ppid=0;
    ev->behavior_alert.process_name[0]=ev->behavior_alert.process_path[0]=ev->behavior_alert.cmdline[0]=0;
    /* The current internal owners use deterministic predicates/window scores;
     * none compute tactic probabilities. Do not derive this from zero values. */
    if (ev->has_tactic_probs_computed && !ev->tactic_probs_computed) {
      ev->behavior_alert.tactic_probs_count=0;
      memset(ev->behavior_alert.tactic_probs,0,sizeof(ev->behavior_alert.tactic_probs));
    }
  }
}
static int projected_evidence_valid(const edr_v1_BehaviorEvent *ev,int dynamic,int *resource_unavailable) {
  if (!projected_version(ev->evidence_projection_version) || !parent_pid_fields_valid(ev) ||
      (ev->required_evidence_fields & ~EDR_EVIDENCE_ALL) ||
      ((ev->required_evidence_fields&EDR_EVIDENCE_REGISTRY_DATA) && !(ev->required_evidence_fields&EDR_EVIDENCE_REGISTRY)) ||
      ((ev->required_evidence_fields&EDR_EVIDENCE_NETWORK_AUX) && !(ev->required_evidence_fields&EDR_EVIDENCE_NETWORK)) ||
      (!dynamic && ev->required_evidence_fields) || !operation_evidence_valid(ev) ||
      (ev->has_behavior_alert && ev->has_tactic_probs_computed &&
       ((!ev->tactic_probs_computed && ev->behavior_alert.tactic_probs_count) ||
        (ev->tactic_probs_computed && ev->behavior_alert.tactic_probs_count!=14)))) return 0;
  edr_v1_BehaviorEvent *projected=malloc(sizeof(*projected));
  if (!projected) { if (resource_unavailable) *resource_unavailable=1; return 0; }
  memcpy(projected,ev,sizeof(*ev)); project_evidence_fields(projected);
  int valid=memcmp(projected,ev,sizeof(*ev))==0;free(projected);return valid;
}
static int generation_matches(const cJSON *ctx,const char *key,uint64_t generation) {
  const cJSON *v=cJSON_GetObjectItemCaseSensitive(ctx,key);
  if (!v) return 1;
  if (cJSON_IsNull(v)) return generation==0;
  char expected[32]; snprintf(expected,sizeof(expected),"%llu",(unsigned long long)generation);
  return generation && cJSON_IsString(v) && !strcmp(v->valuestring,expected);
}
static int supplemental_identity_empty(const edr_v1_BehaviorEvent *ev) {
  return !ev->session_id && !ev->domain[0] && !ev->user_sid[0] && !ev->logon_id[0] &&
    !ev->creator_username[0] && !ev->creator_domain[0] && !ev->creator_sid[0] &&
    !ev->creator_logon_id[0] && !ev->identity_source[0] && !ev->identity_quality[0];
}
/* cJSON stores numbers as doubles. The existing terminal protocol uses a
 * numeric uint64 birth timestamp, so bind its original decimal lexeme to the
 * typed generation instead of rounding it through a double or rewriting it. */
static int terminal_birth_matches(const char *raw,uint64_t expected) {
  static const char key[]="\"creation_filetime_100ns\"";
  const char *p=raw; int found=0;
  while (p && (p=strstr(p,key))) {
    p+=sizeof(key)-1; while (*p==' ' || *p=='\r' || *p=='\n' || *p=='\t') p++;
    if (*p!=':') continue;
    p++; while (*p==' ' || *p=='\r' || *p=='\n' || *p=='\t') p++;
    const char *start=p; uint64_t value=0;
    if (*p<'1' || *p>'9') return 0;
    while (*p>='0' && *p<='9') {
      if (value>(UINT64_MAX-(uint64_t)(*p-'0'))/10u) return 0;
      value=value*10u+(uint64_t)(*p++-'0');
    }
    if ((size_t)(p-start)>20 || value!=expected) return 0;
    while (*p==' ' || *p=='\r' || *p=='\n' || *p=='\t') p++;
    if ((*p!=',' && *p!='}') || found++) return 0;
  }
  return found==1;
}
static int bool_equal(const cJSON *a,const cJSON *b,const char *key) {
  const cJSON *x=cJSON_GetObjectItemCaseSensitive(a,key),*y=cJSON_GetObjectItemCaseSensitive(b,key);
  return cJSON_IsBool(x) && cJSON_IsBool(y) && cJSON_IsTrue(x)==cJSON_IsTrue(y);
}
static int p0_feed_valid(const edr_v1_BehaviorEvent *ev) {
  if (!ev->has_ave_behavior_feed) return 1;
  const edr_v1_AveBehaviorEventFeed *f=&ev->ave_behavior_feed;
  const float units[]={f->target_ip_geoip_risk,f->target_port_risk,f->reg_key_risk,
    f->shellcode_score,f->webshell_score,f->pmfe_confidence,f->ave_confidence};
  for (size_t i=0;i<sizeof(units)/sizeof(units[0]);i++)
    if (!isfinite(units[i]) || units[i]<0 || units[i]>1) return 0;
  if (!isfinite(f->target_path_entropy) || f->target_path_entropy<0 || f->target_path_entropy>8 ||
      !isfinite(f->target_domain_entropy) || f->target_domain_entropy<0 || f->target_domain_entropy>8 ||
      f->target_port>65535 || f->severity_hint>255 || f->target_file_ext_risk>2 ||
      (f->has_ave_event_type && (f->ave_event_type<0 || f->ave_event_type>13)) ||
      (f->file_sha256_hex[0] && !hash(f->file_sha256_hex))) return 0;
  /* Existing full journal facts may duplicate an event target, but cannot
   * supply a second unrelated target through the AVE feed. */
  if (f->target_ip[0] && (ev->which_detail!=edr_v1_BehaviorEvent_network_tag ||
      strcmp(f->target_ip,ev->detail.network.dst_ip) || f->target_port!=ev->detail.network.dst_port)) return 0;
  if (f->target_domain[0] && (ev->which_detail!=edr_v1_BehaviorEvent_dns_tag ||
      strcmp(f->target_domain,ev->detail.dns.query_name))) return 0;
  if (f->target_path[0] && !((ev->which_detail==edr_v1_BehaviorEvent_file_tag &&
      !strcmp(f->target_path,ev->detail.file.target_path)) ||
      (ev->which_detail==edr_v1_BehaviorEvent_registry_tag &&
      !strcmp(f->target_path,ev->detail.registry.key_path)))) return 0;
  return 1;
}
static int p0_terminal_tuple(const edr_v1_BehaviorEvent *ev,cJSON *ctx,const char *phase,
    EdrEgressP0PairAssociation *out) {
  if (!json_fields(ctx,p0_terminal_context_fields,0,0) || !p0_feed_valid(ev) ||
      !ev->event_id[0] || !ev->tenant_id[0] || !ev->endpoint_id[0] || !ev->pid || ev->event_time_ns<=0 ||
      !ev->process_start_key || !ev->process_creation_filetime_100ns) return 0;
  const cJSON *terminal=cJSON_GetObjectItemCaseSensitive(ctx,"enforcement_terminal");
  const cJSON *process=cJSON_GetObjectItemCaseSensitive(terminal,"process");
  const cJSON *evidence=cJSON_GetObjectItemCaseSensitive(ctx,"evidence");
  const cJSON *artifact=cJSON_GetObjectItemCaseSensitive(evidence,"artifact");
  const char *path=ev->image_path_canonical[0]?ev->image_path_canonical:ev->exe_path;
  const char *file_id=string(process,"file_identity");
  char generation[32],commitment[96];
  snprintf(generation,sizeof(generation),"startkey-%016llx",(unsigned long long)ev->process_start_key);
  int valid=same(terminal,"phase",phase) && string(terminal,"rule_id")[0] &&
    string(terminal,"rules_bundle_version")[0] && hash(string(terminal,"rules_bundle_sha256")) &&
    same(terminal,"source_event_key",ev->event_id) && same(terminal,"source_event_id",ev->event_id) &&
    equal_uint(terminal,"process_pid",ev->pid) && same(terminal,"planned_action","terminate_process") &&
    same(process,"generation_key",generation) && terminal_birth_matches(ev->ave_result_json,ev->process_creation_filetime_100ns) &&
    same(process,"canonical_image_path",path) &&
    cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(process,"file_identity_available")) &&
    same(evidence,"file_identity",file_id) && same(artifact,"source","process_image_section") &&
    same(artifact,"quality","action_authoritative") &&
    edr_p0_terminal_identity_key(ev->tenant_id,ev->endpoint_id,string(terminal,"rule_id"),ev->event_id,
      ev->pid,ev->process_start_key,ev->process_creation_filetime_100ns,path,file_id,commitment,sizeof(commitment)) &&
    same(terminal,"terminal_key",commitment);
  if (valid && out) {
    *out=(EdrEgressP0PairAssociation){string(terminal,"terminal_key"),ev->endpoint_id,ev->tenant_id,
      string(terminal,"rule_id"),string(terminal,"rules_bundle_version"),string(terminal,"rules_bundle_sha256"),
      ev->event_id,path,file_id,ev->pid,ev->process_start_key,ev->process_creation_filetime_100ns};
  }
  return valid;
}
static int p0_terminal_context_valid(const edr_v1_BehaviorEvent *ev,cJSON *subject,cJSON *ctx) {
  if (!same(subject,"subject_type","edr_dynamic_rule") || !dynamic_alert(ev,subject) ||
      !json_fields(subject,projected_version(ev->evidence_projection_version)?
        p0_projected_subject_fields:p0_journal_subject_fields,0,0) ||
      !p0_terminal_tuple(ev,ctx,"result",NULL)) return 0;
  const cJSON *terminal=cJSON_GetObjectItemCaseSensitive(ctx,"enforcement_terminal");
  const cJSON *process=cJSON_GetObjectItemCaseSensitive(terminal,"process");
  const cJSON *source=cJSON_GetObjectItemCaseSensitive(subject,"context");
  const cJSON *enforce=cJSON_GetObjectItemCaseSensitive(subject,"enforcement");
  const char *path=ev->image_path_canonical[0]?ev->image_path_canonical:ev->exe_path;
  const cJSON *code=cJSON_GetObjectItemCaseSensitive(terminal,"error_code");
  const cJSON *subject_code=cJSON_GetObjectItemCaseSensitive(enforce,"error_code");
  return same(terminal,"rule_id",string(subject,"rule_id")) &&
    same(terminal,"rules_bundle_version",string(subject,"rules_bundle_version")) &&
    same(terminal,"rules_bundle_sha256",string(subject,"rules_bundle_sha256")) &&
    same(source,"process_path",path) &&
    same(source,"canonical_image_path",path) &&
    (projected_version(ev->evidence_projection_version)?
      (!ev->behavior_alert.process_path[0] && !strcmp(ev->exe_path,path)):
      !strcmp(ev->behavior_alert.process_path,path)) &&
    same(source,"file_identity",string(process,"file_identity")) &&
    generation_matches(source,"process_start_key",ev->process_start_key) &&
    generation_matches(source,"process_creation_filetime_100ns",ev->process_creation_filetime_100ns) &&
    cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(enforce,"requested")) &&
    bool_equal(terminal,enforce,"attempted") && bool_equal(terminal,enforce,"succeeded") &&
    cJSON_IsNumber(code) && cJSON_IsNumber(subject_code) && code->valuedouble==subject_code->valuedouble &&
    same(terminal,"action",string(enforce,"action"));
}
static int p0_intent_fields_valid(const edr_v1_BehaviorEvent *ev,cJSON *ctx,
    EdrEgressP0PairAssociation *out) {
  const cJSON *terminal=cJSON_GetObjectItemCaseSensitive(ctx,"enforcement_terminal");
  /* Intent has no post-action result fields. A phase label may not hide an
   * ordinary result/source frame or establish a real alert by itself. */
  return !ev->has_behavior_alert && p0_terminal_tuple(ev,ctx,"intent",out) &&
    cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(terminal,"requested")) &&
    !cJSON_GetObjectItemCaseSensitive(terminal,"attempted") && !cJSON_GetObjectItemCaseSensitive(terminal,"succeeded") &&
    !cJSON_GetObjectItemCaseSensitive(terminal,"action") && !cJSON_GetObjectItemCaseSensitive(terminal,"error_code") &&
    !cJSON_GetObjectItemCaseSensitive(terminal,"message");
}
static int p0_pair_owned(const edr_v1_BehaviorEvent *ev,cJSON *ctx,const uint8_t *frame,size_t len) {
  EdrEgressP0PairAssociation tuple;
  if (!(ev->has_behavior_alert?p0_terminal_tuple(ev,ctx,"result",&tuple):
      p0_intent_fields_valid(ev,ctx,&tuple))) return 0;
  EdrEgressP0PairValidator validator=atomic_load_explicit(&p0_pair_validator,memory_order_acquire);
  void *user=atomic_load_explicit(&p0_pair_user,memory_order_relaxed);
  return validator && validator(&tuple,frame,len,user)==1;
}
static int terminal_projection_valid(const edr_v1_BehaviorEvent *ev,int *resource_unavailable) {
  if (ev->evidence_projection_version==0) return 1; /* exact historical owner */
  return projected_version(ev->evidence_projection_version) &&
    !ev->has_ave_behavior_feed && ev->image_path_canonical[0] &&
    !strcmp(ev->exe_path,ev->image_path_canonical) && projected_evidence_valid(ev,1,resource_unavailable);
}
static int event_fields_valid(const edr_v1_BehaviorEvent *ev,cJSON *ctx,int *resource_unavailable) {
  if (ev->has_behavior_alert) {
    cJSON *subject=object(ev->behavior_alert.user_subject_json);
    const JsonField *fields=subject_fields(subject);
    int dynamic=same(subject,"subject_type","edr_dynamic_rule");
    int fanout=same(subject,"subject_type","net_fanout");
    int terminal=cJSON_GetObjectItemCaseSensitive(ctx,"enforcement_terminal")!=NULL;
    int valid=terminal?(p0_terminal_context_valid(ev,subject,ctx) && terminal_projection_valid(ev,resource_unavailable)):
      (fields && json_fields(subject,fields,0,0) && !ev->ave_result_json[0] &&
      !ev->has_ave_behavior_feed && projected_evidence_valid(ev,dynamic,resource_unavailable));
    if (valid && dynamic) {
      const cJSON *context=cJSON_GetObjectItemCaseSensitive(subject,"context");
      /* Legacy terminal bytes retain their exact journal commitment; new
       * terminals also enforce the captured rule evidence purpose. */
      valid=((terminal && ev->evidence_projection_version==0) || dynamic_context_purpose(subject,ev->required_evidence_fields,0)) &&
        generation_matches(context,"process_start_key",ev->process_start_key) &&
        generation_matches(context,"process_creation_filetime_100ns",ev->process_creation_filetime_100ns);
    }
    if (valid && ev->behavior_alert.related_iocs_json[0]) {
      cJSON *iocs=document(ev->behavior_alert.related_iocs_json);
      valid=ioc_json_fields(iocs,fanout,0); cJSON_Delete(iocs);
    }
    cJSON_Delete(subject);
    return valid;
  }
  if (cJSON_GetObjectItemCaseSensitive(ctx,"enforcement_terminal"))
    return p0_intent_fields_valid(ev,ctx,NULL) && terminal_projection_valid(ev,resource_unavailable);
  if (ev->has_ave_behavior_feed) return 0;
  const JsonField *fields=standalone_fields(ev,ctx);
  if (!fields || !json_fields(ctx,fields,0,0) || !supplemental_identity_empty(ev)) return 0;
  const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence");
  if (!(ev->type==EDR_EVENT_PMFE_SCAN_RESULT && !pmfe_independent_positive(engine)) &&
      !projected_evidence_valid(ev,0,resource_unavailable)) return 0;
  if (ev->which_detail==edr_v1_BehaviorEvent_script_tag ||
      ev->which_detail==edr_v1_BehaviorEvent_dns_tag ||
      (ev->type==EDR_EVENT_PMFE_SCAN_RESULT && (ev->cmdline[0] ||
        (ev->which_detail && ev->which_detail!=edr_v1_BehaviorEvent_process_tag)))) return 0;
  return 1;
}
int edr_egress_event_project(edr_v1_BehaviorEvent *ev,char *reason,size_t cap) {
  if (!ev) return deny(reason,cap,"projection_arguments_invalid");
  cJSON *ctx=ev->ave_result_json[0]?object(ev->ave_result_json):NULL;
  /* Preserve complete local source evidence and malformed/unknown records.
   * They are subsequently held by admission, never repackaged as alerts. */
  if ((ev->ave_result_json[0] && !ctx) || same(ctx,"p0_disposition","NOT_EVALUABLE")) {
    cJSON_Delete(ctx); return 1;
  }
  if (cJSON_GetObjectItemCaseSensitive(ctx,"enforcement_terminal")) {
    cJSON *subject=ev->has_behavior_alert?object(ev->behavior_alert.user_subject_json):NULL;
    int fresh=projected_version(ev->evidence_projection_version);
    int valid=ev->evidence_projection_version==0 || fresh;
    if (valid && fresh) {
      /* Only fresh producer bytes are projected. Never rewrite the uint64
       * terminal JSON lexeme or use this function to resend a journal. */
      if (ev->evidence_projection_version == EDR_EVIDENCE_PROJECTION_VERSION && !ev->has_parent_pid_state) {
        ev->has_parent_pid_state=true;
        ev->parent_pid_state=ev->ppid?EDR_PARENT_PID_KNOWN:EDR_PARENT_PID_UNKNOWN;
      }
      valid=parent_pid_fields_valid(ev) && operation_evidence_valid(ev);
      if (valid && subject) {
        valid=json_fields(subject,p0_projected_subject_fields,1,0) &&
          dynamic_context_purpose(subject,ev->required_evidence_fields,1);
        char *text=valid?cJSON_PrintUnformatted(subject):NULL;
        valid=text && strlen(text)<sizeof(ev->behavior_alert.user_subject_json);
        if (valid) strcpy(ev->behavior_alert.user_subject_json,text);
        free(text);
      }
      if (valid) {
        ev->has_ave_behavior_feed=false; memset(&ev->ave_behavior_feed,0,sizeof(ev->ave_behavior_feed));
        project_evidence_fields(ev);
        /* The receiver reconstructs omitted display from the canonical actor;
         * its original spelling remains in image_path_raw. */
        if (ev->image_path_canonical[0]) strcpy(ev->exe_path,ev->image_path_canonical);
      }
    }
    if (valid) valid=ev->has_behavior_alert?p0_terminal_context_valid(ev,subject,ctx):p0_intent_fields_valid(ev,ctx,NULL);
    cJSON_Delete(subject); cJSON_Delete(ctx);
    if (!valid) return deny(reason,cap,"p0_terminal_requires_exact_journal_authority");
    if (reason && cap) snprintf(reason,cap,fresh?"p0_terminal_fields_projected":"p0_terminal_exact_journal_retained");
    return 1; /* Neither schema nor projection replaces the exact pair owner. */
  }
  cJSON *subject=NULL,*iocs=NULL; char *subject_text=NULL,*ioc_text=NULL,*ctx_text=NULL;
  const JsonField *fields=NULL; int dynamic=0,fanout=0,recognized=0,valid=1;
  if (ev->has_behavior_alert) {
    subject=object(ev->behavior_alert.user_subject_json); fields=subject_fields(subject);
    recognized=fields!=NULL;
    dynamic=same(subject,"subject_type","edr_dynamic_rule");
    fanout=same(subject,"subject_type","net_fanout");
    if (recognized) {
      valid=json_fields(subject,fields,1,0);
      if (valid && dynamic) valid=dynamic_context_purpose(subject,ev->required_evidence_fields,1);
      if (valid && ev->behavior_alert.related_iocs_json[0]) {
        iocs=document(ev->behavior_alert.related_iocs_json);
        valid=ioc_json_fields(iocs,fanout,1);
      }
      if (valid) {
        subject_text=cJSON_PrintUnformatted(subject);
        if (iocs) ioc_text=cJSON_PrintUnformatted(iocs);
        valid=subject_text && (!iocs || ioc_text) &&
          strlen(subject_text)<sizeof(ev->behavior_alert.user_subject_json) &&
          (!ioc_text || strlen(ioc_text)<sizeof(ev->behavior_alert.related_iocs_json));
      }
    }
  } else {
    fields=standalone_fields(ev,ctx); recognized=fields!=NULL;
    if (recognized) {
      valid=json_fields(ctx,fields,1,0);
      if (valid) {
        ctx_text=cJSON_PrintUnformatted(ctx);
        valid=ctx_text && strlen(ctx_text)<sizeof(ev->ave_result_json);
      }
    }
  }
  if (recognized && valid) {
    ev->has_ave_behavior_feed=false; memset(&ev->ave_behavior_feed,0,sizeof(ev->ave_behavior_feed));
    if (dynamic && !projected_version(ev->evidence_projection_version)) valid=0;
    if (!dynamic) {ev->evidence_projection_version=EDR_EVIDENCE_PROJECTION_VERSION;ev->required_evidence_fields=0;ev->operation_evidence_json[0]=0;}
    if (valid && ev->evidence_projection_version == EDR_EVIDENCE_PROJECTION_VERSION && !ev->has_parent_pid_state) {
      ev->has_parent_pid_state=true;
      ev->parent_pid_state=ev->ppid?EDR_PARENT_PID_KNOWN:EDR_PARENT_PID_UNKNOWN;
    }
    if (valid && !parent_pid_fields_valid(ev)) valid=0;
    if (valid && !operation_evidence_valid(ev)) valid=0;
    if (valid) project_evidence_fields(ev);
    if (subject_text) {
      strcpy(ev->behavior_alert.user_subject_json,subject_text);
      if (ioc_text) strcpy(ev->behavior_alert.related_iocs_json,ioc_text);
      ev->ave_result_json[0]=0; /* Redundant generic score/context stays local. */
    } else if (ctx_text) {
      strcpy(ev->ave_result_json,ctx_text);
      if (ev->which_detail==edr_v1_BehaviorEvent_script_tag ||
          ev->which_detail==edr_v1_BehaviorEvent_dns_tag ||
          (ev->type==EDR_EVENT_PMFE_SCAN_RESULT && ev->which_detail!=edr_v1_BehaviorEvent_process_tag)) {
        ev->which_detail=0; memset(&ev->detail,0,sizeof(ev->detail));
      }
      if (ev->type==EDR_EVENT_PMFE_SCAN_RESULT) ev->cmdline[0]=0;
    }
  }
  cJSON_Delete(ctx); cJSON_Delete(subject); cJSON_Delete(iocs);
  free(subject_text); free(ioc_text); free(ctx_text);
  if (recognized && !valid) return deny(reason,cap,"alert_field_projection_failed");
  if (reason && cap) snprintf(reason,cap,recognized?"alert_fields_projected":"local_record_unchanged");
  return 1;
}

static int frame_validate(const uint8_t *frame,size_t len,char *reason,size_t cap,int require_pair_owner) {
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
  int paired=cJSON_GetObjectItemCaseSensitive(ctx,"enforcement_terminal")!=NULL;
  int intent=!ev->has_behavior_alert && paired;
  int valid = !source_only && (alert_valid(ev) || standalone_engine(ev,ctx,frame,len) ||
    (intent && p0_intent_fields_valid(ev,ctx,NULL)));
  if (valid && ((ev->has_behavior_alert && !paired) ||
      (paired && projected_version(ev->evidence_projection_version)))) {
    cJSON *subject=ev->has_behavior_alert?object(ev->behavior_alert.user_subject_json):NULL;
    const cJSON *authority=paired?cJSON_GetObjectItemCaseSensitive(ctx,"enforcement_terminal"):subject;
    if (paired || same(subject,"subject_type","edr_dynamic_rule")) {
      EdrEgressRuleProjectionValidator validator=atomic_load_explicit(&rule_projection_validator,memory_order_acquire);
      void *user=atomic_load_explicit(&rule_projection_user,memory_order_relaxed);
      int proven=validator?validator(string(authority,"rule_id"),string(authority,"rules_bundle_sha256"),
          ev->required_evidence_fields,ev->operation_evidence_json,user):0;
      if (proven!=1) {
        cJSON_Delete(subject); cJSON_Delete(ctx); free(ev);
        return deny(reason,cap,proven<0?"rule_projection_authority_unavailable":"rule_projection_authority_unproven");
      }
    }
    cJSON_Delete(subject);
  }
  int resource_unavailable=0;
  if (valid && !event_fields_valid(ev,ctx,&resource_unavailable)) {
    cJSON_Delete(ctx); free(ev); return deny(reason,cap,
      resource_unavailable?"egress_validation_allocation_failed":"alert_field_purpose_invalid");
  }
  if (valid && paired && require_pair_owner && !p0_pair_owned(ev,ctx,frame,len)) {
    cJSON_Delete(ctx); free(ev); return deny(reason,cap,"p0_pair_durable_alert_owner_unavailable");
  }
  cJSON_Delete(ctx);
  free(ev);
  if (!valid) return deny(reason,cap,source_only ? "source_only_requires_local_owner_v3" :
    (intent?"p0_pair_durable_alert_owner_unavailable":"alert_provenance_unavailable"));
  if (reason && cap) snprintf(reason,cap,"validated_alert");
  return 1;
}
int edr_egress_frame_validate(const uint8_t *frame,size_t len,char *reason,size_t cap) {
  return frame_validate(frame,len,reason,cap,1);
}

typedef struct {
  const uint8_t *data;
  uint8_t *owned;
  uint32_t raw_len, count;
} BatchView;
static int batch_open(const uint8_t *header,size_t header_len,const uint8_t *payload,
    size_t len,BatchView *view,char *reason,size_t cap) {
  memset(view,0,sizeof(*view));
  if (!header || header_len!=12 || !payload || !len || len>EDR_EGRESS_BATCH_MAX)
    return deny(reason,cap,"batch_size_invalid");
  uint32_t magic=u32(header),count=u32(header+4),raw_len=u32(header+8);
  if (!count || count>EDR_EGRESS_FRAME_COUNT_MAX || !raw_len || raw_len>EDR_EGRESS_BATCH_MAX)
    return deny(reason,cap,"batch_limits_invalid");
  view->data=payload; view->raw_len=raw_len; view->count=count;
  if (magic==EDR_TRANSPORT_BATCH_MAGIC_RAW) {
    if (raw_len!=len) return deny(reason,cap,"batch_length_mismatch");
  } else if (magic==EDR_TRANSPORT_BATCH_MAGIC_LZ4) {
#ifdef EDR_HAVE_LZ4
    view->owned=malloc(raw_len);
    if (!view->owned) return deny(reason,cap,"egress_validation_allocation_failed");
    if (LZ4_decompress_safe((const char*)payload,(char*)view->owned,(int)len,(int)raw_len)!=(int)raw_len) {
      free(view->owned); view->owned=NULL; return deny(reason,cap,"compressed_batch_invalid");
    }
    view->data=view->owned;
#else
    return deny(reason,cap,"compressed_batch_decoder_unavailable");
#endif
  } else return deny(reason,cap,"unknown_batch_format");
  size_t offset=0;
  for (uint32_t i=0;i<count;i++) {
    if (raw_len-offset<4) { free(view->owned); view->owned=NULL;
      return deny(reason,cap,"frame_count_mismatch"); }
    uint32_t n=u32(view->data+offset); offset+=4;
    if (!n || n>EDR_EGRESS_FRAME_MAX || n>raw_len-offset) {
      free(view->owned); view->owned=NULL; return deny(reason,cap,"frame_length_invalid");
    }
    offset+=n;
  }
  if (offset!=raw_len) { free(view->owned); view->owned=NULL;
    return deny(reason,cap,"batch_trailing_bytes"); }
  return 1;
}
static int event_decode(const uint8_t *frame,size_t n,edr_v1_BehaviorEvent *event,
    char *reason,size_t cap) {
  pb_istream_t stream=pb_istream_from_buffer(frame,n);
  if (!schema_known(&stream,edr_v1_BehaviorEvent_fields,0))
    return deny(reason,cap,"unknown_or_invalid_event_schema");
  memset(event,0,sizeof(*event)); stream=pb_istream_from_buffer(frame,n);
  return pb_decode(&stream,edr_v1_BehaviorEvent_fields,event)?1:deny(reason,cap,"event_decode_failed");
}
static int p0_wire_matches(const EdrEgressP0PairAssociation *intent,
    const uint8_t *wire,size_t len,int combined) {
  if (!intent || !wire || len<=16 || len>EDR_EGRESS_FRAME_MAX+16u ||
      u32(wire)!=EDR_TRANSPORT_BATCH_MAGIC_RAW || u32(wire+4)!=1 ||
      u32(wire+8)!=len-12u || u32(wire+12)!=len-16u) return 0;
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event));
  if (!event) return 0;
  /* Intrinsic validation shares every schema/provenance rule with the final
   * guard, but cannot call the journal owner that is invoking this helper. */
  int valid=event_decode(wire+16,len-16,event,NULL,0) && event->has_behavior_alert==!!combined &&
    frame_validate(wire+16,len-16,NULL,0,0);
  cJSON *ctx=valid?object(event->ave_result_json):NULL;
  EdrEgressP0PairAssociation result;
  valid=valid && p0_terminal_tuple(event,ctx,combined?"result":"intent",&result);
  if (valid) {
    const char *a[]={intent->terminal_key,intent->endpoint_id,intent->tenant_id,intent->rule_id,
      intent->rules_bundle_version,intent->rules_bundle_sha256,intent->source_event_id,
      intent->canonical_image_path,intent->file_identity};
    const char *b[]={result.terminal_key,result.endpoint_id,result.tenant_id,result.rule_id,
      result.rules_bundle_version,result.rules_bundle_sha256,result.source_event_id,
      result.canonical_image_path,result.file_identity};
    for (size_t i=0;i<sizeof(a)/sizeof(a[0]);i++) if (!a[i] || strcmp(a[i],b[i])) valid=0;
    valid=valid && intent->pid==result.pid && intent->process_start_key==result.process_start_key &&
      intent->process_creation_filetime_100ns==result.process_creation_filetime_100ns;
  }
  cJSON_Delete(ctx); free(event); return valid;
}
int edr_egress_p0_combined_matches(const EdrEgressP0PairAssociation *tuple,
    const uint8_t *wire,size_t len) {
  return p0_wire_matches(tuple,wire,len,1);
}
int edr_egress_p0_intent_matches(const EdrEgressP0PairAssociation *tuple,
    const uint8_t *wire,size_t len) {
  return p0_wire_matches(tuple,wire,len,0);
}
int edr_egress_batch_has_p0_combined(const uint8_t *wire,size_t len) {
  if (!wire || len<=12) return -1;
  BatchView view;
  if (!batch_open(wire,12,wire+12,len-12,&view,NULL,0)) return -1;
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event));
  if (!event) { free(view.owned); return -1; }
  size_t offset=0; int found=0,understood=1;
  for (uint32_t i=0;i<view.count;i++) {
    uint32_t n=u32(view.data+offset); offset+=4;
    if (!event_decode(view.data+offset,n,event,NULL,0)) { understood=0; break; }
    cJSON *ctx=event->ave_result_json[0]?object(event->ave_result_json):NULL;
    const cJSON *terminal=cJSON_GetObjectItemCaseSensitive(ctx,"enforcement_terminal");
    if (event->ave_result_json[0] && !ctx) understood=0;
    if (event->has_behavior_alert && terminal) {
      if (cJSON_IsObject(terminal) && same(terminal,"phase","result")) found=1;
      else understood=0;
    }
    cJSON_Delete(ctx); if (!understood) break;
    offset+=n;
  }
  free(event); free(view.owned); return understood?found:-1;
}
int edr_egress_batch_validate(const uint8_t *header,size_t header_len,
    const uint8_t *payload,size_t len,char *reason,size_t cap) {
  BatchView view;
  if (!batch_open(header,header_len,payload,len,&view,reason,cap)) return 0;
  size_t offset=0; int ok=1;
  for (uint32_t i=0;i<view.count && ok;i++) {
    uint32_t n=u32(view.data+offset); offset+=4;
    ok=edr_egress_frame_validate(view.data+offset,n,reason,cap); offset+=n;
  }
  free(view.owned);
  if (ok && reason && cap) snprintf(reason,cap,"validated_alert_batch");
  return ok;
}
int edr_egress_batch_validate_scope(const uint8_t *header,size_t header_len,
    const uint8_t *payload,size_t len,const char *tenant,const char *endpoint,
    char *reason,size_t cap) {
  if (!tenant || !tenant[0] || !endpoint || !endpoint[0]) return deny(reason,cap,"egress_scope_unconfigured");
  BatchView view;
  if (!batch_open(header,header_len,payload,len,&view,reason,cap)) return 0;
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event));
  if (!event) { free(view.owned); return deny(reason,cap,"egress_validation_allocation_failed"); }
  size_t offset=0; int ok=1;
  for (uint32_t i=0;i<view.count && ok;i++) {
    uint32_t n=u32(view.data+offset); offset+=4;
    if (!event_decode(view.data+offset,n,event,reason,cap)) { ok=0; break; }
    if (strcmp(event->tenant_id,tenant) || strcmp(event->endpoint_id,endpoint)) {
      deny(reason,cap,"egress_scope_mismatch"); ok=0; break;
    }
    ok=edr_egress_frame_validate(view.data+offset,n,reason,cap); offset+=n;
  }
  free(event); free(view.owned);
  if (ok && reason && cap) snprintf(reason,cap,"validated_alert_batch_scope");
  return ok;
}
int edr_egress_batch_project_alerts(const uint8_t *header,size_t header_len,
    const uint8_t *payload,size_t len,const char *tenant,const char *endpoint,
    uint8_t **out,size_t *out_len,uint32_t *selected,char *reason,size_t cap) {
  if (out) *out=NULL;
  if (out_len) *out_len=0;
  if (selected) *selected=0;
  if (!out || !out_len || !selected || !tenant || !tenant[0] || !endpoint || !endpoint[0])
    return deny(reason,cap,"projection_arguments_invalid");
  BatchView view;
  if (!batch_open(header,header_len,payload,len,&view,reason,cap)) return 0;
  uint8_t *result=malloc(EDR_EGRESS_BATCH_MAX+12u);
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event));
  if (!result || !event) { free(result); free(event); free(view.owned);
    return deny(reason,cap,"egress_validation_allocation_failed"); }
  size_t offset=0,used=12; uint32_t kept=0; int ok=1;
  for (uint32_t i=0;i<view.count && ok;i++) {
    uint32_t n=u32(view.data+offset); offset+=4;
    const uint8_t *frame=view.data+offset;
    if (!event_decode(frame,n,event,reason,cap)) { ok=0; break; }
    if (strcmp(event->tenant_id,tenant) || strcmp(event->endpoint_id,endpoint)) {
      deny(reason,cap,"historical_scope_mismatch"); ok=0; break;
    }
    char why[128]; int eligible=edr_egress_frame_validate(frame,n,why,sizeof(why));
    if (!eligible) {
      cJSON *ctx=event->ave_result_json[0]?object(event->ave_result_json):NULL;
      /* A terminal is an exact action commitment, including when its
       * purpose/owner is unavailable. Historical maintenance must hold it,
       * never make a differently projected child from a failed terminal. */
      if (cJSON_GetObjectItemCaseSensitive(ctx,"enforcement_terminal")) {
        cJSON_Delete(ctx);deny(reason,cap,why);ok=0;break;
      }
      const JsonField *engine_fields=standalone_fields(event,ctx);
      int candidate=event->has_behavior_alert || engine_fields;
      int source_only=same(ctx,"p0_disposition","NOT_EVALUABLE");
      const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence");
      int nonpositive=engine_fields==standalone_pmfe_context && !pmfe_independent_positive(engine);
      const char *schema=string(ctx,"schema"),*engine_schema=string(engine,"schema");
      int unknown=(event->ave_result_json[0] && !ctx) ||
        (schema[0] && strcmp(schema,"agent_decision_v1") && strcmp(schema,"generic_engine_evidence_v1")) ||
        (engine_schema[0] && strcmp(engine_schema,"generic_engine_evidence_v1") && !engine_fields);
      cJSON_Delete(ctx);
      if (unknown || (strcmp(why,"alert_provenance_unavailable") &&
          strcmp(why,"source_only_requires_local_owner_v3") && strcmp(why,"rule_projection_authority_unproven") && strcmp(why,"alert_field_purpose_invalid"))) {
        deny(reason,cap,unknown?"historical_detection_schema_unknown":why); ok=0; break;
      }
      if (source_only) candidate=0;
      if (candidate) {
        /* Rewriting an association-bound nonpositive result would invalidate
         * its exact hash. It needs the existing cache owner, not a marker. */
        cJSON *legacy_subject=event->has_behavior_alert?object(event->behavior_alert.user_subject_json):NULL;
        if (same(legacy_subject,"subject_type","edr_dynamic_rule")) {
          EdrEgressRuleProjectionValidator validator=atomic_load_explicit(&rule_projection_validator,memory_order_acquire);
          void *user=atomic_load_explicit(&rule_projection_user,memory_order_relaxed);
          int proven=validator?validator(string(legacy_subject,"rule_id"),string(legacy_subject,"rules_bundle_sha256"),
              event->required_evidence_fields,event->operation_evidence_json,user):0;
          if (proven!=1) {
            cJSON_Delete(legacy_subject);deny(reason,cap,proven<0?"rule_projection_authority_unavailable":"historical_rule_projection_unproven");ok=0;break;
          }
          event->evidence_projection_version=EDR_EVIDENCE_PROJECTION_VERSION;
        }
        cJSON_Delete(legacy_subject);
        if (nonpositive || !edr_egress_event_project(event,why,sizeof(why))) {
          deny(reason,cap,nonpositive?"historical_pmfe_association_rebind_required":why); ok=0; break;
        }
        size_t available=EDR_EGRESS_BATCH_MAX-(used-12u);
        if (available<=4u) { deny(reason,cap,"projection_batch_capacity"); ok=0; break; }
        pb_ostream_t stream=pb_ostream_from_buffer(result+used+4u,available-4u);
        if (!pb_encode(&stream,edr_v1_BehaviorEvent_fields,event) ||
            stream.bytes_written>EDR_EGRESS_FRAME_MAX ||
            !edr_egress_frame_validate(result+used+4u,stream.bytes_written,why,sizeof(why))) {
          deny(reason,cap,"historical_alert_basis_unproven"); ok=0; break;
        }
        put_u32(result+used,(uint32_t)stream.bytes_written); used+=stream.bytes_written+4u; kept++;
      }
    } else {
      if ((size_t)n+4u>EDR_EGRESS_BATCH_MAX-(used-12u)) {
        deny(reason,cap,"projection_batch_capacity"); ok=0; break;
      }
      put_u32(result+used,n); memcpy(result+used+4u,frame,n); used+=n+4u; kept++;
    }
    offset+=n;
  }
  free(event); free(view.owned);
  if (!ok) { free(result); return 0; }
  put_u32(result,EDR_TRANSPORT_BATCH_MAGIC_RAW); put_u32(result+4,kept); put_u32(result+8,(uint32_t)(used-12));
  *out=result; *out_len=used; *selected=kept;
  if (reason && cap) snprintf(reason,cap,kept?"historical_alert_projection":"historical_no_eligible_alerts");
  return 1;
}
static int batch_note(const uint8_t *header,size_t header_len,const uint8_t *payload,
    size_t len,int removed,char *reason,size_t cap) {
  /* Receipt caller verifies the real server batch-ID/body-hash ACK first.
   * Removal caller runs only after queue FULL delete; the cache independently
   * requires an ACKed exact result. Completion must remain idempotent after
   * the cache stops authorizing a completed nonpositive result. */
  if (!removed && !edr_egress_batch_validate(header,header_len,payload,len,reason,cap)) return 0;
  BatchView view;
  if (!batch_open(header,header_len,payload,len,&view,reason,cap)) return 0;
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event));
  if (!event) { free(view.owned); return deny(reason,cap,"egress_receipt_allocation_failed"); }
  EdrEgressPmfeReceiptHandler handler=removed?
    atomic_load_explicit(&pmfe_queue_removed_handler,memory_order_acquire):
    atomic_load_explicit(&pmfe_receipt_handler,memory_order_acquire);
  void *user=removed?atomic_load_explicit(&pmfe_queue_removed_user,memory_order_relaxed):
    atomic_load_explicit(&pmfe_receipt_user,memory_order_relaxed);
  size_t offset=0; int ok=1;
  for (uint32_t i=0;i<view.count && ok;i++) {
    uint32_t n=u32(view.data+offset); offset+=4;
    if (!event_decode(view.data+offset,n,event,reason,cap)) { ok=0; break; }
    if (!event->has_behavior_alert && event->type==EDR_EVENT_PMFE_SCAN_RESULT) {
      cJSON *ctx=object(event->ave_result_json);
      const cJSON *engine=cJSON_GetObjectItemCaseSensitive(ctx,"engine_evidence");
      if (same(engine,"schema","pmfe_result_v1") &&
          cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(engine,"followup_only")) && string(engine,"source_alert_id")[0]) {
        int positive=pmfe_independent_positive(engine);
        int result=handler?handler(string(engine,"source_alert_id"),event->endpoint_id,event->tenant_id,
          event->event_id,event->pid,event->process_start_key,event->process_creation_filetime_100ns,
          event->event_time_ns,string(engine,"status"),string(engine,"verdict"),view.data+offset,n,user):0;
        if (result<0 || (!positive && result!=1)) {
          deny(reason,cap,result<0?"pmfe_receipt_storage_failed":"pmfe_receipt_owner_unavailable"); ok=0;
        }
      }
      cJSON_Delete(ctx);
    }
    offset+=n;
  }
  free(event); free(view.owned);
  if (ok && reason && cap) snprintf(reason,cap,removed?"validated_queue_removal_recorded":"validated_receipt_recorded");
  return ok;
}
int edr_egress_batch_note_receipt(const uint8_t *header,size_t header_len,
    const uint8_t *payload,size_t len,char *reason,size_t cap) {
  return batch_note(header,header_len,payload,len,0,reason,cap);
}
int edr_egress_batch_note_queue_removed(const uint8_t *header,size_t header_len,
    const uint8_t *payload,size_t len,char *reason,size_t cap) {
  return batch_note(header,header_len,payload,len,1,reason,cap);
}
