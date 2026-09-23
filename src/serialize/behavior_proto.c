#include "edr/behavior_proto.h"

#include "edr/ave_sdk.h"
#include "edr/pmfe.h"
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

typedef struct {
  int truncated;
  char fields[512];
} EdrTransportCompleteness;

static size_t bounded_cstr_len(const char *src, size_t cap);

/* `truncated_fields` is a bounded comma-separated wire contract.  Source
 * omissions are already qualified as `source.<field>`; encoder projection
 * omissions retain their historic unqualified names.  Do not silently retain
 * a prefix when the list itself fills: the explicit marker is evidence that
 * the named set is incomplete. */
static int comma_list_has_exact_span(const char *list, const char *item,
                                     size_t item_len) {
  const char *start;
  if (!list || !item || item_len == 0u) return 0;
  start = list;
  while (*start) {
    const char *end = strchr(start, ',');
    size_t len = end ? (size_t)(end - start) : strlen(start);
    if (len == item_len && memcmp(start, item, len) == 0) return 1;
    if (!end) break;
    start = end + 1u;
  }
  return 0;
}

static void comma_list_mark_overflow(char *dst, size_t cap, const char *marker) {
  size_t used;
  size_t marker_len;
  if (!dst || cap == 0u || !marker || !marker[0]) return;
  used = bounded_cstr_len(dst, cap);
  marker_len = strlen(marker);
  if (used < cap && comma_list_has_exact_span(dst, marker, marker_len)) return;
  if (marker_len >= cap) {
    dst[0] = '\0';
    return;
  }
  if (used < cap && used + (used ? 1u : 0u) + marker_len < cap) {
    if (used) dst[used++] = ',';
    memcpy(dst + used, marker, marker_len + 1u);
    return;
  }
  memcpy(dst, marker, marker_len + 1u);
}

static int comma_list_append_unique_span(char *dst, size_t cap, const char *item,
                                         size_t item_len, const char *overflow_marker) {
  size_t used;
  if (!dst || cap == 0u || !item || item_len == 0u) return 0;
  used = bounded_cstr_len(dst, cap);
  if (used >= cap || item_len >= cap) {
    comma_list_mark_overflow(dst, cap, overflow_marker);
    return 0;
  }
  if (comma_list_has_exact_span(dst, item, item_len)) return 1;
  if (used + (used ? 1u : 0u) + item_len >= cap) {
    comma_list_mark_overflow(dst, cap, overflow_marker);
    return 0;
  }
  if (used) dst[used++] = ',';
  memcpy(dst + used, item, item_len);
  dst[used + item_len] = '\0';
  return 1;
}

static void comma_list_merge(char *dst, size_t dst_cap, const char *src, size_t src_cap,
                             const char *overflow_marker) {
  size_t src_len;
  size_t pos = 0u;
  if (!dst || dst_cap == 0u || !src || src_cap == 0u || !src[0]) return;
  src_len = bounded_cstr_len(src, src_cap);
  if (src_len >= src_cap) {
    comma_list_mark_overflow(dst, dst_cap, overflow_marker);
    return;
  }
  while (pos < src_len) {
    size_t begin = pos;
    while (pos < src_len && src[pos] != ',') ++pos;
    if (pos == begin) {
      comma_list_mark_overflow(dst, dst_cap, overflow_marker);
    } else {
      (void)comma_list_append_unique_span(dst, dst_cap, src + begin, pos - begin,
                                          overflow_marker);
    }
    if (pos < src_len) ++pos;
  }
}

static void merge_truncated_fields(char *dst, size_t dst_cap,
                                   const char *source_fields, size_t source_fields_cap,
                                   const EdrTransportCompleteness *transport) {
  if (!dst || dst_cap == 0u) return;
  dst[0] = '\0';
  comma_list_merge(dst, dst_cap, source_fields, source_fields_cap,
                   "truncated_fields.list_overflow");
  if (transport) {
    comma_list_merge(dst, dst_cap, transport->fields, sizeof(transport->fields),
                     "truncated_fields.list_overflow");
  }
}

static size_t bounded_cstr_len(const char *src, size_t cap) {
  size_t n = 0u;
  if (!src) return 0u;
  while (n < cap && src[n] != '\0') ++n;
  return n;
}

/* Return the longest UTF-8 prefix that fits in max bytes. Invalid leading
 * bytes are copied as individual bytes; a valid multibyte sequence is never
 * cut in half. */
static size_t utf8_prefix_len(const char *src, size_t len, size_t max) {
  size_t i = 0u;
  while (i < len && i < max) {
    const unsigned char c = (unsigned char)src[i];
    size_t width = 1u;
    if (c >= 0xc2u && c <= 0xdfu) width = 2u;
    else if (c >= 0xe0u && c <= 0xefu) width = 3u;
    else if (c >= 0xf0u && c <= 0xf4u) width = 4u;
    if (width == 1u) {
      ++i;
      continue;
    }
    if (i + width > len || i + width > max) break;
    for (size_t j = 1u; j < width; ++j) {
      if (((unsigned char)src[i + j] & 0xc0u) != 0x80u) {
        width = 1u;
        break;
      }
    }
    if (width == 1u) {
      ++i;
      continue;
    }
    i += width;
  }
  return i;
}

/* EdrBehaviorRecord fields have fixed, known capacity. Unlike snprintf(),
 * this never scans beyond that capacity and reports an incomplete transport
 * projection to the sole BehaviorEvent completeness contract. */
static int copy_record_string(char *dst, size_t dst_cap, const char *src,
                              size_t src_cap) {
  size_t src_len;
  size_t copied;
  int truncated;
  if (!dst || dst_cap == 0u) return src && src[0] != '\0';
  if (!src || src_cap == 0u) {
    dst[0] = '\0';
    return 0;
  }
  src_len = bounded_cstr_len(src, src_cap);
  truncated = src_len == src_cap;
  copied = src_len;
  if (copied >= dst_cap) {
    copied = dst_cap - 1u;
    truncated = 1;
  }
  copied = utf8_prefix_len(src, src_len, copied);
  if (copied != src_len) truncated = 1;
  if (copied > 0u) memcpy(dst, src, copied);
  dst[copied] = '\0';
  return truncated;
}

static void note_transport_truncation(EdrTransportCompleteness *state,
                                      const char *field) {
  if (!state || !field || !field[0]) return;
  state->truncated = 1;
  (void)comma_list_append_unique_span(state->fields, sizeof(state->fields), field,
                                      strlen(field), "transport.list_overflow");
}

static void copy_record_transport_field(char *dst, size_t dst_cap, const char *src,
                                        size_t src_cap, EdrTransportCompleteness *state,
                                        const char *field) {
  if (copy_record_string(dst, dst_cap, src, src_cap)) {
    note_transport_truncation(state, field);
  }
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
  unsigned images = pmfe_detail_i(r->script_snippet, "private_exec_image_hits") > 0 ? 1u : 0u;
  unsigned threads = pmfe_detail_i(r->script_snippet, "private_exec_thread_starts") > 0 ? 1u : 0u;
  int injection = pmfe_detail_i(r->script_snippet, "injection_observed") > 0;
  unsigned memfd = pmfe_detail_i(r->script_snippet, "memfd_exec") > 0 ? 1u : 0u;
  unsigned deleted = pmfe_detail_i(r->script_snippet, "deleted_exec") > 0 ? 1u : 0u;
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
    images = images || pmfe_has_positive_json_number(r->pmfe_snapshot, "image_hits");
    dns_hits = dns_hits || pmfe_has_positive_json_number(r->pmfe_snapshot, "dns");
  }
  float conf = edr_pmfe_evidence_score((unsigned)stomp, (unsigned)dns_hits,
      dns_best, ave, images, threads, injection, memfd, deleted);
  m->has_ave_behavior_feed = true;
  m->ave_behavior_feed.pmfe_confidence = conf;
  m->ave_behavior_feed.pmfe_pe_found = images > 0u;
  m->ave_behavior_feed.pmfe_dns_tunnel = (dns_hits || dns_best >= 0.30f) ? true : false;
}

static void fill_ave_behavior_feed(edr_v1_BehaviorEvent *m, const EdrBehaviorRecord *r,
                                   EdrTransportCompleteness *transport) {
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
    copy_record_transport_field(m->ave_behavior_feed.target_path,
                                sizeof(m->ave_behavior_feed.target_path), r->file_path,
                                sizeof(r->file_path), transport, "file_path");
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
    copy_record_transport_field(m->ave_behavior_feed.target_path,
                                sizeof(m->ave_behavior_feed.target_path), r->reg_key_path,
                                sizeof(r->reg_key_path), transport, "reg_key_path");
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

static int record_has_process_context(const EdrBehaviorRecord *r) {
  return r && (r->parent_name[0] || r->parent_path[0] || r->integrity_level[0] ||
               r->parent_cmdline[0] || r->current_directory[0] ||
               r->process_creation_time[0] || r->token_elevation != 0u ||
               r->grandparent_pid != 0u || r->grandparent_name[0] ||
               r->grandparent_path[0]);
}

static void fill_process_context(edr_v1_BehaviorEvent *m, const EdrBehaviorRecord *r,
                                 EdrTransportCompleteness *transport) {
  edr_v1_ProcessContext *ctx = &m->process_context;
  m->has_process_context = record_has_process_context(r) ? true : false;
  memset(ctx, 0, sizeof(*ctx));
  if (!m->has_process_context) return;

  if (r->parent_name[0]) {
    ctx->has_parent_name = true;
    copy_record_transport_field(ctx->parent_name, sizeof(ctx->parent_name), r->parent_name,
                                sizeof(r->parent_name), transport, "parent_name");
  }
  if (r->parent_path[0]) {
    ctx->has_parent_path = true;
    copy_record_transport_field(ctx->parent_path, sizeof(ctx->parent_path), r->parent_path,
                                sizeof(r->parent_path), transport, "parent_path");
  }
  if (r->integrity_level[0]) {
    ctx->has_integrity_level = true;
    copy_str(ctx->integrity_level, sizeof(ctx->integrity_level), r->integrity_level);
  }
  if (r->parent_cmdline[0]) {
    ctx->has_parent_cmdline = true;
    copy_record_transport_field(ctx->parent_cmdline, sizeof(ctx->parent_cmdline),
                                r->parent_cmdline, sizeof(r->parent_cmdline), transport,
                                "parent_cmdline");
  }
  if (r->current_directory[0]) {
    ctx->has_current_directory = true;
    copy_record_transport_field(ctx->current_directory, sizeof(ctx->current_directory),
                                r->current_directory, sizeof(r->current_directory), transport,
                                "current_directory");
  }
  if (r->process_creation_time[0]) {
    ctx->has_process_creation_time = true;
    copy_str(ctx->process_creation_time, sizeof(ctx->process_creation_time),
             r->process_creation_time);
  }
  /* EdrBehaviorRecord uses 1..3 for captured token elevation and 0 for absent.
   * The optional wire field still lets consumers preserve an explicit zero
   * sent by another conforming producer. */
  if (r->token_elevation != 0u) {
    ctx->has_token_elevation = true;
    ctx->token_elevation = r->token_elevation;
  }
  if (r->grandparent_pid != 0u) {
    ctx->has_grandparent_pid = true;
    ctx->grandparent_pid = r->grandparent_pid;
  }
  if (r->grandparent_name[0]) {
    ctx->has_grandparent_name = true;
    copy_str(ctx->grandparent_name, sizeof(ctx->grandparent_name), r->grandparent_name);
  }
  if (r->grandparent_path[0]) {
    ctx->has_grandparent_path = true;
    copy_record_transport_field(ctx->grandparent_path, sizeof(ctx->grandparent_path),
                                r->grandparent_path, sizeof(r->grandparent_path), transport,
                                "grandparent_path");
  }
}

static void fill_oneof_detail(edr_v1_BehaviorEvent *m, const EdrBehaviorRecord *r,
                              EdrTransportCompleteness *transport) {
  m->which_detail = 0;
  memset(&m->detail, 0, sizeof(m->detail));

  if (r->dns_query[0]) {
    m->which_detail = edr_v1_BehaviorEvent_dns_tag;
    copy_record_transport_field(m->detail.dns.query_name, sizeof(m->detail.dns.query_name),
                                r->dns_query, sizeof(r->dns_query), transport, "dns_query");
    return;
  }
  if (r->reg_key_path[0] || r->reg_value_name[0] || r->reg_value_data[0] || r->reg_op[0]) {
    m->which_detail = edr_v1_BehaviorEvent_registry_tag;
    copy_record_transport_field(m->detail.registry.key_path, sizeof(m->detail.registry.key_path),
                                r->reg_key_path, sizeof(r->reg_key_path), transport, "reg_key_path");
    copy_record_transport_field(m->detail.registry.value_name, sizeof(m->detail.registry.value_name),
                                r->reg_value_name, sizeof(r->reg_value_name), transport, "reg_value_name");
    copy_record_transport_field(m->detail.registry.value_data, sizeof(m->detail.registry.value_data),
                                r->reg_value_data, sizeof(r->reg_value_data), transport, "reg_value_data");
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
    copy_record_transport_field(m->detail.network.network_aux_path,
                                sizeof(m->detail.network.network_aux_path), r->network_aux_path,
                                sizeof(r->network_aux_path), transport, "network_aux_path");
    return;
  }
  if (r->file_path[0] || r->file_op[0]) {
    m->which_detail = edr_v1_BehaviorEvent_file_tag;
    copy_str(m->detail.file.operation, sizeof(m->detail.file.operation), r->file_op);
    copy_record_transport_field(m->detail.file.target_path, sizeof(m->detail.file.target_path),
                                r->file_path, sizeof(r->file_path), transport, "file_path");
    m->detail.file.file_size = 0;
    m->detail.file.target_has_motw = (r->file_target_has_motw != 0u);
    return;
  }
  if (r->script_snippet[0]) {
    m->which_detail = edr_v1_BehaviorEvent_script_tag;
    copy_record_transport_field(m->detail.script.snippet, sizeof(m->detail.script.snippet),
                                r->script_snippet, sizeof(r->script_snippet), transport,
                                "script_snippet");
    return;
  }
  if (record_has_process_context(r)) {
    m->which_detail = edr_v1_BehaviorEvent_process_tag;
    copy_record_transport_field(m->detail.process.parent_name,
                                sizeof(m->detail.process.parent_name), r->parent_name,
                                sizeof(r->parent_name), transport, "parent_name");
    copy_record_transport_field(m->detail.process.parent_path, sizeof(m->detail.process.parent_path),
                                r->parent_path, sizeof(r->parent_path), transport, "parent_path");
    copy_str(m->detail.process.integrity_level, sizeof(m->detail.process.integrity_level),
             r->integrity_level);
    /* 取证增强字段：端侧已采集，补齐上报（服务端 pbwire 按字段号 4-10 接住落库）。 */
    copy_record_transport_field(m->detail.process.parent_cmdline,
                                sizeof(m->detail.process.parent_cmdline), r->parent_cmdline,
                                sizeof(r->parent_cmdline), transport, "parent_cmdline");
    copy_record_transport_field(m->detail.process.current_directory,
                                sizeof(m->detail.process.current_directory), r->current_directory,
                                sizeof(r->current_directory), transport, "current_directory");
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

static void fill_behavior_record_event_fields(edr_v1_BehaviorEvent *msg,
                                              const EdrBehaviorRecord *r) {
  EdrTransportCompleteness transport = {0};
  copy_str(msg->event_id, sizeof(msg->event_id), r->event_id);
  copy_str(msg->endpoint_id, sizeof(msg->endpoint_id), r->endpoint_id);
  copy_str(msg->tenant_id, sizeof(msg->tenant_id), r->tenant_id);
  msg->type = (int32_t)r->type;
  msg->event_time_ns = r->event_time_ns;
  msg->pid = r->pid;
  msg->ppid = r->ppid;
  copy_str(msg->process_name, sizeof(msg->process_name), r->process_name);
  copy_record_transport_field(msg->cmdline, sizeof(msg->cmdline), r->cmdline,
                              sizeof(r->cmdline), &transport, "cmdline");
  copy_str(msg->exe_hash, sizeof(msg->exe_hash), r->exe_hash);
  copy_record_transport_field(msg->exe_path, sizeof(msg->exe_path), r->exe_path,
                              sizeof(r->exe_path), &transport, "exe_path");
  copy_str(msg->username, sizeof(msg->username), r->username);
  copy_str(msg->domain, sizeof(msg->domain), r->domain);
  copy_str(msg->user_sid, sizeof(msg->user_sid), r->user_sid);
  copy_str(msg->logon_id, sizeof(msg->logon_id), r->logon_id);
  copy_str(msg->creator_username, sizeof(msg->creator_username), r->creator_username);
  copy_str(msg->creator_domain, sizeof(msg->creator_domain), r->creator_domain);
  copy_str(msg->creator_sid, sizeof(msg->creator_sid), r->creator_sid);
  copy_str(msg->creator_logon_id, sizeof(msg->creator_logon_id), r->creator_logon_id);
  copy_str(msg->identity_source, sizeof(msg->identity_source), r->identity_source);
  copy_str(msg->identity_quality, sizeof(msg->identity_quality), r->identity_quality);
  msg->process_start_key = r->process_start_key;
  msg->process_creation_filetime_100ns = r->process_creation_filetime_100ns;
  copy_record_transport_field(msg->process_generation_source,
                              sizeof(msg->process_generation_source), r->process_generation_source,
                              sizeof(r->process_generation_source), &transport,
                              "process_generation_source");
  copy_record_transport_field(msg->image_path_raw, sizeof(msg->image_path_raw),
                              r->image_path_raw, sizeof(r->image_path_raw), &transport,
                              "image_path_raw");
  copy_record_transport_field(msg->image_path_canonical, sizeof(msg->image_path_canonical),
                              r->image_path_canonical, sizeof(r->image_path_canonical), &transport,
                              "image_path_canonical");
  copy_str(msg->image_path_namespace, sizeof(msg->image_path_namespace),
           r->image_path_namespace);
  copy_str(msg->image_path_resolution_status, sizeof(msg->image_path_resolution_status),
           r->image_path_resolution_status);
  copy_str(msg->image_path_resolution_source, sizeof(msg->image_path_resolution_source),
           r->image_path_resolution_source);
  copy_record_transport_field(msg->source_completeness, sizeof(msg->source_completeness),
                              r->source_completeness, sizeof(r->source_completeness), &transport,
                              "source_completeness");
  msg->evidence_revision = r->evidence_revision;
  copy_str(msg->parent_resolution_status, sizeof(msg->parent_resolution_status),
           r->parent_resolution_status);
  copy_str(msg->parent_resolution_source, sizeof(msg->parent_resolution_source),
           r->parent_resolution_source);
  copy_record_transport_field(msg->parent_creation_time, sizeof(msg->parent_creation_time),
                              r->parent_creation_time, sizeof(r->parent_creation_time), &transport,
                              "parent_creation_time");
  /* Keep parent identity outside `detail`: non-process detail oneofs must not
   * discard the captured parent record. ProcessDetail below remains the
   * compatibility projection for legacy consumers. */
  copy_record_transport_field(msg->parent_name, sizeof(msg->parent_name), r->parent_name,
                              sizeof(r->parent_name), &transport, "parent_name");
  copy_record_transport_field(msg->parent_path, sizeof(msg->parent_path), r->parent_path,
                              sizeof(r->parent_path), &transport, "parent_path");
  fill_process_context(msg, r, &transport);
  msg->session_id = r->session_id;
  if (r->detection_context[0]) {
    copy_record_transport_field(msg->ave_result_json, sizeof(msg->ave_result_json),
                                r->detection_context, sizeof(r->detection_context), &transport,
                                "detection_context");
  } else if (r->pmfe_snapshot[0]) {
    copy_str(msg->ave_result_json, sizeof(msg->ave_result_json), r->pmfe_snapshot);
  } else {
    copy_str(msg->ave_result_json, sizeof(msg->ave_result_json), "");
  }
  msg->priority = r->priority;

  fill_oneof_detail(msg, r, &transport);
  fill_ave_behavior_feed(msg, r, &transport);

  copy_str(msg->transport_completeness, sizeof(msg->transport_completeness),
           transport.truncated ? "TRUNCATED" : "COMPLETE");
  merge_truncated_fields(msg->truncated_fields, sizeof(msg->truncated_fields),
                         r->source_truncated_fields,
                         sizeof(r->source_truncated_fields), &transport);

  msg->mitre_ttps_count = 0;
  if (r->mitre_ttp_count > 0) {
    int n = r->mitre_ttp_count;
    if (n > 8) {
      n = 8;
    }
    msg->mitre_ttps_count = (pb_size_t)n;
    for (int i = 0; i < n; i++) {
      copy_str(msg->mitre_ttps[i], sizeof(msg->mitre_ttps[i]), r->mitre_ttps[i]);
    }
  }
}

static void fill_behavior_alert_event_fields(edr_v1_BehaviorEvent *msg,
                                             const AVEBehaviorAlert *a, const char *endpoint_id,
                                             const char *tenant_id) {
  snprintf(msg->event_id, sizeof(msg->event_id), "bahv_%lld_%u", (long long)a->timestamp_ns,
           (unsigned)a->pid);
  copy_str(msg->endpoint_id, sizeof(msg->endpoint_id), endpoint_id ? endpoint_id : "");
  copy_str(msg->tenant_id, sizeof(msg->tenant_id), tenant_id ? tenant_id : "");
  msg->type = (int32_t)EDR_EVENT_BEHAVIOR_ONNX_ALERT;
  msg->event_time_ns = a->timestamp_ns;
  msg->pid = a->pid;
  msg->ppid = a->ppid;
  copy_str(msg->process_name, sizeof(msg->process_name),
           a->process_name[0] ? a->process_name : "");
  copy_str(msg->cmdline, sizeof(msg->cmdline), a->cmdline[0] ? a->cmdline : "");
  copy_str(msg->exe_path, sizeof(msg->exe_path), a->process_path[0] ? a->process_path : "");
  msg->priority = 0u;
}

static void fill_behavior_alert_fields(edr_v1_BehaviorEvent *msg, const AVEBehaviorAlert *a) {
  msg->has_behavior_alert = true;
  msg->behavior_alert.anomaly_score = a->anomaly_score;
  msg->behavior_alert.tactic_probs_count = 14;
  for (int i = 0; i < 14; i++) {
    msg->behavior_alert.tactic_probs[i] = a->tactic_probs[i];
  }
  copy_str(msg->behavior_alert.triggered_tactics, sizeof(msg->behavior_alert.triggered_tactics),
           a->triggered_tactics[0] ? a->triggered_tactics : "");
  msg->behavior_alert.skip_ai_analysis = a->skip_ai_analysis;
  msg->behavior_alert.needs_l2_review = a->needs_l2_review;
  msg->behavior_alert.timestamp_ns = a->timestamp_ns;
  msg->behavior_alert.pid = a->pid;
  copy_str(msg->behavior_alert.process_name, sizeof(msg->behavior_alert.process_name),
           a->process_name[0] ? a->process_name : "");
  copy_str(msg->behavior_alert.process_path, sizeof(msg->behavior_alert.process_path),
           a->process_path[0] ? a->process_path : "");
  copy_str(msg->behavior_alert.related_iocs_json, sizeof(msg->behavior_alert.related_iocs_json),
           a->related_iocs_json[0] ? a->related_iocs_json : "");
  copy_str(msg->behavior_alert.user_subject_json, sizeof(msg->behavior_alert.user_subject_json),
           a->user_subject_json[0] ? a->user_subject_json : "");
  if (a->user_subject_json[0]) {
    copy_str(msg->behavior_alert.user_subject_status,
             sizeof(msg->behavior_alert.user_subject_status), "present");
  } else {
    copy_str(msg->behavior_alert.user_subject_status,
             sizeof(msg->behavior_alert.user_subject_status), "withheld");
    copy_str(msg->behavior_alert.user_subject_withheld_reason,
             sizeof(msg->behavior_alert.user_subject_withheld_reason),
             "not_provided_by_agent");
  }
  msg->behavior_alert.ppid = a->ppid;
  copy_str(msg->behavior_alert.cmdline, sizeof(msg->behavior_alert.cmdline),
           a->cmdline[0] ? a->cmdline : "");
}

static size_t encode_behavior_event(const edr_v1_BehaviorEvent *msg, uint8_t *out, size_t out_cap) {
  pb_ostream_t stream = pb_ostream_from_buffer(out, out_cap);
  if (!pb_encode(&stream, edr_v1_BehaviorEvent_fields, msg)) {
    return 0;
  }
  return stream.bytes_written;
}

size_t edr_behavior_record_encode_protobuf(const EdrBehaviorRecord *r, uint8_t *out,
                                           size_t out_cap) {
  if (!r || !out || out_cap < 16u) {
    return 0;
  }

  edr_v1_BehaviorEvent msg;
  memset(&msg, 0, sizeof(msg));
  fill_behavior_record_event_fields(&msg, r);

  return encode_behavior_event(&msg, out, out_cap);
}

size_t edr_behavior_alert_encode_protobuf(const AVEBehaviorAlert *a, const char *endpoint_id,
                                          const char *tenant_id, uint8_t *out, size_t out_cap) {
  if (!a || !out || out_cap < edr_v1_BehaviorEvent_size) {
    return 0;
  }
  edr_v1_BehaviorEvent msg;
  memset(&msg, 0, sizeof(msg));

  fill_behavior_alert_event_fields(&msg, a, endpoint_id, tenant_id);
  fill_behavior_alert_fields(&msg, a);
  return encode_behavior_event(&msg, out, out_cap);
}

size_t edr_behavior_record_alert_encode_protobuf(const EdrBehaviorRecord *r,
                                                 const AVEBehaviorAlert *a, uint8_t *out,
                                                 size_t out_cap) {
  if (!r || !a || !out || out_cap < 16u) {
    return 0;
  }

  edr_v1_BehaviorEvent msg;
  memset(&msg, 0, sizeof(msg));
  fill_behavior_record_event_fields(&msg, r);
  fill_behavior_alert_fields(&msg, a);
  return encode_behavior_event(&msg, out, out_cap);
}
