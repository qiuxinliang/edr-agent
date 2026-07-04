#include "edr/transport_v2.h"

#include "edr/config.h"
#include "edr/ingest_http.h"

#include <stdio.h>
#include <string.h>

static EdrTransportV2Config s_cfg;
static EdrTransportV2Runtime s_rt;
static int s_next_stream_id = 1;

static void tv2_copy(char *dst, size_t cap, const char *src, const char *fallback) {
  if (!dst || cap == 0u) {
    return;
  }
  snprintf(dst, cap, "%s", (src && src[0]) ? src : ((fallback && fallback[0]) ? fallback : ""));
}

static const char *channel_name(EdrTransportV2Channel channel) {
  switch (channel) {
    case EDR_TV2_CHANNEL_CONTROL: return "control";
    case EDR_TV2_CHANNEL_HIGH_SEV_TELEMETRY: return "high_sev_telemetry";
    case EDR_TV2_CHANNEL_NORMAL_TELEMETRY: return "normal_telemetry";
    case EDR_TV2_CHANNEL_BACKFILL: return "backfill";
    case EDR_TV2_CHANNEL_UPLOAD: return "upload";
    case EDR_TV2_CHANNEL_COMMAND_RESULT: return "command_result";
    default: return "unknown";
  }
}

static const char *operation_name(EdrTransportV2Operation op) {
  switch (op) {
    case EDR_TV2_OP_REPORT_EVENTS: return "report_events";
    case EDR_TV2_OP_COMMAND_RESULT: return "command_result";
    case EDR_TV2_OP_UPLOAD_FILE: return "upload_file";
    case EDR_TV2_OP_CONTROL_STREAM: return "control_stream";
    case EDR_TV2_OP_CONTROL_ACK: return "control_ack";
    case EDR_TV2_OP_RESUME: return "resume";
    default: return "unknown";
  }
}

static void note_channel(EdrTransportV2Channel channel) {
  switch (channel) {
    case EDR_TV2_CHANNEL_CONTROL: s_rt.channel_control++; break;
    case EDR_TV2_CHANNEL_HIGH_SEV_TELEMETRY: s_rt.channel_high_sev++; break;
    case EDR_TV2_CHANNEL_NORMAL_TELEMETRY: s_rt.channel_normal++; break;
    case EDR_TV2_CHANNEL_BACKFILL: s_rt.channel_backfill++; break;
    case EDR_TV2_CHANNEL_UPLOAD: s_rt.channel_upload++; break;
    case EDR_TV2_CHANNEL_COMMAND_RESULT: s_rt.channel_command_result++; break;
    default: break;
  }
}

void edr_transport_v2_init_from_config(const struct EdrConfig *cfg) {
  memset(&s_cfg, 0, sizeof(s_cfg));
  memset(&s_rt, 0, sizeof(s_rt));
  s_cfg.enabled = 1;
  s_cfg.h2_enabled = 1;
  s_cfg.h2_required = 0;
  s_cfg.control_stream_enabled = 1;
  s_cfg.long_poll_fallback = 1;
  s_cfg.report_events_v2_enabled = 1;
  s_cfg.telemetry_sampling_pct = 100u;
  if (cfg) {
    s_cfg.h2_enabled = cfg->platform.http2_enabled ? 1 : 0;
    s_cfg.h2_required = cfg->platform.http2_require ? 1 : 0;
    s_cfg.control_stream_enabled = cfg->platform.control_stream_enabled ? 1 : 0;
    s_cfg.long_poll_fallback = cfg->platform.long_poll_fallback ? 1 : 0;
    s_cfg.report_events_v2_enabled = cfg->platform.report_events_v2_enabled ? 1 : 0;
    s_cfg.telemetry_sampling_pct = cfg->platform.telemetry_sampling_pct;
    tv2_copy(s_cfg.data_plane_encoding, sizeof(s_cfg.data_plane_encoding),
             cfg->platform.data_plane_encoding, "protobuf");
    tv2_copy(s_cfg.data_plane_compression, sizeof(s_cfg.data_plane_compression),
             cfg->platform.data_plane_compression, "identity");
    tv2_copy(s_cfg.dict_ver, sizeof(s_cfg.dict_ver), cfg->platform.control_dict_version,
             "edr-zstd-dict-v1");
    tv2_copy(s_cfg.schema_ver, sizeof(s_cfg.schema_ver), cfg->platform.control_schema_version,
             "edr-control-schema-v1");
    tv2_copy(s_cfg.profile_id, sizeof(s_cfg.profile_id), cfg->platform.control_profile_id,
             "default-http1-protobuf");
    tv2_copy(s_cfg.qos_dscp, sizeof(s_cfg.qos_dscp), cfg->platform.qos_dscp, "AF21");
    tv2_copy(s_cfg.threshold, sizeof(s_cfg.threshold), cfg->platform.telemetry_threshold, "medium");
    s_cfg.zstd_requested = strcmp(s_cfg.data_plane_compression, "zstd") == 0 ? 1 : 0;
  } else {
    tv2_copy(s_cfg.data_plane_encoding, sizeof(s_cfg.data_plane_encoding), NULL, "protobuf");
    tv2_copy(s_cfg.data_plane_compression, sizeof(s_cfg.data_plane_compression), NULL, "identity");
    tv2_copy(s_cfg.dict_ver, sizeof(s_cfg.dict_ver), NULL, "edr-zstd-dict-v1");
    tv2_copy(s_cfg.schema_ver, sizeof(s_cfg.schema_ver), NULL, "edr-control-schema-v1");
    tv2_copy(s_cfg.profile_id, sizeof(s_cfg.profile_id), NULL, "default-http1-protobuf");
    tv2_copy(s_cfg.qos_dscp, sizeof(s_cfg.qos_dscp), NULL, "AF21");
    tv2_copy(s_cfg.threshold, sizeof(s_cfg.threshold), NULL, "medium");
  }
  if (s_cfg.telemetry_sampling_pct < 1u) {
    s_cfg.telemetry_sampling_pct = 1u;
  }
  if (s_cfg.telemetry_sampling_pct > 100u) {
    s_cfg.telemetry_sampling_pct = 100u;
  }
  edr_transport_v2_get_runtime(&s_rt);
}

void edr_transport_v2_get_config(EdrTransportV2Config *out) {
  if (out) {
    *out = s_cfg;
  }
}

void edr_transport_v2_get_runtime(EdrTransportV2Runtime *out) {
  if (!out) {
    return;
  }
  *out = s_rt;
  out->configured = 1;
  out->enabled = s_cfg.enabled;
  out->h2_enabled = s_cfg.h2_enabled;
  out->h2_required = s_cfg.h2_required;
  out->control_stream_enabled = s_cfg.control_stream_enabled;
  out->long_poll_fallback = s_cfg.long_poll_fallback;
  out->report_events_v2_enabled = s_cfg.report_events_v2_enabled;
  out->zstd_requested = s_cfg.zstd_requested;
  out->telemetry_sampling_pct = s_cfg.telemetry_sampling_pct;
  tv2_copy(out->data_plane_encoding, sizeof(out->data_plane_encoding),
           s_cfg.data_plane_encoding, "protobuf");
  tv2_copy(out->data_plane_compression, sizeof(out->data_plane_compression),
           s_cfg.data_plane_compression, "identity");
  tv2_copy(out->envelope_format, sizeof(out->envelope_format), NULL,
           s_cfg.report_events_v2_enabled ? "protobuf:edr.transport.envelope.v1" : "legacy_json_b64");
  tv2_copy(out->dict_ver, sizeof(out->dict_ver), s_cfg.dict_ver, "edr-zstd-dict-v1");
  tv2_copy(out->schema_ver, sizeof(out->schema_ver), s_cfg.schema_ver, "edr-control-schema-v1");
  tv2_copy(out->profile_id, sizeof(out->profile_id), s_cfg.profile_id, "default-http1-protobuf");
  tv2_copy(out->qos_dscp, sizeof(out->qos_dscp), s_cfg.qos_dscp, "AF21");
  tv2_copy(out->threshold, sizeof(out->threshold), s_cfg.threshold, "medium");
}

void edr_transport_v2_apply_profile(const char *dict_ver, const char *schema_ver,
                                    const char *profile_id, int h2, int zstd,
                                    const char *qos_dscp, unsigned sampling_pct,
                                    const char *threshold, int backpressure_enabled) {
  (void)backpressure_enabled;
  if (dict_ver && dict_ver[0]) {
    tv2_copy(s_cfg.dict_ver, sizeof(s_cfg.dict_ver), dict_ver, NULL);
  }
  if (schema_ver && schema_ver[0]) {
    tv2_copy(s_cfg.schema_ver, sizeof(s_cfg.schema_ver), schema_ver, NULL);
  }
  if (profile_id && profile_id[0]) {
    tv2_copy(s_cfg.profile_id, sizeof(s_cfg.profile_id), profile_id, NULL);
  }
  if (qos_dscp && qos_dscp[0]) {
    tv2_copy(s_cfg.qos_dscp, sizeof(s_cfg.qos_dscp), qos_dscp, NULL);
  }
  if (threshold && threshold[0]) {
    tv2_copy(s_cfg.threshold, sizeof(s_cfg.threshold), threshold, NULL);
  }
  if (h2 >= 0) {
    s_cfg.h2_enabled = h2 ? 1 : 0;
  }
  if (zstd >= 0) {
    s_cfg.zstd_requested = zstd ? 1 : 0;
    tv2_copy(s_cfg.data_plane_compression, sizeof(s_cfg.data_plane_compression),
             zstd ? "zstd" : "identity", NULL);
  }
  if (sampling_pct > 0u) {
    s_cfg.telemetry_sampling_pct = sampling_pct > 100u ? 100u : sampling_pct;
  }
}

int edr_transport_v2_open_stream(EdrTransportV2Channel channel, EdrTransportV2Operation op) {
  int stream_id = s_next_stream_id++;
  if (s_next_stream_id <= 0) {
    s_next_stream_id = 1;
  }
  s_rt.opened_streams++;
  note_channel(channel);
  tv2_copy(s_rt.active_channel, sizeof(s_rt.active_channel), channel_name(channel), NULL);
  tv2_copy(s_rt.last_operation, sizeof(s_rt.last_operation), operation_name(op), NULL);
  return stream_id;
}

int edr_transport_v2_send(int stream_id, const void *data, size_t len) {
  (void)data;
  if (stream_id <= 0 || len == 0u) {
    s_rt.send_fail++;
    tv2_copy(s_rt.last_error, sizeof(s_rt.last_error), NULL, "invalid transport v2 send");
    return -1;
  }
  s_rt.send_ok++;
  s_rt.last_error[0] = '\0';
  return 0;
}

void edr_transport_v2_on_control(const char *frame_type) {
  s_rt.control_frames++;
  tv2_copy(s_rt.active_channel, sizeof(s_rt.active_channel), NULL, "control");
  tv2_copy(s_rt.last_operation, sizeof(s_rt.last_operation), frame_type, "control_frame");
}

void edr_transport_v2_ack(const char *command_id, int ok) {
  (void)command_id;
  if (ok) {
    s_rt.ack_ok++;
  } else {
    s_rt.ack_fail++;
  }
}

void edr_transport_v2_resume(const char *cursor) {
  (void)cursor;
  s_rt.resume_count++;
  tv2_copy(s_rt.last_operation, sizeof(s_rt.last_operation), NULL, "resume");
}

int edr_transport_v2_report_events(const char *batch_id, const uint8_t *header12,
                                   size_t header_len, const uint8_t *payload,
                                   size_t payload_len) {
  int stream_id = edr_transport_v2_open_stream(EDR_TV2_CHANNEL_NORMAL_TELEMETRY,
                                               EDR_TV2_OP_REPORT_EVENTS);
  int rc;
  if (edr_transport_v2_send(stream_id, payload, payload_len) != 0) {
    return -1;
  }
  rc = edr_ingest_http_post_report_events(batch_id, header12, header_len, payload, payload_len);
  if (rc != 0) {
    s_rt.send_fail++;
    tv2_copy(s_rt.last_error, sizeof(s_rt.last_error), NULL, "report_events failed");
  }
  return rc;
}

int edr_transport_v2_command_result(const char *command_id,
                                    const struct EdrSoarCommandMeta *meta,
                                    int execution_status, int exit_code,
                                    const char *detail_utf8) {
  int stream_id = edr_transport_v2_open_stream(EDR_TV2_CHANNEL_COMMAND_RESULT,
                                               EDR_TV2_OP_COMMAND_RESULT);
  int rc;
  if (edr_transport_v2_send(stream_id, command_id, command_id ? strlen(command_id) : 0u) != 0) {
    return -1;
  }
  rc = edr_ingest_http_post_command_result(command_id, meta, execution_status, exit_code, detail_utf8);
  if (rc != 0) {
    s_rt.send_fail++;
    tv2_copy(s_rt.last_error, sizeof(s_rt.last_error), NULL, "command_result failed");
  }
  return rc;
}

int edr_transport_v2_upload_file(const char *upload_id, const char *file_path,
                                 const char *sha256_hex, char *out_minio_key,
                                 size_t out_minio_key_cap) {
  int stream_id = edr_transport_v2_open_stream(EDR_TV2_CHANNEL_UPLOAD, EDR_TV2_OP_UPLOAD_FILE);
  int rc;
  if (edr_transport_v2_send(stream_id, upload_id, upload_id ? strlen(upload_id) : 0u) != 0) {
    return -1;
  }
  rc = edr_ingest_http_upload_file_multipart(upload_id, file_path, sha256_hex,
                                             out_minio_key, out_minio_key_cap);
  if (rc != 0) {
    s_rt.send_fail++;
    tv2_copy(s_rt.last_error, sizeof(s_rt.last_error), NULL, "upload_file failed");
  }
  return rc;
}
