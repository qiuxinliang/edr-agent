/**
 * HTTPS/TLS ingest 主路径：ReportEvents / command result / artifact upload / control stream。
 * legacy gRPC 仅在显式启用时作为 fallback。
 */
#ifndef EDR_INGEST_HTTP_H
#define EDR_INGEST_HTTP_H

#include <stddef.h>
#include <stdint.h>

struct EdrSoarCommandMeta;

/** 在 edr_transport_init_from_config 中调用；rest_base 形如 http://127.0.0.1:8080/api/v1 */
void edr_ingest_http_configure(const char *rest_base, const char *tenant_id, const char *user_id,
                                const char *bearer, const char *endpoint_id, const char *agent_version,
                                const char *ca_file, const char *client_cert_file,
                                const char *client_key_file, const char *client_key_provider,
                                const char *client_cert_store,
                                const char *client_cert_thumbprint,
                                const char *proxy_mode,
                                const char *proxy_url, const char *relay_url);

void edr_ingest_http_configure_transport_options(int http2_enabled, int http2_required,
                                                 int control_stream_enabled,
                                                 int long_poll_fallback,
                                                 int report_events_v2_enabled,
                                                 const char *data_plane_encoding,
                                                 const char *data_plane_compression);

int edr_ingest_http_configured(void);

/** 当前 native HTTP circuit 是否仍处于打开状态；到期时自动复位。 */
int edr_ingest_http_circuit_open(void);

typedef struct {
  int configured;
  int http_fallback_available;
  int insecure_http;
  int mtls_configured;
  int websocket_ready;
  int http2_enabled;
  int http2_required;
  int http2_negotiated;
  int control_stream_enabled;
  int control_stream_ready;
  int long_poll_fallback;
  int report_events_v2_enabled;
  int zstd_requested;
  int zstd_available;
  int zstd_dict_loaded;
  int http2_multiplex_enabled;
  int http2_multiplex_active;
  int poll_backoff_ms;
  int ws_backoff_ms;
  int circuit_open;
  int64_t circuit_until_unix_ms;
  unsigned long ok_count;
  unsigned long fail_count;
  unsigned long http_request_ok_count;
  unsigned long http_request_fail_count;
  unsigned long ws_message_ok_count;
  unsigned long ws_message_fail_count;
  unsigned long ws_pong_count;
  unsigned long command_result_ok_count;
  unsigned long command_result_fail_count;
  unsigned long upload_ok_count;
  unsigned long upload_fail_count;
  unsigned long long_poll_ok_count;
  unsigned long long_poll_fail_count;
  unsigned long control_stream_ok_count;
  unsigned long control_stream_fail_count;
  unsigned long control_stream_heartbeat_count;
  unsigned long control_ack_ok_count;
  unsigned long control_ack_fail_count;
  unsigned long http2_request_ok_count;
  unsigned long http2_request_fail_count;
  unsigned long http2_negotiated_count;
  unsigned long http2_fallback_count;
  unsigned long report_events_v2_ok_count;
  unsigned long report_events_v2_fail_count;
  unsigned long zstd_compress_ok_count;
  unsigned long zstd_compress_fail_count;
  unsigned long http2_multiplex_ok_count;
  unsigned long http2_multiplex_fail_count;
  unsigned long budget_drop_count;
  int64_t last_success_unix_ms;
  int64_t last_failure_unix_ms;
  char last_error[160];
  char circuit_reason[128];
  char connection_mode[32];
  char effective_base_url[512];
  char route_profile_version[96];
  char active_route_url[512];
  int route_count;
  int active_route_index;
  unsigned long route_failover_count;
  char relay_url[512];
  char proxy_mode[32];
  char proxy_url[512];
  char proxy_status[96];
  char client_key_provider[32];
  char mtls_status[96];
  char negotiated_protocol[16];
  char control_stream_status[32];
  char upload_status[32];
  char data_plane_encoding[32];
  char data_plane_compression[32];
  char envelope_format[48];
  char dict_ver[64];
  char schema_ver[64];
  char profile_id[64];
  char zstd_dict_path[512];
  char qos_dscp[32];
  char telemetry_threshold[32];
  unsigned int telemetry_sampling_pct;
  uint64_t zstd_raw_bytes;
  uint64_t zstd_wire_bytes;
  uint64_t zstd_dict_bytes;
  unsigned long requests_this_minute;
  unsigned long request_limit_per_minute;
  uint64_t bytes_this_minute;
  uint64_t byte_limit_per_minute;
  unsigned long tls_handshakes_this_minute;
  unsigned long tls_handshake_limit_per_minute;
  unsigned int slo_success_rate_pct;
} EdrIngestHttpRuntime;

void edr_ingest_http_get_runtime(EdrIngestHttpRuntime *out);

/** 缓存/读取当前策略版本，供行为告警补齐 policy_version 字段。 */
void edr_ingest_http_set_policy_version(const char *policy_version);
void edr_ingest_http_copy_policy_version(char *out, size_t out_cap);

/** 控制面热更新字典 / Schema / 上报画像 / QoS / 背压治理状态。 */
void edr_ingest_http_apply_telemetry_profile(const char *dict_ver, const char *schema_ver,
                                             const char *profile_id, int h2, int zstd,
                                             const char *qos_dscp, unsigned sampling_pct,
                                             const char *threshold, int backpressure_enabled);
void edr_ingest_http_apply_transport_flags(int http2_required, int control_stream_enabled,
                                           int long_poll_fallback,
                                           int report_events_v2_enabled);

typedef struct {
  char config_hash[65];
  char sequence[32];
  char previous_hash[65];
  char signing_key_id[96];
  char signature[192];
  char nonce[96];
  char expires_at[64];
  char signed_payload_b64[2048];
  char rollout_id[96];
  char rollout_stage[48];
  char rollout_bucket[32];
  char rollout_percent[16];
} EdrAgentConfigHeaders;

/** Native HTTPS GET using the configured REST/mTLS/proxy stack; writes a binary-safe response to file. */
int edr_ingest_http_get_url_to_file(const char *url, const char *file_path, size_t max_bytes);
int edr_ingest_http_get_url_to_file_meta(const char *url, const char *file_path,
                                         size_t max_bytes, EdrAgentConfigHeaders *headers);

int edr_ingest_http_post_config_status(const char *tenant_id,
                                       const char *endpoint_id,
                                       const char *agent_version,
                                       const char *policy_version,
                                       const char *config_hash,
                                       const char *config_sequence,
                                       const char *config_nonce,
                                       const char *config_signature,
                                       const char *signing_key_id,
                                       int verified,
                                       const char *reject_reason,
                                       const char *desired_version,
                                       const char *desired_hash,
                                       const char *apply_status,
                                       int restart_required);

/**
 * 发送一批（12B BAT1/BLZ4 头 + payload）；成功返回 0。
 * JSON 体字段与平台 PostReportEvents 一致。
 */
int edr_ingest_http_post_report_events(const char *batch_id, const uint8_t *header12, size_t header_len,
                                       const uint8_t *payload, size_t payload_len);

/** 发送 Agent 引擎运行态 JSON；body 需为完整 JSON 对象。 */
int edr_ingest_http_post_engine_health_json(const char *body_json);

/** 上报指令执行结果；与 gRPC ReportCommandResult 语义一致。 */
int edr_ingest_http_post_command_result(const char *command_id,
                                        const struct EdrSoarCommandMeta *meta,
                                        int execution_status,
                                        int exit_code,
                                        const char *detail_utf8);

/** 上传指令/取证产物；与 gRPC UploadFile 落点一致。 */
int edr_ingest_http_upload_file_multipart(const char *upload_id, const char *file_path,
                                          const char *sha256_hex, char *out_minio_key,
                                          size_t out_minio_key_cap);

/** HTTPS h2 control stream 优先；stream 不可用时由 long-poll 接管命令面。 */
void edr_ingest_http_start_command_poll(void);
void edr_ingest_http_stop_command_poll(void);

#endif
