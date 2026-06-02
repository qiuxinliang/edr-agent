/**
 * HTTP POST /ingest/report-events（与 gRPC ReportEvents payload 同源）。
 * 供行为告警走 gRPC、其余事件走 HTTP 的分流策略使用。
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
                                const char *proxy_mode,
                                const char *proxy_url, const char *relay_url);

int edr_ingest_http_configured(void);

typedef struct {
  int configured;
  int http_fallback_available;
  int insecure_http;
  int mtls_configured;
  int websocket_ready;
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
  unsigned long budget_drop_count;
  int64_t last_success_unix_ms;
  int64_t last_failure_unix_ms;
  char last_error[160];
  char circuit_reason[128];
  char connection_mode[32];
  char effective_base_url[512];
  char relay_url[512];
  char proxy_mode[32];
  char proxy_url[512];
  char proxy_status[96];
  char client_key_provider[32];
  char mtls_status[96];
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

/** Native HTTPS GET using the configured REST/mTLS/proxy stack; writes a binary-safe response to file. */
int edr_ingest_http_get_url_to_file(const char *url, const char *file_path, size_t max_bytes);

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

/** HTTP command long-poll hooks. gRPC ready 时保持休眠，no-gRPC/断链时接管命令面。 */
void edr_ingest_http_start_command_poll(void);
void edr_ingest_http_stop_command_poll(void);

#endif
