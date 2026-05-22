/**
 * HTTP POST /ingest/report-events（与 gRPC ReportEvents payload 同源）。
 * 供行为告警走 gRPC、其余事件走 HTTP 的分流策略使用。
 */
#ifndef EDR_INGEST_HTTP_H
#define EDR_INGEST_HTTP_H

#include <stddef.h>
#include <stdint.h>

/** 在 edr_transport_init_from_config 中调用；rest_base 形如 http://127.0.0.1:8080/api/v1 */
void edr_ingest_http_configure(const char *rest_base, const char *tenant_id, const char *user_id,
                                const char *bearer, const char *endpoint_id, const char *agent_version);

int edr_ingest_http_configured(void);

typedef struct {
  int configured;
  int http_fallback_available;
  int insecure_http;
  unsigned long ok_count;
  unsigned long fail_count;
  int64_t last_success_unix_ms;
  int64_t last_failure_unix_ms;
  char last_error[160];
} EdrIngestHttpRuntime;

void edr_ingest_http_get_runtime(EdrIngestHttpRuntime *out);

/** 缓存/读取当前策略版本，供行为告警补齐 policy_version 字段。 */
void edr_ingest_http_set_policy_version(const char *policy_version);
void edr_ingest_http_copy_policy_version(char *out, size_t out_cap);

/**
 * 发送一批（12B BAT1/BLZ4 头 + payload）；成功返回 0。
 * JSON 体字段与平台 PostReportEvents 一致。
 */
int edr_ingest_http_post_report_events(const char *batch_id, const uint8_t *header12, size_t header_len,
                                       const uint8_t *payload, size_t payload_len);

/** 发送 Agent 引擎运行态 JSON；body 需为完整 JSON 对象。 */
int edr_ingest_http_post_engine_health_json(const char *body_json);

/** HTTP command long-poll hooks. Current lightweight build keeps these as safe no-ops. */
void edr_ingest_http_start_command_poll(void);
void edr_ingest_http_stop_command_poll(void);

#endif
