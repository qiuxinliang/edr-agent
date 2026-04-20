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

/**
 * 发送一批（12B BAT1/BLZ4 头 + payload）；成功返回 0。
 * JSON 体字段与平台 PostReportEvents 一致。
 */
int edr_ingest_http_post_report_events(const char *batch_id, const uint8_t *header12, size_t header_len,
                                       const uint8_t *payload, size_t payload_len);

#endif
