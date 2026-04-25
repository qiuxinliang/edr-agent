/**
 * HTTP POST /ingest/report-events（与 gRPC ReportEvents payload 同源）。
 * 供行为告警走 gRPC、其余事件走 HTTP 的分流策略使用。
 */
#ifndef EDR_INGEST_HTTP_H
#define EDR_INGEST_HTTP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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

struct EdrSoarCommandMeta;
/**
 * POST /ingest/report-command-result，与 gRPC ReportCommandResult 同语义。
 * execution_status 为 `EdrCommandExecutionStatus` 数值；meta 可 NULL（无非编排扩展）。
 * 成功返回 0（HTTP 2xx），否则 -1。
 */
int edr_ingest_http_post_command_result(const char *command_id, const struct EdrSoarCommandMeta *meta,
                                        int execution_status, int exit_code, const char *detail_utf8);

/**
 * 启动 HTTP 长轮询拉取与 gRPC `Subscribe` 对等的 `poll-commands` 指令；无 gRPC 时建议保持开启（见 README）。
 * 在 `edr_ingest_http_configure` 之后、main 在 `edr_transport_init_from_config` 中调用。幂等可重复调。
 * 与 `edr_ingest_http_stop_command_poll` 配对在进程退出前调用（由 `edr_transport_shutdown`）。
 * 受控环境变量 `EDR_CMD_HTTP_POLL=0` 时强制关闭；`1` 时与是否配置 gRPC 无关、始终拉取（通常仅排障用）。
 */
void edr_ingest_http_start_command_poll(void);
void edr_ingest_http_stop_command_poll(void);

/**
 * POST `/ingest/upload-file`（multipart，与 gRPC `UploadFile` 落点一致）。成功 0 并写 minio_key 至 out 缓冲。
 */
int edr_ingest_http_upload_file_multipart(const char *upload_id, const char *file_path, const char *sha256_hex,
                                          char *out_minio_key, size_t out_minio_key_cap);

#ifdef __cplusplus
}
#endif

#endif
