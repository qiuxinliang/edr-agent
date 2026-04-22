/**
 * §7 gRPC（C++ 实现）— mTLS 通道、ReportEvents、Subscribe 服务端流。
 * C 接口供 main / transport 调用。
 */
#ifndef EDR_GRPC_CLIENT_H
#define EDR_GRPC_CLIENT_H

#include <stddef.h>
#include <stdint.h>

struct EdrConfig;
struct EdrSoarCommandMeta;

#ifdef __cplusplus
extern "C" {
#endif

void edr_grpc_client_init(const struct EdrConfig *cfg);
void edr_grpc_client_shutdown(void);
int edr_grpc_client_reconnect_to_target(const char *target);

/**
 * 非 0：已具备 EventIngest stub（可发起 ReportEvents）；0：未建链/占位 stub/初始化失败。
 * 与 HTTP ingest 回退配合：未就绪时可用同一 payload 走 POST .../ingest/report-events。
 */
int edr_grpc_client_ready(void);

/**
 * 上报一批（header12 + payload 与 §6.2 一致）；batch_id 用于幂等。
 * 返回 0 成功，非 0 失败（未启用 gRPC 或未连接时返回 -1）。
 */
int edr_grpc_client_send_batch(const char *batch_id, const uint8_t *header12, size_t header_len,
                                const uint8_t *payload, size_t payload_len);

unsigned long edr_grpc_client_rpc_ok(void);
unsigned long edr_grpc_client_rpc_fail(void);

/**
 * 写入简短 ASCII 诊断（为何 `edr_grpc_client_ready` 可能为 0），供控制台心跳等使用。
 * `cap` 含 NUL；无信息时写入 `"-"`。
 */
void edr_grpc_client_diag(char *buf, size_t cap);

/**
 * 上报指令执行结果（ingest.proto ReportCommandResult），供 SOAR 对账。
 * execution_status 使用 `EdrCommandExecutionStatus` 数值（1=OK …）。
 * 未启用 gRPC 或失败时返回 -1。
 */
int edr_grpc_client_report_command_result(const char *command_id,
                                          const struct EdrSoarCommandMeta *meta, int execution_status,
                                          int exit_code, const char *detail_utf8);

/**
 * Webshell 取证文件流式上传。成功返回 0，并写入 out_minio_key（若非空）。
 * 失败或未启用 gRPC 返回 -1。
 */
int edr_grpc_client_upload_file(const char *alert_id, const char *file_path, const char *sha256_hex,
                                char *out_minio_key, size_t out_minio_key_cap);

#ifdef __cplusplus
}
#endif

#endif
