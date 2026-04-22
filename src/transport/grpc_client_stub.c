/* gRPC 占位：无 libgRPC 或未链接 impl 时使用；SOAR ReportCommandResult 等 RPC 恒失败（-1），见 docs/SOAR_CONTRACT.md §5.1 */
#include "edr/grpc_client.h"

#include "edr/config.h"

void edr_grpc_client_init(const EdrConfig *cfg) { (void)cfg; }

void edr_grpc_client_shutdown(void) {}

int edr_grpc_client_reconnect_to_target(const char *target) {
  (void)target;
  return -1;
}

int edr_grpc_client_ready(void) { return 0; }

int edr_grpc_client_send_batch(const char *batch_id, const uint8_t *header12, size_t header_len,
                               const uint8_t *payload, size_t payload_len) {
  (void)batch_id;
  (void)header12;
  (void)header_len;
  (void)payload;
  (void)payload_len;
  return -1;
}

unsigned long edr_grpc_client_rpc_ok(void) { return 0UL; }

unsigned long edr_grpc_client_rpc_fail(void) { return 0UL; }

int edr_grpc_client_report_command_result(const char *command_id,
                                          const struct EdrSoarCommandMeta *meta, int execution_status,
                                          int exit_code, const char *detail_utf8) {
  (void)command_id;
  (void)meta;
  (void)execution_status;
  (void)exit_code;
  (void)detail_utf8;
  return -1;
}

int edr_grpc_client_upload_file(const char *alert_id, const char *file_path, const char *sha256_hex,
                                char *out_minio_key, size_t out_minio_key_cap) {
  (void)alert_id;
  (void)file_path;
  (void)sha256_hex;
  if (out_minio_key && out_minio_key_cap > 0u) {
    out_minio_key[0] = '\0';
  }
  return -1;
}
