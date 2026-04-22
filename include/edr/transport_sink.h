/**
 * 预处理 → 传输占位：后续替换为 gRPC EventBatch（§6.2）。
 * 批次头 12B：magic（BAT1 原始帧拼接 / BATL LZ4 压缩块）、frame_count、raw_payload_bytes。
 */
#ifndef EDR_TRANSPORT_SINK_H
#define EDR_TRANSPORT_SINK_H

#include <stddef.h>
#include <stdint.h>

struct EdrConfig;

/** 从配置登记上报目标（gRPC mTLS 使用 server.address / 证书路径） */
void edr_transport_init_from_config(const struct EdrConfig *cfg);

/** 与 init 配对：停止 Subscribe 线程并释放 gRPC 资源 */
void edr_transport_shutdown(void);

#define EDR_TRANSPORT_BATCH_MAGIC_RAW 0x31544142u  /* "BAT1" */
#define EDR_TRANSPORT_BATCH_MAGIC_LZ4 0x345a4c42u  /* "BLZ4" LE */

void edr_transport_on_behavior_wire(const uint8_t *data, size_t len);

void edr_transport_on_event_batch(const char *batch_id, const uint8_t *header12, size_t header_len,
                                  const uint8_t *payload, size_t payload_len);

/**
 * 分流上报：use_http=0 → gRPC ReportEvents；use_http=1 → HTTP POST .../ingest/report-events。
 * 统计与失败落盘策略与 edr_transport_on_event_batch 一致。
 */
void edr_transport_send_ingest_batch(int use_http, const char *batch_id, const uint8_t *header12,
                                      size_t header_len, const uint8_t *payload, size_t payload_len);

unsigned long edr_transport_wire_events_count(void);
unsigned long edr_transport_wire_bytes_count(void);
unsigned long edr_transport_batch_count(void);
unsigned long edr_transport_batch_bytes_count(void);
unsigned long edr_transport_batch_lz4_count(void);

#endif
