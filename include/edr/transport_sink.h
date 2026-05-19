/**
 * 传输层抽象 — 批次上报、指标、调度注入。
 * 批次头 12B：magic（BAT1 原始帧拼接 / BATL LZ4 压缩块）、frame_count、raw_payload_bytes。
 */
#ifndef EDR_TRANSPORT_SINK_H
#define EDR_TRANSPORT_SINK_H

#include <stddef.h>
#include <stdint.h>

struct EdrConfig;
struct EdrTransportCtx;

/** 可注入 dispatch 回调：由 transport 内部在工作线程调用，将批次实际发往 gRPC/HTTP。 */
typedef int (*EdrTransportDispatchFn)(int use_http, const char *batch_id,
                                      const uint8_t *header12, size_t header_len,
                                      const uint8_t *payload, size_t payload_len,
                                      void *userdata);

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
size_t edr_transport_wire_bytes_count(void);
unsigned long edr_transport_batch_count(void);
size_t edr_transport_batch_bytes_count(void);
unsigned long edr_transport_batch_lz4_count(void);

/**
 * 注入模拟 dispatch 回调（测试/QUIC/MQTT 传输层替换）。
 * fn 为 NULL 时恢复内置 default_dispatch。
 * userdata 会在每次 dispatch 调用时透传。
 */
void edr_transport_inject_dispatch(EdrTransportDispatchFn fn, void *userdata);

/** 获取内部状态只读指针（测试/监控）。在 init 前返回 NULL。 */
const struct EdrTransportCtx *edr_transport_ctx(void);

#endif