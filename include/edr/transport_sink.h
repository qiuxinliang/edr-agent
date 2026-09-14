/**
 * 批次耐久交接与传输指标。
 * 批次头 12B：magic（BAT1 原始帧拼接 / BATL LZ4 压缩块）、frame_count、raw_payload_bytes。
 */
#ifndef EDR_TRANSPORT_SINK_H
#define EDR_TRANSPORT_SINK_H

#include <stddef.h>
#include <stdint.h>

struct EdrConfig;
/** 从配置登记上报目标；默认使用 HTTPS/TLS ingest 与 HTTPS 控制面。 */
int edr_transport_init_from_config(const struct EdrConfig *cfg);

/** Returns 1 only after workers exited. On timeout retain their dependencies. */
int edr_transport_shutdown(void);

#define EDR_TRANSPORT_BATCH_MAGIC_RAW 0x31544142u  /* "BAT1" */
#define EDR_TRANSPORT_BATCH_MAGIC_LZ4 0x345a4c42u  /* "BLZ4" LE */

void edr_transport_on_behavior_wire(const uint8_t *data, size_t len);

/** Sole batch handoff: 0 means SQLite owns the immutable bytes; -1 retains
 * ownership at the caller. The worker, not the caller, performs network I/O. */
int edr_transport_on_event_batch(const char *batch_id, const uint8_t *header12, size_t header_len,
                                  const uint8_t *payload, size_t payload_len);

unsigned long edr_transport_wire_events_count(void);
size_t edr_transport_wire_bytes_count(void);
unsigned long edr_transport_batch_count(void);
size_t edr_transport_batch_bytes_count(void);
unsigned long edr_transport_batch_lz4_count(void);
unsigned long edr_transport_batch_rejected_count(void);
/** Legacy memory-queue telemetry stays zero: offline_queue_pending is the
 * authoritative depth. Retained for current server/dashboard consumers. */
size_t edr_transport_send_queue_depth(void);
size_t edr_transport_send_queue_capacity(void);
unsigned long edr_transport_queue_full_count(void);
unsigned long edr_transport_queue_full_persisted_count(void);
unsigned long edr_transport_queue_full_sampled_count(void);
unsigned long edr_transport_queue_full_dropped_count(void);

#endif
