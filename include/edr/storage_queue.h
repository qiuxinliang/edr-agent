/**
 * §10 离线队列 — SQLite（可选编译）；用于批次落盘与后续补传。
 */
#ifndef EDR_STORAGE_QUEUE_H
#define EDR_STORAGE_QUEUE_H

#include <stddef.h>
#include <stdint.h>

#include "edr/error.h"

/** 打开/创建队列库；path 为 NULL 时使用 ./edr_queue.db */
EdrError edr_storage_queue_open(const char *path);
void edr_storage_queue_close(void);

/** 是否已成功打开 SQLite 队列（用于 on_fail 策略仅在库可用时入队） */
int edr_storage_queue_is_open(void);

/**
 * 持久化一批：payload 为 §6.2 完整 wire（12 字节头 + 体），与 ReportEvents 一致，便于出队补传。
 * compressed: 与传输层一致，仅作记录。
 * severity: 告警严重级别，用于离线缓冲满时的删除策略（0=低，1=高）
 */
EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,
                                   size_t payload_len, int compressed, int severity);

uint64_t edr_storage_queue_pending_count(void);

/**
 * 从 SQLite 取 pending 批次，经 gRPC 补传（与 flush 时 ReportEvents 载荷一致）。
 * 在预处理循环中周期性调用；内部节流，失败行保留并增加 retry_count。
 */
void edr_storage_queue_poll_drain(void);

#endif