/**
 * §6.2 EventBatch 本地聚合：长度前缀帧拼接，达阈值刷写；载荷前加 BAT1 头便于与 gRPC 对接。
 */
#ifndef EDR_EVENT_BATCH_H
#define EDR_EVENT_BATCH_H

#include "edr/error.h"

#include <stddef.h>
#include <stdint.h>

#ifndef EDR_EVENT_BATCH_CAP
/** 未配置时的默认单批最大字节（§6.2 设计上限 4MB） */
#define EDR_EVENT_BATCH_CAP (256u * 1024u)
#endif

/**
 * 分配批次缓冲并设置上限（§11 upload.batch_max_size_mb / batch_max_events）。
 * max_frames_per_batch 为 0 表示仅按字节上限刷批。
 * flush_timeout_s：有未刷数据时，距最后一次写入超过该秒数则刷批（§6.2）；≤0 关闭。
 */
EdrError edr_event_batch_init(size_t max_bytes, uint32_t max_frames_per_batch,
                              int flush_timeout_s);

/** 刷批并释放缓冲（进程退出 / 预处理线程停止时调用） */
void edr_event_batch_shutdown(void);

/** 按时间条件刷批（预处理线程空闲/轮询时调用） */
void edr_event_batch_poll_timeout(void);

uint64_t edr_event_batch_timeout_flush_count(void);

/** 追加一条线格式事件；内部可能触发刷写。返回 0 成功，-1 失败 */
int edr_event_batch_push(const uint8_t *wire, size_t wire_len);

/** 刷出当前批次 */
void edr_event_batch_flush(void);

#endif
