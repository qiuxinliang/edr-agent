/**
 * 有界 MPMC 队列（Vyukov/1024cores 风格），用于 AVE_FeedEvent 多生产者无锁入队。
 * 需 C11 原子；失败时回退为互斥 + 环（同 API）。
 */
#ifndef EDR_AVE_LF_MPMC_H
#define EDR_AVE_LF_MPMC_H

#include "edr/ave_sdk.h"

#include <stddef.h>

typedef struct AveMpmcQueue AveMpmcQueue;

/** capacity 须为 2 的幂（例如 4096） */
int ave_mpmc_init(AveMpmcQueue **out_q, size_t capacity);
void ave_mpmc_destroy(AveMpmcQueue *q);

/** 0 成功；-1 满 */
int ave_mpmc_try_push(AveMpmcQueue *q, const AVEBehaviorEvent *e);
/** 0 成功；-1 空 */
int ave_mpmc_try_pop(AveMpmcQueue *q, AVEBehaviorEvent *out);

size_t ave_mpmc_approx_depth(const AveMpmcQueue *q);

#endif
