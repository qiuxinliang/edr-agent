#ifndef EDR_TIME_UTIL_H
#define EDR_TIME_UTIL_H

#include <stdint.h>

/** 单调时钟纳秒（用于批次超时、间隔统计，不受系统时间回拨影响） */
uint64_t edr_monotonic_ns(void);

#endif
