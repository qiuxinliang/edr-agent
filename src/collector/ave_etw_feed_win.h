/**
 * ETW 实时路径 → AVE_FeedEvent（与 PMFE/pid_history 并行；PID 维度对齐）。
 */
#ifndef EDR_AVE_ETW_FEED_WIN_H
#define EDR_AVE_ETW_FEED_WIN_H

#include "edr/types.h"

#include <stdint.h>

struct _EVENT_RECORD;

void edr_ave_etw_feed_from_event(struct _EVENT_RECORD *rec, EdrEventType ty, uint64_t ts_ns,
                                 const char *opt_target_ip, const char *opt_target_domain);

#endif
