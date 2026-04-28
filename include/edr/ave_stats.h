#ifndef EDR_AVE_STATS_H
#define EDR_AVE_STATS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t total_infer_requests;
    uint64_t successful_infers;
    uint64_t failed_infers;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t cross_engine_feeds;
    uint64_t shellcode_detections;
    uint64_t webshell_detections;
    uint64_t pmfe_detections;
    double avg_infer_latency_ms;
    double avg_queue_depth;
    uint32_t active_threads;
    uint32_t queue_capacity;
} EdrAveStats;

int edr_ave_get_stats(EdrAveStats *out_stats);
void edr_ave_reset_stats(void);

#ifdef __cplusplus
}
#endif

#endif
