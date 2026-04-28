#include "edr/ave_stats.h"

#include <stdlib.h>
#include <string.h>

static volatile uint64_t s_total_infer_requests = 0;
static volatile uint64_t s_successful_infers = 0;
static volatile uint64_t s_failed_infers = 0;
static volatile uint64_t s_cache_hits = 0;
static volatile uint64_t s_cache_misses = 0;
static volatile uint64_t s_cross_engine_feeds = 0;
static volatile uint64_t s_shellcode_detections = 0;
static volatile uint64_t s_webshell_detections = 0;
static volatile uint64_t s_pmfe_detections = 0;
static volatile double s_avg_infer_latency_ms = 0.0;
static volatile double s_avg_queue_depth = 0.0;
static volatile uint32_t s_active_threads = 0;
static volatile uint32_t s_queue_capacity = 0;

void edr_ave_record_infer_request(void) {
    __sync_fetch_and_add(&s_total_infer_requests, 1);
}

void edr_ave_record_infer_success(double latency_ms) {
    __sync_fetch_and_add(&s_successful_infers, 1);
    double current_avg = s_avg_infer_latency_ms;
    uint64_t count = s_successful_infers;
    s_avg_infer_latency_ms = current_avg + (latency_ms - current_avg) / (double)count;
}

void edr_ave_record_infer_failure(void) {
    __sync_fetch_and_add(&s_failed_infers, 1);
}

void edr_ave_record_cache_hit(void) {
    __sync_fetch_and_add(&s_cache_hits, 1);
}

void edr_ave_record_cache_miss(void) {
    __sync_fetch_and_add(&s_cache_misses, 1);
}

void edr_ave_record_cross_engine_feed(void) {
    __sync_fetch_and_add(&s_cross_engine_feeds, 1);
}

void edr_ave_record_detection(const char *type) {
    if (!type) return;
    if (strcmp(type, "shellcode") == 0) {
        __sync_fetch_and_add(&s_shellcode_detections, 1);
    } else if (strcmp(type, "webshell") == 0) {
        __sync_fetch_and_add(&s_webshell_detections, 1);
    } else if (strcmp(type, "pmfe") == 0) {
        __sync_fetch_and_add(&s_pmfe_detections, 1);
    }
}

void edr_ave_update_queue_stats(double queue_depth, uint32_t active, uint32_t capacity) {
    s_avg_queue_depth = queue_depth;
    s_active_threads = active;
    s_queue_capacity = capacity;
}

int edr_ave_get_stats(EdrAveStats *out_stats) {
    if (!out_stats) {
        return -1;
    }
    memset(out_stats, 0, sizeof(*out_stats));
    out_stats->total_infer_requests = s_total_infer_requests;
    out_stats->successful_infers = s_successful_infers;
    out_stats->failed_infers = s_failed_infers;
    out_stats->cache_hits = s_cache_hits;
    out_stats->cache_misses = s_cache_misses;
    out_stats->cross_engine_feeds = s_cross_engine_feeds;
    out_stats->shellcode_detections = s_shellcode_detections;
    out_stats->webshell_detections = s_webshell_detections;
    out_stats->pmfe_detections = s_pmfe_detections;
    out_stats->avg_infer_latency_ms = s_avg_infer_latency_ms;
    out_stats->avg_queue_depth = s_avg_queue_depth;
    out_stats->active_threads = s_active_threads;
    out_stats->queue_capacity = s_queue_capacity;
    return 0;
}

void edr_ave_reset_stats(void) {
    __sync_synchronize();
    s_total_infer_requests = 0;
    s_successful_infers = 0;
    s_failed_infers = 0;
    s_cache_hits = 0;
    s_cache_misses = 0;
    s_cross_engine_feeds = 0;
    s_shellcode_detections = 0;
    s_webshell_detections = 0;
    s_pmfe_detections = 0;
    s_avg_infer_latency_ms = 0.0;
    s_avg_queue_depth = 0.0;
    s_active_threads = 0;
    s_queue_capacity = 0;
}