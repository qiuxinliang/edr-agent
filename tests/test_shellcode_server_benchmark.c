#include "edr/proto_parse.h"
#include "edr/shellcode_detector.h"
#include "edr/tcp_reassembly.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BENCH_STREAM_BYTES 65535u
#define BENCH_MEMORY_BYTES (16ull * 1024ull * 1024ull)
#define BENCH_SEGMENT_BYTES 512u

static uint32_t env_u32(const char *name, uint32_t fallback, uint32_t min_value, uint32_t max_value) {
  const char *raw = getenv(name);
  if (!raw || !raw[0]) return fallback;
  char *end = NULL;
  unsigned long value = strtoul(raw, &end, 10);
  if (!end || *end != '\0' || value < min_value || value > max_value) return fallback;
  return (uint32_t)value;
}

static EdrTcpStreamKey bench_key(uint32_t flow) {
  EdrTcpStreamKey key;
  memset(&key, 0, sizeof(key));
  key.family = 4u;
  key.src_addr[0] = 10u;
  key.src_addr[1] = (uint8_t)(flow >> 8u);
  key.src_addr[2] = (uint8_t)flow;
  key.src_addr[3] = 10u;
  key.dst_addr[0] = 192u;
  key.dst_addr[1] = 0u;
  key.dst_addr[2] = 2u;
  key.dst_addr[3] = 20u;
  key.src_port = (uint16_t)(20000u + flow);
  key.dst_port = 8080u;
  return key;
}

static void fill_segment(uint8_t *segment, uint32_t flow, uint32_t index) {
  uint32_t state = 0x9e3779b9u ^ (flow * 2654435761u) ^ (index * 2246822519u);
  for (uint32_t i = 0; i < BENCH_SEGMENT_BYTES; i++) {
    state ^= state << 13u;
    state ^= state >> 17u;
    state ^= state << 5u;
    segment[i] = (uint8_t)state;
  }
  if (index == 0u) {
    static const char header[] =
        "POST /rpc HTTP/1.1\r\nHost: benchmark.local\r\nContent-Length: 32768\r\n\r\n";
    memcpy(segment, header, sizeof(header) - 1u);
  }
}

static int inspect_view(const EdrTcpReassemblyView *view, uint64_t *parsed, double *score_sum) {
  if (!view || !view->updated || !view->data || view->length == 0u) return 0;
  EdrProtoShellcodeRegion region;
  EdrProtoParseResult result = edr_proto_find_shellcode_region(view->data, view->length, &region);
  if (result != EDR_PROTO_PARSE_OK || region.payload_len == 0u) return 0;
  *score_sum += edr_shellcode_heuristic_score(view->data + region.payload_off, region.payload_len);
  (*parsed)++;
  return 1;
}

int main(void) {
  const uint32_t flows = env_u32("EDR_SHELLCODE_BENCH_FLOWS", 192u, 16u, 512u);
  const uint32_t segments = env_u32("EDR_SHELLCODE_BENCH_SEGMENTS", 64u, 8u, 128u);
  const uint32_t min_rate = env_u32("EDR_SHELLCODE_BENCH_MIN_SEGMENTS_PER_SEC", 1000u, 1u, 100000000u);
  EdrTcpReassemblyTable *table =
      edr_tcp_reassembly_create(512u, BENCH_STREAM_BYTES, BENCH_MEMORY_BYTES, 30ull * 1000000000ull);
  if (!table) {
    fprintf(stderr, "benchmark: reassembly create failed\n");
    return 1;
  }

  uint8_t segment[BENCH_SEGMENT_BYTES];
  uint64_t submitted = 0u;
  uint64_t parsed = 0u;
  double score_sum = 0.0;
  clock_t started = clock();
  for (uint32_t flow = 0; flow < flows; flow++) {
    EdrTcpStreamKey key = bench_key(flow);
    EdrTcpReassemblyView view;
    const uint32_t base = 100000u + flow * 100000u;

    fill_segment(segment, flow, 0u);
    if (edr_tcp_reassembly_submit(table, &key, base, segment, BENCH_SEGMENT_BYTES,
                                  submitted + 1u, &view) != 0) goto submit_failed;
    submitted++;
    (void)inspect_view(&view, &parsed, &score_sum);

    /* One deterministic gap per flow exercises out-of-order buffering and gap fill. */
    fill_segment(segment, flow, 2u);
    if (edr_tcp_reassembly_submit(table, &key, base + 2u * BENCH_SEGMENT_BYTES, segment,
                                  BENCH_SEGMENT_BYTES, submitted + 1u, &view) != 0) goto submit_failed;
    submitted++;
    (void)inspect_view(&view, &parsed, &score_sum);

    fill_segment(segment, flow, 1u);
    if (edr_tcp_reassembly_submit(table, &key, base + BENCH_SEGMENT_BYTES, segment,
                                  BENCH_SEGMENT_BYTES, submitted + 1u, &view) != 0) goto submit_failed;
    submitted++;
    (void)inspect_view(&view, &parsed, &score_sum);

    for (uint32_t index = 3u; index < segments; index++) {
      fill_segment(segment, flow, index);
      if (edr_tcp_reassembly_submit(table, &key, base + index * BENCH_SEGMENT_BYTES, segment,
                                    BENCH_SEGMENT_BYTES, submitted + 1u, &view) != 0) goto submit_failed;
      submitted++;
      (void)inspect_view(&view, &parsed, &score_sum);
    }
  }

  {
    clock_t finished = clock();
    double seconds = (double)(finished - started) / (double)CLOCKS_PER_SEC;
    if (seconds <= 0.0) seconds = 0.000001;
    double rate = (double)submitted / seconds;
    EdrTcpReassemblyStats stats;
    edr_tcp_reassembly_get_stats(table, &stats);
    printf("{\"flows\":%u,\"segments\":%llu,\"parsed_views\":%llu,"
           "\"cpu_seconds\":%.6f,\"segments_per_second\":%.2f,"
           "\"active_streams\":%u,\"memory_bytes\":%llu,"
           "\"out_of_order\":%llu,\"memory_drops\":%llu,\"score_sum\":%.6f}\n",
           flows, (unsigned long long)submitted, (unsigned long long)parsed, seconds, rate,
           stats.active_streams, (unsigned long long)stats.memory_bytes,
           (unsigned long long)stats.out_of_order_segments,
           (unsigned long long)stats.memory_drops, score_sum);

    int failed = 0;
    if (submitted != (uint64_t)flows * segments) failed = 1;
    if (parsed < (uint64_t)flows * (segments - 2u)) failed = 1;
    if (stats.out_of_order_segments < flows) failed = 1;
    if (stats.memory_bytes > BENCH_MEMORY_BYTES || stats.memory_drops != 0u) failed = 1;
    if (rate < (double)min_rate) failed = 1;
    edr_tcp_reassembly_destroy(table);
    return failed ? 1 : 0;
  }

submit_failed:
  fprintf(stderr, "benchmark: submit failed after %llu segments\n", (unsigned long long)submitted);
  edr_tcp_reassembly_destroy(table);
  return 1;
}
