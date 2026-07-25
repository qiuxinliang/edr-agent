#ifndef EDR_TCP_REASSEMBLY_H
#define EDR_TCP_REASSEMBLY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t family; /* 4 or 6 */
  uint8_t src_addr[16];
  uint8_t dst_addr[16];
  uint16_t src_port;
  uint16_t dst_port;
} EdrTcpStreamKey;

typedef struct EdrTcpReassemblyTable EdrTcpReassemblyTable;

typedef struct {
  const uint8_t *data;
  uint32_t length;
  uint32_t newly_contiguous;
  int updated;
  int truncated;
} EdrTcpReassemblyView;

typedef struct {
  uint64_t segments_seen;
  uint64_t retransmit_bytes;
  uint64_t out_of_order_segments;
  uint64_t gap_waits;
  uint64_t evicted_streams;
  uint64_t memory_drops;
  uint64_t truncated_segments;
  uint32_t active_streams;
  uint64_t memory_bytes;
} EdrTcpReassemblyStats;

EdrTcpReassemblyTable *edr_tcp_reassembly_create(uint32_t max_flows, uint32_t max_stream_bytes,
                                                  uint64_t max_memory_bytes, uint64_t idle_timeout_ns);
void edr_tcp_reassembly_destroy(EdrTcpReassemblyTable *table);

/* The returned view remains valid only until the next submit/reset/destroy call. */
int edr_tcp_reassembly_submit(EdrTcpReassemblyTable *table, const EdrTcpStreamKey *key,
                              uint32_t sequence, const uint8_t *payload, uint32_t payload_len,
                              uint64_t now_ns, EdrTcpReassemblyView *view);
void edr_tcp_reassembly_mark_alerted(EdrTcpReassemblyTable *table, const EdrTcpStreamKey *key);
void edr_tcp_reassembly_mark_scan_pending(EdrTcpReassemblyTable *table, const EdrTcpStreamKey *key);
int edr_tcp_reassembly_complete_scan(EdrTcpReassemblyTable *table, const EdrTcpStreamKey *key,
                                     int alerted, EdrTcpReassemblyView *retry_view);
void edr_tcp_reassembly_get_stats(const EdrTcpReassemblyTable *table, EdrTcpReassemblyStats *out);

#ifdef __cplusplus
}
#endif

#endif
