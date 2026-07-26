#include "edr/tcp_reassembly.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *message) {
  fprintf(stderr, "fail: %s\n", message);
  return 1;
}

static EdrTcpStreamKey key4(uint8_t src, uint16_t sport, uint8_t dst, uint16_t dport) {
  EdrTcpStreamKey key;
  memset(&key, 0, sizeof(key));
  key.family = 4u;
  key.src_addr[0] = 10u;
  key.src_addr[3] = src;
  key.dst_addr[0] = 10u;
  key.dst_addr[3] = dst;
  key.src_port = sport;
  key.dst_port = dport;
  return key;
}

int main(void) {
  EdrTcpReassemblyTable *table = edr_tcp_reassembly_create(64u, 256u, 4096u, 30ull * 1000000000ull);
  if (!table) return fail("create");
  EdrTcpReassemblyView view;
  EdrTcpStreamKey key = key4(1u, 50000u, 2u, 445u);

  if (edr_tcp_reassembly_submit(table, &key, 100u, (const uint8_t *)"AAAA", 4u, 1u, &view) != 0 ||
      !view.updated || view.length != 4u) return fail("first segment");
  if (edr_tcp_reassembly_submit(table, &key, 108u, (const uint8_t *)"CCCC", 4u, 2u, &view) != 0 ||
      view.updated || view.length != 4u) return fail("out of order gap");
  if (edr_tcp_reassembly_submit(table, &key, 104u, (const uint8_t *)"BBBB", 4u, 3u, &view) != 0 ||
      !view.updated || view.length != 12u || memcmp(view.data, "AAAABBBBCCCC", 12u) != 0) {
    return fail("gap fill must expose contiguous stream");
  }
  if (edr_tcp_reassembly_submit(table, &key, 104u, (const uint8_t *)"BBBB", 4u, 4u, &view) != 0 || view.updated) {
    return fail("retransmit must not rescan");
  }
  edr_tcp_reassembly_mark_alerted(table, &key);
  if (edr_tcp_reassembly_submit(table, &key, 112u, (const uint8_t *)"DDDD", 4u, 5u, &view) != 0 || view.updated) {
    return fail("alerted stream must suppress duplicate scans");
  }

  EdrTcpStreamKey prepend_key = key4(3u, 51000u, 4u, 3389u);
  if (edr_tcp_reassembly_submit(table, &prepend_key, 204u, (const uint8_t *)"TAIL", 4u, 6u, &view) != 0) {
    return fail("prepend seed");
  }
  if (edr_tcp_reassembly_submit(table, &prepend_key, 200u, (const uint8_t *)"HEAD", 4u, 7u, &view) != 0 ||
      !view.updated || view.length != 8u || memcmp(view.data, "HEADTAIL", 8u) != 0) {
    return fail("late earlier segment prepend");
  }

  EdrTcpStreamKey reverse = key4(2u, 445u, 1u, 50000u);
  if (edr_tcp_reassembly_submit(table, &reverse, 900u, (const uint8_t *)"REPLY", 5u, 8u, &view) != 0 ||
      view.length != 5u || memcmp(view.data, "REPLY", 5u) != 0) {
    return fail("directions must remain independent");
  }

  EdrTcpStreamKey pending = key4(5u, 52000u, 6u, 5985u);
  if (edr_tcp_reassembly_submit(table, &pending, 1000u, (const uint8_t *)"ONE-", 4u, 9u, &view) != 0 ||
      !view.updated) return fail("pending seed");
  edr_tcp_reassembly_mark_scan_pending(table, &pending);
  if (edr_tcp_reassembly_submit(table, &pending, 1004u, (const uint8_t *)"TWO", 3u, 10u, &view) != 0 ||
      view.updated) return fail("pending flow must coalesce growth");
  EdrTcpReassemblyView retry;
  if (edr_tcp_reassembly_complete_scan(table, &pending, 0, &retry) != 1 || retry.length != 7u ||
      memcmp(retry.data, "ONE-TWO", 7u) != 0) return fail("dirty pending flow retry");
  if (edr_tcp_reassembly_complete_scan(table, &pending, 1, &retry) != 0) return fail("retry alert completion");

  EdrTcpReassemblyStats stats;
  edr_tcp_reassembly_get_stats(table, &stats);
  if (stats.segments_seen != 10u || stats.out_of_order_segments == 0u || stats.retransmit_bytes < 4u ||
      stats.active_streams < 4u || stats.memory_bytes == 0u) {
    return fail("stats");
  }
  edr_tcp_reassembly_destroy(table);
  return 0;
}
