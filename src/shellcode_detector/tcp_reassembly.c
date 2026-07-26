#include "edr/tcp_reassembly.h"

#include <stdlib.h>
#include <string.h>

/* Structured endpoint tuples cluster more than random keys; keep enough open-addressing
 * probes to avoid evicting live streams while the table is still lightly loaded. */
#define EDR_TCP_REASSEMBLY_PROBES 32u

typedef struct {
  int used;
  int alerted;
  int scan_pending;
  int dirty_while_pending;
  EdrTcpStreamKey key;
  uint32_t base_seq;
  uint32_t contiguous_len;
  uint32_t highest_offset;
  uint64_t last_ns;
  uint8_t *data;
  uint8_t *present;
} EdrTcpStreamSlot;

struct EdrTcpReassemblyTable {
  EdrTcpStreamSlot *slots;
  uint32_t slot_count;
  uint32_t mask;
  uint32_t max_stream_bytes;
  uint32_t present_bytes;
  uint64_t max_memory_bytes;
  uint64_t idle_timeout_ns;
  EdrTcpReassemblyStats stats;
};

static uint32_t hash_key(const EdrTcpStreamKey *key) {
  const uint8_t *p = (const uint8_t *)key;
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < sizeof(*key); i++) h = (h ^ p[i]) * 16777619u;
  return h;
}

static int key_equal(const EdrTcpStreamKey *a, const EdrTcpStreamKey *b) {
  return memcmp(a, b, sizeof(*a)) == 0;
}

static void bit_set(uint8_t *bits, uint32_t index) {
  bits[index >> 3u] |= (uint8_t)(1u << (index & 7u));
}

static void bit_clear(uint8_t *bits, uint32_t index) {
  bits[index >> 3u] &= (uint8_t)~(1u << (index & 7u));
}

static int bit_get(const uint8_t *bits, uint32_t index) {
  return (bits[index >> 3u] & (uint8_t)(1u << (index & 7u))) != 0u;
}

static void slot_release(EdrTcpReassemblyTable *table, EdrTcpStreamSlot *slot, int evicted) {
  if (!slot || !slot->used) return;
  free(slot->data);
  free(slot->present);
  slot->data = NULL;
  slot->present = NULL;
  slot->used = 0;
  if (table->stats.active_streams > 0u) table->stats.active_streams--;
  uint64_t bytes = (uint64_t)table->max_stream_bytes + table->present_bytes;
  table->stats.memory_bytes = table->stats.memory_bytes >= bytes ? table->stats.memory_bytes - bytes : 0u;
  if (evicted) table->stats.evicted_streams++;
}

static EdrTcpStreamSlot *oldest_slot(EdrTcpReassemblyTable *table, const EdrTcpStreamSlot *exclude) {
  EdrTcpStreamSlot *oldest = NULL;
  for (uint32_t i = 0; i < table->slot_count; i++) {
    EdrTcpStreamSlot *slot = &table->slots[i];
    if (!slot->used || slot == exclude) continue;
    if (!oldest || slot->last_ns < oldest->last_ns) oldest = slot;
  }
  return oldest;
}

static int reserve_slot_storage(EdrTcpReassemblyTable *table, EdrTcpStreamSlot *slot) {
  uint64_t need = (uint64_t)table->max_stream_bytes + table->present_bytes;
  while (table->stats.memory_bytes + need > table->max_memory_bytes) {
    EdrTcpStreamSlot *victim = oldest_slot(table, slot);
    if (!victim) {
      table->stats.memory_drops++;
      return -1;
    }
    slot_release(table, victim, 1);
  }
  slot->data = (uint8_t *)calloc(1, table->max_stream_bytes);
  slot->present = (uint8_t *)calloc(1, table->present_bytes);
  if (!slot->data || !slot->present) {
    free(slot->data);
    free(slot->present);
    slot->data = NULL;
    slot->present = NULL;
    table->stats.memory_drops++;
    return -1;
  }
  table->stats.memory_bytes += need;
  return 0;
}

static EdrTcpStreamSlot *find_slot(EdrTcpReassemblyTable *table, const EdrTcpStreamKey *key,
                                   uint64_t now_ns) {
  uint32_t start = hash_key(key) & table->mask;
  EdrTcpStreamSlot *candidate = NULL;
  for (uint32_t probe = 0; probe < EDR_TCP_REASSEMBLY_PROBES; probe++) {
    EdrTcpStreamSlot *slot = &table->slots[(start + probe) & table->mask];
    if (slot->used && table->idle_timeout_ns > 0u && now_ns > slot->last_ns &&
        now_ns - slot->last_ns > table->idle_timeout_ns) {
      slot_release(table, slot, 1);
    }
    if (slot->used && key_equal(&slot->key, key)) return slot;
    if (!slot->used && !candidate) candidate = slot;
  }
  if (candidate) return candidate;
  EdrTcpStreamSlot *victim = oldest_slot(table, NULL);
  if (victim) slot_release(table, victim, 1);
  return victim;
}

EdrTcpReassemblyTable *edr_tcp_reassembly_create(uint32_t max_flows, uint32_t max_stream_bytes,
                                                  uint64_t max_memory_bytes, uint64_t idle_timeout_ns) {
  if (max_stream_bytes == 0u || max_memory_bytes < (uint64_t)max_stream_bytes + 1u) return NULL;
  uint32_t count = 64u;
  while (count < max_flows && count < (1u << 20)) count <<= 1u;
  EdrTcpReassemblyTable *table = (EdrTcpReassemblyTable *)calloc(1, sizeof(*table));
  if (!table) return NULL;
  table->slots = (EdrTcpStreamSlot *)calloc(count, sizeof(*table->slots));
  if (!table->slots) {
    free(table);
    return NULL;
  }
  table->slot_count = count;
  table->mask = count - 1u;
  table->max_stream_bytes = max_stream_bytes;
  table->present_bytes = (max_stream_bytes + 7u) / 8u;
  table->max_memory_bytes = max_memory_bytes;
  table->idle_timeout_ns = idle_timeout_ns;
  return table;
}

void edr_tcp_reassembly_destroy(EdrTcpReassemblyTable *table) {
  if (!table) return;
  for (uint32_t i = 0; i < table->slot_count; i++) slot_release(table, &table->slots[i], 0);
  free(table->slots);
  free(table);
}

int edr_tcp_reassembly_submit(EdrTcpReassemblyTable *table, const EdrTcpStreamKey *key,
                              uint32_t sequence, const uint8_t *payload, uint32_t payload_len,
                              uint64_t now_ns, EdrTcpReassemblyView *view) {
  if (!table || !key || !payload || payload_len == 0u || !view) return -1;
  memset(view, 0, sizeof(*view));
  table->stats.segments_seen++;
  EdrTcpStreamSlot *slot = find_slot(table, key, now_ns);
  if (!slot) {
    table->stats.memory_drops++;
    return -1;
  }
  if (!slot->used) {
    memset(slot, 0, sizeof(*slot));
    if (reserve_slot_storage(table, slot) != 0) return -1;
    slot->used = 1;
    slot->key = *key;
    slot->base_seq = sequence;
    table->stats.active_streams++;
  }
  slot->last_ns = now_ns;

  int32_t signed_offset = (int32_t)(sequence - slot->base_seq);
  if (signed_offset < 0) {
    uint32_t prepend = (uint32_t)(-signed_offset);
    if (prepend >= table->max_stream_bytes || slot->highest_offset + prepend > table->max_stream_bytes) {
      table->stats.truncated_segments++;
      view->truncated = 1;
      return 0;
    }
    memmove(slot->data + prepend, slot->data, slot->highest_offset);
    memset(slot->data, 0, prepend);
    for (uint32_t i = slot->highest_offset; i > 0u; i--) {
      uint32_t old_index = i - 1u;
      if (bit_get(slot->present, old_index)) {
        bit_set(slot->present, old_index + prepend);
      } else {
        bit_clear(slot->present, old_index + prepend);
      }
    }
    for (uint32_t i = 0; i < prepend; i++) bit_clear(slot->present, i);
    slot->base_seq = sequence;
    slot->highest_offset += prepend;
    slot->contiguous_len = 0u;
    signed_offset = 0;
    table->stats.out_of_order_segments++;
  }

  uint32_t offset = (uint32_t)signed_offset;
  if (offset >= table->max_stream_bytes) {
    table->stats.truncated_segments++;
    view->truncated = 1;
    return 0;
  }
  uint32_t copy = payload_len;
  if (copy > table->max_stream_bytes - offset) {
    copy = table->max_stream_bytes - offset;
    table->stats.truncated_segments++;
    view->truncated = 1;
  }
  if (offset > slot->contiguous_len) {
    table->stats.out_of_order_segments++;
    table->stats.gap_waits++;
  }
  uint32_t old_contiguous = slot->contiguous_len;
  for (uint32_t i = 0; i < copy; i++) {
    uint32_t at = offset + i;
    if (bit_get(slot->present, at)) table->stats.retransmit_bytes++;
    slot->data[at] = payload[i];
    bit_set(slot->present, at);
  }
  if (offset + copy > slot->highest_offset) slot->highest_offset = offset + copy;
  while (slot->contiguous_len < slot->highest_offset && bit_get(slot->present, slot->contiguous_len)) {
    slot->contiguous_len++;
  }
  view->data = slot->data;
  view->length = slot->contiguous_len;
  view->newly_contiguous = slot->contiguous_len - old_contiguous;
  if (slot->scan_pending && view->newly_contiguous > 0u) slot->dirty_while_pending = 1;
  view->updated = !slot->alerted && !slot->scan_pending && view->newly_contiguous > 0u;
  return 0;
}

void edr_tcp_reassembly_mark_scan_pending(EdrTcpReassemblyTable *table, const EdrTcpStreamKey *key) {
  if (!table || !key) return;
  uint32_t start = hash_key(key) & table->mask;
  for (uint32_t probe = 0; probe < EDR_TCP_REASSEMBLY_PROBES; probe++) {
    EdrTcpStreamSlot *slot = &table->slots[(start + probe) & table->mask];
    if (slot->used && key_equal(&slot->key, key)) {
      slot->scan_pending = 1;
      return;
    }
  }
}

int edr_tcp_reassembly_complete_scan(EdrTcpReassemblyTable *table, const EdrTcpStreamKey *key,
                                     int alerted, EdrTcpReassemblyView *retry_view) {
  if (retry_view) memset(retry_view, 0, sizeof(*retry_view));
  if (!table || !key) return 0;
  uint32_t start = hash_key(key) & table->mask;
  for (uint32_t probe = 0; probe < EDR_TCP_REASSEMBLY_PROBES; probe++) {
    EdrTcpStreamSlot *slot = &table->slots[(start + probe) & table->mask];
    if (!slot->used || !key_equal(&slot->key, key)) continue;
    slot->scan_pending = 0;
    if (alerted) {
      slot->alerted = 1;
      slot->dirty_while_pending = 0;
      return 0;
    }
    if (slot->dirty_while_pending && retry_view && slot->contiguous_len > 0u) {
      slot->dirty_while_pending = 0;
      slot->scan_pending = 1;
      retry_view->data = slot->data;
      retry_view->length = slot->contiguous_len;
      retry_view->newly_contiguous = slot->contiguous_len;
      retry_view->updated = 1;
      return 1;
    }
    return 0;
  }
  return 0;
}

void edr_tcp_reassembly_mark_alerted(EdrTcpReassemblyTable *table, const EdrTcpStreamKey *key) {
  if (!table || !key) return;
  uint32_t start = hash_key(key) & table->mask;
  for (uint32_t probe = 0; probe < EDR_TCP_REASSEMBLY_PROBES; probe++) {
    EdrTcpStreamSlot *slot = &table->slots[(start + probe) & table->mask];
    if (slot->used && key_equal(&slot->key, key)) {
      slot->alerted = 1;
      return;
    }
  }
}

void edr_tcp_reassembly_get_stats(const EdrTcpReassemblyTable *table, EdrTcpReassemblyStats *out) {
  if (!out) return;
  memset(out, 0, sizeof(*out));
  if (table) *out = table->stats;
}
