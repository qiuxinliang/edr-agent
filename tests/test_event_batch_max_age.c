#include "edr/event_batch.h"
#include "edr/storage_queue.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

static uint64_t s_now_ns;
static unsigned s_batch_count;
static uint32_t s_last_frame_count;
static unsigned s_wire_event_count;
static size_t s_wire_bytes;

uint64_t edr_monotonic_ns(void) { return s_now_ns; }

void edr_transport_on_behavior_wire(const uint8_t *data, size_t len) {
  (void)data;
  s_wire_event_count++;
  s_wire_bytes += len;
}

void edr_transport_on_event_batch(const char *batch_id, const uint8_t *header12,
                                  size_t header_len, const uint8_t *payload,
                                  size_t payload_len) {
  (void)batch_id;
  (void)payload;
  (void)payload_len;
  assert(header12 != NULL);
  assert(header_len == 12u);
  s_last_frame_count = (uint32_t)header12[4] |
                       ((uint32_t)header12[5] << 8) |
                       ((uint32_t)header12[6] << 16) |
                       ((uint32_t)header12[7] << 24);
  s_batch_count++;
}

void edr_transport_send_ingest_batch(int use_http, const char *batch_id,
                                     const uint8_t *header12, size_t header_len,
                                     const uint8_t *payload, size_t payload_len) {
  (void)use_http;
  edr_transport_on_event_batch(batch_id, header12, header_len, payload, payload_len);
}

EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,
                                   size_t payload_len, int compressed, int severity) {
  (void)batch_id;
  (void)payload;
  (void)payload_len;
  (void)compressed;
  (void)severity;
  return EDR_OK;
}

int main(void) {
  static const uint8_t frame[] = {0x08u, 0x01u};
  static const uint8_t too_large[4097u] = {0x08u};

  s_now_ns = 1000000000ULL;
  assert(edr_event_batch_init(4096u, 100u, 2) == EDR_OK);
  /* A transport-only profile update must not erase the active batch limits. */
  edr_event_batch_apply_profile(0u, 0);
  assert(edr_event_batch_push(frame, sizeof(frame)) == 0);
  assert(s_wire_event_count == 1u);
  assert(s_wire_bytes == sizeof(frame));

  /* A rejected frame has not entered the in-memory EventBatch, so it must
   * not be counted by the behavior-wire observer. */
  assert(edr_event_batch_push(too_large, sizeof(too_large)) != 0);
  assert(s_wire_event_count == 1u);
  assert(s_wire_bytes == sizeof(frame));

  /* Continuous arrivals must not slide the original batch deadline. */
  s_now_ns = 2000000000ULL;
  assert(edr_event_batch_push(frame, sizeof(frame)) == 0);
  assert(s_wire_event_count == 2u);
  assert(s_wire_bytes == sizeof(frame) * 2u);
  s_now_ns = 2900000000ULL;
  assert(edr_event_batch_push(frame, sizeof(frame)) == 0);
  assert(s_wire_event_count == 3u);
  assert(s_wire_bytes == sizeof(frame) * 3u);
  edr_event_batch_poll_timeout();
  assert(s_batch_count == 0u);

  s_now_ns = 3000000000ULL;
  edr_event_batch_poll_timeout();
  assert(s_batch_count == 1u);
  assert(s_last_frame_count == 3u);
  assert(edr_event_batch_timeout_flush_count() == 1u);

  edr_event_batch_shutdown();
  return 0;
}
