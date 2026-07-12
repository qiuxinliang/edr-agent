#include "edr/event_batch.h"
#include "edr/storage_queue.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

static uint64_t s_now_ns;
static unsigned s_batch_count;
static uint32_t s_last_frame_count;

uint64_t edr_monotonic_ns(void) { return s_now_ns; }

void edr_transport_on_behavior_wire(const uint8_t *data, size_t len) {
  (void)data;
  (void)len;
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

  s_now_ns = 1000000000ULL;
  assert(edr_event_batch_init(4096u, 100u, 2) == EDR_OK);
  /* A transport-only profile update must not erase the active batch limits. */
  edr_event_batch_apply_profile(0u, 0);
  assert(edr_event_batch_push(frame, sizeof(frame)) == 0);

  /* Continuous arrivals must not slide the original batch deadline. */
  s_now_ns = 2000000000ULL;
  assert(edr_event_batch_push(frame, sizeof(frame)) == 0);
  s_now_ns = 2900000000ULL;
  assert(edr_event_batch_push(frame, sizeof(frame)) == 0);
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
