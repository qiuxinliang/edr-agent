#include "edr/event_batch.h"
#include "edr/storage_queue.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#ifdef _WIN32
#include <windows.h>
#define TEST_THREAD_RETURN DWORD WINAPI
typedef HANDLE TestThread;
static void yield_thread(void) { Sleep(0); }
#else
#include <pthread.h>
#include <sched.h>
#define TEST_THREAD_RETURN void *
typedef pthread_t TestThread;
static void yield_thread(void) { sched_yield(); }
#endif
#include "edr/transport_sink.h"
#ifdef EDR_HAVE_LZ4
#include "lz4.h"
#endif

static uint64_t s_now_ns;
static unsigned s_batch_count;
static uint32_t s_last_frame_count;
static unsigned s_wire_event_count;
static size_t s_wire_bytes;
static int s_handoff_failure;
static unsigned s_attempts;
static char s_last_batch_id[64];
static uint8_t s_last_payload[4096];
static size_t s_last_payload_len;
static uint8_t s_last_header[12];
enum { PRODUCERS = 4, FRAMES_PER_PRODUCER = 1000 };
static int s_check_concurrent;
static unsigned s_seen[PRODUCERS * FRAMES_PER_PRODUCER];
static unsigned s_seen_count;
static atomic_int s_start;
static atomic_uint s_progress;

static uint32_t read_u32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint64_t edr_monotonic_ns(void) { return s_now_ns; }

void edr_transport_on_behavior_wire(const uint8_t *data, size_t len) {
  (void)data;
  s_wire_event_count++;
  s_wire_bytes += len;
}

int edr_transport_on_event_batch(const char *batch_id, const uint8_t *header12,
                                  size_t header_len, const uint8_t *payload,
                                  size_t payload_len) {
  s_attempts++;
  assert(strlen(batch_id) < sizeof(s_last_batch_id));
  strcpy(s_last_batch_id, batch_id);
  assert(payload_len <= sizeof(s_last_payload));
  memcpy(s_last_payload, payload, payload_len);
  s_last_payload_len = payload_len;
  assert(header12 != NULL);
  assert(header_len == 12u);
  memcpy(s_last_header, header12, sizeof(s_last_header));
  s_last_frame_count = (uint32_t)header12[4] |
                       ((uint32_t)header12[5] << 8) |
                       ((uint32_t)header12[6] << 16) |
                       ((uint32_t)header12[7] << 24);
  if (s_handoff_failure) return -1;
  if (s_check_concurrent) {
    uint8_t decoded[4096];
    const uint8_t *frames = payload;
    size_t decoded_len = payload_len;
#ifdef EDR_HAVE_LZ4
    if (read_u32(header12) == EDR_TRANSPORT_BATCH_MAGIC_LZ4) {
      int n = LZ4_decompress_safe((const char *)payload, (char *)decoded,
                                  (int)payload_len, (int)sizeof(decoded));
      assert(n > 0);
      decoded_len = (size_t)n;
      frames = decoded;
    }
#else
    (void)decoded;
#endif
    assert(decoded_len == read_u32(header12 + 8));
    size_t pos = 0;
    for (uint32_t i = 0; i < s_last_frame_count; ++i) {
      uint32_t id;
      assert(pos + 8u <= decoded_len && read_u32(frames + pos) == sizeof(id));
      memcpy(&id, frames + pos + 4u, sizeof(id));
      assert(id < PRODUCERS * FRAMES_PER_PRODUCER);
      assert(s_seen[id]++ == 0u);
      s_seen_count++;
      pos += 8u;
    }
    assert(pos == decoded_len);
  }
  s_batch_count++;
  return 0;
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

typedef struct Producer { unsigned index; unsigned accepted; } Producer;

static TEST_THREAD_RETURN produce_frames(void *arg) {
  Producer *producer = (Producer *)arg;
  while (!atomic_load(&s_start)) yield_thread();
  for (unsigned i = 0; i < FRAMES_PER_PRODUCER; ++i) {
    uint32_t id = producer->index * FRAMES_PER_PRODUCER + i;
    if (edr_event_batch_push((const uint8_t *)&id, sizeof(id)) == 0) {
      producer->accepted++;
      atomic_fetch_add(&s_progress, 1u);
    }
  }
  return 0;
}

static TEST_THREAD_RETURN update_profile(void *arg) {
  (void)arg;
  while (!atomic_load(&s_start)) yield_thread();
  for (unsigned i = 0; i < FRAMES_PER_PRODUCER; ++i) {
    edr_event_batch_apply_profile(17u + i % 20u, 1);
    edr_event_batch_poll_timeout();
    (void)edr_event_batch_timeout_flush_count();
    assert(edr_event_batch_flush() == 0);
  }
  return 0;
}

static void test_concurrent_producers(int stop_during_push) {
  TestThread threads[PRODUCERS + 1];
  Producer producers[PRODUCERS] = {{0}};
  memset(s_seen, 0, sizeof(s_seen));
  s_seen_count = 0;
  s_check_concurrent = 1;
  atomic_store(&s_start, 0);
  atomic_store(&s_progress, 0);
  assert(edr_event_batch_init(4096u, 32u, 1) == EDR_OK);
  for (unsigned i = 0; i <= PRODUCERS; ++i) {
    void *arg = NULL;
    if (i < PRODUCERS) { producers[i].index = i; arg = &producers[i]; }
#ifdef _WIN32
    threads[i] = CreateThread(NULL, 0, i < PRODUCERS ? produce_frames : update_profile,
                               arg, 0, NULL);
    assert(threads[i] != NULL);
#else
    assert(pthread_create(&threads[i], NULL,
                           i < PRODUCERS ? produce_frames : update_profile, arg) == 0);
#endif
  }
  atomic_store(&s_start, 1);
  if (stop_during_push) {
    while (atomic_load(&s_progress) < PRODUCERS) yield_thread();
    assert(edr_event_batch_shutdown() == 0);
  }
  for (unsigned i = 0; i <= PRODUCERS; ++i) {
#ifdef _WIN32
    assert(WaitForSingleObject(threads[i], 10000) == WAIT_OBJECT_0);
    CloseHandle(threads[i]);
#else
    assert(pthread_join(threads[i], NULL) == 0);
#endif
  }
  assert(edr_event_batch_shutdown() == 0);
  unsigned accepted = 0;
  for (unsigned i = 0; i < PRODUCERS; ++i) accepted += producers[i].accepted;
  assert(accepted == s_seen_count);
  if (!stop_during_push) assert(accepted == PRODUCERS * FRAMES_PER_PRODUCER);
  uint32_t frame = 0;
  assert(edr_event_batch_push((const uint8_t *)&frame, sizeof(frame)) == -1);
  s_check_concurrent = 0;
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

  assert(edr_event_batch_shutdown() == 0);

  /* A failed flush/shutdown retains one immutable batch, never accepts a
   * second frame under its id, and retries even with ordinary age disabled. */
  assert(edr_event_batch_init(4096u, 1u, 0) == EDR_OK);
  s_handoff_failure = 1;
  assert(edr_event_batch_push(frame, sizeof(frame)) == 0);
  char pending_id[64];
  strcpy(pending_id, s_last_batch_id);
  assert(s_last_frame_count == 1u);
  assert(edr_event_batch_shutdown() == -1);
  assert(edr_event_batch_init(4096u, 1u, 0) != EDR_OK);
  assert(edr_event_batch_push(frame, sizeof(frame)) == -1);
  assert(strcmp(pending_id, s_last_batch_id) == 0);
  assert(s_last_frame_count == 1u);
  assert(s_last_payload_len == sizeof(frame) + 4u);
  assert(memcmp(s_last_payload + 4u, frame, sizeof(frame)) == 0);
  unsigned before = s_attempts;
  for (unsigned i = 0; i < 1000u; ++i)
    assert(edr_event_batch_push(frame, sizeof(frame)) == -1);
  assert(s_attempts == before);
  edr_event_batch_poll_timeout();
  assert(s_attempts == before);
  s_now_ns += 1000000000ULL;
  s_handoff_failure = 0;
  edr_event_batch_poll_timeout();
  assert(s_attempts == before + 1u);
  assert(strcmp(pending_id, s_last_batch_id) == 0);
  assert(s_batch_count == 2u);
  assert(edr_event_batch_shutdown() == 0);

  /* Production LZ4 and RAW retries both retain the exact encoded bytes and
   * header, not just the source frames, under the stable batch id. */
  uint8_t large_frame[2048];
  uint8_t pending_payload[4096];
  uint8_t pending_header[12];
  memset(large_frame, 'x', sizeof(large_frame));
  assert(edr_event_batch_init(4096u, 1u, 1) == EDR_OK);
  s_handoff_failure = 1;
  assert(edr_event_batch_push(large_frame, sizeof(large_frame)) == 0);
  size_t pending_len = s_last_payload_len;
  strcpy(pending_id, s_last_batch_id);
  memcpy(pending_payload, s_last_payload, pending_len);
  memcpy(pending_header, s_last_header, sizeof(pending_header));
#ifdef EDR_HAVE_LZ4
  uint8_t decoded[4096];
  assert(pending_len < sizeof(large_frame));
  assert(LZ4_decompress_safe((const char *)pending_payload, (char *)decoded,
                            (int)pending_len, (int)sizeof(decoded)) ==
         (int)sizeof(large_frame) + 4);
  assert(memcmp(decoded + 4, large_frame, sizeof(large_frame)) == 0);
#else
  assert(pending_len == sizeof(large_frame) + 4u);
#endif
  assert(edr_event_batch_flush() == -1);
  s_handoff_failure = 0;
  assert(edr_event_batch_shutdown() == 0);
  assert(strcmp(pending_id, s_last_batch_id) == 0);
  assert(pending_len == s_last_payload_len);
  assert(memcmp(pending_header, s_last_header, sizeof(pending_header)) == 0);
  assert(memcmp(pending_payload, s_last_payload, pending_len) == 0);
  test_concurrent_producers(0);
  test_concurrent_producers(1);
  return 0;
}
