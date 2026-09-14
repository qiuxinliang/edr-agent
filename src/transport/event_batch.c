#include "edr/event_batch.h"

#include "edr/time_util.h"
#include "edr/transport_sink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>

#ifdef _WIN32
#include <windows.h>
static SRWLOCK s_batch_lock = SRWLOCK_INIT;
static void batch_lock(void) { AcquireSRWLockExclusive(&s_batch_lock); }
static void batch_unlock(void) { ReleaseSRWLockExclusive(&s_batch_lock); }
#else
#include <pthread.h>
static pthread_mutex_t s_batch_lock = PTHREAD_MUTEX_INITIALIZER;
static void batch_lock(void) { pthread_mutex_lock(&s_batch_lock); }
static void batch_unlock(void) { pthread_mutex_unlock(&s_batch_lock); }
#endif

#ifndef ATOMIC_VAR_INIT
#define ATOMIC_VAR_INIT(value) (value)
#endif

#ifdef EDR_HAVE_LZ4
#include "lz4.h"
#endif

#ifndef EDR_LZ4_MIN_IN
#define EDR_LZ4_MIN_IN 1024u
#endif

static uint8_t *s_buf;
static size_t s_cap;
static uint32_t s_max_frames;
static size_t s_used;
static uint32_t s_frame_count;
static atomic_uint_fast64_t s_batch_seq = ATOMIC_VAR_INIT(0);
static atomic_uint_fast64_t s_batch_boot_nonce = ATOMIC_VAR_INIT(0);
static int s_flush_timeout_s;
static uint64_t s_deadline_ns;
static uint64_t s_timeout_flush_count;
static char s_pending_batch_id[64];
static uint8_t s_pending_header[12];
static uint8_t *s_pending_compressed;
static size_t s_pending_payload_len;

static void batch_note_write(void) {
  if (s_flush_timeout_s <= 0) {
    s_deadline_ns = 0;
    return;
  }
  if (s_deadline_ns != 0u) {
    return;
  }
  uint64_t now = edr_monotonic_ns();
  s_deadline_ns = now + (uint64_t)s_flush_timeout_s * 1000000000ULL;
}

static void wr_u32_le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xffu);
  p[1] = (uint8_t)((v >> 8) & 0xffu);
  p[2] = (uint8_t)((v >> 16) & 0xffu);
  p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static void make_batch_id(char *out, size_t cap) {
  uint64_t k = atomic_fetch_add_explicit(&s_batch_seq, 1u, memory_order_relaxed) + 1u;
  uint64_t nonce = atomic_load_explicit(&s_batch_boot_nonce, memory_order_acquire);
  if (nonce == 0u) {
    uint64_t candidate = edr_monotonic_ns() ^ (uint64_t)(uintptr_t)&s_batch_seq ^
                         ((uint64_t)time(NULL) << 19u);
    if (candidate == 0u) candidate = 1u;
    (void)atomic_compare_exchange_strong_explicit(&s_batch_boot_nonce, &nonce, candidate,
                                                   memory_order_release, memory_order_acquire);
    nonce = atomic_load_explicit(&s_batch_boot_nonce, memory_order_acquire);
  }
  snprintf(out, cap, "b-%016llx-%016llx", (unsigned long long)nonce,
           (unsigned long long)k);
}

static int flush_locked(void) {
  int result = -1;
  s_deadline_ns = 0;
  if (!s_buf || s_used == 0u) {
    return 0;
  }
  if (!s_pending_batch_id[0]) {
    make_batch_id(s_pending_batch_id, sizeof(s_pending_batch_id));
    wr_u32_le(s_pending_header, EDR_TRANSPORT_BATCH_MAGIC_RAW);
    wr_u32_le(s_pending_header + 4u, s_frame_count);
    wr_u32_le(s_pending_header + 8u, (uint32_t)s_used);
    s_pending_payload_len = s_used;
#ifdef EDR_HAVE_LZ4
    if (s_used >= EDR_LZ4_MIN_IN) {
      int capacity = LZ4_compressBound((int)s_used);
      uint8_t *compressed = capacity > 0 ? (uint8_t *)malloc((size_t)capacity) : NULL;
      if (compressed) {
        int len = LZ4_compress_default((const char *)s_buf, (char *)compressed,
                                       (int)s_used, capacity);
        if (len > 0 && (size_t)len < s_used) {
          s_pending_compressed = compressed;
          s_pending_payload_len = (size_t)len;
          wr_u32_le(s_pending_header, EDR_TRANSPORT_BATCH_MAGIC_LZ4);
        } else {
          free(compressed);
        }
      }
    }
#endif
  }
  result = edr_transport_on_event_batch(s_pending_batch_id, s_pending_header, 12u,
                                        s_pending_compressed ? s_pending_compressed : s_buf,
                                        s_pending_payload_len);
  if (result != 0) {
    /* The sealed batch cannot change under the same id on a later retry. */
    s_deadline_ns = edr_monotonic_ns() + 1000000000ULL;
    fprintf(stderr, "[batch] durable handoff failed; retained batch=%s frames=%u bytes=%zu\n",
            s_pending_batch_id, s_frame_count, s_used);
    return -1;
  }
  s_used = 0;
  s_frame_count = 0;
  s_pending_batch_id[0] = '\0';
  free(s_pending_compressed);
  s_pending_compressed = NULL;
  s_pending_payload_len = 0;
  return 0;
}

static int shutdown_locked(void);

static EdrError init_locked(size_t max_bytes, uint32_t max_frames_per_batch,
                              int flush_timeout_s) {
  if (shutdown_locked() != 0) return EDR_ERR_INTERNAL;
  s_flush_timeout_s = flush_timeout_s;
  s_deadline_ns = 0;
  s_timeout_flush_count = 0;
  if (max_bytes < 4096u) {
    max_bytes = 4096u;
  }
  if (max_bytes > 64u * 1024u * 1024u) {
    max_bytes = 64u * 1024u * 1024u;
  }
  s_cap = max_bytes;
  s_max_frames = max_frames_per_batch;
  s_buf = (uint8_t *)malloc(s_cap);
  if (!s_buf) {
    s_cap = 0;
    return EDR_ERR_INTERNAL;
  }
  s_used = 0;
  s_frame_count = 0;
  return EDR_OK;
}

EdrError edr_event_batch_init(size_t max_bytes, uint32_t max_frames_per_batch,
                              int flush_timeout_s) {
  batch_lock();
  EdrError result = init_locked(max_bytes, max_frames_per_batch, flush_timeout_s);
  batch_unlock();
  return result;
}

void edr_event_batch_apply_profile(uint32_t max_frames_per_batch, int flush_timeout_s) {
  batch_lock();
  if (flush_timeout_s > 300) {
    flush_timeout_s = 300;
  }
  if (max_frames_per_batch > 0u) {
    s_max_frames = max_frames_per_batch;
  }
  if (flush_timeout_s > 0) {
    s_flush_timeout_s = flush_timeout_s;
  }
  if (s_used > 0u) {
    batch_note_write();
  }
  if (s_max_frames > 0u && s_frame_count >= s_max_frames &&
      (!s_pending_batch_id[0] || !s_deadline_ns || edr_monotonic_ns() >= s_deadline_ns)) {
    flush_locked();
  }
  batch_unlock();
}

static int shutdown_locked(void) {
  if (flush_locked() != 0) return -1;
  free(s_buf);
  s_buf = NULL;
  s_cap = 0;
  s_used = 0;
  s_frame_count = 0;
  s_max_frames = 0;
  s_flush_timeout_s = 0;
  s_deadline_ns = 0;
  return 0;
}

int edr_event_batch_shutdown(void) {
  batch_lock();
  int result = shutdown_locked();
  batch_unlock();
  return result;
}

void edr_event_batch_poll_timeout(void) {
  batch_lock();
  if (s_used != 0u && s_deadline_ns != 0u && edr_monotonic_ns() >= s_deadline_ns) {
    if (flush_locked() == 0) s_timeout_flush_count++;
  }
  batch_unlock();
}

uint64_t edr_event_batch_timeout_flush_count(void) {
  batch_lock();
  uint64_t count = s_timeout_flush_count;
  batch_unlock();
  return count;
}

static int append_frame(const uint8_t *data, size_t len) {
  if (!data || !s_buf || s_cap == 0) {
    return -1;
  }
  if (len > 0xffffffffu || len == 0u) {
    return -1;
  }
  if (s_pending_batch_id[0]) {
    /* Continuous arrivals must not bypass failed-handoff retry dampening. */
    if (s_deadline_ns && edr_monotonic_ns() < s_deadline_ns) return -1;
    if (flush_locked() != 0) return -1;
  }
  size_t need = 4u + len;
  if (need > s_cap) {
    return -1;
  }
  if (s_used + need > s_cap) {
    return 1;
  }
  wr_u32_le(s_buf + s_used, (uint32_t)len);
  memcpy(s_buf + s_used + 4u, data, len);
  s_used += need;
  s_frame_count++;
  batch_note_write();
  if (s_max_frames > 0u && s_frame_count >= s_max_frames) {
    flush_locked();
  }
  return 0;
}

int edr_event_batch_push(const uint8_t *wire, size_t wire_len) {
  batch_lock();
  int r = append_frame(wire, wire_len);
  if (r == 1) {
    r = flush_locked() == 0 ? append_frame(wire, wire_len) : -1;
  }
  if (r == 0) {
    edr_transport_on_behavior_wire(wire, wire_len);
  }
  batch_unlock();
  return r;
}

int edr_event_batch_flush(void) {
  batch_lock();
  int result = flush_locked();
  batch_unlock();
  return result;
}
