#include "edr/event_batch.h"

#include "edr/ingest_http.h"
#include "edr/storage_queue.h"
#include "edr/time_util.h"
#include "edr/transport_sink.h"

#include "edr/v1/event.pb.h"
#include <pb_decode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int persist_strategy_on_fail_only(void) {
  const char *s = getenv("EDR_PERSIST_STRATEGY");
  return s && strcmp(s, "on_fail") == 0;
}

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
static uint64_t s_batch_seq;
static int s_flush_timeout_s;
static uint64_t s_deadline_ns;
static uint64_t s_timeout_flush_count;

static void batch_note_write(void) {
  if (s_flush_timeout_s <= 0) {
    s_deadline_ns = 0;
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
  uint64_t k = ++s_batch_seq;
  unsigned long t = (unsigned long)time(NULL);
  snprintf(out, cap, "b-%lx-%llx", t, (unsigned long long)k);
}

static void maybe_persist(const char *batch_id, const uint8_t *header12, const uint8_t *payload,
                            size_t payload_len, int compressed) {
  if (persist_strategy_on_fail_only()) {
    return;
  }
  const char *e = getenv("EDR_PERSIST_QUEUE");
  if (!e || e[0] != '1') {
    return;
  }
  size_t wire_len = 12u + payload_len;
  uint8_t *wire = (uint8_t *)malloc(wire_len);
  if (!wire) {
    return;
  }
  memcpy(wire, header12, 12u);
  memcpy(wire + 12u, payload, payload_len);
  (void)edr_storage_queue_enqueue(batch_id, wire, wire_len, compressed);
  free(wire);
}

static uint32_t rd_u32_le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/**
 * 与《11》§12.4 及 ingest 划分表一致：仅 **BehaviorEvent.behavior_alert（字段 40）** 走 gRPC；
 * 其余（含 webshell/shellcode/PMFE 等无嵌套 behavior_alert 的 protobuf、以及 wire 帧）走 HTTP。
 */
static int frame_prefers_grpc_path(const uint8_t *frame, size_t frame_len) {
#if defined(EDR_HAVE_NANOPB)
  edr_v1_BehaviorEvent msg = edr_v1_BehaviorEvent_init_zero;
  pb_istream_t st = pb_istream_from_buffer(frame, frame_len);
  if (!pb_decode(&st, edr_v1_BehaviorEvent_fields, &msg)) {
    return 0;
  }
  return msg.has_behavior_alert ? 1 : 0;
#else
  (void)frame;
  (void)frame_len;
  return 0;
#endif
}

static int ingest_split_enabled(void) {
  const char *e = getenv("EDR_EVENT_INGEST_SPLIT");
  if (!e || e[0] == '\0' || strcmp(e, "0") == 0) {
    return 0;
  }
  return edr_ingest_http_configured();
}

static int append_frame_bytes(uint8_t **buf, size_t *bcap, size_t *used, const uint8_t *frame,
                              size_t flen) {
  size_t need = 4u + flen;
  if (*used + need > *bcap) {
    size_t nc = *bcap == 0 ? s_cap : *bcap;
    if (nc < need) {
      nc = need;
    }
    while (*used + need > nc) {
      nc *= 2u;
    }
    uint8_t *nb = (uint8_t *)realloc(*buf, nc);
    if (!nb) {
      return -1;
    }
    *buf = nb;
    *bcap = nc;
  }
  wr_u32_le(*buf + *used, (uint32_t)flen);
  memcpy(*buf + *used + 4u, frame, flen);
  *used += need;
  return 0;
}

static uint32_t count_frames_in_buf(const uint8_t *buf, size_t total) {
  uint32_t n = 0;
  size_t off = 0;
  while (off + 4u <= total) {
    uint32_t fl = rd_u32_le(buf + off);
    if (fl == 0 || off + 4u + (size_t)fl > total) {
      break;
    }
    off += 4u + (size_t)fl;
    n++;
  }
  return n;
}

static void emit_one_channel(const char *batch_id, const uint8_t *raw_body, size_t raw_used,
                             uint32_t frame_count, int use_http) {
  if (!raw_body || raw_used == 0u || frame_count == 0u) {
    return;
  }
  uint8_t header[12];
#ifdef EDR_HAVE_LZ4
  if (raw_used >= EDR_LZ4_MIN_IN) {
    int dst_cap = LZ4_compressBound((int)raw_used);
    if (dst_cap > 0) {
      uint8_t *dst = (uint8_t *)malloc((size_t)dst_cap);
      if (dst) {
        int clen =
            LZ4_compress_default((const char *)raw_body, (char *)dst, (int)raw_used, dst_cap);
        if (clen > 0 && (size_t)clen < raw_used) {
          wr_u32_le(header, EDR_TRANSPORT_BATCH_MAGIC_LZ4);
          wr_u32_le(header + 4, frame_count);
          wr_u32_le(header + 8, (uint32_t)raw_used);
          edr_transport_send_ingest_batch(use_http, batch_id, header, sizeof(header), dst,
                                          (size_t)clen);
          maybe_persist(batch_id, header, dst, (size_t)clen, 1);
          free(dst);
          return;
        }
        free(dst);
      }
    }
  }
#endif
  wr_u32_le(header, EDR_TRANSPORT_BATCH_MAGIC_RAW);
  wr_u32_le(header + 4, frame_count);
  wr_u32_le(header + 8, (uint32_t)raw_used);
  edr_transport_send_ingest_batch(use_http, batch_id, header, sizeof(header), raw_body, raw_used);
  maybe_persist(batch_id, header, raw_body, raw_used, 0);
}

static void flush_split(const char *batch_id_base) {
  uint8_t *grpc_acc = NULL;
  uint8_t *http_acc = NULL;
  size_t gcap = 0, hcap = 0, gused = 0, hused = 0;
  size_t off = 0;
  while (off + 4u <= s_used) {
    uint32_t fl = rd_u32_le(s_buf + off);
    if (fl == 0 || off + 4u + (size_t)fl > s_used) {
      break;
    }
    const uint8_t *frame = s_buf + off + 4u;
    int g = frame_prefers_grpc_path(frame, (size_t)fl);
    if (g) {
      if (append_frame_bytes(&grpc_acc, &gcap, &gused, frame, (size_t)fl) != 0) {
        break;
      }
    } else {
      if (append_frame_bytes(&http_acc, &hcap, &hused, frame, (size_t)fl) != 0) {
        break;
      }
    }
    off += 4u + (size_t)fl;
  }

  char bid_g[80];
  char bid_h[80];
  snprintf(bid_g, sizeof(bid_g), "%s-g", batch_id_base);
  snprintf(bid_h, sizeof(bid_h), "%s-h", batch_id_base);

  uint32_t gfc = count_frames_in_buf(grpc_acc, gused);
  uint32_t hfc = count_frames_in_buf(http_acc, hused);

  if (gused > 0u && gfc > 0u) {
    emit_one_channel(bid_g, grpc_acc, gused, gfc, 0);
  }
  if (hused > 0u && hfc > 0u) {
    emit_one_channel(bid_h, http_acc, hused, hfc, 1);
  }
  free(grpc_acc);
  free(http_acc);
}

static void flush_locked(void) {
  s_deadline_ns = 0;
  if (!s_buf || s_used == 0u) {
    return;
  }
  uint8_t header[12];
  char batch_id[64];
  make_batch_id(batch_id, sizeof(batch_id));

  if (ingest_split_enabled()) {
    flush_split(batch_id);
    s_used = 0;
    s_frame_count = 0;
    return;
  }

#ifdef EDR_HAVE_LZ4
  if (s_used >= EDR_LZ4_MIN_IN) {
    int dst_cap = LZ4_compressBound((int)s_used);
    if (dst_cap > 0) {
      uint8_t *dst = (uint8_t *)malloc((size_t)dst_cap);
      if (dst) {
        int clen =
            LZ4_compress_default((const char *)s_buf, (char *)dst, (int)s_used, dst_cap);
        if (clen > 0 && (size_t)clen < s_used) {
          wr_u32_le(header, EDR_TRANSPORT_BATCH_MAGIC_LZ4);
          wr_u32_le(header + 4, s_frame_count);
          wr_u32_le(header + 8, (uint32_t)s_used);
          edr_transport_on_event_batch(batch_id, header, sizeof(header), dst, (size_t)clen);
          maybe_persist(batch_id, header, dst, (size_t)clen, 1);
          free(dst);
          s_used = 0;
          s_frame_count = 0;
          return;
        }
        free(dst);
      }
    }
  }
#endif
  wr_u32_le(header, EDR_TRANSPORT_BATCH_MAGIC_RAW);
  wr_u32_le(header + 4, s_frame_count);
  wr_u32_le(header + 8, (uint32_t)s_used);
  edr_transport_on_event_batch(batch_id, header, sizeof(header), s_buf, s_used);
  maybe_persist(batch_id, header, s_buf, s_used, 0);
  s_used = 0;
  s_frame_count = 0;
}

EdrError edr_event_batch_init(size_t max_bytes, uint32_t max_frames_per_batch,
                              int flush_timeout_s) {
  edr_event_batch_shutdown();
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

void edr_event_batch_shutdown(void) {
  flush_locked();
  free(s_buf);
  s_buf = NULL;
  s_cap = 0;
  s_used = 0;
  s_frame_count = 0;
  s_max_frames = 0;
  s_flush_timeout_s = 0;
  s_deadline_ns = 0;
}

void edr_event_batch_poll_timeout(void) {
  if (s_flush_timeout_s <= 0 || s_used == 0u || s_deadline_ns == 0u) {
    return;
  }
  if (edr_monotonic_ns() >= s_deadline_ns) {
    flush_locked();
    s_timeout_flush_count++;
  }
}

uint64_t edr_event_batch_timeout_flush_count(void) { return s_timeout_flush_count; }

static int append_frame(const uint8_t *data, size_t len) {
  if (!s_buf || s_cap == 0) {
    return -1;
  }
  if (len > 0xffffffffu || len == 0u) {
    return -1;
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
  edr_transport_on_behavior_wire(wire, wire_len);
  int r = append_frame(wire, wire_len);
  if (r == 1) {
    flush_locked();
    r = append_frame(wire, wire_len);
  }
  return r;
}

void edr_event_batch_flush(void) { flush_locked(); }
