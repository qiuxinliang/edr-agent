#include "fl_pb_wire.h"

#include <string.h>

static int append_varint(uint8_t *out, size_t cap, size_t *off, uint64_t v) {
  for (;;) {
    if (*off >= cap) {
      return 0;
    }
    if (v < 0x80u) {
      out[(*off)++] = (uint8_t)v;
      return 1;
    }
    out[(*off)++] = (uint8_t)((v & 0x7Fu) | 0x80u);
    v >>= 7;
  }
}

static int append_string_field(uint8_t *out, size_t cap, size_t *off, uint32_t field_no,
                               const char *s) {
  size_t len = s ? strlen(s) : 0u;
  uint32_t tag = (field_no << 3u) | 2u;
  if (!append_varint(out, cap, off, tag)) {
    return 0;
  }
  if (!append_varint(out, cap, off, (uint64_t)len)) {
    return 0;
  }
  if (*off + len > cap) {
    return 0;
  }
  if (len > 0u && s) {
    memcpy(out + *off, s, len);
  }
  *off += len;
  return 1;
}

static int append_bytes_field(uint8_t *out, size_t cap, size_t *off, uint32_t field_no,
                              const uint8_t *data, size_t data_len) {
  uint32_t tag = (field_no << 3u) | 2u;
  if (!append_varint(out, cap, off, tag)) {
    return 0;
  }
  if (!append_varint(out, cap, off, (uint64_t)data_len)) {
    return 0;
  }
  if (*off + data_len > cap) {
    return 0;
  }
  if (data_len > 0u && data) {
    memcpy(out + *off, data, data_len);
  }
  *off += data_len;
  return 1;
}

static int append_uint64_field(uint8_t *out, size_t cap, size_t *off, uint32_t field_no,
                               uint64_t v) {
  uint32_t tag = (field_no << 3u) | 0u;
  if (!append_varint(out, cap, off, tag)) {
    return 0;
  }
  if (!append_varint(out, cap, off, v)) {
    return 0;
  }
  return 1;
}

static size_t pb_encode_upload_gradients_core(uint8_t *out, size_t out_cap, const char *endpoint_id,
                                              uint64_t round_id, const uint8_t *sealed, size_t sealed_len,
                                              const char *tenant_id, const char *gradient_upload_id,
                                              uint32_t chunk_index, uint32_t chunk_count, int with_chunks) {
  size_t off = 0;
  if (!out || out_cap == 0u) {
    return 0;
  }
  if (!append_string_field(out, out_cap, &off, 1u, endpoint_id ? endpoint_id : "")) {
    return 0;
  }
  if (!append_uint64_field(out, out_cap, &off, 2u, round_id)) {
    return 0;
  }
  if (!append_bytes_field(out, out_cap, &off, 3u, sealed, sealed_len)) {
    return 0;
  }
  if (tenant_id && tenant_id[0]) {
    if (!append_string_field(out, out_cap, &off, 4u, tenant_id)) {
      return 0;
    }
  }
  if (with_chunks) {
    if (!gradient_upload_id || !gradient_upload_id[0]) {
      return 0;
    }
    if (chunk_count == 0u || chunk_index >= chunk_count) {
      return 0;
    }
    if (!append_string_field(out, out_cap, &off, 5u, gradient_upload_id)) {
      return 0;
    }
    if (!append_uint64_field(out, out_cap, &off, 6u, (uint64_t)chunk_index)) {
      return 0;
    }
    if (!append_uint64_field(out, out_cap, &off, 7u, (uint64_t)chunk_count)) {
      return 0;
    }
  }
  return off;
}

size_t fl_pb_encode_upload_gradients(uint8_t *out, size_t out_cap, const char *endpoint_id,
                                     uint64_t round_id, const uint8_t *sealed, size_t sealed_len,
                                     const char *tenant_id) {
  return pb_encode_upload_gradients_core(out, out_cap, endpoint_id, round_id, sealed, sealed_len, tenant_id, NULL, 0u,
                                         0u, 0);
}

size_t fl_pb_encode_upload_gradients_chunked(uint8_t *out, size_t out_cap, const char *endpoint_id,
                                             uint64_t round_id, const uint8_t *chunk, size_t chunk_len,
                                             const char *tenant_id, const char *gradient_upload_id,
                                             uint32_t chunk_index, uint32_t chunk_count) {
  return pb_encode_upload_gradients_core(out, out_cap, endpoint_id, round_id, chunk, chunk_len, tenant_id,
                                         gradient_upload_id, chunk_index, chunk_count, 1);
}
