#include "fl_gradient_upload.h"

#include "edr/fl_trainer.h"
#include "fl_b64.h"
#include "fl_frozen_layers.h"
#include "fl_http_upload.h"
#include "fl_pb_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#if defined(EDR_HAVE_GRPC_FL)
extern int fl_grpc_upload_gradient_call(const char *target, int insecure, const uint8_t *wire_body,
                                        size_t wire_len, char *errbuf, size_t errcap);
#endif

static void fl_gradient_make_upload_id(char *out, size_t cap) {
  static uint32_t s_seq;
  uint64_t t = (uint64_t)time(NULL);
  uint32_t seq = ++s_seq;
#ifdef _WIN32
  unsigned pid = (unsigned)GetCurrentProcessId();
#else
  unsigned pid = (unsigned)getpid();
#endif
  if (cap < 48u) {
    if (cap > 0u) {
      out[0] = '\0';
    }
    return;
  }
  snprintf(out, cap, "flu-%016llx-%04x-%08x", (unsigned long long)t, (unsigned)(pid & 0xffffu), (unsigned)seq);
}

static int fl_gradient_upload_trace(const unsigned char *data, size_t len) {
  const char *trace = getenv("EDR_FL_UPLOAD_TRACE");
  if (trace && trace[0] && data && len > 0u) {
    FILE *fp = fopen(trace, "ab");
    if (fp) {
      (void)fwrite(data, 1, len, fp);
      fclose(fp);
    }
  }
  return 0;
}

static int fl_gradient_upload_http_one(const unsigned char *chunk, size_t chunk_len, const char *http_url,
                                       const char *endpoint_id, const char *tenant_id, uint64_t round_id,
                                       const char *upload_id, uint32_t chunk_index, uint32_t chunk_count,
                                       const FLTConfig *fc) {
  size_t b64cap = 4u * ((chunk_len + 2u) / 3u) + 8u;
  char *b64 = (char *)malloc(b64cap + 1u);
  char *json = NULL;
  size_t json_cap;
  size_t jl;
  int hr;
  char sfx[2048];
  int sl = 0;
  const char *sfx_use = "";

  if (!b64) {
    return -1;
  }
  if (fl_b64_encode(chunk, chunk_len, b64, b64cap) == 0u) {
    free(b64);
    return -1;
  }
  if (fc) {
    sl = fl_frozen_http_json_suffix(fc, sfx, sizeof(sfx));
    if (sl > 0) {
      sfx_use = sfx;
    }
  }
  json_cap = strlen(b64) + (endpoint_id ? strlen(endpoint_id) : 8u) + (tenant_id ? strlen(tenant_id) : 0u) +
             (upload_id ? strlen(upload_id) : 0u) + 384u + (size_t)(sl > 0 ? (size_t)sl : 0u);
  json = (char *)malloc(json_cap);
  if (!json) {
    free(b64);
    return -1;
  }
  if (upload_id && upload_id[0]) {
    jl = (size_t)snprintf(json, json_cap,
                          "{\"endpoint_id\":\"%s\",\"round_id\":%llu,\"sealed_gradient\":\"%s\","
                          "\"tenant_id\":\"%s\",\"gradient_upload_id\":\"%s\",\"chunk_index\":%u,\"chunk_count\":%u%s}",
                          endpoint_id ? endpoint_id : "", (unsigned long long)round_id, b64,
                          tenant_id ? tenant_id : "", upload_id, (unsigned)chunk_index, (unsigned)chunk_count,
                          sfx_use);
  } else {
    jl = (size_t)snprintf(json, json_cap,
                          "{\"endpoint_id\":\"%s\",\"round_id\":%llu,\"sealed_gradient\":\"%s\","
                          "\"tenant_id\":\"%s\"%s}",
                          endpoint_id ? endpoint_id : "", (unsigned long long)round_id, b64,
                          tenant_id ? tenant_id : "", sfx_use);
  }
  free(b64);
  if (jl >= json_cap) {
    free(json);
    return -1;
  }
  hr = fl_http_post_body(http_url, "application/json", json, jl);
  free(json);
  return hr;
}

static int fl_gradient_upload_grpc_one(const unsigned char *chunk, size_t chunk_len, const char *grpc_target,
                                       const char *endpoint_id, const char *tenant_id, uint64_t round_id,
                                       const char *upload_id, uint32_t chunk_index, uint32_t chunk_count) {
  size_t wire_alloc = chunk_len + 2048u;
  uint8_t *wire = (uint8_t *)malloc(wire_alloc);
  size_t wl;
  int ret = -1;
  const char *ge = getenv("EDR_FL_GRPC_INSECURE");
  int insecure = (ge && ge[0] == '1') ? 1 : 0;

  if (!wire) {
    return -1;
  }
  if (upload_id && upload_id[0]) {
    wl = fl_pb_encode_upload_gradients_chunked(wire, wire_alloc, endpoint_id ? endpoint_id : "unknown", round_id,
                                                 chunk, chunk_len, tenant_id ? tenant_id : "", upload_id,
                                                 chunk_index, chunk_count);
  } else {
    wl = fl_pb_encode_upload_gradients(wire, wire_alloc, endpoint_id ? endpoint_id : "unknown", round_id, chunk,
                                       chunk_len, tenant_id ? tenant_id : "");
  }
  if (wl == 0u) {
    free(wire);
    return -1;
  }
#if defined(EDR_HAVE_GRPC_FL)
  {
    char err[256];
    err[0] = '\0';
    if (fl_grpc_upload_gradient_call(grpc_target, insecure, wire, wl, err, sizeof(err)) == 0) {
      ret = 0;
    } else {
      if (err[0]) {
        fprintf(stderr, "[fl] grpc upload: %s\n", err);
      }
      ret = -1;
    }
  }
#else
  (void)insecure;
  fprintf(stderr, "[fl] grpc gradient: set coordinator_http_url or rebuild with gRPC FL upload\n");
  ret = -1;
#endif
  free(wire);
  return ret;
}

int fl_gradient_upload_bytes(const unsigned char *data, size_t len, const char *http_url, const char *grpc_target,
                             const char *endpoint_id, const char *tenant_id, uint64_t round_id,
                             size_t max_chunk_size, const FLTConfig *fl_cfg) {
  size_t offset = 0;
  char upload_id[64];
  uint32_t chunk_count;
  uint32_t ci;

  (void)fl_gradient_upload_trace(data, len);

  if (!data || len == 0u) {
    return -1;
  }

  if (max_chunk_size == 0u || len <= max_chunk_size) {
    if (http_url && (strncmp(http_url, "http://", 7u) == 0 || strncmp(http_url, "https://", 8u) == 0)) {
      return fl_gradient_upload_http_one(data, len, http_url, endpoint_id, tenant_id, round_id, NULL, 0u, 0u, fl_cfg);
    }
    if (grpc_target && grpc_target[0]) {
      return fl_gradient_upload_grpc_one(data, len, grpc_target, endpoint_id, tenant_id, round_id, NULL, 0u, 0u);
    }
    return 0;
  }

  chunk_count = (uint32_t)((len + max_chunk_size - 1u) / max_chunk_size);
  if (chunk_count == 0u) {
    return -1;
  }
  upload_id[0] = '\0';
  fl_gradient_make_upload_id(upload_id, sizeof(upload_id));

  for (ci = 0u; ci < chunk_count; ci++) {
    size_t take = len - offset;
    if (take > max_chunk_size) {
      take = max_chunk_size;
    }
    if (http_url && (strncmp(http_url, "http://", 7u) == 0 || strncmp(http_url, "https://", 8u) == 0)) {
      if (fl_gradient_upload_http_one(data + offset, take, http_url, endpoint_id, tenant_id, round_id, upload_id, ci,
                                      chunk_count, fl_cfg) != 0) {
        return -1;
      }
    } else if (grpc_target && grpc_target[0]) {
      if (fl_gradient_upload_grpc_one(data + offset, take, grpc_target, endpoint_id, tenant_id, round_id, upload_id,
                                      ci, chunk_count) != 0) {
        return -1;
      }
    }
    offset += take;
  }

  return 0;
}
