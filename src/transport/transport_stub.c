/* §7 gRPC — 占位：单条 wire + §6.2 批次（含 LZ4 批次计数） */

#include "edr/config.h"
#include "edr/grpc_client.h"
#include "edr/ingest_http.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/** 非 0/false/off 时：gRPC 未就绪仍走 HTTP 时每批都打日志（默认只打一次）。 */
static int transport_env_truthy(const char *name) {
  const char *v = getenv(name);
  if (!v || !v[0] || strcmp(v, "0") == 0) {
    return 0;
  }
  if (strcmp(v, "false") == 0 || strcmp(v, "off") == 0 || strcmp(v, "no") == 0 || strcmp(v, "NO") == 0) {
    return 0;
  }
  return 1;
}

static char s_target[256];

void edr_transport_init_from_config(const EdrConfig *cfg) {
  memset(s_target, 0, sizeof(s_target));
  if (!cfg) {
    return;
  }
  snprintf(s_target, sizeof(s_target), "%s", cfg->server.address);
  if (s_target[0]) {
    fprintf(stderr, "[transport] gRPC target: %s\n", s_target);
  }
  {
    const char *erb = getenv("EDR_PLATFORM_REST_BASE");
    const char *rb =
        (erb && erb[0]) ? erb : (cfg->platform.rest_base_url[0] ? cfg->platform.rest_base_url : "");
    const char *br = getenv("EDR_PLATFORM_BEARER");
    const char *bear =
        (br && br[0]) ? br : (cfg->platform.rest_bearer_token[0] ? cfg->platform.rest_bearer_token : "");
    const char *tid = cfg->agent.tenant_id[0] ? cfg->agent.tenant_id : "demo-tenant";
    const char *uid =
        cfg->platform.rest_user_id[0] ? cfg->platform.rest_user_id : "edr-agent";
    edr_ingest_http_configure(rb, tid, uid, bear, cfg->agent.endpoint_id, NULL);
    if (rb && rb[0]) {
      fprintf(stderr, "[transport] HTTP ingest base: %s (EDR_EVENT_INGEST_SPLIT=1: split frames; "
                      "gRPC fail→HTTP fallback when HTTP base set, EDR_EVENT_GRPC_FALLBACK_HTTP=0 to disable)\n",
              rb);
    }
  }
  edr_grpc_client_init(cfg);
}

void edr_transport_shutdown(void) { edr_grpc_client_shutdown(); }

static volatile unsigned long s_wire_events;
static volatile unsigned long s_wire_bytes;
static volatile unsigned long s_batch_count;
static volatile unsigned long s_batch_bytes;
static volatile unsigned long s_batch_lz4;

static uint32_t rd_u32_le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

void edr_transport_on_behavior_wire(const uint8_t *data, size_t len) {
  (void)data;
  if (len == 0) {
    return;
  }
  s_wire_events++;
  s_wire_bytes += (unsigned long)((len > 0xffffffffu) ? 0xffffffffu : len);
}

static int persist_strategy_on_fail_only(void) {
  const char *s = getenv("EDR_PERSIST_STRATEGY");
  return s && strcmp(s, "on_fail") == 0;
}

/** gRPC ReportEvents 失败时是否改走 HTTP（需已配置 rest_base）；`EDR_EVENT_GRPC_FALLBACK_HTTP=0` 关闭。 */
static int grpc_fallback_http_enabled(void) {
  const char *e = getenv("EDR_EVENT_GRPC_FALLBACK_HTTP");
  if (e && (strcmp(e, "0") == 0 || strcmp(e, "false") == 0)) {
    return 0;
  }
  return edr_ingest_http_configured();
}

static void enqueue_wire_on_fail(const char *batch_id, const uint8_t *header12, size_t header_len,
                                 const uint8_t *payload, size_t payload_len) {
  if (!persist_strategy_on_fail_only() || !edr_storage_queue_is_open()) {
    return;
  }
  uint32_t mag = rd_u32_le(header12);
  int compressed = (mag == EDR_TRANSPORT_BATCH_MAGIC_LZ4) ? 1 : 0;
  size_t wlen = header_len + payload_len;
  uint8_t *wire = (uint8_t *)malloc(wlen);
  if (!wire) {
    return;
  }
  memcpy(wire, header12, header_len);
  memcpy(wire + header_len, payload, payload_len);
  (void)edr_storage_queue_enqueue(batch_id, wire, wlen, compressed);
  free(wire);
}

void edr_transport_send_ingest_batch(int use_http, const char *batch_id, const uint8_t *header12,
                                      size_t header_len, const uint8_t *payload, size_t payload_len) {
  if (header_len < 12u || payload_len == 0u) {
    return;
  }
  s_batch_count++;
  s_batch_bytes += (unsigned long)(12u + payload_len);
  if (rd_u32_le(header12) == EDR_TRANSPORT_BATCH_MAGIC_LZ4) {
    s_batch_lz4++;
  }
  int send_rc;
  if (use_http) {
    send_rc = edr_ingest_http_post_report_events(batch_id, header12, header_len, payload, payload_len);
  } else {
    /* gRPC 未建链/占位 stub：只要配了 HTTP ingest，同一 payload 直发 HTTP（不受 EDR_EVENT_GRPC_FALLBACK_HTTP 关闭影响） */
    if (edr_ingest_http_configured() && !edr_grpc_client_ready()) {
      send_rc = edr_ingest_http_post_report_events(batch_id, header12, header_len, payload, payload_len);
      if (send_rc == 0) {
        static int s_logged_grpc_stub_http;
        if (!s_logged_grpc_stub_http || transport_env_truthy("EDR_TRANSPORT_LOG_EVERY_HTTP_FALLBACK")) {
          if (!s_logged_grpc_stub_http) {
            s_logged_grpc_stub_http = 1;
          }
          fprintf(stderr,
                  "[transport] gRPC not ready; sent via HTTP ingest (batch_id=%s). "
                  "Further identical notices suppressed; set EDR_TRANSPORT_LOG_EVERY_HTTP_FALLBACK=1 "
                  "to log every batch.\n",
                  batch_id ? batch_id : "");
        }
      }
    } else {
      send_rc = edr_grpc_client_send_batch(batch_id, header12, header_len, payload, payload_len);
      if (send_rc != 0 && grpc_fallback_http_enabled()) {
        send_rc = edr_ingest_http_post_report_events(batch_id, header12, header_len, payload, payload_len);
        if (send_rc == 0) {
          fprintf(stderr,
                  "[transport] gRPC ReportEvents failed; fell back to HTTP ingest same payload "
                  "(batch_id=%s)\n",
                  batch_id ? batch_id : "");
        }
      }
    }
  }
  if (send_rc != 0) {
    enqueue_wire_on_fail(batch_id, header12, header_len, payload, payload_len);
  }
}

void edr_transport_on_event_batch(const char *batch_id, const uint8_t *header12, size_t header_len,
                                  const uint8_t *payload, size_t payload_len) {
  edr_transport_send_ingest_batch(0, batch_id, header12, header_len, payload, payload_len);
}

unsigned long edr_transport_wire_events_count(void) { return s_wire_events; }

unsigned long edr_transport_wire_bytes_count(void) { return s_wire_bytes; }

unsigned long edr_transport_batch_count(void) { return s_batch_count; }

unsigned long edr_transport_batch_bytes_count(void) { return s_batch_bytes; }

unsigned long edr_transport_batch_lz4_count(void) { return s_batch_lz4; }
