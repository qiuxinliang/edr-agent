/* §7 gRPC — 占位：单条 wire + §6.2 批次（含 LZ4 批次计数） */

#include "edr/config.h"
#include "edr/grpc_client.h"
#include "edr/ingest_http.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
#include "edr/edr_log.h"

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

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

typedef struct EdrSendJob {
  int use_http;
  char *batch_id;
  size_t header_len;
  size_t payload_len;
  uint8_t *wire;
  struct EdrSendJob *next;
} EdrSendJob;

static char s_target[256];
static volatile unsigned long s_wire_events;
static volatile unsigned long s_wire_bytes;
static volatile unsigned long s_batch_count;
static volatile unsigned long s_batch_bytes;
static volatile unsigned long s_batch_lz4;
static EdrSendJob *s_q_head;
static EdrSendJob *s_q_tail;
static size_t s_q_len;
static size_t s_q_cap = 256u;
static int s_q_started;
#ifdef _WIN32
static CRITICAL_SECTION s_q_mu;
static CONDITION_VARIABLE s_q_cv;
static HANDLE s_q_thr;
static volatile LONG s_q_run;
#else
static pthread_mutex_t s_q_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_q_cv = PTHREAD_COND_INITIALIZER;
static pthread_t s_q_thr;
static volatile int s_q_run;
#endif

static uint32_t rd_u32_le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
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

static void edr_transport_send_ingest_batch_now(int use_http, const char *batch_id, const uint8_t *header12,
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
          EDR_LOGV("[transport] gRPC not ready; HTTP ingest batch_id=%s (EDR_TRANSPORT_LOG_EVERY_HTTP_FALLBACK=1 repeats)\n",
                   batch_id ? batch_id : "");
        }
      }
    } else {
      send_rc = edr_grpc_client_send_batch(batch_id, header12, header_len, payload, payload_len);
      if (send_rc != 0 && grpc_fallback_http_enabled()) {
        send_rc = edr_ingest_http_post_report_events(batch_id, header12, header_len, payload, payload_len);
        if (send_rc == 0) {
          EDR_LOGV("[transport] gRPC ReportEvents failed; HTTP fallback ok batch_id=%s\n", batch_id ? batch_id : "");
        }
      }
    }
  }
  if (send_rc != 0) {
    enqueue_wire_on_fail(batch_id, header12, header_len, payload, payload_len);
  }
}

static EdrSendJob *make_send_job(int use_http, const char *batch_id, const uint8_t *header12, size_t header_len,
                                 const uint8_t *payload, size_t payload_len) {
  if (!header12 || !payload || header_len < 12u || payload_len == 0u) {
    return NULL;
  }
  EdrSendJob *j = (EdrSendJob *)calloc(1, sizeof(*j));
  if (!j) {
    return NULL;
  }
  j->wire = (uint8_t *)malloc(header_len + payload_len);
  if (!j->wire) {
    free(j);
    return NULL;
  }
  memcpy(j->wire, header12, header_len);
  memcpy(j->wire + header_len, payload, payload_len);
  if (batch_id && batch_id[0]) {
    size_t n = strlen(batch_id);
    j->batch_id = (char *)malloc(n + 1u);
    if (!j->batch_id) {
      free(j->wire);
      free(j);
      return NULL;
    }
    memcpy(j->batch_id, batch_id, n + 1u);
  }
  j->use_http = use_http;
  j->header_len = header_len;
  j->payload_len = payload_len;
  return j;
}

static void free_send_job(EdrSendJob *j) {
  if (!j) {
    return;
  }
  free(j->wire);
  free(j->batch_id);
  free(j);
}

static int queue_push_job(EdrSendJob *j) {
  if (!j) {
    return -1;
  }
#ifdef _WIN32
  EnterCriticalSection(&s_q_mu);
  if (!s_q_run || s_q_len >= s_q_cap) {
    LeaveCriticalSection(&s_q_mu);
    return -1;
  }
  if (s_q_tail) {
    s_q_tail->next = j;
  } else {
    s_q_head = j;
  }
  s_q_tail = j;
  s_q_len++;
  WakeConditionVariable(&s_q_cv);
  LeaveCriticalSection(&s_q_mu);
#else
  pthread_mutex_lock(&s_q_mu);
  if (!s_q_run || s_q_len >= s_q_cap) {
    pthread_mutex_unlock(&s_q_mu);
    return -1;
  }
  if (s_q_tail) {
    s_q_tail->next = j;
  } else {
    s_q_head = j;
  }
  s_q_tail = j;
  s_q_len++;
  pthread_cond_signal(&s_q_cv);
  pthread_mutex_unlock(&s_q_mu);
#endif
  return 0;
}

static EdrSendJob *queue_pop_wait(void) {
#ifdef _WIN32
  EnterCriticalSection(&s_q_mu);
  while (s_q_run && !s_q_head) {
    SleepConditionVariableCS(&s_q_cv, &s_q_mu, INFINITE);
  }
  EdrSendJob *j = s_q_head;
  if (j) {
    s_q_head = j->next;
    if (!s_q_head) {
      s_q_tail = NULL;
    }
    s_q_len--;
    j->next = NULL;
  }
  LeaveCriticalSection(&s_q_mu);
  return j;
#else
  pthread_mutex_lock(&s_q_mu);
  while (s_q_run && !s_q_head) {
    pthread_cond_wait(&s_q_cv, &s_q_mu);
  }
  EdrSendJob *j = s_q_head;
  if (j) {
    s_q_head = j->next;
    if (!s_q_head) {
      s_q_tail = NULL;
    }
    s_q_len--;
    j->next = NULL;
  }
  pthread_mutex_unlock(&s_q_mu);
  return j;
#endif
}

#ifdef _WIN32
static unsigned __stdcall transport_sender_thread(void *unused) {
  (void)unused;
  for (;;) {
    EdrSendJob *j = queue_pop_wait();
    if (!j) {
      if (!s_q_run) {
        break;
      }
      continue;
    }
    edr_transport_send_ingest_batch_now(j->use_http, j->batch_id, j->wire, j->header_len, j->wire + j->header_len,
                                        j->payload_len);
    free_send_job(j);
  }
  return 0;
}
#else
static void *transport_sender_thread(void *unused) {
  (void)unused;
  for (;;) {
    EdrSendJob *j = queue_pop_wait();
    if (!j) {
      if (!s_q_run) {
        break;
      }
      continue;
    }
    edr_transport_send_ingest_batch_now(j->use_http, j->batch_id, j->wire, j->header_len, j->wire + j->header_len,
                                        j->payload_len);
    free_send_job(j);
  }
  return NULL;
}
#endif

static void transport_queue_start(void) {
  const char *e = getenv("EDR_TRANSPORT_SEND_QUEUE_CAP");
  if (e && e[0]) {
    long v = strtol(e, NULL, 10);
    if (v >= 8 && v <= 8192) {
      s_q_cap = (size_t)v;
    }
  }
#ifdef _WIN32
  InitializeCriticalSection(&s_q_mu);
  InitializeConditionVariable(&s_q_cv);
  s_q_run = 1;
  s_q_thr = (HANDLE)_beginthreadex(NULL, 0, transport_sender_thread, NULL, 0, NULL);
  if (!s_q_thr) {
    s_q_run = 0;
    s_q_started = 0;
  } else {
    s_q_started = 1;
  }
#else
  s_q_run = 1;
  if (pthread_create(&s_q_thr, NULL, transport_sender_thread, NULL) != 0) {
    s_q_run = 0;
    s_q_started = 0;
  } else {
    s_q_started = 1;
  }
#endif
  if (s_q_started) {
    fprintf(stderr,
            "[transport] send_queue_cap=%zu (EDR_TRANSPORT_SEND_QUEUE_CAP; see "
            "docs/WP6_TRANSPORT_BATCH_QUANTIFIED_OPS.md)\n",
            s_q_cap);
  }
}

static void transport_queue_stop(void) {
  if (!s_q_started) {
    return;
  }
#ifdef _WIN32
  EnterCriticalSection(&s_q_mu);
  s_q_run = 0;
  WakeConditionVariable(&s_q_cv);
  LeaveCriticalSection(&s_q_mu);
  if (s_q_thr) {
    WaitForSingleObject(s_q_thr, 30000);
    CloseHandle(s_q_thr);
    s_q_thr = NULL;
  }
  for (;;) {
    EdrSendJob *j = NULL;
    EnterCriticalSection(&s_q_mu);
    if (s_q_head) {
      j = s_q_head;
      s_q_head = j->next;
      if (!s_q_head) {
        s_q_tail = NULL;
      }
      s_q_len--;
    }
    LeaveCriticalSection(&s_q_mu);
    if (!j) {
      break;
    }
    free_send_job(j);
  }
  DeleteCriticalSection(&s_q_mu);
#else
  pthread_mutex_lock(&s_q_mu);
  s_q_run = 0;
  pthread_cond_signal(&s_q_cv);
  pthread_mutex_unlock(&s_q_mu);
  pthread_join(s_q_thr, NULL);
  for (;;) {
    pthread_mutex_lock(&s_q_mu);
    EdrSendJob *j = s_q_head;
    if (j) {
      s_q_head = j->next;
      if (!s_q_head) {
        s_q_tail = NULL;
      }
      s_q_len--;
    }
    pthread_mutex_unlock(&s_q_mu);
    if (!j) {
      break;
    }
    free_send_job(j);
  }
#endif
  s_q_started = 0;
}

void edr_transport_init_from_config(const EdrConfig *cfg) {
  memset(s_target, 0, sizeof(s_target));
  if (!cfg) {
    return;
  }
  snprintf(s_target, sizeof(s_target), "%s", cfg->server.address);
  if (s_target[0]) {
    EDR_LOGV("[transport] gRPC target: %s\n", s_target);
  }
  {
    const char *erb = getenv("EDR_PLATFORM_REST_BASE");
    const char *rb = (erb && erb[0]) ? erb : (cfg->platform.rest_base_url[0] ? cfg->platform.rest_base_url : "");
    const char *br = getenv("EDR_PLATFORM_BEARER");
    const char *bear = (br && br[0]) ? br : (cfg->platform.rest_bearer_token[0] ? cfg->platform.rest_bearer_token : "");
    const char *tid = cfg->agent.tenant_id[0] ? cfg->agent.tenant_id : "demo-tenant";
    const char *uid = cfg->platform.rest_user_id[0] ? cfg->platform.rest_user_id : "edr-agent";
    edr_ingest_http_configure(rb, tid, uid, bear, cfg->agent.endpoint_id, NULL);
    if (rb && rb[0]) {
      const char *sp = getenv("EDR_EVENT_INGEST_SPLIT");
      int split_on = (sp && sp[0] && strcmp(sp, "0") != 0);
      fprintf(stderr, "[transport] HTTP ingest: %s\n", rb);
      fprintf(stderr,
              "[transport] EDR_EVENT_INGEST_SPLIT=%s (non-zero: split BehaviorAlert->gRPC path vs rest->HTTP; 0: single "
              "edr_transport_on_event_batch path. See docs/WP4_HTTP_TRANSPORT_OPS.md)\n",
              split_on ? "on" : "off");
      EDR_LOGV("%s",
               "  (verbose) EDR_EVENT_GRPC_FALLBACK_HTTP=0 disables gRPC->HTTP on ReportEvents fail; "
               "EDR_TRANSPORT_LOG_EVERY_HTTP_FALLBACK=1 repeats stub-path HTTP logs.\n");
    }
  }
  transport_queue_start();
  edr_grpc_client_init(cfg);
  edr_ingest_http_start_command_poll();
}

void edr_transport_shutdown(void) {
  transport_queue_stop();
  edr_ingest_http_stop_command_poll();
  edr_grpc_client_shutdown();
}

void edr_transport_send_ingest_batch(int use_http, const char *batch_id, const uint8_t *header12,
                                      size_t header_len, const uint8_t *payload, size_t payload_len) {
  EdrSendJob *j = make_send_job(use_http, batch_id, header12, header_len, payload, payload_len);
  if (!j) {
    edr_transport_send_ingest_batch_now(use_http, batch_id, header12, header_len, payload, payload_len);
    return;
  }
  if (queue_push_job(j) != 0) {
    edr_transport_send_ingest_batch_now(use_http, batch_id, header12, header_len, payload, payload_len);
    free_send_job(j);
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
