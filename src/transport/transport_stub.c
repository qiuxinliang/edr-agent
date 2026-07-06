/**
 * 传输层 — 批次入队、工作线程、gRPC/HTTP 调度、指标计数。
 *
 * EdrTransportCtx 将 15 个 file-scope 全局变量收敛为单一结构体；
 * dispatch 函数指针通过 edr_transport_inject_dispatch 可注入（测试/QUIC/MQTT）。
 */
#include "edr/transport_sink.h"

#include "edr/config.h"
#include "edr/edr_log.h"
#include "edr/ingest_http.h"
#include "edr/storage_queue.h"
#include "edr/transport_v2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <pthread.h>
#include <unistd.h>
#else
#include <process.h>
#include <windows.h>
#endif

/* ---- 内部类型 ---- */

typedef struct EdrSendJob {
  int use_http;
  char batch_id[64];
  uint8_t header12[12];
  size_t header_len;
  uint8_t *payload;
  size_t payload_len;
  struct EdrSendJob *next;
} EdrSendJob;

typedef struct EdrTransportCtx {
  /* --- 调度层 --- */
  char target[256];
  EdrTransportDispatchFn dispatch;
  void *dispatch_ud;

  /* --- 指标层 --- */
  unsigned long wire_events;
  size_t wire_bytes;
  unsigned long batch_count;
  size_t batch_bytes;
  unsigned long batch_lz4;
  unsigned long queue_full_total;
  unsigned long queue_full_persisted;
  unsigned long queue_full_sampled;
  unsigned long queue_full_dropped;

  /* --- 队列层 --- */
  EdrSendJob *q_head;
  EdrSendJob *q_tail;
  size_t q_len;
  size_t q_cap;
  int q_started;

#ifndef _WIN32
  pthread_mutex_t q_mu;
  pthread_cond_t q_cv;
  pthread_t q_thr;
#else
  CRITICAL_SECTION q_mu;
  CONDITION_VARIABLE q_cv;
  HANDLE q_thr;
#endif
  volatile int q_run;
} EdrTransportCtx;

/* ---- 单例 ---- */

static EdrTransportCtx g_ctx;

/* ---- dispatch fallback 策略 ---- */

static int env_truthy(const char *name) {
  const char *v = getenv(name);
  return v && (strcmp(v, "1") == 0 || strcmp(v, "true") == 0 || strcmp(v, "TRUE") == 0);
}

static int target_is_loopback(const char *s) {
  return s && (strncmp(s, "127.0.0.1", 9) == 0 || strncmp(s, "localhost", 9) == 0 ||
               strncmp(s, "[::1]", 5) == 0 || strncmp(s, "::1", 3) == 0);
}

static int url_is_loopback_http(const char *s) {
  return s && (strncmp(s, "http://127.0.0.1", 16) == 0 || strncmp(s, "http://localhost", 16) == 0 ||
               strncmp(s, "http://[::1]", 12) == 0);
}

static int header_lz4(const uint8_t *header12, size_t header_len) {
  if (!header12 || header_len < 4u) {
    return 0;
  }
  uint32_t m = (uint32_t)header12[0] | ((uint32_t)header12[1] << 8) |
               ((uint32_t)header12[2] << 16) | ((uint32_t)header12[3] << 24);
  return m == EDR_TRANSPORT_BATCH_MAGIC_LZ4;
}

static int persist_wire_batch(const char *batch_id, const uint8_t *header12, size_t header_len,
                              const uint8_t *payload, size_t payload_len, int severity) {
  if (!edr_storage_queue_is_open() || !batch_id || !header12 || header_len < 12u || !payload ||
      payload_len == 0u) {
    return -1;
  }
  size_t wire_len = header_len + payload_len;
  uint8_t *wire = (uint8_t *)malloc(wire_len);
  if (!wire) {
    return -1;
  }
  memcpy(wire, header12, header_len);
  memcpy(wire + header_len, payload, payload_len);
  EdrError er = edr_storage_queue_enqueue(batch_id, wire, wire_len, header_lz4(header12, header_len), severity);
  free(wire);
  return er == EDR_OK ? 0 : -1;
}

static unsigned low_priority_full_sample_permille(void) {
  const char *e = getenv("EDR_TRANSPORT_LOWPRI_FULL_SAMPLE_PERMILLE");
  long v = e && e[0] ? strtol(e, NULL, 10) : 100L;
  if (v < 0) v = 0;
  if (v > 1000) v = 1000;
  return (unsigned)v;
}

static int default_dispatch(int use_http, const char *batch_id,
                            const uint8_t *header12, size_t header_len,
                            const uint8_t *payload, size_t payload_len,
                            void *userdata) {
  (void)userdata;
  int ok = 0;

  /* 路径 1: HTTPS/TLS ingest 默认主路径 */
  if (edr_ingest_http_configured()) {
    const char *e = getenv("EDR_EVENT_GRPC_FALLBACK_HTTP");
    int allow_fallback = (!e || e[0] == '\0' || strcmp(e, "0") != 0);
    if (use_http == 1 || allow_fallback) {
      ok = edr_transport_v2_report_events(batch_id, header12, header_len, payload, payload_len);
      if (ok == 0) return 0;
    }
  }

  /* 路径 2: 离线持久化 */
  {
    const char *ps = getenv("EDR_PERSIST_STRATEGY");
    int persist_on_fail = (ps && strcmp(ps, "on_fail") == 0);
    if (!persist_on_fail || edr_storage_queue_is_open()) {
      size_t wire_len = header_len + payload_len;
      uint8_t *wire = (uint8_t *)malloc(wire_len);
      if (wire) {
        memcpy(wire, header12, header_len);
        memcpy(wire + header_len, payload, payload_len);
        (void)edr_storage_queue_enqueue(batch_id, wire, wire_len, header_lz4(header12, header_len), use_http == 0 ? 1 : 0);
        free(wire);
      }
    }
  }

  return -1;
}

/* ---- 队列锁 ---- */

static void q_lock(EdrTransportCtx *ctx) {
#ifndef _WIN32
  pthread_mutex_lock(&ctx->q_mu);
#else
  EnterCriticalSection(&ctx->q_mu);
#endif
}

static void q_unlock(EdrTransportCtx *ctx) {
#ifndef _WIN32
  pthread_mutex_unlock(&ctx->q_mu);
#else
  LeaveCriticalSection(&ctx->q_mu);
#endif
}

static void q_wait(EdrTransportCtx *ctx) {
#ifndef _WIN32
  pthread_cond_wait(&ctx->q_cv, &ctx->q_mu);
#else
  SleepConditionVariableCS(&ctx->q_cv, &ctx->q_mu, INFINITE);
#endif
}

static void q_signal(EdrTransportCtx *ctx) {
#ifndef _WIN32
  pthread_cond_signal(&ctx->q_cv);
#else
  WakeConditionVariable(&ctx->q_cv);
#endif
}

/* ---- 队列 push / pop ---- */

static int q_push(EdrTransportCtx *ctx, int use_http, const char *batch_id,
                  const uint8_t *header12, size_t header_len,
                  const uint8_t *payload, size_t payload_len) {
  q_lock(ctx);
  if (ctx->q_len >= ctx->q_cap) {
    static unsigned long low_sample_seq;
    int high_priority = (use_http == 0);
    int persisted = 0;
    int sampled = 0;
    ctx->queue_full_total++;
    if (high_priority) {
      persisted = (persist_wire_batch(batch_id, header12, header_len, payload, payload_len, 1) == 0);
    } else {
      unsigned ppm = low_priority_full_sample_permille();
      if (ppm > 0u) {
        unsigned long seq = ++low_sample_seq;
        sampled = ((seq % 1000ul) < (unsigned long)ppm);
        if (sampled) {
          persisted = (persist_wire_batch(batch_id, header12, header_len, payload, payload_len, 0) == 0);
        }
      }
    }
    if (persisted) {
      ctx->queue_full_persisted++;
      if (sampled) {
        ctx->queue_full_sampled++;
      }
    } else {
      ctx->queue_full_dropped++;
    }
    q_unlock(ctx);
    EDR_LOGE("[transport] queue full (%zu/%zu), %s batch %s%s\n",
             ctx->q_len, ctx->q_cap,
             persisted ? "persisted overflow" : "dropping overflow",
             batch_id ? batch_id : "",
             high_priority ? " priority=high" : " priority=low");
    return -1;
  }

  EdrSendJob *job = (EdrSendJob *)calloc(1, sizeof(EdrSendJob));
  if (!job) {
    q_unlock(ctx);
    return -1;
  }
  job->use_http = use_http;
  if (batch_id) snprintf(job->batch_id, sizeof(job->batch_id), "%s", batch_id);
  memcpy(job->header12, header12, header_len < 12 ? header_len : 12);
  job->header_len = header_len;
  job->payload = (uint8_t *)malloc(payload_len);
  if (!job->payload) {
    free(job);
    q_unlock(ctx);
    return -1;
  }
  memcpy(job->payload, payload, payload_len);
  job->payload_len = payload_len;

  if (ctx->q_tail) {
    ctx->q_tail->next = job;
  } else {
    ctx->q_head = job;
  }
  ctx->q_tail = job;
  ctx->q_len++;

  q_signal(ctx);
  q_unlock(ctx);
  return 0;
}

static EdrSendJob *q_pop(EdrTransportCtx *ctx) {
  EdrSendJob *job = ctx->q_head;
  if (!job) return NULL;
  ctx->q_head = job->next;
  if (!ctx->q_head) ctx->q_tail = NULL;
  ctx->q_len--;
  return job;
}

static void q_free_job(EdrSendJob *job) {
  if (!job) return;
  free(job->payload);
  free(job);
}

/* ---- 工作线程 ---- */

static void process_one_job(EdrTransportCtx *ctx, EdrSendJob *job) {
  EdrTransportDispatchFn fn = ctx->dispatch ? ctx->dispatch : default_dispatch;
  (void)fn(job->use_http, job->batch_id, job->header12, job->header_len,
           job->payload, job->payload_len, ctx->dispatch_ud);
}

static unsigned read_u32_le(const uint8_t *p, size_t off) {
  return (unsigned)p[off] | ((unsigned)p[off + 1] << 8) |
         ((unsigned)p[off + 2] << 16) | ((unsigned)p[off + 3] << 24);
}

#ifndef _WIN32
static void *worker_thread(void *arg) {
#else
static unsigned __stdcall worker_thread(void *arg) {
#endif
  EdrTransportCtx *ctx = (EdrTransportCtx *)arg;
  while (ctx->q_run) {
    q_lock(ctx);
    while (ctx->q_run && ctx->q_head == NULL) {
      q_wait(ctx);
    }
    if (!ctx->q_run) { q_unlock(ctx); break; }
    EdrSendJob *job = q_pop(ctx);
    q_unlock(ctx);

    if (job) {
      process_one_job(ctx, job);
      q_free_job(job);
    }
  }
  return 0;
}

/* ---- 公共 API ---- */

void edr_transport_init_from_config(const struct EdrConfig *cfg) {
  if (!cfg) return;

  EdrTransportCtx *c = &g_ctx;

  /* gRPC 目标 */
  snprintf(c->target, sizeof(c->target), "%s", cfg->server.address);

  /* dispatch 默认为内置实现 */
  c->dispatch = NULL;  /* NULL → 使用 default_dispatch */
  c->dispatch_ud = NULL;

  /* 指标清零 */
  c->wire_events = 0;
  c->wire_bytes = 0;
  c->batch_count = 0;
  c->batch_bytes = 0;
  c->batch_lz4 = 0;
  c->queue_full_total = 0;
  c->queue_full_persisted = 0;
  c->queue_full_sampled = 0;
  c->queue_full_dropped = 0;

  /* 队列容量：环境变量可覆盖 */
  {
    const char *ecap = getenv("EDR_TRANSPORT_SEND_QUEUE_CAP");
    unsigned long v = ecap ? strtoul(ecap, NULL, 10) : 256;
    if (v < 8) v = 8;
    if (v > 8192) v = 8192;
    c->q_cap = (size_t)v;
  }
  c->q_head = NULL;
  c->q_tail = NULL;
  c->q_len = 0;
  c->q_started = 0;
  c->q_run = 0;

  EdrConfig secure_cfg = *cfg;
  const int allow_insecure_env =
      env_truthy("EDR_ALLOW_INSECURE_TRANSPORT") || env_truthy("EDR_DEV_ALLOW_INSECURE_TRANSPORT");
  const int allow_grpc_insecure = allow_insecure_env || target_is_loopback(cfg->server.address);
  if (secure_cfg.server.grpc_insecure && !allow_grpc_insecure) {
    secure_cfg.server.grpc_insecure = false;
    EDR_LOGE("%s", "[transport] production policy forced grpc_insecure=false; configure mTLS certs or set EDR_ALLOW_INSECURE_TRANSPORT=1 only for lab\n");
  } else if (secure_cfg.server.grpc_insecure) {
    EDR_LOGE("%s", "[transport] insecure gRPC allowed for loopback/dev only\n");
  }
  const char *rest_base_env = getenv("EDR_PLATFORM_REST_BASE");
  const char *rest_bearer_env = getenv("EDR_PLATFORM_BEARER");
  const char *rest_base = (rest_base_env && rest_base_env[0]) ? rest_base_env : secure_cfg.platform.rest_base_url;
  const char *rest_bearer = (rest_bearer_env && rest_bearer_env[0]) ? rest_bearer_env : cfg->platform.rest_bearer_token;
  const int allow_rest_insecure = allow_insecure_env || url_is_loopback_http(rest_base);
  if (rest_base && strncmp(rest_base, "http://", 7) == 0 && !allow_rest_insecure) {
    rest_base = "";
    EDR_LOGE("%s", "[transport] production policy disabled non-HTTPS REST ingest; configure platform.rest_base_url=https://...\n");
  }

  /* 配置 HTTP ingest */
  edr_ingest_http_configure(
      rest_base,
      cfg->agent.tenant_id,
      cfg->platform.rest_user_id,
      rest_bearer,
      cfg->agent.endpoint_id,
      NULL /* agent_version */,
      cfg->server.ca_cert,
      cfg->server.client_cert,
      cfg->server.client_key,
      cfg->server.client_key_provider,
      cfg->server.client_cert_store,
      cfg->server.client_cert_thumbprint,
      cfg->platform.proxy_mode,
      cfg->platform.proxy_url,
      cfg->platform.relay_url);
  {
    EdrRequestSigningConfig reqsig;
    memset(&reqsig, 0, sizeof(reqsig));
    reqsig.enabled = cfg->platform.request_signing.enabled ? 1 : 0;
    snprintf(reqsig.key_id, sizeof(reqsig.key_id), "%s", cfg->platform.request_signing.key_id);
    snprintf(reqsig.secret, sizeof(reqsig.secret), "%s", cfg->platform.request_signing.secret);
    edr_ingest_http_configure_request_signing(&reqsig);
  }
  edr_ingest_http_set_policy_version(cfg->preprocessing.rules_version);
  edr_ingest_http_configure_transport_options(
      cfg->platform.http2_enabled ? 1 : 0,
      cfg->platform.http2_require ? 1 : 0,
      cfg->platform.control_stream_enabled ? 1 : 0,
      cfg->platform.long_poll_fallback ? 1 : 0,
      cfg->platform.report_events_v2_enabled ? 1 : 0,
      cfg->platform.data_plane_encoding,
      cfg->platform.data_plane_compression);
  edr_transport_v2_init_from_config(cfg);

  /* 启动命令轮询 */
  edr_ingest_http_start_command_poll();

  /* 队列线程 */
#ifndef _WIN32
  pthread_mutex_init(&c->q_mu, NULL);
  pthread_cond_init(&c->q_cv, NULL);
  c->q_run = 1;
  c->q_started = 1;
  if (pthread_create(&c->q_thr, NULL, worker_thread, c) != 0) {
    c->q_run = 0;
    c->q_started = 0;
    EDR_LOGE("%s", "[transport] worker thread create failed\n");
  }
#else
  InitializeCriticalSection(&c->q_mu);
  InitializeConditionVariable(&c->q_cv);
  c->q_run = 1;
  c->q_started = 1;
  c->q_thr = (HANDLE)_beginthreadex(NULL, 0, worker_thread, c, 0, NULL);
  if (c->q_thr == 0) {
    c->q_run = 0;
    c->q_started = 0;
    EDR_LOGE("%s", "[transport] worker thread create failed\n");
  }
#endif
}

void edr_transport_shutdown(void) {
  EdrTransportCtx *c = &g_ctx;

  /* 停止工作线程 */
  c->q_run = 0;
  if (c->q_started) {
    q_lock(c);
    q_signal(c);
    q_unlock(c);
#ifndef _WIN32
    pthread_join(c->q_thr, NULL);
    pthread_mutex_destroy(&c->q_mu);
    pthread_cond_destroy(&c->q_cv);
#else
    WaitForSingleObject(c->q_thr, 15000);
    CloseHandle(c->q_thr);
    DeleteCriticalSection(&c->q_mu);
#endif
    c->q_started = 0;
  }

  /* 释放队列残留 */
  while (c->q_head) {
    EdrSendJob *j = c->q_head;
    c->q_head = j->next;
    q_free_job(j);
  }
  c->q_tail = NULL;
  c->q_len = 0;

  /* 停止命令轮询 */
  edr_ingest_http_stop_command_poll();
}

void edr_transport_on_behavior_wire(const uint8_t *data, size_t len) {
  (void)data;
  g_ctx.wire_events++;
  g_ctx.wire_bytes += len;
}

/* 内部辅助：从 header 读 MAGIC 类型 */
static int is_lz4_batch(const uint8_t *header12) {
  return header12 && read_u32_le(header12, 0) == EDR_TRANSPORT_BATCH_MAGIC_LZ4;
}

void edr_transport_on_event_batch(const char *batch_id, const uint8_t *header12,
                                  size_t header_len, const uint8_t *payload,
                                  size_t payload_len) {
  EdrTransportCtx *c = &g_ctx;
  if (!batch_id || !header12 || header_len < 12 || !payload || payload_len == 0) return;

  c->batch_count++;
  c->batch_bytes += payload_len;
  if (is_lz4_batch(header12)) c->batch_lz4++;

  (void)q_push(c, 0, batch_id, header12, header_len, payload, payload_len);
}

void edr_transport_send_ingest_batch(int use_http, const char *batch_id,
                                     const uint8_t *header12, size_t header_len,
                                     const uint8_t *payload, size_t payload_len) {
  EdrTransportCtx *c = &g_ctx;
  if (!batch_id || !header12 || header_len < 12 || !payload || payload_len == 0) return;

  c->batch_count++;
  c->batch_bytes += payload_len;
  if (is_lz4_batch(header12)) c->batch_lz4++;

  (void)q_push(c, use_http, batch_id, header12, header_len, payload, payload_len);
}

unsigned long edr_transport_wire_events_count(void) { return g_ctx.wire_events; }
size_t edr_transport_wire_bytes_count(void) { return g_ctx.wire_bytes; }
unsigned long edr_transport_batch_count(void) { return g_ctx.batch_count; }
size_t edr_transport_batch_bytes_count(void) { return g_ctx.batch_bytes; }
unsigned long edr_transport_batch_lz4_count(void) { return g_ctx.batch_lz4; }

size_t edr_transport_send_queue_depth(void) {
  EdrTransportCtx *c = &g_ctx;
  size_t n = 0;
  if (!c->q_started) return 0;
  q_lock(c);
  n = c->q_len;
  q_unlock(c);
  return n;
}

size_t edr_transport_send_queue_capacity(void) { return g_ctx.q_cap; }
unsigned long edr_transport_queue_full_count(void) { return g_ctx.queue_full_total; }
unsigned long edr_transport_queue_full_persisted_count(void) { return g_ctx.queue_full_persisted; }
unsigned long edr_transport_queue_full_sampled_count(void) { return g_ctx.queue_full_sampled; }
unsigned long edr_transport_queue_full_dropped_count(void) { return g_ctx.queue_full_dropped; }

void edr_transport_inject_dispatch(EdrTransportDispatchFn fn, void *userdata) {
  g_ctx.dispatch = fn;
  g_ctx.dispatch_ud = userdata;
}

const EdrTransportCtx *edr_transport_ctx(void) { return &g_ctx; }
