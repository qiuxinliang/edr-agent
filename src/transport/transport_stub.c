/* One durable batch owner, one network drain worker. Control transport keeps
 * its existing independent lifetime, signing and TLS configuration. */
#include "edr/transport_sink.h"
#include "edr/config.h"
#include "edr/edr_log.h"
#include "edr/ingest_http.h"
#include "edr/storage_queue.h"
#include "edr/transport_v2.h"
#include "edr/time_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#ifndef _WIN32
#include <pthread.h>
#include <time.h>
#include <errno.h>
static pthread_mutex_t s_wake_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_wake_cv = PTHREAD_COND_INITIALIZER;
static pthread_t s_thread;
#else
#include <process.h>
#include <windows.h>
static SRWLOCK s_wake_mu = SRWLOCK_INIT;
static CONDITION_VARIABLE s_wake_cv = CONDITION_VARIABLE_INIT;
static HANDLE s_thread;
#endif

#ifndef EDR_TRANSPORT_STOP_TIMEOUT_MS
#define EDR_TRANSPORT_STOP_TIMEOUT_MS 15000u
#endif
static atomic_int s_started;
static atomic_int s_run;
static atomic_int s_exited = 1;
static atomic_ulong s_wire_events, s_batch_count, s_batch_lz4, s_batch_rejected;
static atomic_size_t s_wire_bytes, s_batch_bytes;

static int env_truthy(const char *name) {
  const char *v = getenv(name);
  return v && (strcmp(v, "1") == 0 || strcmp(v, "true") == 0 || strcmp(v, "TRUE") == 0);
}
static int url_is_loopback_http(const char *s) {
  return s && (strncmp(s, "http://127.0.0.1", 16) == 0 || strncmp(s, "http://localhost", 16) == 0 ||
               strncmp(s, "http://[::1]", 12) == 0);
}
static void wake_worker(void) {
#ifndef _WIN32
  pthread_mutex_lock(&s_wake_mu);
  pthread_cond_signal(&s_wake_cv);
  pthread_mutex_unlock(&s_wake_mu);
#else
  AcquireSRWLockExclusive(&s_wake_mu);
  WakeConditionVariable(&s_wake_cv);
  ReleaseSRWLockExclusive(&s_wake_mu);
#endif
}
static void wait_for_work(void) {
#ifndef _WIN32
  struct timespec until;
  clock_gettime(CLOCK_REALTIME, &until);
  until.tv_nsec += 250000000L;
  if (until.tv_nsec >= 1000000000L) { until.tv_nsec -= 1000000000L; until.tv_sec++; }
  pthread_mutex_lock(&s_wake_mu);
  if (atomic_load(&s_run)) (void)pthread_cond_timedwait(&s_wake_cv, &s_wake_mu, &until);
  pthread_mutex_unlock(&s_wake_mu);
#else
  AcquireSRWLockExclusive(&s_wake_mu);
  if (atomic_load(&s_run)) (void)SleepConditionVariableSRW(&s_wake_cv, &s_wake_mu, 250u, 0);
  ReleaseSRWLockExclusive(&s_wake_mu);
#endif
}
#ifndef _WIN32
static void *worker_thread(void *unused) {
#else
static unsigned __stdcall worker_thread(void *unused) {
#endif
  (void)unused;
  while (atomic_load(&s_run)) {
    edr_storage_queue_poll_drain();
    wait_for_work();
  }
  atomic_store(&s_exited, 1);
#ifndef _WIN32
  return NULL;
#else
  return 0;
#endif
}

int edr_transport_init_from_config(const struct EdrConfig *cfg) {
  if (!cfg || atomic_load(&s_started)) return 0;
  atomic_store(&s_wire_events, 0);
  atomic_store(&s_wire_bytes, 0);
  atomic_store(&s_batch_count, 0);
  atomic_store(&s_batch_bytes, 0);
  atomic_store(&s_batch_lz4, 0);
  atomic_store(&s_batch_rejected, 0);
  const int allow_insecure_env =
      env_truthy("EDR_ALLOW_INSECURE_TRANSPORT") || env_truthy("EDR_DEV_ALLOW_INSECURE_TRANSPORT");
  const char *rest_base_env = getenv("EDR_PLATFORM_REST_BASE");
  const char *rest_bearer_env = getenv("EDR_PLATFORM_BEARER");
  const char *rest_base = (rest_base_env && rest_base_env[0]) ? rest_base_env : cfg->platform.rest_base_url;
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
  /* Runtime policy and preprocessing rules have independent identities.  The
   * signed runtime-policy pull sets this value after verification; until then
   * report the explicit local fallback instead of mislabeling a rules bundle
   * as the applied endpoint policy. */
  edr_ingest_http_set_policy_version(NULL);
  edr_ingest_http_configure_transport_options(
      cfg->platform.http2_enabled ? 1 : 0,
      cfg->platform.http2_require ? 1 : 0,
      cfg->platform.control_stream_enabled ? 1 : 0,
      cfg->platform.long_poll_fallback ? 1 : 0,
      cfg->platform.report_events_v2_enabled ? 1 : 0,
      cfg->platform.data_plane_encoding,
      cfg->platform.data_plane_compression);
  edr_ingest_http_configure_control_transport_options(
      cfg->platform.control_http2_enabled ? 1 : 0,
      cfg->platform.control_http2_require ? 1 : 0,
      cfg->platform.control_http1_fallback ? 1 : 0);
  edr_transport_v2_init_from_config(cfg);


  atomic_store(&s_exited, 0);
  atomic_store(&s_run, 1);
#ifndef _WIN32
  if (pthread_create(&s_thread, NULL, worker_thread, NULL) != 0) {
#else
  s_thread = (HANDLE)_beginthreadex(NULL, 0, worker_thread, NULL, 0, NULL);
  if (!s_thread) {
#endif
    atomic_store(&s_run, 0);
    atomic_store(&s_exited, 1);
    EDR_LOGE("%s", "[transport] durable drain worker create failed\n");
    return 0;
  }
  atomic_store(&s_started, 1);
  edr_ingest_http_start_command_poll();
  return 1;
}

int edr_transport_shutdown(void) {
  if (!atomic_load(&s_started)) return 1;
  atomic_store(&s_run, 0);
  wake_worker();
  /* Existing HTTP cancellation also interrupts a telemetry drain in flight.
   * The caller stops command/result producers before this final teardown. */
  edr_ingest_http_cancel_inflight();
#ifdef _WIN32
  if (WaitForSingleObject(s_thread, EDR_TRANSPORT_STOP_TIMEOUT_MS) != WAIT_OBJECT_0) {
#else
  uint64_t deadline = edr_monotonic_ns() + (uint64_t)EDR_TRANSPORT_STOP_TIMEOUT_MS * 1000000ULL;
  while (!atomic_load(&s_exited) && edr_monotonic_ns() < deadline) {
    struct timespec delay = {0, 1000000L};
    nanosleep(&delay, NULL);
  }
  if (!atomic_load(&s_exited)) {
#endif
    EDR_LOGE("%s", "[transport] shutdown timed out; retaining worker and queue dependencies\n");
    return 0;
  }
#ifdef _WIN32
  CloseHandle(s_thread);
  s_thread = NULL;
#else
  if (pthread_join(s_thread, NULL) != 0) return 0;
#endif
  atomic_store(&s_started, 0);
  return 1;
}

void edr_transport_on_behavior_wire(const uint8_t *data, size_t len) {
  (void)data;
  atomic_fetch_add(&s_wire_events, 1);
  atomic_fetch_add(&s_wire_bytes, len);
}

int edr_transport_on_event_batch(const char *batch_id, const uint8_t *header12,
                                  size_t header_len, const uint8_t *payload,
                                  size_t payload_len) {
  uint8_t *wire;
  EdrError rc = EDR_ERR_INVALID_ARG;
  const char *reason = "invalid_batch";
  uint32_t magic;
  if (!atomic_load(&s_started) || !atomic_load(&s_run)) {
    reason = "transport_not_running";
    goto rejected;
  }
  if (!batch_id || !batch_id[0] || !header12 || header_len != 12u ||
      !payload || !payload_len || payload_len > SIZE_MAX - 12u) goto rejected;
  if (!edr_storage_queue_is_open()) {
    reason = "durable_queue_not_open";
    rc = EDR_ERR_SQLITE_OPEN;
    goto rejected;
  }
  wire = (uint8_t *)malloc(12u + payload_len);
  if (!wire) {
    reason = "batch_allocation_failed";
    rc = EDR_ERR_INTERNAL;
    goto rejected;
  }
  memcpy(wire, header12, 12u);
  memcpy(wire + 12u, payload, payload_len);
  magic = (uint32_t)header12[0] | ((uint32_t)header12[1] << 8) |
          ((uint32_t)header12[2] << 16) | ((uint32_t)header12[3] << 24);
  /* Keep this lane's established priority; P0 combined/source-only rows retain
   * their separate admission and ACK contracts in the same durable owner. */
  rc = edr_storage_queue_enqueue(batch_id, wire, 12u + payload_len,
                                 magic == EDR_TRANSPORT_BATCH_MAGIC_LZ4, 1);
  free(wire);
  if (rc != EDR_OK) {
    reason = "sqlite_enqueue_failed";
    goto rejected;
  }
  atomic_fetch_add(&s_batch_count, 1);
  atomic_fetch_add(&s_batch_bytes, payload_len);
  if (magic == EDR_TRANSPORT_BATCH_MAGIC_LZ4) atomic_fetch_add(&s_batch_lz4, 1);
  wake_worker();
  return 0;
rejected:
  atomic_fetch_add(&s_batch_rejected, 1);
  EDR_LOGE("[transport] durable batch handoff failed reason=%s error=%d; caller retains bytes\n",
           reason, (int)rc);
  return -1;
}

unsigned long edr_transport_wire_events_count(void) { return atomic_load(&s_wire_events); }
size_t edr_transport_wire_bytes_count(void) { return atomic_load(&s_wire_bytes); }
unsigned long edr_transport_batch_count(void) { return atomic_load(&s_batch_count); }
size_t edr_transport_batch_bytes_count(void) { return atomic_load(&s_batch_bytes); }
unsigned long edr_transport_batch_lz4_count(void) { return atomic_load(&s_batch_lz4); }
unsigned long edr_transport_batch_rejected_count(void) { return atomic_load(&s_batch_rejected); }
/* Current server/dashboard fields describe a RAM send queue. It no longer
 * exists; the already-reported offline_queue_pending describes SQLite. */
size_t edr_transport_send_queue_depth(void) { return 0; }
size_t edr_transport_send_queue_capacity(void) { return 0; }
unsigned long edr_transport_queue_full_count(void) { return 0; }
unsigned long edr_transport_queue_full_persisted_count(void) { return 0; }
unsigned long edr_transport_queue_full_sampled_count(void) { return 0; }
unsigned long edr_transport_queue_full_dropped_count(void) { return 0; }
