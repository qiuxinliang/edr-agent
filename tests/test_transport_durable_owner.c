#include "edr/transport_sink.h"
#include "edr/transport_v2.h"
#include "edr/ingest_http.h"
#include "edr/storage_queue.h"
#include "edr/config.h"
#include "edr/time_util.h"
#include <assert.h>
#include <stdatomic.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
static DWORD s_main_thread;
static void pause_ms(void) { Sleep(1u); }
#else
#include <pthread.h>
#include <time.h>
static pthread_t s_main_thread;
static void pause_ms(void) { struct timespec t = {0, 1000000L}; nanosleep(&t, NULL); }
#endif
static atomic_int s_block, s_in_drain, s_open = 1, s_fail_enqueue;
static unsigned s_enqueued, s_cancelled;

void edr_ingest_http_configure(const char *a, const char *b, const char *c,
 const char *d, const char *e, const char *f, const char *g, const char *h,
 const char *i, const char *j, const char *k, const char *l, const char *m,
 const char *n, const char *o) {
 (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;
 (void)i;(void)j;(void)k;(void)l;(void)m;(void)n;(void)o;
}
void edr_ingest_http_configure_transport_options(int a,int b,int c,int d,int e,
 const char *f,const char *g) {(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;}
void edr_ingest_http_configure_control_transport_options(int a,int b,int c) {(void)a;(void)b;(void)c;}
void edr_ingest_http_configure_request_signing(const EdrRequestSigningConfig *c) {(void)c;}
void edr_ingest_http_set_policy_version(const char *p) {(void)p;}
void edr_ingest_http_start_command_poll(void) {}
void edr_ingest_http_cancel_inflight(void) { s_cancelled++; }
void edr_transport_v2_init_from_config(const struct EdrConfig *c) {(void)c;}
int edr_storage_queue_is_open(void) { return atomic_load(&s_open); }
EdrError edr_storage_queue_enqueue(const char *id,const uint8_t *wire,size_t len,int compressed,int severity) {
  assert(strcmp(id,"batch-fixture") == 0);
  assert(len == 14u && wire[12] == 8u && wire[13] == 1u);
  assert(!compressed && severity == 1);
  if (atomic_load(&s_fail_enqueue)) return EDR_ERR_INTERNAL;
  s_enqueued++;
  return EDR_OK;
}
void edr_storage_queue_poll_drain(void) {
#ifdef _WIN32
  assert(GetCurrentThreadId() != s_main_thread);
#else
  assert(!pthread_equal(pthread_self(), s_main_thread));
#endif
  atomic_store(&s_in_drain, 1);
  while (atomic_load(&s_block)) pause_ms();
  atomic_store(&s_in_drain, 0);
}
int main(void) {
  EdrConfig cfg = {0};
  const uint8_t header[12] = {0x42,0x41,0x54,0x31,1,0,0,0,2,0,0,0};
  const uint8_t payload[2] = {8,1};
#ifdef _WIN32
  s_main_thread = GetCurrentThreadId();
#else
  s_main_thread = pthread_self();
#endif
  atomic_store(&s_block, 1);
  assert(edr_transport_init_from_config(&cfg));
  uint64_t deadline = edr_monotonic_ns() + 2000000000ULL;
  while (!atomic_load(&s_in_drain) && edr_monotonic_ns() < deadline) pause_ms();
  assert(atomic_load(&s_in_drain));
  assert(edr_transport_on_event_batch("batch-fixture",header,12,payload,2) == 0);
  assert(s_enqueued == 1u && edr_transport_batch_count() == 1u);
  atomic_store(&s_fail_enqueue, 1);
  assert(edr_transport_on_event_batch("batch-fixture",header,12,payload,2) == -1);
  assert(s_enqueued == 1u && edr_transport_batch_rejected_count() == 1u);
  assert(!edr_transport_shutdown());
  assert(s_cancelled == 1u && atomic_load(&s_in_drain));
  assert(!edr_transport_init_from_config(&cfg));
  assert(edr_transport_on_event_batch("batch-fixture",header,12,payload,2) == -1);
  atomic_store(&s_block, 0);
  deadline = edr_monotonic_ns() + 2000000000ULL;
  while (atomic_load(&s_in_drain) && edr_monotonic_ns() < deadline) pause_ms();
  assert(edr_transport_shutdown());
  assert(edr_transport_shutdown());
  assert(edr_transport_init_from_config(&cfg));
  assert(edr_transport_shutdown());
  return 0;
}
