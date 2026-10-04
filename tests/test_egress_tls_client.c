/* Synthetic inputs through the real AVE detector, production codec, SQLite
 * delivery owner, HTTPS transport and receipt validation. No native sensors or
 * service loop start; the detector callback only captures its actual alert. */
#include "edr/ingest_http.h"
#include "edr/behavior_proto.h"
#include "edr/ave_sdk.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
#include "edr/types.h"
#include "sqlite3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#ifdef _WIN32
#include <windows.h>
static void pause_retry(void) { Sleep(1200u); }
#else
#include <time.h>
static void pause_retry(void) { struct timespec t = {1, 200000000L}; nanosleep(&t, NULL); }
#endif

static unsigned failed;
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "synthetic TLS check failed: %s\n", #expr); failed++; } } while (0)
static void wr(uint8_t *p, uint32_t value) { for (unsigned i = 0; i < 4u; ++i) p[i] = (uint8_t)(value >> (i * 8u)); }
static int row_count(const char *db_path, const char *batch_id, const char *status) {
  sqlite3 *db = NULL; sqlite3_stmt *stmt = NULL; int count = -1;
  if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
      sqlite3_prepare_v2(db, status ? "SELECT COUNT(*) FROM event_queue WHERE batch_id=? AND status=?" :
          "SELECT COUNT(*) FROM event_queue WHERE batch_id=?", -1, &stmt, NULL) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, batch_id, -1, SQLITE_TRANSIENT);
    if (status) sqlite3_bind_text(stmt, 2, status, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
  }
  sqlite3_finalize(stmt); if (db) sqlite3_close(db); return count;
}
static void synthetic_record(EdrBehaviorRecord *r) {
  memset(r, 0, sizeof(*r)); r->type = EDR_EVENT_NET_CONNECT; r->pid = 42; r->ppid = 21;
  r->priority = 0; r->event_time_ns = 1700000000000000000LL;
  strcpy(r->event_id, "synthetic-source"); strcpy(r->endpoint_id, "synthetic-endpoint");
  strcpy(r->tenant_id, "synthetic-tenant"); strcpy(r->cmdline, "synthetic.exe --required-alert-context");
  strcpy(r->process_name, "synthetic.exe"); strcpy(r->net_dst, "127.0.0.1"); r->net_dport = 443;
}
typedef struct DetectorCapture {
  AVEBehaviorAlert alert;
  atomic_uint detected;
  unsigned accepted_inputs;
} DetectorCapture;
static void AVE_CALL capture_detection(const AVEBehaviorAlert *alert, void *user_data) {
  DetectorCapture *capture = user_data;
  capture->alert = *alert;
  atomic_fetch_add_explicit(&capture->detected, 1u, memory_order_release);
}
static int detect_synthetic_input(const EdrBehaviorRecord *r, DetectorCapture *capture) {
  AVEConfig config = {0};
  AVECallbacks callbacks = {0};
  AVEBehaviorEvent event = {0};
  config.max_concurrent_scans = 2;
  config.behavior_monitor_enabled = true;
  callbacks.on_behavior_alert = capture_detection;
  callbacks.user_data = capture;
  event.event_type = AVE_EVT_LSASS_ACCESS;
  event.pid = r->pid;
  event.ppid = r->ppid;
  event.timestamp_ns = r->event_time_ns;
  event.severity_hint = UINT8_MAX;
  event.behavior_flags = UINT32_MAX;
  snprintf(event.process_name, sizeof(event.process_name), "%s", r->process_name);
  snprintf(event.cmdline, sizeof(event.cmdline), "%s", r->cmdline);
  snprintf(event.target_ip, sizeof(event.target_ip), "%s", r->net_dst);
  event.target_port = r->net_dport;
  if (AVE_Init(&config) != AVE_OK) {
    fprintf(stderr, "synthetic detector initialization failed\n");
    return 0;
  }
  int ok = AVE_RegisterCallbacks(&callbacks) == AVE_OK &&
           AVE_StartBehaviorMonitor() == AVE_OK;
  if (ok) {
    ok = AVE_FeedEventEx(&event, sizeof(event)) == AVE_OK;
    if (ok) capture->accepted_inputs++;
    ok = ok && AVE_DrainBehaviorMonitor(5000u) == AVE_OK;
  }
  AVE_Shutdown();
  return ok && atomic_load_explicit(&capture->detected, memory_order_acquire) == 1u &&
         capture->alert.pid == r->pid && capture->alert.timestamp_ns == r->event_time_ns;
}
static size_t make_wire(EdrBehaviorRecord *r, const AVEBehaviorAlert *alert, uint8_t *wire, size_t cap) {
  size_t n;
  if (alert) {
    n = edr_behavior_record_alert_encode_protobuf(r, alert, wire + 16u, cap - 16u);
  } else n = edr_behavior_record_encode_protobuf(r, wire + 16u, cap - 16u);
  if (!n) return 0;
  wr(wire, EDR_TRANSPORT_BATCH_MAGIC_RAW); wr(wire + 4u, 1u); wr(wire + 8u, (uint32_t)n + 4u);
  wr(wire + 12u, (uint32_t)n); return n + 16u;
}
int main(int argc, char **argv) {
  if (argc != 7) {
    fprintf(stderr, "usage: test_egress_tls_client BASE_URL CA CLIENT_CERT CLIENT_KEY QUEUE_PATH MODE\n"); return 2;
  }
  edr_ingest_http_configure(argv[1], "synthetic-tenant", "", "", "synthetic-endpoint", "test-v1",
      argv[2], argv[3], argv[4], "pem", "", "", "direct", "", "");
  edr_ingest_http_set_policy_version("synthetic-p1");
  int v2 = !strcmp(argv[6], "positive-v2");
  edr_ingest_http_configure_transport_options(0, 0, 0, 0, v2, "protobuf", v2 ? "zstd" : "none");
  if (strcmp(argv[6], "positive") && strcmp(argv[6], "positive-ip") && !v2) {
    int rc = edr_ingest_http_post_heartbeat();
    printf("{\"mode\":\"%s\",\"tls_rejected\":%s}\n", argv[6], rc != 0 ? "true" : "false");
    return rc != 0 ? 0 : 1;
  }
  EdrBehaviorRecord *r = calloc(1, sizeof(*r));
  uint8_t *ordinary = malloc(256u * 1024u), *alert = malloc(256u * 1024u);
  if (!r || !ordinary || !alert) return 2;
  DetectorCapture capture = {0};
  synthetic_record(r);
  size_t ordinary_len = make_wire(r, NULL, ordinary, 256u * 1024u);
  CHECK(detect_synthetic_input(r, &capture));
  r->type = EDR_EVENT_BEHAVIOR_ONNX_ALERT;
  size_t alert_len = make_wire(r, &capture.alert, alert, 256u * 1024u);
  CHECK(ordinary_len && alert_len);
  unsigned enqueued = 0;
  EdrError queue_result;
  edr_storage_queue_configure(4u, 72u);
  CHECK(edr_storage_queue_open(argv[5]) == EDR_OK);
  queue_result = edr_storage_queue_enqueue("tls-ordinary", ordinary, ordinary_len, 0, 0);
  CHECK(queue_result == EDR_OK); if (queue_result == EDR_OK) enqueued++;
  queue_result = edr_storage_queue_enqueue("tls-alert", alert, alert_len, 0, 1);
  CHECK(queue_result == EDR_OK); if (queue_result == EDR_OK) enqueued++;
  edr_storage_queue_poll_drain();
  CHECK(row_count(argv[5], "tls-ordinary", "policy_held") == 1);
  CHECK(row_count(argv[5], "tls-alert", NULL) == 0);
  CHECK(edr_ingest_http_post_heartbeat() == 0);
  queue_result = edr_storage_queue_enqueue("tls-ack-lost", alert, alert_len, 0, 1);
  CHECK(queue_result == EDR_OK); if (queue_result == EDR_OK) enqueued++;
  pause_retry(); edr_storage_queue_poll_drain();
  CHECK(row_count(argv[5], "tls-ack-lost", "pending") == 1);
  edr_storage_queue_close();
  pause_retry(); CHECK(edr_storage_queue_open(argv[5]) == EDR_OK);
  CHECK(row_count(argv[5], "tls-ordinary", "policy_held") == 1);
  edr_storage_queue_poll_drain();
  CHECK(row_count(argv[5], "tls-ack-lost", NULL) == 0);
  /* Server duplicate delivery is acknowledged for the exact original body. */
  CHECK(edr_ingest_http_post_report_events("tls-alert", alert, 12u, alert + 12u, alert_len - 12u) == 0);
  CHECK(edr_ingest_http_post_report_events("tls-ack-mismatch", alert, 12u, alert + 12u, alert_len - 12u) != 0);
  const char *health = "{\"endpoint_id\":\"synthetic-endpoint\",\"agent_version\":\"test-v1\",\"policy_version\":\"synthetic-p1\",\"engine_health\":{\"reported_at_unix_ms\":1700000000000,\"sensor_health\":{\"file_read_collection\":{\"metadata_gate\":{\"healthy\":false,\"durable_failures\":2,\"reason\":\"synthetic-secret-user\"}}},\"p0_acceptance\":{\"source_only\":{\"terminal_unhealthy\":true,\"retry_pending\":3,\"reason\":\"process_generation_or_correlation_unavailable\"}},\"resource\":{\"rss_mb\":12,\"cpu_percent\":1},\"config_recovery\":{\"active\":true,\"source\":\"synthetic-secret-path\"},\"capability_manifest\":{\"schema\":\"edr.agent.capabilities.v1\",\"features\":{\"pmfe\":{\"code_supported\":true,\"build_supported\":true,\"policy_enabled\":true,\"runtime_status\":\"healthy\"},\"sqlite\":{\"code_supported\":true,\"build_supported\":true,\"policy_enabled\":true,\"runtime_status\":\"healthy\"}}},\"raw_event\":{\"cmdline\":\"synthetic-secret-command\"}}}";
  CHECK(edr_ingest_http_post_engine_health_json(health) == 0);
  CHECK(edr_ingest_http_post_engine_health_json(health) == 0);
  CHECK(edr_ingest_http_post_json_suffix("ingest/engine-health", health, NULL, 0u) != 0);
  CHECK(edr_ingest_http_post_command_result_typed("synthetic-command", "rtq_execute", NULL, 0, 0, "synthetic-secret-result") != 0);
  int retryable = 1; char error[160];
  edr_ingest_http_get_last_command_result_delivery_error(error, sizeof(error), &retryable);
  CHECK(retryable == 0);
  const char *blocked[] = {"endpoints/synthetic-endpoint/attack-surface", "ingest/agent-upgrade-event", "ingest/unknown"};
  for (size_t i = 0; i < 3u; ++i) CHECK(edr_ingest_http_post_json_suffix(blocked[i], "{\"raw\":\"synthetic-secret\"}", NULL, 0u) != 0);
  char key[256];
  CHECK(edr_ingest_http_upload_file_multipart("synthetic-upload", argv[5], "", key, sizeof(key)) != 0);
  CHECK(row_count(argv[5], "tls-ordinary", "policy_held") == 1);
  edr_storage_queue_close(); free(r); free(ordinary); free(alert);
  printf("{\"mode\":\"%s\",\"collected\":2,\"collection_source\":\"synthetic_fixture\",\"detector_inputs\":%u,\"detected\":%u,\"enqueued\":%u,\"ordinary_bytes\":%zu,\"alert_bytes\":%zu,\"failed_checks\":%u}\n", argv[6], capture.accepted_inputs, atomic_load(&capture.detected), enqueued, ordinary_len, alert_len, failed);
  return failed ? 1 : 0;
}
