/* An isolated command receiver, actual durable executor/SQLite reader and HTTP
 * policy gate. No transport, collector or service thread starts in this test. */
#include "edr/command.h"
#include "edr/command_state.h"
#include "edr/command_result_json.h"
#include "edr/config.h"
#include "edr/egress_request_policy.h"
#include "edr/local_evidence_cache.h"
#include "edr/sha256.h"
#include "cJSON.h"
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define test_env(k, v) _putenv_s(k, v)
#else
#define test_env(k, v) setenv(k, v, 1)
#endif

static const char type[] = "alert_window_query_v1";
static char payload[640];

static int64_t make_request(void) {
  struct timespec now;
  assert(timespec_get(&now, TIME_UTC) == TIME_UTC);
  int64_t anchor = (int64_t)now.tv_sec * INT64_C(1000000000) + now.tv_nsec;
  int n = snprintf(
      payload, sizeof(payload),
      "{\"tenant_id\":\"t\",\"endpoint_id\":\"ep\",\"alert_id\":\"a\",\"source_event_id\":\"e\",\"pid\":42,"
      "\"process_start_key\":\"18446744073709551615\",\"process_creation_filetime_100ns\":\"133700000000000001\","
      "\"source_time_ns\":\"%lld\",\"kind\":\"network\",\"from_ns\":\"%lld\","
      "\"until_ns\":\"%lld\",\"limit\":50,\"max_bytes\":8192}",
      (long long)anchor, (long long)(anchor - INT64_C(120000000000)), (long long)(anchor + INT64_C(120000000000)));
  assert(n > 0 && (size_t)n < sizeof(payload));
  return anchor;
}

/* Materialize the owner, its actual edge and a recycled PID through the same
 * record writer as the Agent. The independent SQL witness joins the original
 * fact to that owner and checks its stored connection, before reading any result. */
static void record_connection(int64_t anchor, char fact_id[65]) {
  EdrBehaviorRecord *r = calloc(1, sizeof(*r));
  assert(r);
  edr_behavior_record_init(r);
  strcpy(r->endpoint_id, "ep");
  strcpy(r->tenant_id, "t");
  strcpy(r->event_id, "e");
  r->pid = 42;
  r->priority = 1;
  r->process_start_key = UINT64_MAX;
  r->process_creation_filetime_100ns = UINT64_C(133700000000000001);
  r->event_time_ns = anchor;
  r->type = EDR_EVENT_FILE_WRITE;
  r->file_actor_generation_validated = 1;
  strcpy(r->file_path, "C:/synthetic/window-source.exe");
  strcpy(r->detection_context, "{\"severity\":\"P1\"}");
  assert(edr_local_evidence_cache_is_candidate(r));
  edr_local_evidence_cache_record_behavior(r);
  r->type = EDR_EVENT_NET_CONNECT;
  r->file_path[0] = r->detection_context[0] = 0;
  strcpy(r->net_dst, "192.0.2.74");
  strcpy(r->event_id, "synthetic-related");
  r->net_dport = 51742;
  r->event_time_ns = anchor + 1;
  assert(!edr_local_evidence_cache_is_candidate(r));
  edr_local_evidence_cache_record_behavior(r);
  r->process_creation_filetime_100ns++;
  r->event_time_ns++;
  r->net_dport = 51744;
  strcpy(r->event_id, "synthetic-recycled");
  edr_local_evidence_cache_record_behavior(r);
  free(r);

  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  assert(sqlite3_open_v2("synthetic-cache.db", &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  const char *sql =
      "SELECT f.fact_id FROM context_facts f JOIN context_reference_projection r ON r.fact_id=f.fact_id "
      "JOIN artifacts a ON a.candidate_id=r.candidate_id AND a.artifact_type='p0_context_bundle' "
      "WHERE a.tenant_id='t' AND a.endpoint_id='ep' AND json_extract(a.manifest_json,'$.source_event_id')='e' "
      "AND json_extract(f.manifest_template_json,'$.remote_port')=51742";
  assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW);
  assert(sqlite3_column_bytes(st, 0) == 64);
  memcpy(fact_id, sqlite3_column_text(st, 0), 64);
  fact_id[64] = 0;
  assert(sqlite3_step(st) == SQLITE_DONE);
  sqlite3_finalize(st);
  sqlite3_close(db);
}

static EVP_PKEY *test_signer(void) {
  EVP_PKEY_CTX *generator = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  EVP_PKEY *key = NULL;
  assert(generator && EVP_PKEY_keygen_init(generator) == 1 && EVP_PKEY_keygen(generator, &key) == 1);
  EVP_PKEY_CTX_free(generator);
  BIO *pub = BIO_new(BIO_s_mem());
  char pem[256];
  assert(pub && PEM_write_bio_PUBKEY(pub, key) == 1);
  int n = BIO_read(pub, pem, sizeof(pem) - 1);
  assert(n > 0 && (size_t)n < sizeof(pem));
  pem[n] = 0;
  assert(test_env("EDR_COMMAND_SIGNING_PUBLIC_KEY", pem) == 0);
  BIO_free(pub);
  return key;
}

static void sign_command(EVP_PKEY *key, const char *id, EdrSoarCommandMeta *m) {
  char hash[65], wire[512];
  unsigned char signature[64], encoded[89];
  size_t size = sizeof(signature);
  assert(edr_sha256_hex((const uint8_t *)payload, strlen(payload), hash) == 0);
  int n = snprintf(wire, sizeof(wire), "%s\n%s\n%s\n%lld\n%u\n%s", id, type, id, (long long)m->issued_at_unix_ms,
                   m->deadline_ms, hash);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  assert(n > 0 && (size_t)n < sizeof(wire) && ctx);
  assert(EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1);
  assert(EVP_DigestSign(ctx, signature, &size, (const unsigned char *)wire, (size_t)n) == 1 && size == 64);
  EVP_MD_CTX_free(ctx);
  assert(EVP_EncodeBlock(encoded, signature, (int)size) == 88);
  for (char *c = (char *)encoded; *c; ++c) {
    if (*c == '+')
      *c = '-';
    else if (*c == '/')
      *c = '_';
    else if (*c == '=') {
      *c = 0;
      break;
    }
  }
  snprintf(m->idempotency_key, sizeof(m->idempotency_key), "%s|sigv2|ed25519|test|%s", id, encoded);
  snprintf(m->soar_correlation_id, sizeof(m->soar_correlation_id), "%s", id);
}

int main(void) {
  const char *id = "lcq-synthetic-window-signed";
  EdrConfig cfg = {0};
  strcpy(cfg.agent.tenant_id, "t");
  strcpy(cfg.agent.endpoint_id, "ep");
  cfg.command.allow_rtq_readonly = 1;
  edr_command_bind_config(&cfg);
  assert(test_env("EDR_COMMAND_STATE_DIR", "command-state") == 0);
  assert(test_env("EDR_SOAR_REPORT_ALWAYS", "1") == 0);
  edr_egress_set_command_result_validator(edr_command_state_result_authorized);
  assert(edr_local_evidence_cache_open_with_policy("synthetic-cache.db", 16, 1, 4) == 0);
  int64_t anchor = make_request();
  EdrSoarCommandMeta meta = {0};
  meta.issued_at_unix_ms = (int64_t)time(NULL) * 1000;
  meta.deadline_ms = 60000;
  EVP_PKEY *key = test_signer();
  sign_command(key, id, &meta);
  assert(edr_command_receive_envelope(id, type, (const uint8_t *)"{}", 2, &meta) == 0);
  assert(edr_command_state_has_final(id, &meta) == 0 && edr_command_state_count_inbox() == 0);
  assert(edr_command_receive_envelope(id, type, (const uint8_t *)payload, strlen(payload), &meta) == 1);
  assert(edr_command_state_count_inbox() == 1 && edr_command_replay_persisted_inbox_once() == 1);
  assert(edr_command_state_count_inbox() == 0);
  EdrCommandStateRecord *r = calloc(1, sizeof(*r));
  assert(r && edr_command_state_begin(id, type, &meta, NULL, r) == EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  assert(r->execution_status == 1 && !r->exit_code && r->report_pending && !r->report_policy_held);
  cJSON *receipt = cJSON_Parse(r->detail);
  assert(receipt &&
         !strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(receipt, "coverage")), "owner_unavailable"));
  assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(receipt, "rows")) == 0);
  char *http = edr_command_result_http_json("ep", "test", id, type, 1, 0, r->detail, meta.issued_at_unix_ms,
                                            r->soar_correlation_id, "", "");
  char why[128];
  assert(http && edr_egress_request_validate_for_scope("POST", "ingest/report-command-result", "application/json",
                                                       http, strlen(http), "t", "ep", why, sizeof(why)) == 0);
  assert(edr_command_receive_envelope(id, type, (const uint8_t *)payload, strlen(payload), &meta) == 0);
  assert(edr_command_state_count_inbox() == 0);

  edr_command_result_json_free(http);
  cJSON_Delete(receipt);
  char fact_id[65];
  record_connection(anchor, fact_id);
  /* Existing server task-ID derivation for tenant t, alert a, actor
   * synthetic-analyst, and this fixed synthetic request_id. */
  const char *request_id = "lcq1.1794361630687.69c92518-3a30-4201-a51a-081303e114bd";
  id = "lcq-baaa5e22dc2029994236126cee6b78907e66e1507fb9edc0";
  sign_command(key, id, &meta);
  assert(edr_command_receive_envelope(id, type, (const uint8_t *)payload, strlen(payload), &meta) == 1);
  assert(edr_command_replay_persisted_inbox_once() == 1);
  assert(edr_command_state_begin(id, type, &meta, NULL, r) == EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  assert(r->execution_status == 1 && r->exit_code == 0 && r->report_pending && !r->report_policy_held);
  receipt = cJSON_Parse(r->detail);
  assert(receipt &&
         !strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(receipt, "coverage")), "retained_window"));
  const cJSON *rows = cJSON_GetObjectItemCaseSensitive(receipt, "rows");
  assert(cJSON_GetArraySize(rows) == 1);
  const cJSON *row = cJSON_GetArrayItem(rows, 0);
  assert(!strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(row, "fact_id")), fact_id));
  assert(cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(row, "remote_port")) == 51742);
  assert(!strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(row, "remote_ip")), "192.0.2.74"));
  assert(!strcmp(r->soar_correlation_id, id));
  http = edr_command_result_http_json("ep", "test", id, type, 1, 0, r->detail, meta.issued_at_unix_ms,
                                      r->soar_correlation_id, "", "");
  assert(http && edr_egress_request_validate_for_scope("POST", "ingest/report-command-result", "application/json",
                                                       http, strlen(http), "t", "ep", why, sizeof(why)) == 0);
  printf("{\"request_id\":\"%s\",\"actor\":\"synthetic-analyst\",\"request\":%s,\"http\":%s}\n", request_id, payload,
         http);

  id = "lcq-synthetic-rebound";
  sign_command(key, id, &meta);
  assert(edr_command_receive_envelope(id, type, (const uint8_t *)payload, strlen(payload), &meta) == 1);
  strcpy(cfg.agent.tenant_id, "other");
  edr_command_bind_config(&cfg);
  assert(edr_command_replay_persisted_inbox_once() == 1);
  assert(edr_command_state_begin(id, type, &meta, NULL, r) == EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  assert(r->execution_status != 1 && !strstr(r->detail, "edr.alert-window.v1"));
  strcpy(cfg.agent.tenant_id, "t");
  edr_command_bind_config(&cfg);

  id = "lcq-synthetic-window-disabled";
  sign_command(key, id, &meta);
  assert(edr_command_receive_envelope(id, type, (const uint8_t *)payload, strlen(payload), &meta) == 1);
  assert(test_env("EDR_RTQ_READONLY_ENABLED", "0") == 0);
  assert(edr_command_replay_persisted_inbox_once() == 1);
  assert(edr_command_state_begin(id, type, &meta, NULL, r) == EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  assert(r->execution_status != 1 && !strstr(r->detail, "edr.alert-window.v1"));

  id = "lcq-synthetic-expired";
  meta.issued_at_unix_ms -= 120000;
  sign_command(key, id, &meta);
  assert(edr_command_receive_envelope(id, type, (const uint8_t *)payload, strlen(payload), &meta) == 0);
  assert(edr_command_state_count_inbox() == 0);
  edr_command_on_internal_envelope("auto-synthetic-window", type, (const uint8_t *)payload, strlen(payload), NULL);
  assert(edr_command_state_count_inbox() == 0 && !edr_command_state_has_final("auto-synthetic-window", NULL));

  edr_command_result_json_free(http);
  cJSON_Delete(receipt);
  free(r);
  EVP_PKEY_free(key);
  edr_local_evidence_cache_close();
  edr_command_bind_config(NULL);
  puts("signed alert-window replay: owner miss and exact post connection, final egress verified, duplicate "
       "suppressed, readonly policy enforced");
  return 0;
}
