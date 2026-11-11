/* Owner-bound synthetic workload for native command execution and signed
 * receipt delivery. Transport modes accept only an isolated loopback receiver. */
#include "edr/command.h"
#include "edr/ingest_http.h"
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

static const char type[] = "alert_window_query_v2";
static char payload[640];

static void make_request(int64_t anchor) {
  int n = snprintf(
      payload, sizeof(payload),
      "{\"tenant_id\":\"t\",\"endpoint_id\":\"ep\",\"alert_id\":\"a\",\"source_event_id\":\"e\",\"pid\":42,"
      "\"process_start_key\":\"18446744073709551615\",\"process_creation_filetime_100ns\":\"133700000000000001\","
      "\"source_time_ns\":\"%lld\",\"kind\":\"network\",\"from_ns\":\"%lld\","
      "\"until_ns\":\"%lld\",\"limit\":50,\"max_bytes\":8192}",
      (long long)anchor, (long long)(anchor - INT64_C(120000000000)), (long long)(anchor + INT64_C(120000000000)));
  assert(n > 0 && (size_t)n < sizeof(payload));
}

/* Match cachedInvestigationTaskID's JSON array and 24-byte SHA-256 prefix.
 * Keep the synthetic UUID stable while deriving its time and task from this run. */
static void make_investigation_ids(int64_t issued_ms, char request_id[80], char task_id[53]) {
  char seed[256], digest[65];
  int n = snprintf(request_id, 80, "lcq1.%lld.69c92518-3a30-4201-a51a-081303e114bd", (long long)issued_ms);
  assert(n > 0 && n < 80);
  n = snprintf(seed, sizeof(seed), "[\"edr.local-cache-investigation.v1\",\"t\",\"a\",\"synthetic-analyst\",\"%s\"]",
               request_id);
  assert(n > 0 && (size_t)n < sizeof(seed) && edr_sha256_hex((const uint8_t *)seed, (size_t)n, digest) == 0);
  assert(snprintf(task_id, 53, "lcq-%.48s", digest) == 52);
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

static void install_test_public_key(EVP_PKEY *key) {
  BIO *pub = BIO_new(BIO_s_mem());
  char pem[256];
  assert(pub && PEM_write_bio_PUBKEY(pub, key) == 1);
  int n = BIO_read(pub, pem, sizeof(pem) - 1);
  assert(n > 0 && (size_t)n < sizeof(pem));
  pem[n] = 0;
  assert(test_env("EDR_COMMAND_SIGNING_PUBLIC_KEY", pem) == 0);
  BIO_free(pub);
}

static EVP_PKEY *test_signer(void) {
  EVP_PKEY_CTX *generator = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  EVP_PKEY *key = NULL;
  assert(generator && EVP_PKEY_keygen_init(generator) == 1 && EVP_PKEY_keygen(generator, &key) == 1);
  EVP_PKEY_CTX_free(generator);
  install_test_public_key(key);
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

/* The loopback receiver disappears once (old server), then returns a swapped
 * ACK. Recovery reopens the durable terminal before the exact ACK arrives. */
static void private_transport(const char *base, EdrCommandStateRecord *r, EdrSoarCommandMeta *meta) {
  edr_ingest_http_configure(base,"t","test","synthetic-token","ep","test","ca.pem","client.pem",
                            "client.key","pem",NULL,NULL,"direct",NULL,NULL);
  EdrRequestSigningConfig signing = {1, "synthetic-key", "c3ludGhldGlj"};
  edr_ingest_http_configure_request_signing(&signing);
  meta->result_finished_unix_ms = r->result_finished_unix_ms;
  const int64_t first_finish = r->result_finished_unix_ms;
  for (int i = 0; i < 3; ++i) {
    int rc = edr_ingest_http_post_command_result_typed(r->command_id,type,meta,1,0,r->detail);
    if (i == 2) {
      assert(rc == EDR_INGEST_COMMAND_RESULT_OK && edr_command_state_mark_reported(r) == 0);
    } else {
      assert(rc == EDR_INGEST_COMMAND_RESULT_RETRYABLE_FAILURE);
      assert(edr_command_state_mark_report_retry(r,"synthetic receiver unavailable",first_finish) == 0);
      char id[sizeof(r->command_id)];
      strcpy(id,r->command_id);
      assert(edr_command_state_begin(id,type,meta,NULL,r) == EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
      assert(r->report_pending && r->result_finished_unix_ms == first_finish);
    }
  }
}

static cJSON *fixture_object(const char *path, char *wire, size_t capacity) {
  FILE *f = fopen(path, "rb");
  assert(f);
  size_t length = fread(wire, 1, capacity, f);
  assert(!ferror(f) && feof(f) && length > 0 && length < capacity);
  assert(fclose(f) == 0);
  wire[length] = 0;
  cJSON *o = edr_egress_parse_purpose_object(wire, length);
  assert(o);
  return o;
}

static const char *fixture_string(const cJSON *object, const char *key) {
  const char *s = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(object,key));
  assert(s && *s);
  return s;
}

static void ordered_go_receipt(const char *envelope_path, const char *transport_path) {
  char wire[16384], options[4096], raw_payload[4097];
  cJSON *job = fixture_object(envelope_path,wire,sizeof(wire));
  cJSON *transport = fixture_object(transport_path,options,sizeof(options));
  cJSON *request = fixture_object("payload.json",raw_payload,sizeof(raw_payload));
  const cJSON *env = cJSON_GetObjectItemCaseSensitive(job,"envelope");
  assert(cJSON_Compare(request,cJSON_GetObjectItemCaseSensitive(env,"payload"),1));
  const char *pub = fixture_string(job,"public_key_hex");
  unsigned char raw[32];
  assert(strlen(pub)==64 && strspn(pub,"0123456789abcdef")==64);
  for (size_t i = 0; i < sizeof(raw); i++) {
    unsigned pair;
    assert(sscanf(pub + i*2,"%2x",&pair) == 1);
    raw[i] = (unsigned char)pair;
  }
  EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,raw,sizeof(raw));
  assert(key);
  install_test_public_key(key);
  EVP_PKEY_free(key);

  const char *url = fixture_string(transport,"base_url");
  unsigned port;
  int consumed = 0;
  assert(sscanf(url,"https://127.0.0.1:%u/api/v1%n",&port,&consumed)==1 &&
         consumed > 0 && (size_t)consumed==strlen(url) && port>0 && port<=65535);
  const char *id = fixture_string(env,"command_id"), *correlation = fixture_string(env,"soar_correlation_id");
  const char *idem = fixture_string(env,"idempotency_key");
  assert(!strcmp(fixture_string(env,"command_type"),type) && !strcmp(id,correlation));
  EdrConfig cfg = {0};
  strcpy(cfg.agent.tenant_id,"t");
  strcpy(cfg.agent.endpoint_id,"ep");
  cfg.command.allow_rtq_readonly=1;
  edr_command_bind_config(&cfg);
  assert(test_env("EDR_COMMAND_STATE_DIR","command-state")==0);
  edr_ingest_http_configure(url,"t","agent:ep",fixture_string(transport,"bearer"),"ep","test",
      fixture_string(transport,"ca_file"),fixture_string(transport,"cert_file"),fixture_string(transport,"key_file"),
      "pem",NULL,NULL,"direct",NULL,NULL);
  edr_ingest_http_configure_control_transport_options(0,0,1);
  EdrRequestSigningConfig signing={0};
  signing.enabled=1;
  const char *kid=fixture_string(transport,"key_id"), *secret=fixture_string(transport,"secret");
  assert(strlen(kid)<sizeof(signing.key_id) && strlen(secret)<sizeof(signing.secret));
  strcpy(signing.key_id,kid);
  strcpy(signing.secret,secret);
  edr_ingest_http_configure_request_signing(&signing);
  assert(edr_local_evidence_cache_open_with_policy("synthetic-cache.db",16,1,4)==0);
  char fact_id[65];
  record_connection(strtoll(fixture_string(request,"source_time_ns"),NULL,10),fact_id);
  EdrSoarCommandMeta m={0};
  assert(strlen(correlation)<sizeof(m.soar_correlation_id) && strlen(idem)<sizeof(m.idempotency_key));
  strcpy(m.soar_correlation_id,correlation);
  strcpy(m.idempotency_key,idem);
  m.issued_at_unix_ms=(int64_t)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(env,"issued_at_unix_ms"));
  m.deadline_ms=(uint32_t)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(env,"deadline_ms"));
  assert(m.deadline_ms==60000);
  assert(edr_command_receive_envelope(id,type,(const uint8_t *)raw_payload,strlen(raw_payload),&m)==1);
  assert(edr_command_replay_persisted_inbox_once()==1);
  EdrCommandStateRecord *r=calloc(1,sizeof(*r));
  assert(r && edr_command_state_begin(id,type,&m,NULL,r)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  assert(r->execution_status==1 && !r->exit_code && r->report_pending && !r->report_policy_held);
  assert(strstr(r->detail,fact_id) && !strstr(r->detail,"51744"));
  m.result_finished_unix_ms=r->result_finished_unix_ms;
  assert(edr_ingest_http_post_command_result_typed(id,type,&m,1,0,r->detail)==0);
  assert(edr_command_state_mark_reported(r)==0);
  free(r);
  edr_local_evidence_cache_close();
  cJSON_Delete(request);
  cJSON_Delete(transport);
  cJSON_Delete(job);
}

int main(int argc, char **argv) {
  if (argc == 4 && !strcmp(argv[1],"--ordered-go")) {
    ordered_go_receipt(argv[2],argv[3]);
    return 0;
  }
  assert(argc == 1 || argc == 2 || (argc == 3 && !strcmp(argv[1],"--private-transport")));
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
  struct timespec now;
  assert(timespec_get(&now, TIME_UTC) == TIME_UTC);
  int64_t anchor = (int64_t)now.tv_sec * INT64_C(1000000000) + now.tv_nsec;
  make_request(anchor);
  EdrSoarCommandMeta meta = {0};
  meta.issued_at_unix_ms = anchor / INT64_C(1000000);
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
  char *http = edr_command_result_http_json("ep", "test", id, type, 1, 0, r->detail, r->result_finished_unix_ms,
                                            r->soar_correlation_id, "", "");
  char why[128];
  assert(http && edr_egress_request_validate_for_scope("POST", EDR_ALERT_WINDOW_RESULT_SUFFIX, "application/json",
                                                       http, strlen(http), "t", "ep", why, sizeof(why)) == 0);
  assert(edr_command_receive_envelope(id, type, (const uint8_t *)payload, strlen(payload), &meta) == 0);
  assert(edr_command_state_count_inbox() == 0);

  edr_command_result_json_free(http);
  cJSON_Delete(receipt);
  char fact_id[65];
  record_connection(anchor, fact_id);
  char request_id[80], task_id[53];
  make_investigation_ids(meta.issued_at_unix_ms, request_id, task_id);
  long long key_time_ms = 0;
  assert(sscanf(request_id, "lcq1.%lld.", &key_time_ms) == 1 && key_time_ms == meta.issued_at_unix_ms);
  id = task_id;
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
  http = edr_command_result_http_json("ep", "test", id, type, 1, 0, r->detail, r->result_finished_unix_ms,
                                      r->soar_correlation_id, "", "");
  assert(http && edr_egress_request_validate_for_scope("POST", EDR_ALERT_WINDOW_RESULT_SUFFIX, "application/json",
                                                       http, strlen(http), "t", "ep", why, sizeof(why)) == 0);
  printf("{\"request_id\":\"%s\",\"actor\":\"synthetic-analyst\",\"issued_at_unix_ms\":%lld,\"deadline_ms\":%u,"
         "\"request\":%s,\"http\":%s}\n", request_id, (long long)meta.issued_at_unix_ms, meta.deadline_ms, payload, http);
  if (argc == 2) {
    /* Opt-in cross-language fixture. Export only the ephemeral public key. */
    uint8_t public_key[32];
    size_t key_size = sizeof(public_key);
    assert(EVP_PKEY_get_raw_public_key(key, public_key, &key_size) == 1 && key_size == sizeof(public_key));
    FILE *fixture = fopen(argv[1], "wbx");
    assert(fixture && fprintf(fixture, "{\"public_key_hex\":\"") > 0);
    for (size_t i = 0; i < key_size; ++i) assert(fprintf(fixture, "%02x", (unsigned)public_key[i]) == 2);
    assert(fprintf(fixture, "\",\"request_id\":\"%s\",\"actor\":\"synthetic-analyst\",\"envelope\":{"
        "\"command_id\":\"%s\",\"command_type\":\"%s\",\"issued_at_unix_ms\":%lld,\"deadline_ms\":%u,"
        "\"idempotency_key\":\"%s\",\"soar_correlation_id\":\"%s\",\"payload\":%s},\"http\":%s}\n",
        request_id, id, type, (long long)meta.issued_at_unix_ms, meta.deadline_ms,
        meta.idempotency_key, meta.soar_correlation_id, payload, http) > 0);
    assert(fclose(fixture) == 0);
  }

  if (argc == 3) private_transport(argv[2],r,&meta);

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
