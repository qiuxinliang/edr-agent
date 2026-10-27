/* Real cache/query implementation; reuse the existing isolated fixture. */
#define main evidence_cache_fixture_main
#include "test_local_evidence_cache_candidate.c"
#undef main

static void check_recall(const char *output, const char *coverage, unsigned count) {
  cJSON *root = cJSON_Parse(output); assert(root);
  const cJSON *manifest = cJSON_GetObjectItemCaseSensitive(root, "manifest");
  const cJSON *rows = cJSON_GetObjectItemCaseSensitive(root, "rows");
  assert(cJSON_IsObject(manifest) && cJSON_IsArray(rows));
  assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root, "absence_is_evidence")));
  assert(!strcmp(cJSON_GetObjectItemCaseSensitive(manifest,"coverage_status")->valuestring,coverage));
  assert(cJSON_GetObjectItemCaseSensitive(manifest,"serialized_count")->valueint == (int)count);
  assert(cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(manifest,"omitted_count")));
  assert(cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(manifest,"retained_count")));
  const cJSON *interval = cJSON_GetObjectItemCaseSensitive(manifest,"requested_interval");
  assert(!strcmp(cJSON_GetObjectItemCaseSensitive(interval,"from_ns")->valuestring,"1699999400000000000"));
  assert(!strcmp(cJSON_GetObjectItemCaseSensitive(interval,"until_ns")->valuestring,"1700000300000000000"));
  char *encoded = cJSON_PrintUnformatted(rows); assert(encoded);
  char digest[65]; assert(edr_sha256_hex((const uint8_t *)encoded,strlen(encoded),digest)==0);
  assert(!strcmp(cJSON_GetObjectItemCaseSensitive(manifest,"payload_digest")->valuestring,digest));
  assert(cJSON_GetObjectItemCaseSensitive(manifest,"payload_bytes")->valuedouble == (double)strlen(encoded));
  cJSON_free(encoded);
  char *metadata = cJSON_PrintUnformatted(manifest); assert(metadata && strlen(metadata) < 1400u);
  printf("recall_contract rows=%u coverage=%s manifest_bytes=%zu payload_bytes=%u\n",
      count, coverage, strlen(metadata), (unsigned)cJSON_GetObjectItemCaseSensitive(manifest,"payload_bytes")->valuedouble);
  cJSON_free(metadata); cJSON_Delete(root);
}

int main(void) {
  const int64_t now = INT64_C(1700000000000000000);
  char path[512], queue_path[512], output[16384]; sqlite3 *db = NULL;
  assert(make_test_sqlite_path(path,sizeof(path))==0);
  assert(make_test_sqlite_path(queue_path,sizeof(queue_path))==0);
  edr_local_evidence_cache_test_set_now_unix_ns(now);
  edr_storage_queue_configure(16,1);
  assert(edr_storage_queue_open(queue_path)==EDR_OK);
  assert(edr_local_evidence_cache_open(path,16,1)==0);
  EdrSoarCommandMeta meta={0}; meta.issued_at_unix_ms=now/1000000LL; meta.deadline_ms=60000;
  EdrCommandResultAuthorization *auth=&meta.result_authorization;
  strcpy(auth->command_id,"recall-contract"); strcpy(auth->command_type,"rtq_query");
  strcpy(auth->tenant_id,"retention-tenant"); strcpy(auth->endpoint_id,"retention-endpoint");
  auth->expires_unix_ms=meta.issued_at_unix_ms+60000;
  snprintf(auth->content_contract,sizeof(auth->content_contract),
      "{\"schema\":\"edr.command.result-purpose.v1\",\"kind\":\"cached_rtq\",\"max_bytes\":16383,"
      "\"max_rows\":50,\"window_s\":600,\"issued_unix_ms\":%lld,\"request\":{}}",(long long)meta.issued_at_unix_ms);
  assert(edr_local_evidence_cache_query_authorized_json(auth->command_id,&meta,output,sizeof(output))==0);
  check_recall(output,"unknown",0);
  assert(sqlite3_open(path,&db)==SQLITE_OK);
  retention_group_fixture(db,"recall-one",1,now-1,now-1,now-1);
  compact_exec(db,"UPDATE p0_candidates SET source_completeness='COMPLETE';");
  assert(edr_local_evidence_cache_query_authorized_json(auth->command_id,&meta,output,sizeof(output))==0);
  check_recall(output,"unknown",1); /* A complete row cannot prove continuous collection. */
  compact_exec(db,"UPDATE p0_candidates SET source_completeness='TRUNCATED',source_truncated_fields='source.cmdline';");
  assert(edr_local_evidence_cache_query_authorized_json(auth->command_id,&meta,output,sizeof(output))==0);
  check_recall(output,"partial",1);
  assert(strstr(output,"source_fields_incomplete"));
  compact_exec(db,"UPDATE p0_candidates SET source_completeness='COMPLETE',source_truncated_fields='',"
      "context_window_state='active',context_window_gap_reason='service_restart_gap';");
  assert(edr_local_evidence_cache_query_authorized_json(auth->command_id,&meta,output,sizeof(output))==0);
  check_recall(output,"partial",1);
  assert(strstr(output,"service_restart_gap") && strstr(output,"window_observation_gap"));
  assert(edr_local_evidence_cache_query_authorized_json(auth->command_id,&meta,output,512)!=0);
  assert(strstr(output,"byte budget exhausted"));
  sqlite3_close(db); edr_local_evidence_cache_close();
  assert(edr_local_evidence_cache_open(path,16,1)==0);
  assert(edr_local_evidence_cache_query_authorized_json(auth->command_id,&meta,output,sizeof(output))==0);
  check_recall(output,"partial",1);
  edr_local_evidence_cache_close(); edr_storage_queue_close();
  cleanup_test_sqlite_path(path); cleanup_test_sqlite_path(queue_path);
  edr_local_evidence_cache_test_set_now_unix_ns(0);
  puts("PASS: authorized recall coverage, unknown omissions, digest, byte budget and reopen contract");
  return 0;
}
