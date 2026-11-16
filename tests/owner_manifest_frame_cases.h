/* The transition reader accepts a previous experimental frame. All candidate
 * writes, including a successful replay of that frame, still produce TEXT. */
#if defined(EDR_HAVE_SQLITE) && defined(EDR_HAVE_ZSTD)
#include <zstd.h>

/* Keep a real owner, its slots and both time fields. Only the optional
 * synthetic member differs. A valid checksum alone cannot bound JSON work. */
static void replace_frame_test_member(sqlite3_stmt *st, const char *owner, size_t bytes,
                                      int shape) {
  unsigned count = shape == 2 ? 880u : 32000u;
  size_t prefix = shape == 2 ? 1040u : 0u;
  char *json = malloc(bytes + count * (16 + prefix) + 32);
  assert(json && bytes > 1 && owner[bytes - 1] == '}');
  memcpy(json, owner, bytes - 1);
  char *next = json + bytes - 1;
  next += sprintf(next, ",\"extra\":");
  if (shape) {
    *next++ = '{';
    for (unsigned i = 0; i < count; ++i) {
      if (i) *next++ = ',';
      *next++ = '"';
      memset(next, 'x', prefix); next += prefix;
      next += sprintf(next, "k%05u\":0", i);
    }
    *next++ = '}';
  } else {
    *next++ = '"';
    for (unsigned i = 0; i < count; ++i) {
      memcpy(next, ":{,}[]\\\"", 8);
      next += 8;
    }
    *next++ = '"';
  }
  *next++ = '}';
  size_t length = (size_t)(next - json);
  ZSTD_CCtx *cc = ZSTD_createCCtx();
  unsigned char *frame = malloc(length);
  assert(cc && frame && !ZSTD_isError(ZSTD_CCtx_setParameter(cc, ZSTD_c_checksumFlag, 1)));
  size_t n = ZSTD_compress2(cc, frame, length, json, length);
  assert(!ZSTD_isError(n) && n < length);
  assert(sqlite3_bind_blob(st, 1, frame, (int)n, SQLITE_TRANSIENT) == SQLITE_OK &&
         sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(sqlite3_db_handle(st)) == 1 &&
         sqlite3_reset(st) == SQLITE_OK);
  ZSTD_freeCCtx(cc); free(frame); free(json);
}

static void test_registry_observation_reopen(void) {
  const int64_t sec = INT64_C(1000000000), base = INT64_C(1750062200000000101);
  EdrBehaviorRecord *r = calloc(1, sizeof(*r));
  char path[640], queue_path[640]; assert(r && !make_test_sqlite_path(path, sizeof(path)));
  assert(!make_test_sqlite_path(queue_path,sizeof(queue_path)));
  edr_storage_queue_configure(16,24);
  assert(edr_storage_queue_open(queue_path)==EDR_OK);
  edr_local_evidence_cache_test_set_now_unix_ns(base);
  assert(!edr_local_evidence_cache_open(path, 512, 72));
  init_window_registry(r, "observed-default", base, sec, "HKCU/Software/Observed", "", 0);
  r->registry_name_observation = EDR_REG_NAME_DEFAULT;
  record_ordinary_expected(r,0);
  strcpy(r->event_id,"duplicate-observed-default");
  record_ordinary_expected(r,1);
  init_window_registry(r, "unknown-name", base, 2*sec, "HKCU/Software/Observed", "", 0);
  record_ordinary_expected(r,0);
  init_window_registry(r, "observed-A", base, 3*sec, "HKCU/Software/Observed", "A", 0);
  r->registry_name_observation = EDR_REG_NAME_OBSERVED;
  edr_local_evidence_cache_record_behavior(r);
  window_deliver(r, "observation-owner", base, 4*sec, 0, 0);
  EdrAlertWindowQuery q = {0};
  q.tenant_id=r->tenant_id; q.endpoint_id=r->endpoint_id;
  q.alert_id=q.source_event_id="observation-owner"; q.source_time_ns=r->event_time_ns;
  q.pid=r->pid; q.process_start_key=r->process_start_key;
  q.process_creation_filetime_100ns=r->process_creation_filetime_100ns;
  q.kind="registry"; q.from_ns=q.source_time_ns-120*sec; q.until_ns=q.source_time_ns+120*sec;
  q.limit=20; q.max_bytes=8192; q.expires_unix_ms=base/1000000+60000;
  init_window_registry(r, "post-default", base, 5*sec, "HKCU/Software/Post", "", 0);
  r->registry_name_observation=EDR_REG_NAME_DEFAULT;
  edr_local_evidence_cache_record_behavior(r);
  init_window_registry(r, "post-unknown", base, 6*sec, "HKCU/Software/Post", "", 0);
  edr_local_evidence_cache_record_behavior(r);
  edr_local_evidence_cache_close();
  /* A historical owner writer emitted empty strings without proof. Preserve
   * that ambiguity on reopen alongside a new post-context omitted name. */
  sqlite3 *legacy_db=NULL; sqlite3_stmt *legacy_st=NULL;
  assert(sqlite3_open(path,&legacy_db)==SQLITE_OK);
  assert(sqlite3_prepare_v2(legacy_db,"SELECT manifest_json FROM artifacts WHERE artifact_type='p0_context_bundle'",-1,&legacy_st,NULL)==SQLITE_OK);
  assert(sqlite3_step(legacy_st)==SQLITE_ROW);
  cJSON *legacy=cJSON_Parse((const char *)sqlite3_column_text(legacy_st,0)); assert(legacy);
  sqlite3_finalize(legacy_st);
  cJSON *context=cJSON_GetObjectItemCaseSensitive(legacy,"context"); unsigned converted=0;
  for(cJSON *event=context->child;event;event=event->next) {
    if(cJSON_HasObjectItem(event,"registry_name_observation")) {
      assert(!cJSON_HasObjectItem(event,"registry_value"));
      cJSON_DeleteItemFromObjectCaseSensitive(event,"registry_name_observation");
      assert(cJSON_AddStringToObject(event,"registry_value","")); ++converted;
    }
  }
  assert(converted==1);
  char *legacy_json=cJSON_PrintUnformatted(legacy); assert(legacy_json);
  assert(sqlite3_prepare_v2(legacy_db,"UPDATE artifacts SET manifest_json=? WHERE artifact_type='p0_context_bundle'",-1,&legacy_st,NULL)==SQLITE_OK);
  assert(sqlite3_bind_text(legacy_st,1,legacy_json,-1,SQLITE_TRANSIENT)==SQLITE_OK && sqlite3_step(legacy_st)==SQLITE_DONE);
  sqlite3_finalize(legacy_st); sqlite3_close(legacy_db); cJSON_free(legacy_json); cJSON_Delete(legacy);
  assert(!edr_local_evidence_cache_open(path,512,72));
  cJSON *answer=window_answer(&q), *rows=cJSON_GetObjectItemCaseSensitive(answer,"rows");
  assert(cJSON_GetArraySize(rows)==3);
  unsigned defaults=0, names=0;
  for(cJSON *row=rows->child;row;row=row->next) {
    const char *value=page_string(row,"registry_value");
    if(!*value) { assert(cJSON_GetArraySize(row)==9 && !cJSON_HasObjectItem(row,"default_observed")); ++defaults; }
    else { assert(!strcmp(value,"A")); ++names; }
  }
  assert(defaults==2 && names==1);
  unsigned missing=0;
  cJSON *gaps=cJSON_GetObjectItemCaseSensitive(answer,"gap_reasons");
  for(cJSON *gap=gaps->child;gap;gap=gap->next)
    missing += !strcmp(gap->valuestring,"registry_fields_missing");
  assert(missing==1);
  const char *window_export=getenv("EDR_REGISTRY_WINDOW_EXPORT");
  if(window_export && window_export[0]) {
    char *raw=cJSON_PrintUnformatted(answer); assert(raw);
    FILE *f=fopen(window_export,"wb"); assert(f);
    assert(fwrite(raw,1,strlen(raw),f)==strlen(raw) && !fclose(f));
    cJSON_free(raw);
  }
  cJSON_Delete(answer);
  EdrSoarCommandMeta meta;
  edr_local_evidence_cache_test_set_now_unix_ns(base+7*sec);
  retained_recall_contract(&meta,r,base+7*sec,"{\"event_type\":\"registry\"}",50);
  cJSON *contract=cJSON_Parse(meta.result_authorization.content_contract); assert(contract);
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(contract,"event_type"),31);
  char *contract_json=cJSON_PrintUnformatted(contract); assert(contract_json);
  snprintf(meta.result_authorization.content_contract,sizeof(meta.result_authorization.content_contract),"%s",contract_json);
  cJSON_free(contract_json); cJSON_Delete(contract);
  char recalled[16384];
  int query_rc=edr_local_evidence_cache_query_authorized_json(meta.result_authorization.command_id,&meta,recalled,sizeof(recalled));
  if(query_rc) fprintf(stderr,"registry observation RTQ: %s\n",recalled);
  assert(!query_rc);
  retained_recall_export("EDR_REGISTRY_RTQ_EXPORT",&meta,recalled);
  answer=cJSON_Parse(recalled); assert(answer);
  rows=cJSON_GetObjectItemCaseSensitive(answer,"rows");
  unsigned unknown=0; defaults=names=0;
  for(cJSON *row=rows->child;row;row=row->next) {
    cJSON *value=cJSON_GetObjectItemCaseSensitive(row,"registry_value");
    if(!value) ++unknown;
    else if(!value->valuestring[0]) { assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(row,"default_observed"))); ++defaults; }
    else { assert(!strcmp(value->valuestring,"A")); ++names; }
  }
  assert(unknown==2 && defaults==2 && names==1);
  cJSON_Delete(answer); edr_local_evidence_cache_close();
  edr_storage_queue_close(); cleanup_test_sqlite_path(queue_path);
  cleanup_test_sqlite_path(path); edr_local_evidence_cache_test_set_now_unix_ns(0); free(r);
}

static void test_owner_manifest_frame(void) {
  const int64_t sec = INT64_C(1000000000), base = INT64_C(1750061200000000101);
  EdrBehaviorRecord *r = calloc(1, sizeof(*r));
  char path[640], plain[8193], actual[8193];
  assert(r && !make_test_sqlite_path(path, sizeof(path)));
  edr_local_evidence_cache_test_set_now_unix_ns(base);
  assert(!edr_local_evidence_cache_open(path, 512, 72));
  window_deliver(r, "frame-pre", base, sec + 1, 53001, 0);
  window_deliver(r, "frame-owner", base, 2 * sec, 0, 0);
  EdrAlertWindowQuery q = {0};
  q.tenant_id = r->tenant_id; q.endpoint_id = r->endpoint_id;
  q.alert_id = q.source_event_id = "frame-owner"; q.source_time_ns = r->event_time_ns;
  q.pid = r->pid; q.process_start_key = r->process_start_key;
  q.process_creation_filetime_100ns = r->process_creation_filetime_100ns;
  q.kind = "network"; q.from_ns = base; q.until_ns = q.source_time_ns;
  q.limit = 2; q.max_bytes = 8192; q.expires_unix_ms = base / 1000000 + 60000;
  edr_local_evidence_cache_close();
  assert(!edr_local_evidence_cache_open(path, 512, 72));
  assert(!edr_local_evidence_cache_query_alert_window_json(&q, plain, sizeof(plain)));
  cJSON *root = cJSON_Parse(plain);
  cJSON *rows = cJSON_GetObjectItemCaseSensitive(root, "rows");
  assert(cJSON_GetArraySize(rows) == 1 &&
         cJSON_GetObjectItemCaseSensitive(rows->child, "remote_port")->valueint == 53001 &&
         !strcmp(page_string(rows->child, "event_time_ns"), "1750061201000000102"));
  cJSON_Delete(root);
  edr_local_evidence_cache_close();

  sqlite3 *db = NULL; sqlite3_stmt *st = NULL;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, "SELECT manifest_json FROM artifacts WHERE artifact_type='p0_context_bundle'",
                            -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW);
  assert(sqlite3_column_type(st, 0) == SQLITE_TEXT);
  int bytes = sqlite3_column_bytes(st, 0);
  const char *text = (const char *)sqlite3_column_text(st, 0);
  ZSTD_CCtx *cc = ZSTD_createCCtx();
  unsigned char *frame = malloc((size_t)bytes);
  assert(cc && frame && text && !ZSTD_isError(ZSTD_CCtx_setParameter(cc, ZSTD_c_checksumFlag, 1)));
  char *saved = malloc((size_t)bytes); assert(saved);
  memcpy(saved, text, (size_t)bytes);
  size_t n = ZSTD_compress2(cc, frame, (size_t)bytes, text, (size_t)bytes);
  assert(n > 0 && n < (size_t)bytes && sqlite3_step(st) == SQLITE_DONE);
  sqlite3_finalize(st); ZSTD_freeCCtx(cc);
  const char *sql = "UPDATE artifacts SET manifest_json=?1 WHERE artifact_type='p0_context_bundle'";
  assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK);
  assert(sqlite3_bind_blob(st, 1, frame, (int)n, SQLITE_TRANSIENT) == SQLITE_OK &&
         sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1 && sqlite3_reset(st) == SQLITE_OK);
  assert(!edr_local_evidence_cache_open(path, 512, 72));
  assert(!edr_local_evidence_cache_query_alert_window_json(&q, actual, sizeof(actual)) && !strcmp(plain, actual));

  replace_frame_test_member(st, saved, (size_t)bytes, 0);
  assert(!edr_local_evidence_cache_query_alert_window_json(&q, actual, sizeof(actual)) && !strcmp(plain, actual));
  replace_frame_test_member(st, saved, (size_t)bytes, 2);
  page_expect_error(&q, EDR_PARENT_CONTEXT_ERROR_INTEGRITY);
  replace_frame_test_member(st, saved, (size_t)bytes, 1);
  free(saved);
  page_expect_error(&q, EDR_PARENT_CONTEXT_ERROR_INTEGRITY);
  EdrEvidenceCacheStatus wide_before, wide_after;
  edr_local_evidence_cache_get_status(&wide_before);
  edr_local_evidence_cache_record_behavior(r);
  edr_local_evidence_cache_get_status(&wide_after);
  assert(wide_after.candidate_failure_reasons[EDR_EVIDENCE_FAILURE_INVALID] ==
         wide_before.candidate_failure_reasons[EDR_EVIDENCE_FAILURE_INVALID] + 1);
  frame[n-1] ^= 1;
  assert(sqlite3_bind_blob(st, 1, frame, (int)n, SQLITE_TRANSIENT) == SQLITE_OK &&
         sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1 && sqlite3_reset(st) == SQLITE_OK);
  page_expect_error(&q, EDR_PARENT_CONTEXT_ERROR_INTEGRITY);
  EdrEvidenceCacheStatus before, after;
  edr_local_evidence_cache_get_status(&before);
  edr_local_evidence_cache_record_behavior(r);
  edr_local_evidence_cache_get_status(&after);
  assert(after.candidate_failure_reasons[EDR_EVIDENCE_FAILURE_INVALID] ==
         before.candidate_failure_reasons[EDR_EVIDENCE_FAILURE_INVALID] + 1);
  assert(compact_scalar(db, "SELECT count(*) FROM artifacts WHERE artifact_type='p0_context_bundle' "
                            "AND typeof(manifest_json)='blob'") == 1);
  frame[n-1] ^= 1;
  assert(sqlite3_bind_blob(st, 1, frame, (int)n, SQLITE_TRANSIENT) == SQLITE_OK &&
         sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1);
  sqlite3_finalize(st); free(frame);
  edr_local_evidence_cache_record_behavior(r);
  assert(compact_scalar(db, "SELECT count(*) FROM artifacts WHERE artifact_type='p0_context_bundle' "
                            "AND typeof(manifest_json)='text'") == 1);
  assert(sqlite3_close(db) == SQLITE_OK);
  edr_local_evidence_cache_close();
  assert(!edr_local_evidence_cache_open(path, 512, 72));
  assert(!edr_local_evidence_cache_query_alert_window_json(&q, actual, sizeof(actual)) && !strcmp(plain, actual));
  edr_local_evidence_cache_close();
  cleanup_test_sqlite_path(path);
  edr_local_evidence_cache_test_set_now_unix_ns(0);
  free(r);
  test_registry_observation_reopen();
}
#endif
