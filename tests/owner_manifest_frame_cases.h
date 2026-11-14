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
}
#endif
