/* This is a reader fixture. The released writer omits registry fields from
 * pre slots. Populate only those fields in a closed, synthetic test database,
 * retaining the writer's original slot order, exact times, owner, and layout. */
#if defined(EDR_HAVE_SQLITE)
static void page_registry_fields(unsigned id, char key[1024], char value[512]) {
  uint32_t seed = id + 1u;
  int prefix = snprintf(key, 1024, "HKCU/Software/Lab/%03u/", id);
  assert(prefix > 0 && prefix < 1023);
  for (int i = prefix; i < 1023; ++i) {
    seed = seed * 1664525u + 1013904223u;
    key[i] = (char)('a' + (seed >> 24) % 26);
  }
  key[1023] = 0;
  for (unsigned i = 0; i < 511; ++i) {
    seed = seed * 1664525u + 1013904223u;
    value[i] = (char)('a' + (seed >> 24) % 26);
  }
  value[511] = 0;
}

static void seed_page_registry(const char *path, int64_t anchor) {
  const char *sql = "UPDATE artifacts SET manifest_json=json_set(manifest_json,"
      "'$.context['||?1||'].registry_key',?2,'$.context['||?1||'].registry_value',?3,"
      "'$.context['||?1||'].registry_op','set_value') WHERE artifact_type='p0_context_bundle' "
      "AND json_extract(manifest_json,'$.source_event_id')='manifest-bound' "
      "AND json_array_length(manifest_json,'$.context')=32 "
      "AND json_extract(manifest_json,'$.context['||?1||'].type')=?4 "
      "AND json_extract(manifest_json,'$.context['||?1||'].event_time_ns')=?5";
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK);
  compact_exec(db, "BEGIN IMMEDIATE");
  assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK);
  for (unsigned i = 0; i < 32; ++i) {
    char key[1024], value[512];
    page_registry_fields(31u - i, key, value);
    assert(sqlite3_bind_int(st, 1, (int)i) == SQLITE_OK &&
           sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(st, 3, value, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_int(st, 4, EDR_EVENT_REG_SET_VALUE) == SQLITE_OK &&
           sqlite3_bind_int64(st, 5, anchor - (int64_t)(i + 1) * INT64_C(1000000000)) == SQLITE_OK &&
           sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1 && sqlite3_reset(st) == SQLITE_OK);
  }
  sqlite3_finalize(st);
  compact_exec(db, "COMMIT");
  assert(sqlite3_close(db) == SQLITE_OK);
}

static const char *page_string(const cJSON *obj, const char *field) {
  const char *s = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, field));
  assert(s);
  return s;
}

static void page_expect_error(const EdrAlertWindowQuery *q, int expected) {
  char out[8193] = "must be cleared";
  assert(edr_local_evidence_cache_query_alert_window_json(q, out, sizeof(out)) == expected && !out[0]);
}

static void test_alert_window_pre_page(void) {
  const int64_t sec = INT64_C(1000000000), anchor = INT64_C(1750061200000000101);
  for (int compact = 0; compact < 2; ++compact) {
    char path[640], id[48], key[1024], value[512], snapshot[65] = "", receipt_hash[65] = "";
    EdrBehaviorRecord *r = calloc(1, sizeof(*r));
    assert(r && make_test_sqlite_path(path, sizeof(path)) == 0);
    test_setenv("EDR_EVIDENCE_CONTEXT_WINDOW_S", "45");
    edr_local_evidence_cache_test_set_now_unix_ns(anchor - 40 * sec);
    edr_local_evidence_cache_test_set_retention_monotonic_ms(1000000);
    assert((compact ? edr_local_evidence_cache_open(path, 16, 24) : test_open_legacy_context(path, 16, 24)) == 0);
    for (unsigned i = 0; i < 32; ++i) {
      snprintf(id, sizeof(id), "reg-%u", i);
      page_registry_fields(i, key, value);
      window_registry_input(r, id, anchor, ((int64_t)i - 32) * sec, key, value, 0);
    }
    window_deliver(r, "manifest-bound", anchor, 0, 0, 0);
    window_registry_input(r, "post-control", anchor, sec, "HKCU/Lab/Post", "post-only", 0);
    edr_local_evidence_cache_close();
    seed_page_registry(path, anchor);
    assert(edr_local_evidence_cache_open(path, 16, 24) == 0);
    EdrAlertWindowQuery q = {0};
    q.tenant_id = r->tenant_id; q.endpoint_id = r->endpoint_id; q.alert_id = "reg-alert";
    q.source_event_id = "manifest-bound"; q.source_time_ns = anchor; q.pid = r->pid;
    q.process_start_key = r->process_start_key; q.process_creation_filetime_100ns = r->process_creation_filetime_100ns;
    q.kind = "registry"; q.from_ns = anchor - 32 * sec; q.until_ns = anchor + sec;
    q.limit = 50; q.max_bytes = 8192; q.expires_unix_ms = anchor / 1000000 + 30000;
    cJSON *old = window_answer(&q);
    const int unpaged = cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(old, "rows"));
    assert(unpaged == 4 && !strcmp(page_string(old, "schema"), "edr.alert-window.v1") &&
           cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(old, "output_truncated")));
    cJSON_Delete(old);
    q.pre_snapshot_sha256 = ""; q.previous_result_sha256 = ""; q.previous_task_id = "";
    unsigned next_slot = 0, pages = 0, largest = 0;
    for (;;) {
      char out[8193];
      assert(++pages <= 32 && edr_local_evidence_cache_query_alert_window_json(&q, out, sizeof(out)) == 0);
      size_t bytes = strlen(out);
      assert(bytes && bytes <= q.max_bytes);
      if (bytes > largest) largest = (unsigned)bytes;
      cJSON *root = cJSON_Parse(out);
      assert(root && !strcmp(page_string(root, "schema"), "edr.alert-window.pre-page.v1") &&
             !strcmp(page_string(root, "coverage"), "retained_window") &&
             cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root, "scan_limited")));
      const char *hash = page_string(root, "snapshot_sha256");
      assert(strlen(hash) == 64 && strspn(hash, "0123456789abcdef") == 64);
      if (pages == 1) strcpy(snapshot, hash);
      else assert(!strcmp(hash, snapshot));
      const cJSON *page = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(root, "scope"), "pre_page");
      assert(page && cJSON_GetObjectItemCaseSensitive(page, "start_slot")->valueint == (int)next_slot &&
             !strcmp(page_string(page, "previous_task_id"), q.previous_task_id) &&
             !strcmp(page_string(page, "previous_result_sha256"), q.previous_result_sha256) &&
             !strcmp(page_string(page, "snapshot_sha256"), q.pre_snapshot_sha256));
      const cJSON *rows = cJSON_GetObjectItemCaseSensitive(root, "rows"), *row;
      assert(cJSON_IsArray(rows) && cJSON_GetArraySize(rows) > 0);
      cJSON_ArrayForEach(row, rows) {
        const cJSON *slot = cJSON_GetObjectItemCaseSensitive(row, "slot");
        assert(next_slot < 32 && cJSON_IsNumber(slot) && slot->valueint == (int)next_slot);
        page_registry_fields(31u - next_slot, key, value);
        char ts[32];
        snprintf(ts, sizeof(ts), "%lld", (long long)(anchor - (int64_t)(next_slot + 1) * sec));
        assert(!strcmp(page_string(row, "phase"), "pre") && !cJSON_HasObjectItem(row, "fact_id") &&
               !strcmp(page_string(row, "registry_key"), key) && !strcmp(page_string(row, "registry_value"), value) &&
               !strcmp(page_string(row, "registry_op"), "set_value") && !strcmp(page_string(row, "event_time_ns"), ts));
        ++next_slot;
      }
      int more = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "output_truncated"));
      cJSON_Delete(root);
      assert(!!more == (next_slot < 32));
      if (!more) break;
      assert(edr_sha256_hex((const uint8_t *)out, bytes, receipt_hash) == 0);
      q.pre_start_slot = next_slot; q.pre_snapshot_sha256 = snapshot; q.previous_result_sha256 = receipt_hash;
      q.previous_task_id = "lcq-0123456789abcdef0123456789abcdef0123456789abcdef";
      if (pages == 1) {
        EdrAlertWindowQuery changed = q;
        changed.alert_id = "other-alert"; page_expect_error(&changed, EDR_PARENT_CONTEXT_ERROR_INTEGRITY);
        changed = q; ++changed.from_ns; page_expect_error(&changed, EDR_PARENT_CONTEXT_ERROR_INTEGRITY);
        changed = q; --changed.limit; page_expect_error(&changed, EDR_PARENT_CONTEXT_ERROR_INTEGRITY);
        edr_local_evidence_cache_close();
        assert(edr_local_evidence_cache_open(path, 16, 24) == 0);
      }
    }
    assert(next_slot == 32 && pages > 1);
    EdrAlertWindowQuery tiny = q;
    tiny.pre_start_slot = 0; tiny.pre_snapshot_sha256 = ""; tiny.previous_task_id = ""; tiny.previous_result_sha256 = "";
    tiny.max_bytes = 1200;
    page_expect_error(&tiny, EDR_PARENT_CONTEXT_ERROR_BUDGET);
    edr_local_evidence_cache_close();
    sqlite3 *db = NULL;
    assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK);
    compact_exec(db, "UPDATE artifacts SET manifest_json=json_set(manifest_json,'$.context[0].registry_value','changed') "
                     "WHERE artifact_type='p0_context_bundle' AND json_extract(manifest_json,'$.source_event_id')='manifest-bound'");
    assert(sqlite3_changes(db) == 1 && sqlite3_close(db) == SQLITE_OK);
    assert(edr_local_evidence_cache_open(path, 16, 24) == 0);
    page_expect_error(&q, EDR_PARENT_CONTEXT_ERROR_INTEGRITY);
    printf("layout=%d frozen=32 unpaged=%d paged_exact=%u pages=%u largest_bytes=%u "
           "reopened=1 scope_swap_rejected=1 changed_consumed_slot_rejected=1 small_budget_rejected=1\n",
           compact, unpaged, next_slot, pages, largest);
    edr_local_evidence_cache_close(); cleanup_test_sqlite_path(path); free(r);
  }
}
#endif
