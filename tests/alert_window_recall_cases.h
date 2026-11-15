#if defined(EDR_HAVE_SQLITE)
static void window_deliver(EdrBehaviorRecord *r, const char *id, int64_t base, int64_t offset, unsigned port,
                           int wrong_actor) {
  init_floor_parent(r, base - INT64_C(90000000000));
  r->event_time_ns = base + offset;
  edr_local_evidence_cache_test_set_now_unix_ns(r->event_time_ns);
  s_test_monotonic_ns = (uint64_t)(INT64_C(100000000000) + offset);
  snprintf(r->event_id, sizeof(r->event_id), "%s", id);
  if (!port) {
    r->type = EDR_EVENT_FILE_WRITE;
    r->file_actor_generation_validated = 1;
    snprintf(r->file_path, sizeof(r->file_path), "C:/Data/%s.exe", id);
    strcpy(r->detection_context, "{\"severity\":\"P1\"}");
  } else {
    r->type = EDR_EVENT_NET_CONNECT;
    r->net_dport = port;
    strcpy(r->net_dst, "192.0.2.74");
    if (wrong_actor) ++r->process_creation_filetime_100ns;
  }
  assert(!!edr_local_evidence_cache_is_candidate(r) == !port);
  edr_local_evidence_cache_record_behavior(r);
}

static void init_window_registry(EdrBehaviorRecord *r, const char *id, int64_t base, int64_t offset,
                                  const char *key, const char *value, int wrong) {
  init_floor_parent(r, base - INT64_C(90000000000));
  r->event_time_ns = base + offset;
  edr_local_evidence_cache_test_set_now_unix_ns(r->event_time_ns);
  s_test_monotonic_ns = (uint64_t)(INT64_C(100000000000) + offset);
  r->type = EDR_EVENT_REG_SET_VALUE;
  strcpy(r->event_id, id);
  strcpy(r->reg_key_path, key);
  strcpy(r->reg_value_name, value);
  strcpy(r->reg_op, "set_value");
  strcpy(r->reg_value_data, "private-registry-data");
  if (wrong) ++r->process_creation_filetime_100ns;
}

static void window_registry_input(EdrBehaviorRecord *r, const char *id, int64_t base, int64_t offset,
                                  const char *key, const char *value, int wrong) {
  init_window_registry(r, id, base, offset, key, value, wrong);
  assert(!edr_local_evidence_cache_is_candidate(r));
  edr_local_evidence_cache_record_behavior(r);
}

static cJSON *window_answer(const EdrAlertWindowQuery *q) {
  char out[8193];
  int rc = edr_local_evidence_cache_query_alert_window_json(q, out, sizeof(out));
  if (rc) fprintf(stderr, "window recall failed with %d for %s\n", rc, q->source_event_id);
  assert(rc == 0);
  cJSON *root = cJSON_Parse(out);
  assert(root && !strstr(out, "floor-child.exe") && !strstr(out, "C:/Data/"));
  return root;
}

static void test_alert_window_recall_contract(int require_registry_pre) {
  const int64_t sec = INT64_C(1000000000), base = INT64_C(1750061200000000101);
  for (int compact = 0; compact < 2; ++compact) {
    char path[640], shared[65] = {0};
    EdrBehaviorRecord *r = calloc(1, sizeof(*r));
    assert(r);
    assert(make_test_sqlite_path(path, sizeof(path)) == 0);
    test_setenv("EDR_EVIDENCE_CONTEXT_WINDOW_S", "45");
    edr_local_evidence_cache_test_set_now_unix_ns(base - 40 * sec);
    edr_local_evidence_cache_test_set_retention_monotonic_ms(1000000);
    assert((compact ? edr_local_evidence_cache_open(path, 16, 24) : test_open_legacy_context(path, 16, 24)) == 0);
    window_deliver(r, "only-A", base, -35 * sec, 51741, 0);
    window_registry_input(r, "reg-pre", base, -30 * sec, "HKCU/Software/Pre", "pre", 0);
    window_registry_input(r, "reg-pre-default", base, -30 * sec + 1, "HKCU/Software/前窗", "", 0);
    window_registry_input(r, "reg-pre-wrong", base, -29 * sec, "HKCU/Software/WrongPre", "wrong", 1);
    window_deliver(r, "anchor-A", base, 0, 0, 0);
    window_deliver(r, "anchor-B", base, 20 * sec, 0, 0);
    window_deliver(r, "shared", base, 25 * sec, 51742, 0);
    window_deliver(r, "shared-next-ns", base, 25 * sec + 1, 51745, 0);
    window_deliver(r, "recycled", base, 26 * sec, 51744, 1);
    window_registry_input(r, "reg-post", base, 28 * sec, "HKCU/Software/Post", "调查值", 0);
    window_registry_input(r, "reg-default", base, 29 * sec, "HKCU/Software/Default", "", 0);
    window_registry_input(r, "reg-wrong", base, 30 * sec, "HKCU/Software/Wrong", "x", 1);
    window_deliver(r, "only-B", base, 55 * sec, 51743, 0);
    edr_local_evidence_cache_close();
    assert(edr_local_evidence_cache_open(path, 16, 24) == 0);
    EdrAlertWindowQuery q = {0};
    q.tenant_id = r->tenant_id;
    q.endpoint_id = r->endpoint_id;
    q.pid = r->pid;
    q.process_start_key = r->process_start_key;
    q.process_creation_filetime_100ns = r->process_creation_filetime_100ns;
    q.from_ns = base - 40 * sec;
    q.until_ns = base + 60 * sec;
    q.expires_unix_ms = q.until_ns / 1000000 + 30000;
    q.kind = "network";
    q.max_bytes = 8192;
    q.limit = 50;
    for (int b = 0; b < 2; ++b) {
      q.alert_id = b ? "alert-B" : "alert-A";
      q.source_event_id = b ? "anchor-B" : "anchor-A";
      q.source_time_ns = base + b * 20 * sec;
      cJSON *root = window_answer(&q), *rows = cJSON_GetObjectItemCaseSensitive(root, "rows");
      assert(!strcmp(cJSON_GetObjectItemCaseSensitive(root, "coverage")->valuestring, "retained_window"));
      assert(cJSON_GetArraySize(rows) == 3);
      const cJSON *row;
      unsigned mask = 0;
      cJSON_ArrayForEach(row, rows) {
        int port = cJSON_GetObjectItemCaseSensitive(row, "remote_port")->valueint;
        assert(port >= 51741 && port <= 51745);
        mask |= 1u << (port - 51741);
        int pre = port == 51741;
        int64_t ts = base + (pre ? -35 * sec : port == 51743 ? 55 * sec : 25 * sec) + (port == 51745);
        char decimal[32];
        snprintf(decimal, sizeof(decimal), "%lld", (long long)ts);
        assert(!strcmp(cJSON_GetObjectItemCaseSensitive(row, "event_time_ns")->valuestring, decimal));
        assert(!strcmp(cJSON_GetObjectItemCaseSensitive(row, "phase")->valuestring, pre ? "pre" : "post"));
        assert(cJSON_HasObjectItem(row, "slot") == pre && cJSON_HasObjectItem(row, "fact_id") == !pre);
        if (port == 51742) {
          const char *fid = cJSON_GetObjectItemCaseSensitive(row, "fact_id")->valuestring;
          assert(strlen(fid) == 64);
          if (b)
            assert(!strcmp(fid, shared));
          else
            strcpy(shared, fid);
        }
      }
      assert(mask == (unsigned)(b ? 22 : 19));
      cJSON_Delete(root);
    }
    q.kind = "registry";
    q.alert_id = "alert-A";
    q.source_event_id = "anchor-A";
    q.source_time_ns = base;
    cJSON *registry = window_answer(&q), *reg_rows = cJSON_GetObjectItemCaseSensitive(registry, "rows");
    assert(cJSON_GetArraySize(reg_rows) == (require_registry_pre ? 4 : 2));
    int unicode = 0, default_value = 0, pre_value = 0, pre_default = 0;
    const cJSON *reg;
    cJSON_ArrayForEach(reg, reg_rows) {
      const char *key = cJSON_GetObjectItemCaseSensitive(reg, "registry_key")->valuestring;
      const char *value = cJSON_GetObjectItemCaseSensitive(reg, "registry_value")->valuestring;
      assert(!strcmp(cJSON_GetObjectItemCaseSensitive(reg, "registry_op")->valuestring, "set_value"));
      assert(!cJSON_HasObjectItem(reg, "reg_value_data"));
      pre_default += !strcmp(key, "HKCU/Software/前窗") && !*value;
      pre_value += !strcmp(key, "HKCU/Software/Pre") && !strcmp(value, "pre");
      unicode += !strcmp(key, "HKCU/Software/Post") && !strcmp(value, "调查值");
      default_value += !strcmp(key, "HKCU/Software/Default") && !*value;
    }
    assert(unicode == 1 && default_value == 1);
    assert(pre_value == require_registry_pre && pre_default == require_registry_pre);
    /* Recall preserves integer nanoseconds for the adjacent pre-window facts. */
    cJSON_ArrayForEach(reg, reg_rows) {
      const char *key = cJSON_GetObjectItemCaseSensitive(reg, "registry_key")->valuestring;
      if (!strcmp(key, "HKCU/Software/Pre") || !strcmp(key, "HKCU/Software/前窗")) {
        char expected[32];
        int64_t ts = base - 30 * sec + !strcmp(key, "HKCU/Software/前窗");
        snprintf(expected, sizeof(expected), "%lld", (long long)ts);
        assert(!strcmp(cJSON_GetObjectItemCaseSensitive(reg, "event_time_ns")->valuestring, expected));
        assert(!strcmp(cJSON_GetObjectItemCaseSensitive(reg, "phase")->valuestring, "pre"));
      }
    }
    int legacy_gap = 0;
    const cJSON *gap;
    cJSON_ArrayForEach(gap, cJSON_GetObjectItemCaseSensitive(registry, "gap_reasons")) legacy_gap |=
        !strcmp(gap->valuestring, "registry_fields_missing");
    assert(legacy_gap == !require_registry_pre);
    cJSON_Delete(registry);
    q.kind = "network";
    q.alert_id = "alert-B";
    q.source_event_id = "anchor-B";
    q.source_time_ns = base + 20 * sec;
    ++q.process_creation_filetime_100ns;
    cJSON *root = window_answer(&q);
    assert(!strcmp(cJSON_GetObjectItemCaseSensitive(root, "coverage")->valuestring, "owner_unavailable"));
    assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(root, "rows")) == 0);
    cJSON_Delete(root);
    --q.process_creation_filetime_100ns;
    q.until_ns = base + 25 * sec;
    root = window_answer(&q);
    assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(root, "rows")) == 1);
    cJSON_Delete(root);
    q.until_ns = base + 60 * sec;
    q.max_bytes = 950;
    root = window_answer(&q);
    assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "output_truncated")));
    assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(root, "rows")) < 3);
    char *encoded_result = cJSON_PrintUnformatted(root);
    assert(encoded_result && strlen(encoded_result) <= q.max_bytes);
    cJSON_free(encoded_result);
    cJSON_Delete(root);
    q.max_bytes = 8192;
    q.limit = 1;
    root = window_answer(&q);
    assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "output_truncated")));
    assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root, "scan_limited")));
    cJSON_Delete(root);
    /* Mutate the synthetic shared fact in a separate connection. No row,
     * including the unaffected ones encountered earlier, may escape. */
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    assert(sqlite3_open(path, &db) == SQLITE_OK);
    assert(sqlite3_prepare_v2(
               db,
               "UPDATE context_facts SET "
               "manifest_template_json=replace(manifest_template_json,'192.0.2.74','192.0.2.75') WHERE fact_id=?;",
               -1, &st, NULL) == SQLITE_OK);
    assert(sqlite3_bind_text(st, 1, shared, -1, SQLITE_STATIC) == SQLITE_OK);
    assert(sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1);
    sqlite3_finalize(st);
    sqlite3_close(db);
    char out[8193] = "must be cleared";
    assert(edr_local_evidence_cache_query_alert_window_json(&q, out, sizeof(out)) ==
               EDR_PARENT_CONTEXT_ERROR_INTEGRITY &&
           !out[0]);
    edr_local_evidence_cache_close();
    cleanup_test_sqlite_path(path);
    free(r);
    test_unsetenv("EDR_EVIDENCE_CONTEXT_WINDOW_S");
    edr_local_evidence_cache_test_set_now_unix_ns(0);
    edr_local_evidence_cache_test_set_retention_monotonic_ms(-1);
    s_test_monotonic_ns = 0;
  }
}
#endif

/* One real candidate and its independently sourced post-window records.
 * Reopen before querying so persisted source-quality markers are exercised. */
static void test_registry_source_fidelity(void) {
  static const char *markers[] = {
      "source.reg_key_path", "source.reg_value_name", "source.reg_op", "source.list_overflow",
      "reg_key_path", "reg_value_name", "reg_op", "source.source_completeness",
      NULL, "source.reg_value_data", "source.reg_key_path_extra", "source.other"};
  const int64_t base = INT64_C(1750061200000000101), sec = INT64_C(1000000000);
  EdrBehaviorRecord *r = calloc(1, sizeof(*r));
  assert(r);
  for (int compact = 0; compact < 2; ++compact) {
    char path[640];
    assert(make_test_sqlite_path(path, sizeof(path)) == 0);
    test_setenv("EDR_EVIDENCE_CONTEXT_WINDOW_S", "45");
    s_test_monotonic_ns = UINT64_C(100000000000);
    edr_local_evidence_cache_test_set_retention_monotonic_ms(1000000);
    edr_local_evidence_cache_test_set_now_unix_ns(base);
    assert((compact ? edr_local_evidence_cache_open(path, 16, 24) : test_open_legacy_context(path, 16, 24)) == 0);
    window_deliver(r, "registry-fidelity", base, 0, 0, 0);
    for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); ++i) {
      char id[32];
      snprintf(id, sizeof(id), "fidelity-%u", (unsigned)i);
      init_window_registry(r, id, base, (int64_t)(i + 1) * sec, "HKCU/Software/Fidelity", id, 0);
      if (markers[i]) edr_behavior_mark_source_truncated(r, markers[i]);
      else strcpy(r->source_completeness, "TRUNCATED");
      if (i == 11) strcpy(r->source_completeness, "NOT_EVALUABLE");
      edr_local_evidence_cache_record_behavior(r);
    }
    edr_local_evidence_cache_close();
    assert(edr_local_evidence_cache_open(path,16,24) == 0);
    EdrAlertWindowQuery q = {0};
    q.tenant_id = r->tenant_id;
    q.endpoint_id = r->endpoint_id;
    q.alert_id = "alert-registry";
    q.source_event_id = "registry-fidelity";
    q.pid = r->pid;
    q.process_start_key = r->process_start_key;
    q.process_creation_filetime_100ns = r->process_creation_filetime_100ns;
    q.source_time_ns = q.from_ns = base;
    q.until_ns = base + 20 * sec;
    q.expires_unix_ms = q.until_ns / 1000000 + 30000;
    q.kind = "registry";
    q.limit = 50;
    q.max_bytes = 8192;
    cJSON *answer = window_answer(&q);
    const cJSON *row;
    unsigned correct = 0, incomplete = 0, gaps = 0;
    cJSON_ArrayForEach(row, cJSON_GetObjectItemCaseSensitive(answer, "rows")) {
      const char *value = cJSON_GetObjectItemCaseSensitive(row, "registry_value")->valuestring;
      if (!strcmp(value, "fidelity-9")) correct |= 1;
      else if (!strcmp(value, "fidelity-10")) correct |= 2;
      else ++incomplete;
    }
    cJSON_ArrayForEach(row, cJSON_GetObjectItemCaseSensitive(answer, "gap_reasons"))
      if (!strcmp(row->valuestring, "registry_fields_missing")) ++gaps;
    fprintf(stderr, "registry_source_fidelity layout=%d incomplete_projected=%u controls=%u gaps=%u\n",
            compact, incomplete, correct, gaps);
    assert(incomplete == 0 && correct == 3 && gaps == 1);
    cJSON_Delete(answer);
    edr_local_evidence_cache_close();
    cleanup_test_sqlite_path(path);
  }
  edr_local_evidence_cache_test_set_now_unix_ns(0);
  edr_local_evidence_cache_test_set_retention_monotonic_ms(-1);
  s_test_monotonic_ns = 0;
  free(r);
}

static void test_alert_window_recall(void) { test_alert_window_recall_contract(1); }
