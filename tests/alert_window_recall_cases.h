#if defined(EDR_HAVE_SQLITE)
static void window_deliver_fields(EdrBehaviorRecord *r, const char *id, int64_t base,
                                  int64_t offset, const char *ip, unsigned port, int wrong_actor) {
  init_floor_parent(r, base - INT64_C(90000000000));
  r->event_time_ns = base + offset;
  edr_local_evidence_cache_test_set_now_unix_ns(r->event_time_ns);
  s_test_monotonic_ns = (uint64_t)(INT64_C(100000000000) + offset);
  snprintf(r->event_id, sizeof(r->event_id), "%s", id);
  if (!ip) {
    r->type = EDR_EVENT_FILE_WRITE;
    r->file_actor_generation_validated = 1;
    snprintf(r->file_path, sizeof(r->file_path), "C:/Data/%s.exe", id);
    strcpy(r->detection_context, "{\"severity\":\"P1\"}");
  } else {
    r->type = EDR_EVENT_NET_CONNECT;
    r->net_dport = port;
    strcpy(r->net_dst, ip);
    if (wrong_actor) ++r->process_creation_filetime_100ns;
  }
  assert(!!edr_local_evidence_cache_is_candidate(r) == !ip);
  edr_local_evidence_cache_record_behavior(r);
}

static void window_deliver(EdrBehaviorRecord *r, const char *id, int64_t base, int64_t offset,
                           unsigned port, int wrong_actor) {
  window_deliver_fields(r, id, base, offset, port ? "192.0.2.74" : NULL, port, wrong_actor);
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
  /* This helper models an explicitly observed native value name. Unknown
   * historical empty records use init_window_registry directly instead. */
  r->registry_name_observation = value[0] ? EDR_REG_NAME_OBSERVED : EDR_REG_NAME_DEFAULT;
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
    window_deliver_fields(r, "unknown-pre", base, -36 * sec, "", 0, 0);
    window_deliver(r, "only-A", base, -35 * sec, 51741, 0);
    window_registry_input(r, "reg-pre", base, -30 * sec, "HKCU/Software/Pre", "pre", 0);
    window_registry_input(r, "reg-pre-default", base, -30 * sec + 1, "HKCU/Software/前窗", "", 0);
    window_registry_input(r, "reg-pre-wrong", base, -29 * sec, "HKCU/Software/WrongPre", "wrong", 1);
    window_deliver(r, "anchor-A", base, 0, 0, 0);
    window_deliver(r, "anchor-B", base, 20 * sec, 0, 0);
    for (int i = 0; i < 8; ++i) {
      char id[32];
      snprintf(id, sizeof(id), "a-unknown-post-%d", i);
      window_deliver_fields(r, id, base, 24 * sec + i, "", 0, 0);
    }
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
      /* A new signed port scope finds post evidence hidden by the original
       * mixed window limit, without changing that limit or scanning budget. */
      q.limit = 1;
      root = window_answer(&q);
      assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "output_truncated")));
      cJSON_Delete(root);
      q.kind = "network_port"; q.remote_port = 51742;
      root = window_answer(&q); rows = cJSON_GetObjectItemCaseSensitive(root, "rows");
      assert(cJSON_GetArraySize(rows) == 1);
      assert(cJSON_GetObjectItemCaseSensitive(rows->child, "remote_port")->valueint == 51742);
      assert(!strcmp(cJSON_GetObjectItemCaseSensitive(rows->child, "phase")->valuestring, "post"));
      assert(cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(root, "scope"), "remote_port")->valueint == 51742);
      cJSON_Delete(root);
      q.remote_port = 51741;
      root = window_answer(&q); rows = cJSON_GetObjectItemCaseSensitive(root, "rows");
      assert(cJSON_GetArraySize(rows) == !b);
      if (!b) assert(!strcmp(cJSON_GetObjectItemCaseSensitive(rows->child, "phase")->valuestring, "pre"));
      cJSON_Delete(root);
      q.remote_port = 51744; /* Wrong generation stays absent. */
      root = window_answer(&q);
      assert(!cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(root, "rows")));
      const cJSON *gaps = cJSON_GetObjectItemCaseSensitive(root, "gap_reasons");
      assert(cJSON_IsArray(gaps) && cJSON_GetArraySize(gaps) > 0);
      assert(!strcmp(cJSON_GetArrayItem(gaps, cJSON_GetArraySize(gaps) - 1)->valuestring, "unknown"));
      assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root, "scan_limited")));
      assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root, "output_truncated")));
      cJSON_Delete(root);
      char invalid[8193]; q.remote_port = 0;
      assert(edr_local_evidence_cache_query_alert_window_json(&q, invalid, sizeof(invalid)) == EDR_PARENT_CONTEXT_ERROR_INVALID);
      q.remote_port = 65536;
      assert(edr_local_evidence_cache_query_alert_window_json(&q, invalid, sizeof(invalid)) == EDR_PARENT_CONTEXT_ERROR_INVALID);
      q.remote_port = 51742; q.pre_snapshot_sha256 = "";
      assert(edr_local_evidence_cache_query_alert_window_json(&q, invalid, sizeof(invalid)) == EDR_PARENT_CONTEXT_ERROR_INVALID);
      q.pre_snapshot_sha256 = NULL; q.kind = "network";
      assert(edr_local_evidence_cache_query_alert_window_json(&q, invalid, sizeof(invalid)) == EDR_PARENT_CONTEXT_ERROR_INVALID);
      q.remote_port = 0; q.limit = 50;

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
    /* Simulate external corruption in this disposable test store. The normal
     * retention owner blocks deletion while a fact has a live reference. */
    db = NULL;
    st = NULL;
    assert(sqlite3_open(path, &db) == SQLITE_OK);
    assert(sqlite3_exec(db, "PRAGMA foreign_keys=OFF; DROP TRIGGER context_fact_retention_delete;",
                        NULL, NULL, NULL) == SQLITE_OK);
    assert(sqlite3_prepare_v2(db, "DELETE FROM context_facts WHERE fact_id=?;", -1, &st, NULL) == SQLITE_OK);
    assert(sqlite3_bind_text(st, 1, shared, -1, SQLITE_STATIC) == SQLITE_OK);
    assert(sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1);
    sqlite3_finalize(st);
    sqlite3_close(db);
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
static void test_alert_window_invalid_network_fields(void) {
  const int64_t sec = INT64_C(1000000000), base = INT64_C(1750061200000000101);
  const struct { const char *ip; unsigned port; } malformed[] = {
    {"", 51742}, {"192.0.2.74", 0}, {"192.0.2.74", 65536}
  };
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
    char path[640], out[8193] = "must be cleared";
    EdrBehaviorRecord *r = calloc(1, sizeof(*r));
    assert(r && make_test_sqlite_path(path, sizeof(path)) == 0);
    test_setenv("EDR_EVIDENCE_CONTEXT_WINDOW_S", "45");
    edr_local_evidence_cache_test_set_now_unix_ns(base - 10 * sec);
    edr_local_evidence_cache_test_set_retention_monotonic_ms(1000000);
    assert(edr_local_evidence_cache_open(path, 16, 24) == 0);
    window_deliver(r, "anchor", base, 0, 0, 0);
    window_deliver_fields(r, "invalid", base, sec, malformed[i].ip, malformed[i].port, 0);
    window_deliver(r, "valid", base, 2 * sec, 51742, 0);
    edr_local_evidence_cache_close();
    assert(edr_local_evidence_cache_open(path, 16, 24) == 0);
    EdrAlertWindowQuery q = {
      .tenant_id = r->tenant_id, .endpoint_id = r->endpoint_id,
      .alert_id = "alert", .source_event_id = "anchor",
      .pid = r->pid, .process_start_key = r->process_start_key,
      .process_creation_filetime_100ns = r->process_creation_filetime_100ns,
      .source_time_ns = base, .from_ns = base - sec, .until_ns = base + 3 * sec,
      .expires_unix_ms = base / 1000000 + 30000,
      .kind = "network_port", .remote_port = 51742, .limit = 50, .max_bytes = 8192,
    };
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

static void test_alert_window_file_actor(void) {
  const int64_t base = INT64_C(1750061200000000101);
  EdrBehaviorRecord *r = calloc(1, sizeof(*r));
  assert(r);
  for (int compact = 0; compact < 2; ++compact) {
    char path[640], candidate[200];
    assert(make_test_sqlite_path(path, sizeof(path)) == 0);
    edr_local_evidence_cache_test_set_now_unix_ns(base);
    edr_local_evidence_cache_test_set_retention_monotonic_ms(1000000);
    assert((compact ? edr_local_evidence_cache_open(path, 16, 24)
                    : test_open_legacy_context(path, 16, 24)) == 0);
    window_deliver(r, "file-anchor", base, 0, 0, 0);
    sqlite_candidate_id_for_source_event(path, r->event_id, candidate, sizeof(candidate));
    EdrAlertWindowQuery q = {
        .tenant_id = r->tenant_id, .endpoint_id = r->endpoint_id,
        .alert_id = "file-alert", .source_event_id = "file-anchor",
        .pid = r->pid, .process_start_key = r->process_start_key,
        .process_creation_filetime_100ns = r->process_creation_filetime_100ns,
        .source_time_ns = base, .from_ns = base - INT64_C(120000000000),
        .until_ns = base + INT64_C(120000000000),
        .expires_unix_ms = base / 1000000 + 30000, .kind = "file_write", .limit = 50, .max_bytes = 8192,
    };
    /* A, a sibling linked through the same parent, and a reused instance of
     * A's PID all have a retained owner ref. Only A is the signed subject. */
    init_floor_parent(r, base - INT64_C(90000000000));
    r->type = EDR_EVENT_FILE_WRITE;
    strcpy(r->event_id, "write-A");
    strcpy(r->file_path, "C:/Lab/subject-A.bin");
    r->event_time_ns = base + 1;
    assert(!edr_local_evidence_cache_is_candidate(r));
    edr_local_evidence_cache_record_behavior(r);
    assert(sqlite_post_artifact_count(path, candidate, "write-A") == 1);
    ++r->pid;
    ++r->process_start_key;
    ++r->process_creation_filetime_100ns;
    edr_behavior_bind_parent_context(r);
    r->event_time_ns = base + 2;
    strcpy(r->event_id, "write-B");
    strcpy(r->file_path, "C:/Lab/sibling-B.bin");
    edr_local_evidence_cache_record_behavior(r);
    assert(sqlite_post_artifact_count(path, candidate, "write-B") == 1);
    r->pid = q.pid;
    edr_behavior_bind_parent_context(r);
    r->event_time_ns = base + 3;
    strcpy(r->event_id, "write-reused");
    strcpy(r->file_path, "C:/Lab/reused-PID.bin");
    edr_local_evidence_cache_record_behavior(r);
    assert(sqlite_post_artifact_count(path, candidate, "write-reused") == 1);

    edr_local_evidence_cache_close();
    assert(edr_local_evidence_cache_open(path, 16, 24) == 0);
    cJSON *result = window_answer(&q);
    const cJSON *rows = cJSON_GetObjectItemCaseSensitive(result, "rows");
    assert(cJSON_GetArraySize(rows) == 1);
    assert(!strcmp(cJSON_GetObjectItemCaseSensitive(rows->child, "file_path")->valuestring, "C:/Lab/subject-A.bin"));
    assert(!strcmp(cJSON_GetObjectItemCaseSensitive(rows->child, "file_path_quality")->valuestring, "unconfirmed"));
    cJSON_Delete(result);
    assert(sqlite_post_artifact_count(path, candidate, "write-B") == 1);
    printf("alert_window_file_actor layout=%d reopened=1 subject=1 sibling=0 reused=0\n", compact);
    edr_local_evidence_cache_close();
    cleanup_test_sqlite_path(path);
  }
  edr_local_evidence_cache_test_set_now_unix_ns(0);
  edr_local_evidence_cache_test_set_retention_monotonic_ms(-1);
  s_test_monotonic_ns = 0;
  free(r);
}

static void test_alert_window_recall(void) {
  test_alert_window_recall_contract(1);
  test_alert_window_file_actor();
}

#if defined(EDR_HAVE_SQLITE)
static void test_registry_sidecar_wrap(void) {
  const int64_t base = INT64_C(1750061200000000101), sec = INT64_C(1000000000);
  char path[640], key[1024], value[512];
  EdrBehaviorRecord *r = calloc(1, sizeof(*r));
  assert(r && make_test_sqlite_path(path, sizeof(path)) == 0);
  memset(key, 'k', sizeof(key)); key[1023] = 0;
  memset(value, 'v', sizeof(value)); value[511] = 0;
  /* Complete UTF-8 at each actual source capacity, not byte-truncated text. */
  memcpy(key + 1020, "键", 3); memcpy(value + 508, "值", 3);
  test_setenv("EDR_EVIDENCE_CONTEXT_WINDOW_S", "45");
  edr_local_evidence_cache_test_set_now_unix_ns(base - 40 * sec);
  edr_local_evidence_cache_test_set_retention_monotonic_ms(1000000);
  assert(edr_local_evidence_cache_open(path, 16, 24) == 0);
  window_registry_input(r, "wrap-stale", base, -40 * sec, "HKCU/Stale", "stale", 0);
  for (unsigned n = 0; n < 257; ++n) {
    char id[40]; snprintf(id, sizeof(id), "wrap-nonreg-%u", n);
    window_deliver(r, id, base, -39 * sec + n, 54000 + n, n != 256);
  }
  window_registry_input(r, "wrap-max", base, -2 * sec, key, value, 0);
  init_window_registry(r, "wrap-clipped", base, -sec, "HKCU/Clipped", "", 0);
  edr_behavior_mark_source_truncated(r, "source.reg_value_name");
  edr_local_evidence_cache_record_behavior(r);
  window_registry_input(r, "wrap-default", base, -sec + 1, "HKCU/Default", "", 0);
  window_deliver(r, "wrap-anchor", base, 0, 0, 0);
  window_registry_input(r, "wrap-post", base, sec, "HKCU/Post", "post", 0);
  edr_local_evidence_cache_close();
  assert(edr_local_evidence_cache_open(path, 16, 24) == 0);
  EdrAlertWindowQuery q = {0};
  q.tenant_id = r->tenant_id; q.endpoint_id = r->endpoint_id;
  q.alert_id = "wrap-alert"; q.source_event_id = "wrap-anchor";
  q.pid = r->pid; q.process_start_key = r->process_start_key;
  q.process_creation_filetime_100ns = r->process_creation_filetime_100ns;
  q.source_time_ns = base; q.from_ns = base - 45 * sec; q.until_ns = base + 2 * sec;
  q.expires_unix_ms = q.until_ns / 1000000 + 30000;
  q.kind = "registry"; q.limit = 50; q.max_bytes = 8192;
  cJSON *answer = window_answer(&q);
  const cJSON *row; unsigned seen = 0, gaps = 0;
  assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(answer, "rows")) == 3);
  cJSON_ArrayForEach(row, cJSON_GetObjectItemCaseSensitive(answer, "rows")) {
    const char *k = cJSON_GetObjectItemCaseSensitive(row, "registry_key")->valuestring;
    const char *v = cJSON_GetObjectItemCaseSensitive(row, "registry_value")->valuestring;
    assert(!strcmp(cJSON_GetObjectItemCaseSensitive(row, "registry_op")->valuestring, "set_value"));
    if (!strcmp(k, key)) { assert(!strcmp(v, value)); seen |= 1; }
    else if (!strcmp(k, "HKCU/Default")) { assert(!*v); seen |= 2; }
    else { assert(!strcmp(k, "HKCU/Post") && !strcmp(v, "post")); seen |= 4; }
  }
  cJSON_ArrayForEach(row, cJSON_GetObjectItemCaseSensitive(answer, "gap_reasons"))
    gaps += !strcmp(row->valuestring, "registry_fields_missing");
  assert(seen == 7 && gaps == 1);
  cJSON_Delete(answer); edr_local_evidence_cache_close();
  /* Recreate the old TEXT owner's absent optional registry fields, rather than
   * asking today's writer to reproduce the old omission. */
  sqlite3 *db = NULL; sqlite3_stmt *st = NULL;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, "SELECT manifest_json FROM artifacts WHERE artifact_type='p0_context_bundle'", -1, &st, NULL) == SQLITE_OK);
  assert(sqlite3_step(st) == SQLITE_ROW);
  cJSON *legacy = cJSON_Parse((const char *)sqlite3_column_text(st, 0));
  assert(legacy); sqlite3_finalize(st);
  cJSON *item;
  unsigned same_generation_network = 0;
  cJSON_ArrayForEach(item, cJSON_GetObjectItemCaseSensitive(legacy, "context")) {
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(item, "type");
    if (type && type->valueint == EDR_EVENT_NET_CONNECT) {
      ++same_generation_network;
      assert(!cJSON_HasObjectItem(item, "registry_key"));
      assert(!cJSON_HasObjectItem(item, "registry_value"));
      assert(!cJSON_HasObjectItem(item, "registry_op"));
    }
    cJSON_DeleteItemFromObjectCaseSensitive(item, "registry_key");
    cJSON_DeleteItemFromObjectCaseSensitive(item, "registry_value");
    cJSON_DeleteItemFromObjectCaseSensitive(item, "registry_op");
  }
  assert(same_generation_network == 1);
  char *text = cJSON_PrintUnformatted(legacy); assert(text);
  assert(sqlite3_prepare_v2(db, "UPDATE artifacts SET manifest_json=? WHERE artifact_type='p0_context_bundle'", -1, &st, NULL) == SQLITE_OK);
  assert(sqlite3_bind_text(st, 1, text, -1, SQLITE_STATIC) == SQLITE_OK && sqlite3_step(st) == SQLITE_DONE);
  sqlite3_finalize(st); sqlite3_close(db); cJSON_free(text); cJSON_Delete(legacy);
  assert(edr_local_evidence_cache_open(path, 16, 24) == 0);
  answer = window_answer(&q);
  assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(answer, "rows")) == 1);
  row = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(answer, "rows"), 0);
  assert(!strcmp(cJSON_GetObjectItemCaseSensitive(row, "registry_key")->valuestring, "HKCU/Post"));
  assert(!strcmp(cJSON_GetObjectItemCaseSensitive(row, "registry_value")->valuestring, "post"));
  assert(!strcmp(cJSON_GetObjectItemCaseSensitive(row, "phase")->valuestring, "post"));
  gaps = 0;
  cJSON_ArrayForEach(row, cJSON_GetObjectItemCaseSensitive(answer, "gap_reasons"))
    gaps += !strcmp(row->valuestring, "registry_fields_missing");
  assert(gaps == 1); cJSON_Delete(answer);
  edr_local_evidence_cache_close(); cleanup_test_sqlite_path(path);
  edr_local_evidence_cache_test_set_now_unix_ns(0);
  edr_local_evidence_cache_test_set_retention_monotonic_ms(-1);
  s_test_monotonic_ns = 0; free(r);
}
#endif
