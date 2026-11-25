/* Opt-in workload for the SQLite owner-range experiment. Always run in a new
 * synthetic working directory. No command in this fixture takes a DB path. */
#define DENSE_BASE INT64_C(1750061200000000101)
#define DENSE_MS INT64_C(1000000)
#define DENSE_SEC INT64_C(1000000000)

static void dense_range_tick(int64_t offset) {
  edr_local_evidence_cache_test_set_now_unix_ns(DENSE_BASE + offset);
  s_test_monotonic_ns = (uint64_t)(100 * DENSE_SEC + offset);
  edr_local_evidence_cache_test_set_retention_monotonic_ms((uint64_t)(1000000 + offset / DENSE_MS));
}

static void dense_range_write(EdrBehaviorRecord *r) {
  EdrBehaviorRecord *late = calloc(1, sizeof(*late));
  assert(late);
  window_deliver(r, "range-only-A", DENSE_BASE, -45 * DENSE_SEC + 2 * DENSE_MS, 51741, 0);
  for (unsigned i = 0; i < 32; ++i) {
    init_floor_parent(r, DENSE_BASE - 90 * DENSE_SEC);
    r->type = EDR_EVENT_FILE_WRITE;
    r->file_actor_generation_validated = 1;
    strcpy(r->file_path, "C:\\Users\\lab\\AppData\\Local\\Temp\\updater.exe");
    snprintf(r->event_id, sizeof(r->event_id), "range-write-%02u", i);
    r->event_time_ns = DENSE_BASE + i * DENSE_MS;
    dense_range_tick(i * DENSE_MS);
    assert(edr_local_evidence_cache_is_candidate(r));
    edr_local_evidence_cache_record_behavior(r);
    if (i == 0 || i == 7) assert(edr_local_evidence_cache_record_alert_context(r, NULL) == 0);
    if (i == 15) *late = *r;
  }
  window_deliver(r, "range-before-alert", DENSE_BASE, DENSE_SEC, 51742, 0);
  dense_range_tick(2 * DENSE_SEC);
  assert(edr_local_evidence_cache_record_alert_context(late, NULL) == 0);
  window_deliver(r, "range-shared", DENSE_BASE, 3 * DENSE_SEC, 51743, 0);
  window_deliver(r, "range-reused-pid", DENSE_BASE, 4 * DENSE_SEC, 51744, 1);
  window_deliver(r, "range-only-late", DENSE_BASE, 45 * DENSE_SEC + 10 * DENSE_MS, 51745, 0);
  free(late);
}

static void dense_range_query(EdrBehaviorRecord *r) {
  init_floor_parent(r, DENSE_BASE - 90 * DENSE_SEC);
  EdrAlertWindowQuery q = {0};
  q.kind = "network";
  q.tenant_id = r->tenant_id;
  q.endpoint_id = r->endpoint_id;
  q.pid = r->pid;
  q.process_start_key = r->process_start_key;
  q.process_creation_filetime_100ns = r->process_creation_filetime_100ns;
  q.from_ns = DENSE_BASE - 46 * DENSE_SEC;
  q.until_ns = DENSE_BASE + 46 * DENSE_SEC;
  q.expires_unix_ms = q.until_ns / DENSE_MS + 30000;
  q.max_bytes = 8192;
  q.limit = 50;
  const unsigned ids[] = {0, 7, 15};
  const unsigned expected[] = {7, 6, 22};
  for (unsigned i = 0; i < 3; ++i) {
    char id[40], answer[8193];
    snprintf(id, sizeof(id), "range-write-%02u", ids[i]);
    q.source_event_id = id;
    q.alert_id = id;
    q.source_time_ns = DENSE_BASE + ids[i] * DENSE_MS;
    assert(edr_local_evidence_cache_query_alert_window_json(&q, answer, sizeof(answer)) == 0);
    cJSON *root = cJSON_Parse(answer);
    assert(root);
    const cJSON *row, *rows = cJSON_GetObjectItemCaseSensitive(root, "rows");
    unsigned ports = 0;
    cJSON_ArrayForEach(row, rows) {
      const cJSON *p = cJSON_GetObjectItemCaseSensitive(row, "remote_port");
      assert(cJSON_IsNumber(p) && p->valueint>=51741 && p->valueint<=51745);
      unsigned bit = 1u << (p->valueint-51741);
      assert(!(ports & bit));
      ports |= bit;
    }
    assert(ports == expected[i]);
    printf("%s\n", answer);
    cJSON_Delete(root);
  }
}

static void run_dense_owner_range_witness(const char *stage) {
  static const char path[] = "dense-range-synthetic.sqlite";
  assert(!strcmp(stage,"init") || !strcmp(stage,"write") || !strcmp(stage,"continue") || !strcmp(stage,"query"));
  sqlite3 *db = NULL;
  if (strcmp(stage,"init")) {
    assert(sqlite3_open_v2(path,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK);
    assert(compact_scalar(db,"SELECT count(*) FROM range_synthetic_marker WHERE id=751")==1);
    assert(sqlite3_close(db)==SQLITE_OK);
  } else {
    FILE *fp = fopen(path, "rb");
    assert(!fp && errno == ENOENT);
  }
  test_setenv("EDR_EVIDENCE_CONTEXT_WINDOW_S","45");
  int64_t start = !strcmp(stage, "continue") ? 48 * DENSE_SEC :
                  !strcmp(stage, "query") ? 46 * DENSE_SEC : -45 * DENSE_SEC;
  dense_range_tick(start);
  assert(edr_local_evidence_cache_open(path,32,24)==0);
  if (!strcmp(stage,"init")) {
    assert(sqlite3_open(path,&db)==SQLITE_OK);
    compact_exec(db,"CREATE TABLE range_synthetic_marker(id INTEGER PRIMARY KEY);"
                    "INSERT INTO range_synthetic_marker VALUES(751);");
    assert(sqlite3_close(db)==SQLITE_OK);
  } else {
    EdrBehaviorRecord *r = calloc(1,sizeof(*r));
    assert(r);
    if (!strcmp(stage,"write")) dense_range_write(r);
    else if (!strcmp(stage,"continue")) {
      window_deliver(r, "range-new-owner", DENSE_BASE, 48 * DENSE_SEC, 0, 0);
      window_deliver(r, "range-new-fact", DENSE_BASE, 49 * DENSE_SEC, 51746, 0);
    } else dense_range_query(r);
    free(r);
  }
  edr_local_evidence_cache_close();
}
