/* Diagnostic probe for the known retired-candidate replay gap. This is not a
 * passing CTest: exit 1 means an identical source recreated a retired owner.
 * Reuse the established synthetic cache fixture and its no-network stubs. */
#define main evidence_cache_fixture_main
#include "test_local_evidence_cache_candidate.c"
#undef main

static int retired_candidate_replay_probe(int reopen) {
  const int64_t now = INT64_C(1700000000000000000);
  char path[512];
  EdrBehaviorRecord record;
  assert(make_test_sqlite_path(path, sizeof(path)) == 0);
  edr_local_evidence_cache_test_set_now_unix_ns(now);
  s_test_monotonic_ns = UINT64_C(1000000000);
  assert(edr_local_evidence_cache_open(path, 16, 1) == 0);
  init_record(&record, EDR_EVENT_NET_CONNECT);
  record.priority = 3;
  record.pid = 74504;
  record.event_time_ns = now;
  record.net_dport = 445;
  set_record_generation(&record, UINT64_C(74504));
  strcpy(record.endpoint_id, "replay-retired-endpoint");
  strcpy(record.tenant_id, "replay-retired-tenant");
  strcpy(record.event_id, "replay-retired-source");
  strcpy(record.net_dst, "10.74.50.4");
  edr_local_evidence_cache_record_behavior(&record);
  unsigned admitted = sqlite_table_count(path, "p0_candidates");
  assert(admitted == 1);

  edr_local_evidence_cache_test_set_now_unix_ns(now + INT64_C(7200000000000));
  s_test_monotonic_ns += UINT64_C(7200000000000);
  for (unsigned i = 0; i < 8 && sqlite_table_count(path, "p0_candidates"); ++i)
    retention_poll();
  unsigned retired = sqlite_table_count(path, "p0_candidates");
  assert(retired == 0);
  if (reopen) {
    edr_local_evidence_cache_close();
    assert(edr_local_evidence_cache_open(path, 16, 1) == 0);
  }
  edr_local_evidence_cache_record_behavior(&record);
  unsigned after = sqlite_table_count(path, "p0_candidates");
  sqlite3 *db = NULL;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  long long created = compact_scalar(db,
      "SELECT COALESCE(MAX(created_ns),0) FROM p0_candidates");
  long long visible = compact_scalar(db, "SELECT COUNT(*) FROM materialized_artifacts");
  assert(sqlite3_close(db) == SQLITE_OK);
  printf("{\"test\":\"retired_candidate_replay\",\"reopened\":%s,"
      "\"initial_candidates\":%u,\"after_retirement\":%u,"
      "\"after_identical_source_replay\":%u,\"visible_artifacts_after_replay\":%lld,"
      "\"created_ns_after_replay\":%lld,\"expected_after_replay\":0}\n",
      reopen ? "true" : "false", admitted, retired, after, visible, created);
  edr_local_evidence_cache_close();
  cleanup_test_sqlite_path(path);
  edr_local_evidence_cache_test_set_now_unix_ns(0);
  s_test_monotonic_ns = UINT64_C(1000000000);
  return after != 0;
}

int main(int argc, char **argv) {
  if (argc != 1 && !(argc == 2 && !strcmp(argv[1], "--expect-no-resurrection"))) {
    fprintf(stderr, "usage: %s [--expect-no-resurrection]\n", argv[0]);
    return 2;
  }
  int failure = retired_candidate_replay_probe(0);
  failure |= retired_candidate_replay_probe(1);
  return failure;
}
