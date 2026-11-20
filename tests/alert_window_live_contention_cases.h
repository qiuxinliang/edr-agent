/* Isolated Windows validation using the real mutex and monotonic clock. */
#if defined(_WIN32) && defined(EDR_HAVE_SQLITE)
typedef struct {
  HANDLE locked, entering;
  uint64_t target_ns, holder_entered_ns, held_start_ns, signal_seen_ns, hold_end_ns, unlocked_ns;
} UtmLiveWindowHold;

static void utm_live_window_locked(void *opaque) {
  UtmLiveWindowHold *hold = opaque;
  hold->held_start_ns = soak_monotonic_ns();
  assert(SetEvent(hold->locked));
  assert(WaitForSingleObject(hold->entering, 5000) == WAIT_OBJECT_0);
  hold->signal_seen_ns = soak_monotonic_ns();
  do {
    YieldProcessor();
    hold->hold_end_ns = soak_monotonic_ns();
  } while (hold->hold_end_ns - hold->signal_seen_ns < hold->target_ns);
}

static DWORD WINAPI utm_live_window_holder(void *opaque) {
  UtmLiveWindowHold *hold = opaque;
  hold->holder_entered_ns = soak_monotonic_ns();
  edr_local_evidence_cache_test_hold_mutex_notify(0, utm_live_window_locked, hold);
  hold->unlocked_ns = soak_monotonic_ns();
  return 0;
}

static void test_alert_window_live_contention(void) {
  const int64_t sec = INT64_C(1000000000);
  struct timespec wall;
  assert(timespec_get(&wall, TIME_UTC) == TIME_UTC);
  const int64_t now = (int64_t)wall.tv_sec * sec + wall.tv_nsec;
  const int64_t base = now - 30 * sec;
  char path[640], reference[8193];
  EdrBehaviorRecord *r = calloc(1, sizeof(*r));
  assert(r && make_test_sqlite_path(path, sizeof(path)) == 0);
  edr_local_evidence_cache_test_set_now_unix_ns(base - 30 * sec);
  edr_local_evidence_cache_test_set_retention_monotonic_ms(1000000);
  assert(edr_local_evidence_cache_open(path, 16, 24) == 0);
  window_deliver(r, "pre-hit", base, -25 * sec, 51741, 0);
  window_deliver(r, "anchor-A", base, 0, 0, 0);
  window_deliver(r, "recycled", base, 6 * sec, 51744, 1);
  window_deliver(r, "post-hit", base, 7 * sec, 51742, 0);
  EdrAlertWindowQuery q = {
      .alert_id = "alert-A", .source_event_id = "anchor-A", .kind = "network",
      .tenant_id = r->tenant_id, .endpoint_id = r->endpoint_id,
      .pid = r->pid, .process_start_key = r->process_start_key,
      .process_creation_filetime_100ns = r->process_creation_filetime_100ns,
      .from_ns = base - 30 * sec, .source_time_ns = base, .until_ns = base + 30 * sec,
      .expires_unix_ms = now / 1000000 + 60000, .limit = 50, .max_bytes = 8192,
  };
  edr_local_evidence_cache_test_set_now_unix_ns(0);
  s_test_real_monotonic = 1;
  assert(edr_local_evidence_cache_query_alert_window_json(&q, reference, sizeof(reference)) == 0);
  cJSON *response = cJSON_Parse(reference);
  assert(response && !strcmp(cJSON_GetObjectItemCaseSensitive(response, "coverage")->valuestring, "retained_window"));
  assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(response, "rows")) == 2);
  assert(strstr(reference, "51741") && strstr(reference, "51742") && !strstr(reference, "51744"));
  cJSON_Delete(response);

  unsigned invalid = 0;
  for (unsigned trial = 1; trial <= 3; ++trial) {
    UtmLiveWindowHold hold = {.target_ns = (trial + 1u) * 1000000ULL};
    hold.locked = CreateEventW(NULL, TRUE, FALSE, NULL);
    hold.entering = CreateEventW(NULL, TRUE, FALSE, NULL);
    assert(hold.locked && hold.entering);
    EdrEvidenceCacheStatus before, after;
    const uint64_t status_entered_ns = soak_monotonic_ns();
    edr_local_evidence_cache_get_status(&before);
    const uint64_t status_elapsed_ns = soak_monotonic_ns() - status_entered_ns;
    EvidenceCacheTestThread holder = evidence_cache_test_start_thread(utm_live_window_holder, &hold);
    assert(WaitForSingleObject(hold.locked, 5000) == WAIT_OBJECT_0);
    assert(SetEvent(hold.entering));
    uint64_t query_start_ns = soak_monotonic_ns();
    char out[8193] = "stale evidence";
    int rc = edr_local_evidence_cache_query_alert_window_json(&q, out, sizeof(out));
    uint64_t query_end_ns = soak_monotonic_ns();
    evidence_cache_test_join_thread(holder);
    edr_local_evidence_cache_get_status(&after);
    assert(CloseHandle(hold.entering));
    assert(CloseHandle(hold.locked));
    const uint64_t held_ns = hold.hold_end_ns - hold.held_start_ns;
    const uint64_t unlock_bound_ns = hold.unlocked_ns - hold.held_start_ns;
    const int overlaps = query_start_ns < hold.hold_end_ns;
    const int longer_than_target = held_ns > hold.target_ns + 500000ULL;
    const int above_retry_cutoff = hold.hold_end_ns > query_start_ns &&
        hold.hold_end_ns - query_start_ns >= 20000000ULL;
    const int equal = !rc && !strcmp(reference, out);
    const int empty = !out[0];
    /* Snapshots are taken before the status call unlocks. Only the first
     * status, holder and successful query can contribute to this delta.
     * A first-try query contributes zero wait. Subtract upper bounds on the
     * other two waits, plus 1 us for independent QPC timestamp rounding. */
    const uint64_t samples = after.mutex_lock_samples - before.mutex_lock_samples;
    const uint64_t wait_ns = after.mutex_wait_total_ns - before.mutex_wait_total_ns;
    const uint64_t other_wait_bound_ns = status_elapsed_ns +
        (hold.held_start_ns - hold.holder_entered_ns) + 1000ULL;
    const uint64_t query_wait_lower_ns = samples == 3u && wait_ns > other_wait_bound_ns
        ? wait_ns - other_wait_bound_ns : 0;
    invalid += !(equal && overlaps && !above_retry_cutoff && query_wait_lower_ns);
    printf("live trial=%u target_ns=%llu held_ns=%llu unlock_bound_ns=%llu signal_to_hold_end_ns=%llu "
           "query_elapsed_ns=%llu rc=%d equal=%d empty=%d overlap=%d "
           "longer_than_target_tolerance=%d above_retry_cutoff=%d samples=%llu lock_wait_ns=%llu "
           "other_wait_bound_ns=%llu query_wait_lower_ns=%llu\n",
        trial, (unsigned long long)hold.target_ns, (unsigned long long)held_ns,
        (unsigned long long)unlock_bound_ns, (unsigned long long)(hold.hold_end_ns - hold.signal_seen_ns),
        (unsigned long long)(query_end_ns - query_start_ns), rc, equal, empty, overlaps,
        longer_than_target, above_retry_cutoff, (unsigned long long)samples,
        (unsigned long long)wait_ns, (unsigned long long)other_wait_bound_ns,
        (unsigned long long)query_wait_lower_ns);
    fflush(stdout);
  }
  edr_local_evidence_cache_close();
  edr_local_evidence_cache_test_set_retention_monotonic_ms(-1);
  s_test_real_monotonic = 0;
  cleanup_test_sqlite_path(path);
  free(r);
  assert(!invalid);
}
#endif
