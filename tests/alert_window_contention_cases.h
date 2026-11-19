#if defined(EDR_HAVE_SQLITE)
typedef enum {
  WINDOW_REAL_HOLD, WINDOW_SHORT, WINDOW_RETRY_LIMIT, WINDOW_SCHEDULER_DELAY,
  WINDOW_EXPIRES, WINDOW_SHARED_BUDGET, WINDOW_CLOCK_FAILURE, WINDOW_SHORT_REMAINING
} WindowContentionCase;

typedef struct {
  atomic_int locked, release;
  EvidenceCacheTestThread thread;
  WindowContentionCase mode;
  unsigned retries, reads;
  int joined;
  int64_t expiry_ms;
} AlertWindowContention;

static void window_contention_pause(void) {
#if defined(_WIN32)
  Sleep(1);
#else
  struct timespec pause = {0, 1000000};
  (void)nanosleep(&pause, NULL);
#endif
}

static void window_contention_locked(void *opaque) {
  AlertWindowContention *ctx = opaque;
  atomic_store(&ctx->locked, 1);
  if (ctx->mode == WINDOW_REAL_HOLD) return;
  uint64_t started = soak_monotonic_ns();
  while (!atomic_load(&ctx->release)) {
    assert(soak_monotonic_ns() - started < UINT64_C(5000000000));
    window_contention_pause();
  }
}

#if defined(_WIN32)
static DWORD WINAPI window_contention_holder(void *opaque) {
#else
static void *window_contention_holder(void *opaque) {
#endif
  AlertWindowContention *ctx = opaque;
  edr_local_evidence_cache_test_hold_mutex_notify(
      ctx->mode == WINDOW_REAL_HOLD ? 1200 : 0, window_contention_locked, ctx);
  return 0;
}

static void window_release_holder(AlertWindowContention *ctx) {
  if (ctx->joined) return;
  atomic_store(&ctx->release, 1);
  evidence_cache_test_join_thread(ctx->thread);
  ctx->joined = 1;
}

static void window_contention_step(int after_read, void *opaque) {
  AlertWindowContention *ctx = opaque;
  if (after_read) {
    ++ctx->reads;
    /* This ends past the original 2 s deadline, but would still fit a
     * fresh 2 s budget starting after the successful retry. */
    if (ctx->mode == WINDOW_SHARED_BUDGET) s_test_monotonic_ns += UINT64_C(1997000000);
    if (ctx->mode == WINDOW_CLOCK_FAILURE) s_test_monotonic_ns = 0;
    return;
  }
  ++ctx->retries;
  s_test_monotonic_ns += ctx->mode == WINDOW_SCHEDULER_DELAY ? 20000000u : 5000000u;
  if (ctx->mode != WINDOW_RETRY_LIMIT && ctx->mode != WINDOW_SHORT_REMAINING) window_release_holder(ctx);
  if (ctx->mode == WINDOW_EXPIRES)
    edr_local_evidence_cache_test_set_now_unix_ns(ctx->expiry_ms * INT64_C(1000000));
}

static void window_contended_query(const EdrAlertWindowQuery *q, WindowContentionCase mode,
    int expected, const char *reference) {
  AlertWindowContention ctx = {.mode = mode, .expiry_ms = q->expires_unix_ms};
  atomic_init(&ctx.locked, 0);
  atomic_init(&ctx.release, 0);
  ctx.thread = evidence_cache_test_start_thread(window_contention_holder, &ctx);
  uint64_t started = soak_monotonic_ns();
  while (!atomic_load(&ctx.locked)) {
    assert(soak_monotonic_ns() - started < UINT64_C(5000000000));
    window_contention_pause();
  }
  s_test_monotonic_ns = UINT64_C(1000000000);
  if (mode != WINDOW_REAL_HOLD)
    edr_local_evidence_cache_test_alert_window_steps(window_contention_step, &ctx);
  char out[8193] = "stale evidence";
  started = soak_monotonic_ns();
  int rc = edr_local_evidence_cache_query_alert_window_json(q, out, sizeof(out));
  uint64_t elapsed_ms = (soak_monotonic_ns() - started) / UINT64_C(1000000);
  edr_local_evidence_cache_test_alert_window_steps(NULL, NULL);
  window_release_holder(&ctx);
  fprintf(stderr, "window contention case=%d expected=%d actual=%d retries=%u read=%u elapsed=%llu ms\n",
      (int)mode, expected, rc, ctx.retries, ctx.reads, (unsigned long long)elapsed_ms);
  assert(rc == expected);
  if (!expected) assert(!strcmp(out, reference));
  else assert(!out[0]);
  if (mode == WINDOW_REAL_HOLD) {
    assert(elapsed_ms < 600);
  } else {
    assert(ctx.retries == (mode == WINDOW_RETRY_LIMIT ? 2u : 1u));
    assert(ctx.reads == (mode == WINDOW_SHORT || mode == WINDOW_SHARED_BUDGET ||
                         mode == WINDOW_CLOCK_FAILURE ? 1u : 0u));
  }
}

static void test_alert_window_contention(void) {
  const int64_t sec = INT64_C(1000000000), base = INT64_C(1750061200000000101);
  char path[640], reference[8193], out[8193];
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
      .expires_unix_ms = base / 1000000 + 60000, .limit = 50, .max_bytes = 8192,
  };
  assert(edr_local_evidence_cache_query_alert_window_json(&q, reference, sizeof(reference)) == 0);
  cJSON *response = cJSON_Parse(reference);
  assert(response && !strcmp(cJSON_GetObjectItemCaseSensitive(response, "coverage")->valuestring, "retained_window"));
  assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(response, "rows")) == 2);
  assert(strstr(reference, "51741") && strstr(reference, "51742") && !strstr(reference, "51744"));
  cJSON_Delete(response);
  window_contended_query(&q, WINDOW_SHORT, 0, reference);
  window_contended_query(&q, WINDOW_REAL_HOLD, EDR_PARENT_CONTEXT_ERROR_BUSY, NULL);
  window_contended_query(&q, WINDOW_RETRY_LIMIT, EDR_PARENT_CONTEXT_ERROR_BUSY, NULL);
  EdrAlertWindowQuery short_budget = q;
  /* The fixture wall time is the last delivered event. The first 5 ms
   * pause leaves only 4 ms of the signed request budget for retrying. */
  short_budget.expires_unix_ms = (base + 7 * sec) / 1000000 + 9;
  window_contended_query(&short_budget, WINDOW_SHORT_REMAINING, EDR_PARENT_CONTEXT_ERROR_BUSY, NULL);
  window_contended_query(&q, WINDOW_SCHEDULER_DELAY, EDR_PARENT_CONTEXT_ERROR_BUSY, NULL);
  window_contended_query(&q, WINDOW_SHARED_BUDGET, EDR_PARENT_CONTEXT_ERROR_BUDGET, NULL);
  window_contended_query(&q, WINDOW_CLOCK_FAILURE, EDR_PARENT_CONTEXT_ERROR_BUDGET, NULL);
  EdrAlertWindowQuery other = q;
  other.source_event_id = "anchor-other";
  assert(edr_local_evidence_cache_query_alert_window_json(&other, out, sizeof(out)) == 0);
  response = cJSON_Parse(out);
  assert(response && !strcmp(cJSON_GetObjectItemCaseSensitive(response, "coverage")->valuestring, "owner_unavailable"));
  assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(response, "rows")) == 0);
  cJSON_Delete(response);
  window_contended_query(&q, WINDOW_EXPIRES, EDR_PARENT_CONTEXT_ERROR_EXPIRED, NULL);
  strcpy(out, "stale evidence");
  assert(edr_local_evidence_cache_query_alert_window_json(&q, out, sizeof(out)) ==
      EDR_PARENT_CONTEXT_ERROR_EXPIRED && !out[0]);
  edr_local_evidence_cache_close();
  edr_local_evidence_cache_test_set_now_unix_ns(0);
  edr_local_evidence_cache_test_set_retention_monotonic_ms(-1);
  s_test_monotonic_ns = UINT64_C(1000000000);
  cleanup_test_sqlite_path(path);
  free(r);
}
#endif
