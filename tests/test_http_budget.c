#include "http_budget.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>

int main(void) {
  EdrHttpBudget budget = {0};
  EdrHttpBudgetLimits limits = {600u, 64u * 1024u * 1024u, 120u};
  const int64_t now = 60000;
  assert(edr_http_budget_is_telemetry("https://host/api/v1/ingest/report-events"));
  assert(edr_http_budget_is_telemetry("https://host/api/v1/ingest/report-events?x=1"));
  assert(!edr_http_budget_is_telemetry("https://host/api/v1/ingest/heartbeat?x=/ingest/report-events"));
  assert(!edr_http_budget_is_telemetry("https://host/api/v1/ingest/report-events-other"));
  assert(!edr_http_budget_is_telemetry("https://host/api/v1/ingest/control/stream"));
  assert(!edr_http_budget_is_telemetry(NULL));
  for (int i = 0; i < 108; ++i)
    assert(edr_http_budget_admit(&budget, now, limits, 512u, 1, 1, 1) == EDR_HTTP_BUDGET_ADMITTED);
  assert(edr_http_budget_admit(&budget, now, limits, 512u, 1, 1, 1) == EDR_HTTP_BUDGET_DEFERRED);
  assert(budget.requests == 108u && budget.tls_handshakes == 108u);
  assert(budget.telemetry_deferred_until_ms == 120000);
  /* Local retries neither spend the reserve nor postpone its reset. */
  for (int i = 0; i < 10000; ++i)
    assert(edr_http_budget_admit(&budget, now + i, limits, 512u, 1, 1, 1) == EDR_HTTP_BUDGET_DEFERRED);
  for (int i = 0; i < 12; ++i)
    assert(edr_http_budget_admit(&budget, now, limits, 512u, 1, 1, 0) == EDR_HTTP_BUDGET_ADMITTED);
  assert(edr_http_budget_admit(&budget, now, limits, 512u, 1, 1, 0) == EDR_HTTP_BUDGET_EXHAUSTED);
  assert(budget.requests == 120u && budget.tls_handshakes == 120u);
  assert(edr_http_budget_admit(&budget, 59999, limits, 512u, 1, 1, 0) == EDR_HTTP_BUDGET_EXHAUSTED);
  assert(edr_http_budget_admit(&budget, 120000, limits, 512u, 1, 1, 1) == EDR_HTTP_BUDGET_ADMITTED);
  assert(budget.requests == 1u && budget.tls_handshakes == 1u && budget.telemetry_deferred_until_ms == 0);
  budget = (EdrHttpBudget){0};
  /* Native keepalive charges requests separately from new connections. */
  for (int i = 0; i < 540; ++i)
    assert(edr_http_budget_admit(&budget, now, limits, 512u, 1, 0, 1) == EDR_HTTP_BUDGET_ADMITTED);
  assert(edr_http_budget_admit(&budget, now, limits, 0u, 0, 1, 1) == EDR_HTTP_BUDGET_ADMITTED);
  assert(budget.requests == 540u && budget.tls_handshakes == 1u);
  assert(edr_http_budget_admit(&budget, now, limits, 512u, 1, 0, 1) == EDR_HTTP_BUDGET_DEFERRED);
  assert(edr_http_budget_admit(&budget, now, limits, 512u, 1, 0, 0) == EDR_HTTP_BUDGET_ADMITTED);
  assert(edr_http_budget_fits(0u, 90u, 100u, 1));
  assert(!edr_http_budget_fits(90u, 1u, 100u, 1));
  assert(edr_http_budget_fits(90u, 10u, 100u, 0));
  assert(!edr_http_budget_fits(UINT64_MAX, 1u, UINT64_MAX, 0));
  assert(!edr_http_budget_fits(0u, 1u, 1u, 1));
  assert(edr_http_budget_fits(0u, 1u, 1u, 0));
  assert(!edr_http_budget_fits(0u, 1u, 0u, 0));
  assert(edr_http_budget_admit(&budget, 0, limits, 0u, 1, 0, 0) == EDR_HTTP_BUDGET_EXHAUSTED);
  puts("HTTP telemetry budget isolation passed");
  return 0;
}
