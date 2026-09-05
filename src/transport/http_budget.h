#ifndef EDR_HTTP_BUDGET_H
#define EDR_HTTP_BUDGET_H

#include <stdint.h>
#include <string.h>

typedef struct {
  int64_t window_minute;
  uint64_t requests;
  uint64_t bytes;
  uint64_t tls_handshakes;
  int64_t telemetry_deferred_until_ms;
} EdrHttpBudget;

typedef struct {
  uint64_t requests;
  uint64_t bytes;
  uint64_t tls_handshakes;
} EdrHttpBudgetLimits;

enum { EDR_HTTP_BUDGET_EXHAUSTED = -1, EDR_HTTP_BUDGET_DEFERRED = 0,
       EDR_HTTP_BUDGET_ADMITTED = 1 };

static inline int edr_http_budget_is_telemetry(const char *url) {
  static const char suffix[] = "/ingest/report-events";
  const char *path;
  const char *scheme;
  size_t length;
  if (!url) return 0;
  scheme = strstr(url, "://");
  path = scheme ? strchr(scheme + 3, '/') : url;
  if (!path) return 0;
  length = strcspn(path, "?#");
  return length >= sizeof(suffix) - 1u &&
         memcmp(path + length - (sizeof(suffix) - 1u), suffix,
                sizeof(suffix) - 1u) == 0;
}

static inline void edr_http_budget_refresh(EdrHttpBudget *state, int64_t now_ms) {
  int64_t minute = now_ms / 60000;
  /* A wall-clock rollback must not manufacture a second full window. */
  if (minute > state->window_minute) {
    state->window_minute = minute;
    state->requests = state->bytes = state->tls_handshakes = 0u;
    state->telemetry_deferred_until_ms = 0;
  }
}

static inline int edr_http_budget_fits(uint64_t used, uint64_t cost,
                                      uint64_t limit, int telemetry) {
  if (telemetry && limit > 0u) {
    uint64_t reserve = limit / 10u;
    limit -= reserve ? reserve : 1u;
  }
  return used <= limit && cost <= limit - used;
}

/* Caller serializes access. Telemetry cannot spend the final 10% of any
 * existing budget, nor turn its own saturation into a control-plane outage.
 * No allowance is added: control requests still share the original totals. */
static inline int edr_http_budget_admit(EdrHttpBudget *state, int64_t now_ms,
                                      EdrHttpBudgetLimits limits, uint64_t bytes,
                                      int request, int tls, int telemetry) {
  if (now_ms <= 0) return EDR_HTTP_BUDGET_EXHAUSTED;
  edr_http_budget_refresh(state, now_ms);
  if (telemetry && now_ms < state->telemetry_deferred_until_ms)
    return EDR_HTTP_BUDGET_DEFERRED;
  if (!edr_http_budget_fits(state->requests, request ? 1u : 0u, limits.requests, telemetry) ||
      !edr_http_budget_fits(state->bytes, bytes, limits.bytes, telemetry) ||
      !edr_http_budget_fits(state->tls_handshakes, tls ? 1u : 0u,
                           limits.tls_handshakes, telemetry)) {
    if (!telemetry) return EDR_HTTP_BUDGET_EXHAUSTED;
    state->telemetry_deferred_until_ms =
        state->window_minute >= INT64_MAX / 60000 - 1
            ? INT64_MAX : (state->window_minute + 1) * 60000;
    return EDR_HTTP_BUDGET_DEFERRED;
  }
  state->requests += request ? 1u : 0u;
  state->bytes += bytes;
  state->tls_handshakes += tls ? 1u : 0u;
  return EDR_HTTP_BUDGET_ADMITTED;
}

#endif
