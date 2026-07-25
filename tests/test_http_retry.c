#include "edr/http_retry.h"
#include "edr/request_signing.h"

#include <stdio.h>
#include <string.h>

typedef struct {
  EdrRequestSigningConfig signing;
  EdrHttpAttemptOutcome outcomes[3];
  char nonces[3][33];
  unsigned int calls;
} RetryFixture;

static int copy_header(const char *headers, const char *name, char *out, size_t cap) {
  char needle[96];
  const char *start;
  const char *end;
  size_t len;
  if (snprintf(needle, sizeof(needle), "%s: ", name) >= (int)sizeof(needle)) {
    return -1;
  }
  start = strstr(headers, needle);
  if (!start) {
    return -1;
  }
  start += strlen(needle);
  end = strstr(start, "\r\n");
  if (!end) {
    return -1;
  }
  len = (size_t)(end - start);
  if (len + 1u > cap) {
    return -1;
  }
  memcpy(out, start, len);
  out[len] = '\0';
  return 0;
}

static EdrHttpAttemptOutcome signed_attempt(void *opaque, unsigned int attempt) {
  RetryFixture *fixture = (RetryFixture *)opaque;
  char headers[1024];
  if (!fixture || attempt >= 3u ||
      edr_reqsig_build_headers(&fixture->signing, "POST",
                               "/api/v1/ingest/report-command-result", "ep-1",
                               (const unsigned char *)"{}", 2u,
                               1700000000000LL + (long long)attempt,
                               headers, sizeof(headers)) != 0 ||
      copy_header(headers, "X-EDR-Nonce", fixture->nonces[attempt],
                  sizeof(fixture->nonces[attempt])) != 0) {
    return EDR_HTTP_ATTEMPT_RESPONSE_FAILURE;
  }
  fixture->calls++;
  return fixture->outcomes[attempt];
}

static int expect(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "%s\n", message);
    return 0;
  }
  return 1;
}

static RetryFixture fixture_with(EdrHttpAttemptOutcome first,
                                 EdrHttpAttemptOutcome second) {
  RetryFixture fixture;
  memset(&fixture, 0, sizeof(fixture));
  fixture.signing.enabled = 1;
  snprintf(fixture.signing.key_id, sizeof(fixture.signing.key_id), "%s", "reqsig_test");
  snprintf(fixture.signing.secret, sizeof(fixture.signing.secret), "%s", "a2V5");
  fixture.outcomes[0] = first;
  fixture.outcomes[1] = second;
  return fixture;
}

int main(void) {
  unsigned int attempts = 0u;
  EdrHttpAttemptOutcome outcome;
  int ok = 1;

  RetryFixture lost_response = fixture_with(EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE,
                                             EDR_HTTP_ATTEMPT_SUCCESS);
  outcome = edr_http_run_attempts(2u, signed_attempt, &lost_response, &attempts);
  ok &= expect(outcome == EDR_HTTP_ATTEMPT_SUCCESS && attempts == 2u &&
                   lost_response.calls == 2u,
               "a response-loss transport failure must retry once");
  ok &= expect(lost_response.nonces[0][0] && lost_response.nonces[1][0] &&
                   strcmp(lost_response.nonces[0], lost_response.nonces[1]) != 0,
               "each HTTP attempt must build a fresh request-signature nonce");

  RetryFixture unauthorized = fixture_with(EDR_HTTP_ATTEMPT_RESPONSE_FAILURE,
                                            EDR_HTTP_ATTEMPT_SUCCESS);
  outcome = edr_http_run_attempts(2u, signed_attempt, &unauthorized, &attempts);
  ok &= expect(outcome == EDR_HTTP_ATTEMPT_RESPONSE_FAILURE && attempts == 1u &&
                   unauthorized.calls == 1u,
               "an HTTP 401 response must not be immediately retried");

  RetryFixture unavailable = fixture_with(EDR_HTTP_ATTEMPT_RESPONSE_FAILURE,
                                           EDR_HTTP_ATTEMPT_SUCCESS);
  outcome = edr_http_run_attempts(2u, signed_attempt, &unavailable, &attempts);
  ok &= expect(outcome == EDR_HTTP_ATTEMPT_RESPONSE_FAILURE && attempts == 1u &&
                   unavailable.calls == 1u,
               "an HTTP 503 response must be left to the durable retry layer");

  RetryFixture disconnected = fixture_with(EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE,
                                            EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE);
  outcome = edr_http_run_attempts(2u, signed_attempt, &disconnected, &attempts);
  ok &= expect(outcome == EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE && attempts == 2u &&
                   disconnected.calls == 2u,
               "transport failures must remain bounded to two attempts");

  ok &= expect(edr_http_status_code_from_line("HTTP/1.1 401 Unauthorized") == 401,
               "HTTP 401 status must be parsed");
  ok &= expect(edr_http_status_code_from_line("HTTP/2 503") == 503,
               "HTTP/2 503 status must be parsed");
  ok &= expect(edr_http_status_code_from_line("not-http") == 0,
               "invalid status lines must not invent a status code");
  ok &= expect(!edr_http_delivery_status_retryable(401),
               "HTTP 401 replay rejection must be terminal");
  ok &= expect(edr_http_delivery_status_retryable(408) &&
                   edr_http_delivery_status_retryable(429) &&
                   edr_http_delivery_status_retryable(503) &&
                   edr_http_delivery_status_retryable(0),
               "timeouts, throttling, server errors and transport failures must remain retryable");

  return ok ? 0 : 1;
}
