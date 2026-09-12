#include "edr/http_retry.h"
#include "edr/request_signing.h"

#include <stdio.h>
#include <string.h>

typedef struct {
  const char *response_status_lines[3];
  char nonces[3][33];
  char timestamps[3][32];
  char signatures[3][65];
  char body_hashes[3][65];
  char bodies[3][96];
  unsigned int calls;
  unsigned int clock_calls;
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

static int64_t attempt_now_ms(void *opaque) {
  RetryFixture *fixture = (RetryFixture *)opaque;
  fixture->clock_calls++;
  return 1700000000000LL;
}

static EdrHttpAttemptOutcome capture_transmission(
    void *opaque, const char *headers, size_t headers_len,
    const char *body, size_t body_len) {
  RetryFixture *fixture = (RetryFixture *)opaque;
  unsigned int attempt;
  (void)headers_len;
  if (!fixture || fixture->calls >= 3u || !headers ||
      (body_len > 0u && !body)) {
    return EDR_HTTP_ATTEMPT_LOCAL_FAILURE;
  }
  attempt = fixture->calls++;
  if (copy_header(headers, "X-EDR-Nonce", fixture->nonces[attempt],
                  sizeof(fixture->nonces[attempt])) != 0 ||
      copy_header(headers, "X-EDR-Timestamp-Ms", fixture->timestamps[attempt],
                  sizeof(fixture->timestamps[attempt])) != 0 ||
      copy_header(headers, "X-EDR-Signature", fixture->signatures[attempt],
                  sizeof(fixture->signatures[attempt])) != 0 ||
      copy_header(headers, "X-EDR-Content-SHA256", fixture->body_hashes[attempt],
                  sizeof(fixture->body_hashes[attempt])) != 0 ||
      body_len >= sizeof(fixture->bodies[attempt])) {
    return EDR_HTTP_ATTEMPT_LOCAL_FAILURE;
  }
  memcpy(fixture->bodies[attempt], body, body_len);
  fixture->bodies[attempt][body_len] = '\0';
  if (!fixture->response_status_lines[attempt]) {
    return EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE;
  }
  {
    int status = edr_http_status_code_from_line(fixture->response_status_lines[attempt]);
    if (status == 0) {
      return EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE;
    }
    return status >= 200 && status < 300
               ? EDR_HTTP_ATTEMPT_SUCCESS
               : EDR_HTTP_ATTEMPT_RESPONSE_FAILURE;
  }
}

static int expect(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "%s\n", message);
    return 0;
  }
  return 1;
}

static RetryFixture fixture_with(const char *first, const char *second) {
  RetryFixture fixture;
  memset(&fixture, 0, sizeof(fixture));
  fixture.response_status_lines[0] = first;
  fixture.response_status_lines[1] = second;
  return fixture;
}

int main(void) {
  static const char body[] = "{\"command_id\":\"cmd-stable-1\"}";
  EdrRequestSigningConfig signing;
  EdrHttpRequestAttemptSpec spec;
  unsigned int attempts = 0u;
  EdrHttpAttemptOutcome outcome;
  int ok = 1;

  memset(&signing, 0, sizeof(signing));
  signing.enabled = 1;
  snprintf(signing.key_id, sizeof(signing.key_id), "%s", "reqsig_test");
  snprintf(signing.secret, sizeof(signing.secret), "%s", "a2V5");
  memset(&spec, 0, sizeof(spec));
  spec.signing = &signing;
  spec.method = "POST";
  spec.path = "/api/v1/ingest/report-command-result";
  spec.host = "127.0.0.1";
  spec.content_type = "application/json";
  spec.body = body;
  spec.body_len = sizeof(body) - 1u;
  spec.tenant_id = "tenant-1";
  spec.endpoint_id = "ep-1";
  spec.user_id = "edr-agent";
  spec.permission_set = "telemetry:write";
  spec.keepalive = 1;

  RetryFixture lost_response = fixture_with(NULL, "HTTP/1.1 200 OK");
  outcome = edr_http_execute_request_attempts(
      &spec, 2u, attempt_now_ms, &lost_response,
      capture_transmission, &lost_response, &attempts);
  ok &= expect(outcome == EDR_HTTP_ATTEMPT_SUCCESS && attempts == 2u &&
                   lost_response.calls == 2u,
               "a response-loss transport failure must retry once");
  ok &= expect(lost_response.nonces[0][0] && lost_response.nonces[1][0] &&
                   strcmp(lost_response.nonces[0], lost_response.nonces[1]) != 0,
               "each HTTP attempt must build a fresh request-signature nonce");
  ok &= expect(strcmp(lost_response.timestamps[0], lost_response.timestamps[1]) != 0 &&
                   strcmp(lost_response.signatures[0], lost_response.signatures[1]) != 0,
               "each transmission must rebuild timestamp and signature");
  ok &= expect(strcmp(lost_response.body_hashes[0], lost_response.body_hashes[1]) == 0,
               "transport retry must keep the stable business body unchanged");
  ok &= expect(strcmp(lost_response.bodies[0], body) == 0 &&
                   strcmp(lost_response.bodies[1], body) == 0,
               "the actual I/O boundary must receive the same business body on retry");

  RetryFixture unauthorized = fixture_with("HTTP/1.1 401 Unauthorized", "HTTP/1.1 200 OK");
  outcome = edr_http_execute_request_attempts(
      &spec, 2u, attempt_now_ms, &unauthorized,
      capture_transmission, &unauthorized, &attempts);
  ok &= expect(outcome == EDR_HTTP_ATTEMPT_RESPONSE_FAILURE && attempts == 1u &&
                   unauthorized.calls == 1u,
               "an HTTP 401 response must not be immediately retried");

  RetryFixture unavailable = fixture_with("HTTP/1.1 503 Service Unavailable", "HTTP/1.1 200 OK");
  outcome = edr_http_execute_request_attempts(
      &spec, 2u, attempt_now_ms, &unavailable,
      capture_transmission, &unavailable, &attempts);
  ok &= expect(outcome == EDR_HTTP_ATTEMPT_RESPONSE_FAILURE && attempts == 1u &&
                   unavailable.calls == 1u,
               "an HTTP 503 response must be left to the durable retry layer");

  RetryFixture disconnected = fixture_with(NULL, NULL);
  outcome = edr_http_execute_request_attempts(
      &spec, 2u, attempt_now_ms, &disconnected,
      capture_transmission, &disconnected, &attempts);
  ok &= expect(outcome == EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE && attempts == 2u &&
                   disconnected.calls == 2u,
               "transport failures must remain bounded to two attempts");

  RetryFixture excessive_limit = fixture_with(NULL, NULL);
  outcome = edr_http_execute_request_attempts(
      &spec, 100u, attempt_now_ms, &excessive_limit,
      capture_transmission, &excessive_limit, &attempts);
  ok &= expect(outcome == EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE && attempts == 3u &&
                   excessive_limit.calls == 3u,
               "immediate transport retries have a hard production cap");

  ok &= expect(edr_http_status_code_from_line("HTTP/1.1 401 Unauthorized") == 401,
               "HTTP 401 status must be parsed");
  ok &= expect(edr_http_status_code_from_line("HTTP/2 503") == 503,
               "HTTP/2 503 status must be parsed");
  ok &= expect(edr_http_status_code_from_line("not-http") == 0,
               "invalid status lines must not invent a status code");
  ok &= expect(edr_http_classify_response(403, 0) ==
                   EDR_HTTP_ATTEMPT_RESPONSE_FAILURE,
               "a parsed HTTP 403 must not retry when its body truncates");
  ok &= expect(edr_http_classify_response(200, 0) ==
                   EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE,
               "a truncated successful response remains a transport failure");
  return ok ? 0 : 1;
}
