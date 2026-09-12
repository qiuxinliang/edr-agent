#ifndef EDR_HTTP_RETRY_H
#define EDR_HTTP_RETRY_H

#include "edr/request_signing.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum EdrHttpAttemptOutcome {
  EDR_HTTP_ATTEMPT_SUCCESS = 0,
  EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE = 1,
  EDR_HTTP_ATTEMPT_RESPONSE_FAILURE = 2,
  EDR_HTTP_ATTEMPT_LOCAL_FAILURE = 3,
} EdrHttpAttemptOutcome;

typedef int64_t (*EdrHttpNowMsFn)(void *opaque);
typedef EdrHttpAttemptOutcome (*EdrHttpTransmitFn)(
    void *opaque, const char *headers, size_t headers_len,
    const char *body, size_t body_len);

typedef struct EdrHttpRequestAttemptSpec {
  const EdrRequestSigningConfig *signing;
  const char *method;
  const char *path;
  const char *host;
  const char *content_type;
  const char *body;
  size_t body_len;
  const char *tenant_id;
  const char *endpoint_id;
  const char *user_id;
  const char *bearer_token;
  const char *permission_set;
  int keepalive;
} EdrHttpRequestAttemptSpec;

/* Returns a three-digit HTTP status code, or zero for a malformed/non-HTTP
 * status line. This deliberately does not decide durable retry policy. */
int edr_http_status_code_from_line(const char *line);
EdrHttpAttemptOutcome edr_http_classify_response(int status_code,
                                                 int message_complete);

/* Production native-request boundary: each callback invocation receives a
 * newly assembled request with a fresh signing timestamp, nonce and
 * signature. The stable body is never rebuilt or mutated by this layer.
 * Immediate attempts are hard-capped at three even if a caller asks for more. */
EdrHttpAttemptOutcome edr_http_execute_request_attempts(
    const EdrHttpRequestAttemptSpec *spec, unsigned int max_attempts,
    EdrHttpNowMsFn now_ms_fn, void *now_ms_opaque,
    EdrHttpTransmitFn transmit_fn, void *transmit_opaque,
    unsigned int *out_attempts);

int edr_http_build_request_headers(const EdrHttpRequestAttemptSpec *spec,
                                   int64_t timestamp_ms,
                                   char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif
