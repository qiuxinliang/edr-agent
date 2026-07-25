#include "edr/http_retry.h"

#include <ctype.h>
#include <stdlib.h>

EdrHttpAttemptOutcome edr_http_run_attempts(unsigned int max_attempts,
                                            EdrHttpAttemptFn attempt_fn,
                                            void *ctx,
                                            unsigned int *attempts_run) {
  EdrHttpAttemptOutcome outcome = EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE;
  unsigned int run = 0u;
  if (!attempt_fn || max_attempts == 0u) {
    if (attempts_run) {
      *attempts_run = 0u;
    }
    return outcome;
  }
  for (unsigned int attempt = 0u; attempt < max_attempts; attempt++) {
    run++;
    outcome = attempt_fn(ctx, attempt);
    if (outcome != EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE) {
      break;
    }
  }
  if (attempts_run) {
    *attempts_run = run;
  }
  return outcome;
}

int edr_http_delivery_status_retryable(long status_code) {
  return !(status_code >= 400 && status_code < 500 &&
           status_code != 408 && status_code != 429);
}

long edr_http_status_code_from_line(const char *status_line) {
  const char *p = status_line;
  char *end = NULL;
  long code;
  if (!p) {
    return 0;
  }
  while (*p && !isspace((unsigned char)*p)) {
    p++;
  }
  while (*p && isspace((unsigned char)*p)) {
    p++;
  }
  code = strtol(p, &end, 10);
  return end && end != p && code >= 100 && code <= 999 ? code : 0;
}
