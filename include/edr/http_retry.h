#ifndef EDR_HTTP_RETRY_H
#define EDR_HTTP_RETRY_H

#include <stddef.h>

typedef enum {
  EDR_HTTP_ATTEMPT_SUCCESS = 0,
  EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE = 1,
  EDR_HTTP_ATTEMPT_RESPONSE_FAILURE = 2,
} EdrHttpAttemptOutcome;

typedef EdrHttpAttemptOutcome (*EdrHttpAttemptFn)(void *ctx, unsigned int attempt);

EdrHttpAttemptOutcome edr_http_run_attempts(unsigned int max_attempts,
                                            EdrHttpAttemptFn attempt_fn,
                                            void *ctx,
                                            unsigned int *attempts_run);

long edr_http_status_code_from_line(const char *status_line);
int edr_http_delivery_status_retryable(long status_code);

#endif
