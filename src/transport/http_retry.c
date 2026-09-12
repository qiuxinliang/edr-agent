#include "edr/http_retry.h"

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct EdrHttpExecuteContext {
  const EdrHttpRequestAttemptSpec *spec;
  EdrHttpNowMsFn now_ms_fn;
  void *now_ms_opaque;
  EdrHttpTransmitFn transmit_fn;
  void *transmit_opaque;
  int64_t last_timestamp_ms;
  int have_last_timestamp;
} EdrHttpExecuteContext;

typedef EdrHttpAttemptOutcome (*EdrHttpAttemptFn)(void *opaque,
                                                  unsigned int attempt);

static EdrHttpAttemptOutcome run_attempts(unsigned int max_attempts,
                                          EdrHttpAttemptFn attempt_fn,
                                          void *opaque,
                                          unsigned int *out_attempts) {
  EdrHttpAttemptOutcome outcome = EDR_HTTP_ATTEMPT_LOCAL_FAILURE;
  unsigned int attempts = 0u;
  if (out_attempts) {
    *out_attempts = 0u;
  }
  if (!attempt_fn || max_attempts == 0u) {
    return outcome;
  }
  for (unsigned int attempt = 0u; attempt < max_attempts; attempt++) {
    outcome = attempt_fn(opaque, attempt);
    attempts++;
    if (outcome != EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE) {
      break;
    }
  }
  if (out_attempts) {
    *out_attempts = attempts;
  }
  return outcome;
}

int edr_http_status_code_from_line(const char *line) {
  const char *space;
  if (!line || strncmp(line, "HTTP/", 5u) != 0) {
    return 0;
  }
  space = strchr(line + 5u, ' ');
  if (!space) {
    return 0;
  }
  while (*space == ' ') {
    space++;
  }
  if (strlen(space) < 3u) {
    return 0;
  }
  if (!isdigit((unsigned char)space[0]) ||
      !isdigit((unsigned char)space[1]) ||
      !isdigit((unsigned char)space[2]) ||
      (space[3] != '\0' && !isspace((unsigned char)space[3]))) {
    return 0;
  }
  return (space[0] - '0') * 100 + (space[1] - '0') * 10 + (space[2] - '0');
}

EdrHttpAttemptOutcome edr_http_classify_response(int status_code,
                                                 int message_complete) {
  if (status_code >= 200 && status_code < 300 && message_complete) {
    return EDR_HTTP_ATTEMPT_SUCCESS;
  }
  if (status_code > 0) {
    return status_code >= 200 && status_code < 300
               ? EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE
               : EDR_HTTP_ATTEMPT_RESPONSE_FAILURE;
  }
  return EDR_HTTP_ATTEMPT_TRANSPORT_FAILURE;
}

int edr_http_build_request_headers(const EdrHttpRequestAttemptSpec *spec,
                                   int64_t timestamp_ms,
                                   char *out, size_t out_cap) {
  char signature_headers[1024];
  size_t used;
  int n;
  if (!spec || !spec->method || !spec->path || !spec->host || !out || out_cap == 0u ||
      (spec->body_len > 0u && !spec->body)) {
    return -1;
  }
  n = snprintf(out, out_cap, "%s %s HTTP/1.1\r\nHost: %s\r\n",
               spec->method, spec->path, spec->host);
  if (n <= 0 || (size_t)n >= out_cap) {
    return -1;
  }
  used = (size_t)n;
  if (spec->content_type && spec->content_type[0]) {
    n = snprintf(out + used, out_cap - used, "Content-Type: %s\r\n",
                 spec->content_type);
    if (n <= 0 || (size_t)n >= out_cap - used) {
      return -1;
    }
    used += (size_t)n;
  }
  if (spec->body_len > 0u || strcmp(spec->method, "POST") == 0) {
    n = snprintf(out + used, out_cap - used, "Content-Length: %zu\r\n",
                 spec->body_len);
    if (n <= 0 || (size_t)n >= out_cap - used) {
      return -1;
    }
    used += (size_t)n;
  }
  n = snprintf(out + used, out_cap - used,
               "X-Tenant-ID: %s\r\n"
               "X-Endpoint-ID: %s\r\n"
               "X-User-ID: %s\r\n"
               "X-Permission-Set: %s\r\n",
               spec->tenant_id && spec->tenant_id[0] ? spec->tenant_id : "demo-tenant",
               spec->endpoint_id ? spec->endpoint_id : "",
               spec->user_id && spec->user_id[0] ? spec->user_id : "edr-agent",
               spec->permission_set && spec->permission_set[0]
                   ? spec->permission_set
                   : "telemetry:write,endpoint:attack_surface_report");
  if (n <= 0 || (size_t)n >= out_cap - used) {
    return -1;
  }
  used += (size_t)n;
  if (spec->bearer_token && spec->bearer_token[0]) {
    n = snprintf(out + used, out_cap - used, "Authorization: Bearer %s\r\n",
                 spec->bearer_token);
    if (n <= 0 || (size_t)n >= out_cap - used) {
      return -1;
    }
    used += (size_t)n;
  }
  if (edr_reqsig_build_headers(spec->signing, spec->method, spec->path,
                               spec->endpoint_id,
                               (const uint8_t *)(spec->body ? spec->body : ""),
                               spec->body ? spec->body_len : 0u,
                               timestamp_ms, signature_headers,
                               sizeof(signature_headers)) != 0) {
    return -1;
  }
  if (signature_headers[0]) {
    n = snprintf(out + used, out_cap - used, "%s", signature_headers);
    if (n <= 0 || (size_t)n >= out_cap - used) {
      return -1;
    }
    used += (size_t)n;
  }
  n = snprintf(out + used, out_cap - used, "Connection: %s\r\n\r\n",
               spec->keepalive ? "keep-alive" : "close");
  if (n <= 0 || (size_t)n >= out_cap - used) {
    return -1;
  }
  return (int)(used + (size_t)n);
}

static EdrHttpAttemptOutcome execute_request_attempt(void *opaque,
                                                     unsigned int attempt) {
  EdrHttpExecuteContext *ctx = (EdrHttpExecuteContext *)opaque;
  char headers[8192];
  int headers_len;
  int64_t timestamp_ms;
  (void)attempt;
  if (!ctx || !ctx->spec || !ctx->now_ms_fn || !ctx->transmit_fn) {
    return EDR_HTTP_ATTEMPT_LOCAL_FAILURE;
  }
  timestamp_ms = ctx->now_ms_fn(ctx->now_ms_opaque);
  if (ctx->have_last_timestamp && timestamp_ms <= ctx->last_timestamp_ms &&
      ctx->last_timestamp_ms < INT64_MAX) {
    timestamp_ms = ctx->last_timestamp_ms + 1LL;
  }
  ctx->last_timestamp_ms = timestamp_ms;
  ctx->have_last_timestamp = 1;
  headers_len = edr_http_build_request_headers(
      ctx->spec, timestamp_ms, headers, sizeof(headers));
  if (headers_len <= 0) {
    return EDR_HTTP_ATTEMPT_LOCAL_FAILURE;
  }
  return ctx->transmit_fn(ctx->transmit_opaque, headers, (size_t)headers_len,
                          ctx->spec->body, ctx->spec->body_len);
}

EdrHttpAttemptOutcome edr_http_execute_request_attempts(
    const EdrHttpRequestAttemptSpec *spec, unsigned int max_attempts,
    EdrHttpNowMsFn now_ms_fn, void *now_ms_opaque,
    EdrHttpTransmitFn transmit_fn, void *transmit_opaque,
    unsigned int *out_attempts) {
  EdrHttpExecuteContext ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.spec = spec;
  ctx.now_ms_fn = now_ms_fn;
  ctx.now_ms_opaque = now_ms_opaque;
  ctx.transmit_fn = transmit_fn;
  ctx.transmit_opaque = transmit_opaque;
  if (max_attempts > 3u) {
    max_attempts = 3u;
  }
  return run_attempts(max_attempts, execute_request_attempt, &ctx, out_attempts);
}
