#ifndef EDR_EGRESS_REQUEST_POLICY_H
#define EDR_EGRESS_REQUEST_POLICY_H

#include <stddef.h>

/* A local policy rejection is never a server acknowledgement. */
#define EDR_EGRESS_REQUEST_DENIED (-3)
#define EDR_EGRESS_HEALTH_MAX_BYTES (32768u)
#define EDR_EGRESS_BATCH_WIRE_MAX_BYTES (8u * 1024u * 1024u)

int edr_egress_request_validate(const char *method, const char *suffix_or_url,
                                const char *content_type, const void *body,
                                size_t body_len, char *reason, size_t reason_cap);
/* Real transports use configured authority in addition to the purpose mask.
 * Report envelopes and every decoded frame must match both identities. */
int edr_egress_request_validate_for_scope(const char *method, const char *suffix_or_url,
    const char *content_type, const void *body, size_t body_len,
    const char *tenant_id, const char *endpoint_id, char *reason, size_t reason_cap);

/* Projects existing health state only; raw events are never health inputs.
 * Caller releases the returned JSON with free(). Existing health revision/ACK
 * ownership remains in health_upload.c. No original batch is modified here. */
char *edr_egress_health_project(const char *body, char *reason, size_t reason_cap);

#endif
