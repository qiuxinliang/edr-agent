#ifndef EDR_HEALTH_UPLOAD_H
#define EDR_HEALTH_UPLOAD_H
#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"
/* Owned by the main-loop health producer. No mutable state is shared with
 * transport workers; only an acknowledged full snapshot becomes a base. */
typedef struct {
 cJSON *base;
 char revision[65];
 uint64_t full_at_ns;
 unsigned delta_version; /* ACK-negotiated; zero/legacy uses block delta v1. */
 uint64_t full_count, delta_count, resync_count, attempt_bytes, full_bytes;
} EdrHealthUpload;
typedef int (*EdrHealthSend)(const char *, char *, size_t, void *);
int edr_health_upload(EdrHealthUpload *state, const char *body, uint64_t now_ns,
                      EdrHealthSend send, void *ctx);
void edr_health_upload_reset(EdrHealthUpload *state);
#endif
