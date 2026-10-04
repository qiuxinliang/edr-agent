#ifndef EDR_EGRESS_BATCH_POLICY_H
#define EDR_EGRESS_BATCH_POLICY_H
#include <stddef.h>
#include <stdint.h>

#define EDR_EGRESS_POLICY_VERSION "minimal-egress-v1"
#define EDR_EGRESS_BATCH_MAX (4u * 1024u * 1024u)
#define EDR_EGRESS_FRAME_MAX (256u * 1024u)
#define EDR_EGRESS_FRAME_COUNT_MAX 4096u

/* Validate the immutable bytes, including every compressed/replayed frame.
 * 1 = eligible; 0 = retain locally for review. This never means server ACK. */
int edr_egress_batch_validate(const uint8_t *header, size_t header_len,
    const uint8_t *payload, size_t payload_len, char *reason, size_t reason_cap);
int edr_egress_frame_validate(const uint8_t *frame, size_t frame_len,
    char *reason, size_t reason_cap);
#endif
