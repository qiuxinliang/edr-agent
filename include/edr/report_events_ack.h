#ifndef EDR_REPORT_EVENTS_ACK_H
#define EDR_REPORT_EVENTS_ACK_H
#include <stddef.h>
#include <stdint.h>
/* Authenticated, exact-batch policy disposition; never an acknowledgement. */
#define EDR_REPORT_EVENTS_POLICY_HELD (-8)
int edr_report_events_policy_held(const char *response, const char *tenant_id,
    const char *endpoint_id, const char *batch_id, const uint8_t *header,
    size_t header_len, const uint8_t *payload, size_t payload_len);
/* HTTP success alone is insufficient. Validate a v1 whole-batch receipt from
 * the authenticated server against the original decoded BAT1 bytes. */
int edr_report_events_acknowledged(const char *response, const char *endpoint_id,
                                   const char *batch_id, const uint8_t *header,
                                   size_t header_len, const uint8_t *payload, size_t payload_len);
#endif
