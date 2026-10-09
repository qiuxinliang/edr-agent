#ifndef EDR_VALIDATION_TRACE_H
#define EDR_VALIDATION_TRACE_H
#include "edr/behavior_record.h"
#include "edr/sensor_interest.h"

/* Opt-in local observation only. Never supplies detection, admission or ACK
 * authority. One new protected file, 8 MiB, 300 seconds, 128 generations and
 * 128 batches. No rotation, remote upload, runtime policy change or overwrite.
 * Process scope is an exact executable basename and its direct children.
 * Unresolved identity remains unresolved in the output. */
int edr_validation_trace_start(const char *path, const char *image, unsigned seconds);
/* Parent diagnosis uses the same protected owner and bounds, but never records
 * request bodies. It selects normalized/identity_enriched/enriched/wire and
 * actor/cache diagnostic stages before scope accounting. Only closed owner
 * reason codes are retained; arbitrary producer text is never logged.
 * Environment startup selects it with
 * EDR_VALIDATION_TRACE_PURPOSE=parent_identity; the default keeps the existing
 * egress-validation contract. Unknown explicit purposes are rejected. */
int edr_validation_trace_start_parent(const char *path, const char *image, unsigned seconds);
void edr_validation_trace_start_from_env(void);
/* Observation-cost guard only; never detection/admission/ACK authority. */
int edr_validation_trace_enabled(void);
void edr_validation_trace_event(const EdrBehaviorRecord *record,
                              const char *stage, const char *reason);
/* Compare only values from this same captured record around an owning
 * enrichment operation. These observations supply no parent authority. */
void edr_validation_trace_parent_change(const EdrBehaviorRecord *record,
                                       uint32_t previous_ppid, uint8_t previous_state,
                                       const char *stage);
/* Encoder supplies the actual projected fields before freezing/hash. Actor
 * tuple and event_id remain those of source; NULL source is not attributed.
 * wire_event_id is the actual output ID, for aggregate AVE-to-source mapping;
 * NULL means it is the unchanged source ID. No command, identity text, parent
 * details or wire body are logged. */
void edr_validation_trace_parent_wire(const EdrBehaviorRecord *source,
                                    uint32_t wire_ppid, uint32_t wire_state,
                                    uint32_t projection_version, uint64_t required_fields,
                                    const char *rule_id, const char *wire_event_id);
void edr_validation_trace_interest(const EdrSensorInterestEvent *event, int64_t ns,
                                 const char *stage, const char *reason);
void edr_validation_trace_bind(const EdrBehaviorRecord *record, const char *batch_id,
                             const uint8_t *wire, size_t length);
void edr_validation_trace_request(const char *batch_id, const void *body, size_t length,
                                  const char *content_type);
/* Main-loop owner only; producers never wait for disk writes. Footer `events`
 * keeps its event-encoding attempt meaning; `persisted_events` counts complete
 * event rows written by successful flushes. Capacity/lock/identity/batch/format
 * losses are separate local diagnostic counters, never product loss or ACK. */
void edr_validation_trace_flush(void);
void edr_validation_trace_stop(void);
#endif
