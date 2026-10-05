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
void edr_validation_trace_start_from_env(void);
void edr_validation_trace_event(const EdrBehaviorRecord *record,
                              const char *stage, const char *reason);
void edr_validation_trace_interest(const EdrSensorInterestEvent *event, int64_t ns,
                                 const char *stage, const char *reason);
void edr_validation_trace_bind(const EdrBehaviorRecord *record, const char *batch_id,
                             const uint8_t *wire, size_t length);
void edr_validation_trace_request(const char *batch_id, const void *body, size_t length,
                                  const char *content_type);
/* Main-loop owner only; producers never wait for disk writes. */
void edr_validation_trace_flush(void);
void edr_validation_trace_stop(void);
#endif
