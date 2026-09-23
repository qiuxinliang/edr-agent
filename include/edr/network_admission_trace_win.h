#ifndef EDR_NETWORK_ADMISSION_TRACE_WIN_H
#define EDR_NETWORK_ADMISSION_TRACE_WIN_H

#include <windows.h>
#include <evntcons.h>
#include "edr/behavior_record.h"
#include "edr/sensor_interest.h"
#include "edr/types.h"

/* Diagnostic only: first 128 completed loopback events for one destination
 * port, at most 120 seconds. No payload, command line, or arbitrary file data. */
#define EDR_NETWORK_TRACE_LIMIT 128u
#define EDR_NETWORK_TRACE_MAX_MS 120000u
typedef struct {
  uint64_t sequence, event_ns, observed_filetime, start_key, birth;
  uint64_t input_start_key, input_birth, actor_start_key, actor_birth;
  uint32_t header_pid, payload_pid, pid, sport, dport, actor_error;
  uint16_t event_id;
  uint8_t opcode;
  char provider[40], src[64], dst[64], protocol[16], process_name[256];
  char actor_reason[64];
  int prepared, actor_bound, interest, writeback, admitted, published;
  const char *reason; /* collector-owned constant, never provider text */
} EdrNetworkAdmissionTrace;

/* Start is lifecycle-owned; requires a new absolute local path and existing
 * parent directory. Returns -1 on diagnostic failure, 0 disabled, 1 started.
 * Failure must never change collection/admission. */
int edr_network_trace_start(const char *path, uint32_t port, uint32_t duration_ms);
void edr_network_trace_start_from_env(void);
void edr_network_trace_prepare(EdrNetworkAdmissionTrace *trace,
                             const EVENT_RECORD *record, const EdrEventSlot *slot,
                             const EdrSensorInterestEvent *interest);
void edr_network_trace_begin(EdrNetworkAdmissionTrace *trace, const EdrBehaviorRecord *decoded);
void edr_network_trace_actor(EdrNetworkAdmissionTrace *trace,
                             const EdrBehaviorRecord *br, int bound, DWORD error);
void edr_network_trace_identity(EdrNetworkAdmissionTrace *trace, const EdrBehaviorRecord *br);
int edr_network_trace_admission(EdrNetworkAdmissionTrace *trace, int admitted, const char *reason);
/* Callback/decoder: memory only, never waits for the file writer. */
void edr_network_trace_finish(EdrNetworkAdmissionTrace *trace);
/* Existing health sampler and joined collector stop own disk I/O. */
void edr_network_trace_flush(void);
void edr_network_trace_stop(void);
#endif
