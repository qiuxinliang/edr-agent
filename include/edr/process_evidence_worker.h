#ifndef EDR_PROCESS_EVIDENCE_WORKER_H
#define EDR_PROCESS_EVIDENCE_WORKER_H

#include "edr/windows_file_identity.h"

#include <stdint.h>

typedef struct {
  /* Authoritative format only: win-fileid-v1:<serial64>:<file-id-128>. */
  char file_identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  uint64_t file_write_time;
  char sha256[65];
  char hash_quality[24];
  char hash_reason[EDR_WINDOWS_FILE_IDENTITY_REASON_CAP];
  char signature_status[24];
  char signature_source[32];
  char signer[256];
  char thumbprint[80];
  char revocation[24];
  /* Longest current value is "verified_catalog_cache_chain". Keep this
   * independent from signature_reason so a future quality value cannot
   * overwrite the adjacent evidence field. */
  char signature_quality[40];
  char signature_reason[EDR_WINDOWS_FILE_IDENTITY_REASON_CAP];
} EdrProcessEvidence;

typedef struct {
  uint32_t slots_used;
  uint32_t capacity;
  uint64_t queued;
  uint64_t requests_total;
  uint64_t ready_hits;
  uint64_t pending_reuse;
  uint64_t misses;
  uint64_t backpressure;
  uint64_t cache_evictions;
  uint64_t stale_rejected;
  uint64_t hash_admissions;
  uint64_t hash_attempts;
  uint64_t signature_admissions;
  uint64_t signature_attempts;
  uint64_t wait_timeouts;
  uint64_t queue_deadlines;
  uint64_t shutdown_timeouts;
  uint32_t terminal_unhealthy;
  uint32_t worker_stalled;
} EdrProcessEvidenceMetrics;

/* A bounded asynchronous cache. generation is the raw ETW ProcessStartKey;
 * results from a different process instance are deliberately invisible.
 * Repeated requests retrieve the first captured pathname snapshot even if
 * that path is deleted/replaced. This does not prove the process image. */
int edr_process_evidence_worker_start(void);
void edr_process_evidence_worker_stop(void);
int edr_process_evidence_request(const char *canonical_path, uint64_t generation,
                                 uint64_t monotonic_ns, EdrProcessEvidence *out);
/* Wait only from a preprocess worker, never from the ETW callback.  The
 * timeout is caller-bounded; an unfinished job is reported as unknown. */
int edr_process_evidence_wait(const char *canonical_path, uint64_t generation,
                              uint64_t monotonic_ns, uint64_t max_wait_ns,
                              EdrProcessEvidence *out);
void edr_process_evidence_worker_get_metrics(EdrProcessEvidenceMetrics *out);

#ifdef EDR_PROCESS_EVIDENCE_TESTING
/* Test-only deterministic WVT-path observations. Production has no override:
 * these let the Windows worker test cover A->B and B->A pathname races even
 * though the held no-write/no-delete handle normally prevents the OS swap. */
void edr_process_evidence_test_set_wvt_path_sequence(
    const char *before_identity, uint64_t before_write_time_100ns,
    const char *after_identity, uint64_t after_write_time_100ns);
void edr_process_evidence_test_set_synthetic_wvt_result(int enabled);
#endif

#endif
