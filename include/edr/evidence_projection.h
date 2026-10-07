#ifndef EDR_EVIDENCE_PROJECTION_H
#define EDR_EVIDENCE_PROJECTION_H
#include <stdint.h>

/* Captured by the detecting owner, not inferred from labels or scores at send
 * time. P0 derives these bits from its retained immutable matcher snapshot. */
#define EDR_EVIDENCE_PROJECTION_VERSION 2u
#define EDR_EVIDENCE_COMMAND        (UINT64_C(1) << 0)
#define EDR_EVIDENCE_PARENT_NAME    (UINT64_C(1) << 1)
#define EDR_EVIDENCE_PARENT_PATH    (UINT64_C(1) << 2)
#define EDR_EVIDENCE_PARENT_COMMAND (UINT64_C(1) << 3)
#define EDR_EVIDENCE_CHAIN_DEPTH    (UINT64_C(1) << 4)
#define EDR_EVIDENCE_FILE           (UINT64_C(1) << 5)
#define EDR_EVIDENCE_NETWORK        (UINT64_C(1) << 6)
#define EDR_EVIDENCE_NETWORK_AUX    (UINT64_C(1) << 7)
#define EDR_EVIDENCE_REGISTRY       (UINT64_C(1) << 8)
#define EDR_EVIDENCE_SCRIPT         (UINT64_C(1) << 9)
#define EDR_EVIDENCE_TOKEN          (UINT64_C(1) << 10)
#define EDR_EVIDENCE_USER           (UINT64_C(1) << 11)
#define EDR_EVIDENCE_OPERATION      (UINT64_C(1) << 12)
#define EDR_EVIDENCE_REGISTRY_DATA  (UINT64_C(1) << 13)
#define EDR_EVIDENCE_ALL            ((UINT64_C(1) << 14) - 1u)
#endif
