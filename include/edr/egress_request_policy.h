#ifndef EDR_EGRESS_REQUEST_POLICY_H
#define EDR_EGRESS_REQUEST_POLICY_H

#include <stddef.h>
#include <stdint.h>

/* A local policy rejection is never a server acknowledgement. */
#define EDR_EGRESS_REQUEST_DENIED (-3)
#define EDR_EGRESS_AUTHORIZATION_EXPIRED (-4)
#define EDR_EGRESS_LOCAL_STATE_FAILURE (-5)
#define EDR_EGRESS_OUTCOME_UNKNOWN (-6)
#define EDR_EGRESS_PAYLOAD_POLICY_HELD (-7)
#define EDR_EGRESS_POLICY_HOLD_SCHEMA 1
/* A scoped preflight never authorizes a payload. Final validators remain mandatory. */
typedef enum EdrEgressPurpose {
  EDR_EGRESS_ARTIFACT = 1,
  EDR_EGRESS_ATTACK_SURFACE = 2,
  EDR_EGRESS_UPGRADE_EVENT = 3,
  EDR_EGRESS_UPGRADE_LOG = 4
} EdrEgressPurpose;
typedef struct EdrEgressTaskScope {
  char tenant_id[128], endpoint_id[128], command_id[128], task_id[129];
  char artifact_id[129], artifact_sha256[65], target_version[65];
  char operation[16], upgrade_class[32];
} EdrEgressTaskScope;
/* Owner must resolve the signed, durable external agent_update inbox and its
 * current authority. 0 permits inspection; DENIED/EXPIRED hold; local failure retries. */
typedef int (*EdrEgressTaskScopeLookup)(const char *command_id, EdrEgressTaskScope *out);
void edr_egress_set_task_scope_lookup(EdrEgressTaskScopeLookup lookup);
int edr_egress_task_preflight(EdrEgressPurpose purpose, const char *command_id,
                              EdrEgressTaskScope *out);
int edr_egress_is_policy_hold(int result);
/* The upgrade owner compares path/hash/size against its durable journal. */
typedef int (*EdrEgressUpgradeLogValidator)(const EdrEgressTaskScope *scope,
    const char *upload_id, const char *path, const char *sha256, uint64_t *size);
void edr_egress_set_upgrade_log_validator(EdrEgressUpgradeLogValidator validator);
int edr_egress_upload_preflight(const char *command_id, const char *upload_id,
    const char *path, const char *sha256, uint64_t *expected_size);
/* Strict minimal event projection; source journal/event bytes remain unchanged. */
const char *edr_egress_upgrade_failure_value(const char *field,const char *candidate);
char *edr_egress_upgrade_event_project(const char *body, int *result);
#define EDR_EGRESS_HEALTH_MAX_BYTES (32768u)
#define EDR_EGRESS_BATCH_WIRE_MAX_BYTES (8u * 1024u * 1024u)
#define EDR_EGRESS_COMMAND_RESULT_MAX_BYTES (128u * 1024u)

/* Shared strict object boundary: complete input, no duplicate keys or decoded
 * NUL strings. The caller owns the returned cJSON object. */
struct cJSON;
struct cJSON *edr_egress_parse_purpose_object(const void *body, size_t len);
#define EDR_EGRESS_POLICY_VERSION "minimal-egress-v4"

/* Registered by command state before transport starts. Missing owner denies
 * results; registering a callback never authorizes a route or arbitrary body.
 * Callback returns 1 for exact allowed bytes, 0 for denial, -4 for expiry and
 * -5 for a local ownership read failure. */
typedef int (*EdrEgressCommandResultValidator)(const char *tenant_id,
    const char *endpoint_id, const void *body, size_t len);
void edr_egress_set_command_result_validator(EdrEgressCommandResultValidator validator);

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
