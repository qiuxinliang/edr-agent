#ifndef EDR_EGRESS_BATCH_POLICY_H
#define EDR_EGRESS_BATCH_POLICY_H
#include <stddef.h>
#include <stdint.h>
struct _edr_v1_BehaviorEvent;

#define EDR_EGRESS_POLICY_VERSION "minimal-egress-v1"
#define EDR_EGRESS_PROJECTOR_VERSION "alert-fields-v1"
#define EDR_EGRESS_BATCH_MAX (4u * 1024u * 1024u)
#define EDR_EGRESS_FRAME_MAX (256u * 1024u)
#define EDR_EGRESS_FRAME_COUNT_MAX 4096u

/* Validate alerts and their proven necessary context as immutable bytes,
 * including every compressed/replayed frame.
 * 1 = eligible; 0 = retain locally for review. This never means server ACK. */
int edr_egress_batch_validate(const uint8_t *header, size_t header_len,
    const uint8_t *payload, size_t payload_len, char *reason, size_t reason_cap);
int edr_egress_frame_validate(const uint8_t *frame, size_t frame_len,
    char *reason, size_t reason_cap);
int edr_egress_batch_validate_scope(const uint8_t *header, size_t header_len,
    const uint8_t *payload, size_t payload_len,
    const char *tenant_id, const char *endpoint_id,
    char *reason, size_t reason_cap);

/* Pure producer-side minimization of the temporary serialization message.
 * Ordinary/source-only records retain their complete local representation.
 * This does not authorize sending or confirm a PMFE association. */
int edr_egress_event_project(struct _edr_v1_BehaviorEvent *event,
    char *reason, size_t reason_cap);

/* Explicit maintenance only: decode the whole historical batch, verify every
 * frame's tenant/endpoint, and select proven alerts/their original required
 * paired intents into a fresh BAT1 body.
 * Already eligible frames are copied byte-for-byte; understood legacy alerts
 * use the same owner projector and a fresh encoding. The caller retains the
 * ORIGINAL full payload/hash and records EDR_EGRESS_PROJECTOR_VERSION lineage.
 * 1 = understood (including zero selected frames);
 * 0 = unsupported/corrupt/foreign scope, with no output. The caller owns the
 * output and must assign a NEW batch identity. Neither result means ACK. */
int edr_egress_batch_project_alerts(const uint8_t *header, size_t header_len,
    const uint8_t *payload, size_t payload_len,
    const char *tenant_id, const char *endpoint_id,
    uint8_t **out_full_wire, size_t *out_len, uint32_t *allowed_frames,
    char *reason, size_t reason_cap);

/* Registered by the existing durable evidence-cache owner before transport
 * starts. Atomic unregistration is safe while readers finish: production uses
 * NULL user and the cache callback independently checks its locked lifetime.
 * A non-NULL user must outlive all callers; replacing different owners/users
 * requires caller quiescence. The validator must check a durable
 * original alert, exact process generation and SHA of these final bytes.
 * Missing/unavailable ownership denies nonpositive follow-ups. */
typedef int (*EdrEgressPmfeAssociationValidator)(const char *source_alert_id,
    const char *endpoint_id, const char *tenant_id, const char *event_id,
    uint32_t pid, uint64_t process_start_key,
    uint64_t process_creation_filetime_100ns, int64_t event_time_ns,
    const char *status, const char *verdict,
    const uint8_t *frame, size_t frame_len, void *user);
void edr_egress_set_pmfe_association_validator(
    EdrEgressPmfeAssociationValidator validator, void *user);
/* Receipt handler: -1 = durable storage/integrity failure, 0 = no matching
 * result owner, 1 = exact matching result durably acknowledged. Called only
 * after the real server receipt has been validated, before queue deletion. */
typedef EdrEgressPmfeAssociationValidator EdrEgressPmfeReceiptHandler;
void edr_egress_set_pmfe_receipt_handler(EdrEgressPmfeReceiptHandler handler, void *user);
int edr_egress_batch_note_receipt(const uint8_t *header, size_t header_len,
    const uint8_t *payload, size_t payload_len, char *reason, size_t reason_cap);
void edr_egress_set_pmfe_queue_removed_handler(EdrEgressPmfeReceiptHandler handler, void *user);
int edr_egress_batch_note_queue_removed(const uint8_t *header, size_t header_len,
    const uint8_t *payload, size_t payload_len, char *reason, size_t reason_cap);

/* Required P0 alert context: the current receiver needs the immutable intent
 * paired with a proven combined alert. This tuple alone never authorizes it.
 * The queue's durable journal owner verifies exact ORIGINAL intent/combined
 * bytes/SHA and the same scoped tuple on both journal frames.
 * Callbacks must avoid acquiring a queue mutex already held by the caller.
 * Registry/user lifetime rules are the same as the PMFE registry above. */
typedef struct EdrEgressP0PairAssociation {
  const char *terminal_key, *endpoint_id, *tenant_id;
  const char *rule_id, *rules_bundle_version, *rules_bundle_sha256;
  const char *source_event_id, *canonical_image_path, *file_identity;
  uint32_t pid;
  uint64_t process_start_key, process_creation_filetime_100ns;
} EdrEgressP0PairAssociation;
typedef int (*EdrEgressP0PairValidator)(const EdrEgressP0PairAssociation *intent,
    const uint8_t *frame, size_t frame_len, void *user);
void edr_egress_set_p0_pair_validator(EdrEgressP0PairValidator validator, void *user);
/* Pure journal consumers: an original single BAT1 frame must pass intrinsic
 * schema/provenance and match every association field. They deliberately do
 * not invoke the journal callback. Neither function authorizes HTTP or ACK. */
int edr_egress_p0_combined_matches(const EdrEgressP0PairAssociation *intent,
    const uint8_t *combined_full_wire, size_t wire_len);
int edr_egress_p0_intent_matches(const EdrEgressP0PairAssociation *intent,
    const uint8_t *intent_full_wire, size_t wire_len);
/* Maintenance classification only: 1 = a decoded paired result/alert exists,
 * 0 = fully decoded with none, -1 = unsupported/corrupt/indeterminate. This
 * never establishes the presence of its required intent or receiver alert. */
int edr_egress_batch_has_p0_combined(const uint8_t *full_wire, size_t wire_len);
#endif
