/*
 * P0 直出：与 edr-backend/platform/config/p0_golden_vectors.json + dynamicrules 对拍（CI：
 * validate_p0_golden_vectors.py、go test TestP0RuleGolden_FromManifest）。改 C 端匹配时务必同步
 * 向量与 Go 测试，并跑 edr-backend/scripts/verify_p0_bundle_version_alignment.sh。
 */
#include "edr/p0_rule_direct_emit.h"
#include "edr/p0_rule_match.h"
#include "edr/p0_rule_ir.h"
#include "edr/policy_enforcement.h"
#include "edr/policy_v2.h"
#include "edr/p0_source_only_contract.h"
#include "edr/windows_file_identity.h"

#include "edr/adaptive_collection.h"
#include "edr/ave_sdk.h"
#include "edr/behavior_alert_emit.h"
#include "edr/behavior_record.h"
#include "edr/resource.h"
#include "edr/sha256.h"
#include "edr/storage_queue.h"
#include "edr/types.h"
#include "edr/enrich_parent_info.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
static SRWLOCK s_p0_state_lock = SRWLOCK_INIT;
static void p0_state_lock(void) { AcquireSRWLockExclusive(&s_p0_state_lock); }
static void p0_state_unlock(void) { ReleaseSRWLockExclusive(&s_p0_state_lock); }
#else
#include <pthread.h>
#include <time.h>
static pthread_mutex_t s_p0_state_lock = PTHREAD_MUTEX_INITIALIZER;
static void p0_state_lock(void) { pthread_mutex_lock(&s_p0_state_lock); }
static void p0_state_unlock(void) { pthread_mutex_unlock(&s_p0_state_lock); }
#endif

/* Only an exact source-event replay is deduplicated.  PID, timestamp, and
 * rule alone are never an identity: different actions can legitimately
 * collide on all three.  EDR_P0_DEDUP_SEC=0 retains its test/compatibility
 * meaning of disabling the in-memory replay guard. */
#define P0_DEDUP_SLOTS 64u
#define P0_SOURCE_ONLY_RETRY_SLOTS 8u
#define P0_SOURCE_ONLY_COMMITTED_SLOTS 64u
#define P0_SOURCE_ONLY_RETRY_MS 250u
struct p0_dedup_slot {
  /* Gate IDs are trust-boundary identities too.  Do not truncate a long
   * source-only gate before exact-replay comparison. */
  char rule_id[64];
  char endpoint_id[EDR_BR_ID_LEN];
  uint32_t pid;
  int64_t  event_time_ns;
  uint64_t last_ms;
  uint32_t suppressed_count;
  uint8_t pending;
  uint64_t generation;
  uint64_t process_generation_key;
  char source_event_id[EDR_BR_ID_LEN];
  char source_semantic_sha256[65];
};
static struct p0_dedup_slot s_p0_dedup[P0_DEDUP_SLOTS];
static uint32_t s_p0_dedup_next;
static uint64_t s_p0_dedup_generation;
static uint64_t s_p0_dedup_suppressed_total;
static uint64_t s_p0_dedup_exact_suppressed;
static uint64_t s_p0_dedup_pending_backpressure;
static uint64_t s_p0_emit_user_subject_full, s_p0_emit_user_subject_degraded;
static uint64_t s_p0_emit_alerts_with_optional_omission, s_p0_emit_values_truncated, s_p0_emit_escape_overflow_values;
static uint64_t s_p0_emit_minimal_failures, s_p0_emit_emitted_without_full_context;
static uint64_t s_p0_emit_critical_reservations;
static uint64_t s_p0_emit_governor_suppressed;
static uint64_t s_p0_emit_source_only_backpressure_emitted;
static uint64_t s_p0_emit_source_only_backpressure_failed;
typedef struct p0_source_only_retry_slot {
  EdrBehaviorRecord record;
  EdrStorageQueueP0SourceOnlyLatch latch;
  char source_event_id[EDR_BR_ID_LEN];
  char source_semantic_sha256[65];
  uint64_t generation;
  uint64_t next_retry_ms;
  uint8_t pending;
  uint8_t latch_valid;
  uint8_t recovery_audit;
} p0_source_only_retry_slot;
typedef struct p0_source_only_committed_slot {
  char source_event_id[EDR_BR_ID_LEN];
  char source_semantic_sha256[65];
  uint8_t valid;
} p0_source_only_committed_slot;
static p0_source_only_retry_slot s_p0_source_only_retry[P0_SOURCE_ONLY_RETRY_SLOTS];
static p0_source_only_committed_slot
    s_p0_source_only_committed[P0_SOURCE_ONLY_COMMITTED_SLOTS];
static uint32_t s_p0_source_only_retry_next;
static uint32_t s_p0_source_only_committed_next;
static uint64_t s_p0_source_only_retry_generation;
static uint64_t s_p0_source_only_retry_attempts;
static uint64_t s_p0_source_only_retry_committed;
static uint64_t s_p0_source_only_retry_capacity_exhausted;
/* A process start is deliberately unhealthy until main explicitly proves the
 * existing SQLite queue can make two FULL header commits. This avoids a crash
 * turning a previously unrecorded P0 source-only gate into an action window. */
static int s_p0_source_only_terminal_unhealthy = 1;
static int s_p0_source_only_unrecoverable;
static int s_p0_source_only_latch_sync_required;
static int s_p0_source_only_persistent_latch_active;
static int s_p0_source_only_recovery_verified;
static int s_p0_source_only_loss_detected;
static int s_p0_source_only_loss_audit_durable;
/* A restart cannot reconstruct which event families an existing durable
 * latch covered, so startup begins globally fused. During one process
 * lifetime, known source-only faults only pause their owning family. */
static uint32_t s_p0_source_only_unhealthy_families = UINT32_MAX;
static uint64_t s_p0_source_only_latch_counter;
static uint64_t s_p0_source_only_latch_epoch;
static char s_p0_source_only_queue_nonce[33];
static char s_p0_source_only_runtime_tenant[64];
static char s_p0_source_only_runtime_endpoint[EDR_BR_ID_LEN];
static char s_p0_source_only_terminal_reason[96] = "source_only_restart_recovery_required";
#ifdef EDR_P0_DIRECT_EMIT_TESTING
static void p0_reset_rate_state_locked(void);
#endif
static int p0_build_source_only_delivery_record(
    const EdrStorageQueueP0SourceOnlyLatch *latch, EdrBehaviorRecord *out);
static int p0_source_only_record_is_delivery_loss(const EdrBehaviorRecord *record);
#ifdef EDR_P0_DIRECT_EMIT_TESTING
static uint64_t s_p0_test_monotonic_ms;
void edr_p0_rule_test_reset_dedup(void) {
  p0_state_lock();
  memset(s_p0_dedup, 0, sizeof(s_p0_dedup));
  memset(s_p0_source_only_retry, 0, sizeof(s_p0_source_only_retry));
  memset(s_p0_source_only_committed, 0, sizeof(s_p0_source_only_committed));
  s_p0_dedup_next = 0u;
  s_p0_dedup_generation = 0u;
  s_p0_dedup_suppressed_total = s_p0_dedup_exact_suppressed =
      s_p0_dedup_pending_backpressure = 0u;
  s_p0_source_only_retry_next = 0u;
  s_p0_source_only_committed_next = 0u;
  s_p0_source_only_retry_generation = 0u;
  s_p0_source_only_retry_attempts = 0u;
  s_p0_source_only_retry_committed = 0u;
  s_p0_source_only_retry_capacity_exhausted = 0u;
  s_p0_source_only_terminal_unhealthy = 0;
  s_p0_source_only_unrecoverable = 0;
  s_p0_source_only_latch_sync_required = 0;
  s_p0_source_only_persistent_latch_active = 0;
  s_p0_source_only_recovery_verified = 1;
  s_p0_source_only_loss_detected = 0;
  s_p0_source_only_loss_audit_durable = 0;
  s_p0_source_only_unhealthy_families = 0u;
  s_p0_source_only_latch_counter = 0u;
  s_p0_source_only_latch_epoch = 0u;
  s_p0_source_only_queue_nonce[0] = '\0';
  s_p0_source_only_runtime_tenant[0] = '\0';
  s_p0_source_only_runtime_endpoint[0] = '\0';
  s_p0_source_only_terminal_reason[0] = '\0';
  p0_reset_rate_state_locked();
  s_p0_emit_user_subject_full = s_p0_emit_user_subject_degraded =
      s_p0_emit_alerts_with_optional_omission = s_p0_emit_values_truncated =
      s_p0_emit_escape_overflow_values = s_p0_emit_minimal_failures =
      s_p0_emit_emitted_without_full_context = s_p0_emit_critical_reservations =
      s_p0_emit_governor_suppressed = s_p0_emit_source_only_backpressure_emitted =
          s_p0_emit_source_only_backpressure_failed = 0u;
  p0_state_unlock();
}
void edr_p0_rule_test_force_source_only_startup(void) {
  p0_state_lock();
  memset(s_p0_source_only_retry, 0, sizeof(s_p0_source_only_retry));
  s_p0_source_only_terminal_unhealthy = 1;
  s_p0_source_only_unrecoverable = 0;
  s_p0_source_only_latch_sync_required = 0;
  s_p0_source_only_persistent_latch_active = 0;
  s_p0_source_only_recovery_verified = 0;
  s_p0_source_only_loss_detected = 0;
  s_p0_source_only_loss_audit_durable = 0;
  s_p0_source_only_unhealthy_families = UINT32_MAX;
  s_p0_source_only_latch_counter = 0u;
  s_p0_source_only_latch_epoch = 0u;
  s_p0_source_only_queue_nonce[0] = '\0';
  snprintf(s_p0_source_only_terminal_reason,
           sizeof(s_p0_source_only_terminal_reason), "%s",
           "source_only_restart_recovery_required");
  p0_state_unlock();
}
void edr_p0_rule_test_set_monotonic_ms(uint64_t value) { p0_state_lock(); s_p0_test_monotonic_ms=value; p0_state_unlock(); }
#endif

void edr_p0_rule_get_dedup_metrics(EdrP0DedupMetrics *out) {
  if (!out) return;
  p0_state_lock();
  out->suppressed_total = s_p0_dedup_suppressed_total;
  out->exact_suppressed = s_p0_dedup_exact_suppressed;
  out->equal_quality_suppressed = 0u;
  out->identity_upgrade_seen = 0u;
  out->lower_quality_suppressed = 0u;
  out->intermediate_upgrade_suppressed = 0u;
  /* The former (timestamp,pid,type) pre-rule gate was intentionally removed:
   * distinct source events may share those fields and must reach the exact
   * source-event dedup below.  Retain the wire metric as a zero legacy field. */
  out->pre_rule_event_duplicates = 0u;
  out->pending_backpressure = s_p0_dedup_pending_backpressure;
  p0_state_unlock();
}

void edr_p0_rule_get_emit_metrics(EdrP0EmitMetrics *out) {
  if (!out) return;
  p0_state_lock();
  out->user_subject_full=s_p0_emit_user_subject_full; out->user_subject_degraded=s_p0_emit_user_subject_degraded;
  out->alerts_with_optional_omission=s_p0_emit_alerts_with_optional_omission; out->values_truncated=s_p0_emit_values_truncated; out->escape_overflow_values=s_p0_emit_escape_overflow_values;
  out->minimal_failures=s_p0_emit_minimal_failures; out->emitted_without_full_context=s_p0_emit_emitted_without_full_context;
  out->critical_reservations=s_p0_emit_critical_reservations;
  out->governor_suppressed=s_p0_emit_governor_suppressed;
  out->source_only_backpressure_emitted=s_p0_emit_source_only_backpressure_emitted;
  out->source_only_backpressure_failed=s_p0_emit_source_only_backpressure_failed;
  out->source_only_retry_pending = 0u;
  for (uint32_t i = 0u; i < P0_SOURCE_ONLY_RETRY_SLOTS; ++i) {
    if (s_p0_source_only_retry[i].pending) out->source_only_retry_pending++;
  }
  out->source_only_retry_attempts = s_p0_source_only_retry_attempts;
  out->source_only_retry_committed = s_p0_source_only_retry_committed;
  out->source_only_retry_capacity_exhausted = s_p0_source_only_retry_capacity_exhausted;
  out->source_only_terminal_unhealthy = s_p0_source_only_terminal_unhealthy;
  out->source_only_unhealthy_families = s_p0_source_only_unhealthy_families;
  out->source_only_loss_detected = s_p0_source_only_loss_detected;
  out->source_only_latch_counter = s_p0_source_only_latch_counter;
  out->source_only_latch_epoch = s_p0_source_only_latch_epoch;
  snprintf(out->source_only_queue_nonce, sizeof(out->source_only_queue_nonce), "%s",
           s_p0_source_only_queue_nonce);
  snprintf(out->source_only_terminal_reason, sizeof(out->source_only_terminal_reason), "%s",
           s_p0_source_only_terminal_reason);
  p0_state_unlock();
}

void edr_p0_rule_source_only_set_runtime_identity(const char *tenant_id,
                                                   const char *endpoint_id) {
  p0_state_lock();
  snprintf(s_p0_source_only_runtime_tenant, sizeof(s_p0_source_only_runtime_tenant), "%s",
           tenant_id ? tenant_id : "");
  snprintf(s_p0_source_only_runtime_endpoint, sizeof(s_p0_source_only_runtime_endpoint), "%s",
           endpoint_id ? endpoint_id : "");
  p0_state_unlock();
}

/* Process PID is reusable.  Keep the record's creation generation and the
 * canonical image identity in every dedup key; incomplete legacy records
 * retain key 0 only for their own compatibility path. */
static uint64_t p0_generation_key(const EdrBehaviorRecord *br) {
  const char *path;
  const unsigned char *p;
  uint64_t hash = 1469598103934665603ULL;
  if (!br || !br->process_creation_filetime_100ns) return 0u;
  path = br->image_path_canonical[0] ? br->image_path_canonical : br->exe_path;
  for (unsigned shift = 0u; shift < 64u; shift += 8u) {
    hash = (hash ^ (unsigned char)(br->process_creation_filetime_100ns >> shift)) * 1099511628211ULL;
  }
  hash = (hash ^ (unsigned char)'|') * 1099511628211ULL;
  for (p = (const unsigned char *)path; *p; ++p) {
    unsigned char c = *p;
    if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
    hash = (hash ^ c) * 1099511628211ULL;
  }
  return hash;
}

static void p0_dedup_digest_text(EdrSha256Ctx *ctx, const char *value) {
  uint32_t length = value ? (uint32_t)strlen(value) : 0u;
  uint8_t length_le[4];
  length_le[0] = (uint8_t)(length & 0xffu);
  length_le[1] = (uint8_t)((length >> 8u) & 0xffu);
  length_le[2] = (uint8_t)((length >> 16u) & 0xffu);
  length_le[3] = (uint8_t)((length >> 24u) & 0xffu);
  edr_sha256_update(ctx, length_le, sizeof(length_le));
  if (length) edr_sha256_update(ctx, (const uint8_t *)value, length);
}

static void p0_dedup_digest_u64(EdrSha256Ctx *ctx, uint64_t value) {
  uint8_t bytes[8];
  for (size_t i = 0u; i < sizeof(bytes); ++i) {
    bytes[i] = (uint8_t)(value >> (i * 8u));
  }
  edr_sha256_update(ctx, bytes, sizeof(bytes));
}

static void p0_source_event_id(const EdrBehaviorRecord *br, char *out, size_t out_cap) {
  if (!out || out_cap == 0u) return;
  if (br && br->event_id[0]) {
    snprintf(out, out_cap, "%s", br->event_id);
    return;
  }
  snprintf(out, out_cap, "synthetic:%u:%d:%lld", br ? br->pid : 0u,
           br ? (int)br->type : 0, br ? (long long)br->event_time_ns : 0LL);
}

/* Exact replay identity includes the declared source event ID and a
 * collision-resistant commitment over every serialized/matcher-relevant
 * source field.  Never use a PID/timestamp tuple as an admission gate: two
 * distinct actions can share both values under load.  There is deliberately
 * no broad "enrichment is mutable" exclusion here: a changed user,
 * generation, parent/chain, registry value, port, path, or evidence context
 * is a different security assertion and must not be silently suppressed. */
static int p0_source_semantic_sha256(const EdrBehaviorRecord *br, char *out, size_t out_cap) {
  EdrSha256Ctx ctx;
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  static const char hex[] = "0123456789abcdef";
  if (!br || !out || out_cap < 65u) return 0;
  edr_sha256_init(&ctx);
  p0_dedup_digest_text(&ctx, "edr-p0-source-semantic-v2");
#define P0_DIGEST_TEXT(field) p0_dedup_digest_text(&ctx, br->field)
#define P0_DIGEST_U64(field) p0_dedup_digest_u64(&ctx, (uint64_t)br->field)
  P0_DIGEST_TEXT(event_id); P0_DIGEST_TEXT(endpoint_id); P0_DIGEST_TEXT(tenant_id);
  P0_DIGEST_U64(event_time_ns); P0_DIGEST_U64(pid); P0_DIGEST_U64(ppid);
  P0_DIGEST_TEXT(process_name); P0_DIGEST_TEXT(cmdline); P0_DIGEST_TEXT(exe_hash);
  P0_DIGEST_TEXT(exe_path); P0_DIGEST_TEXT(image_path_raw); P0_DIGEST_TEXT(image_path_canonical);
  P0_DIGEST_TEXT(image_path_namespace); P0_DIGEST_TEXT(image_path_resolution_status);
  P0_DIGEST_TEXT(image_path_resolution_source); P0_DIGEST_TEXT(source_completeness);
  P0_DIGEST_TEXT(source_truncated_fields);
  P0_DIGEST_U64(evidence_revision); P0_DIGEST_TEXT(username); P0_DIGEST_TEXT(user_sid);
  P0_DIGEST_TEXT(logon_id); P0_DIGEST_TEXT(creator_username); P0_DIGEST_TEXT(creator_domain);
  P0_DIGEST_TEXT(creator_sid); P0_DIGEST_TEXT(creator_logon_id); P0_DIGEST_TEXT(identity_source);
  P0_DIGEST_TEXT(identity_quality); P0_DIGEST_U64(session_id); P0_DIGEST_U64(process_chain_depth);
  P0_DIGEST_U64(type); P0_DIGEST_U64(is_security_4688); P0_DIGEST_U64(priority);
  P0_DIGEST_TEXT(parent_name); P0_DIGEST_TEXT(parent_path); P0_DIGEST_TEXT(parent_resolution_status);
  P0_DIGEST_TEXT(parent_resolution_source); P0_DIGEST_TEXT(file_op); P0_DIGEST_U64(file_target_has_motw);
  P0_DIGEST_TEXT(file_path); P0_DIGEST_U64(file_key);
  P0_DIGEST_TEXT(collector_evidence_gate); P0_DIGEST_TEXT(collector_evidence_reason);
  P0_DIGEST_TEXT(net_src); P0_DIGEST_TEXT(net_dst);
  P0_DIGEST_U64(net_sport); P0_DIGEST_U64(net_dport); P0_DIGEST_TEXT(net_proto);
  P0_DIGEST_TEXT(network_aux_path); P0_DIGEST_TEXT(dns_query); P0_DIGEST_TEXT(reg_key_path);
  P0_DIGEST_TEXT(reg_value_name); P0_DIGEST_TEXT(reg_value_data); P0_DIGEST_TEXT(reg_old_value_data);
  P0_DIGEST_TEXT(reg_op); P0_DIGEST_TEXT(reg_source); P0_DIGEST_TEXT(reg_attribution);
  P0_DIGEST_TEXT(reg_detail_status); P0_DIGEST_TEXT(script_snippet); P0_DIGEST_TEXT(pmfe_snapshot);
  P0_DIGEST_TEXT(detection_context); P0_DIGEST_U64(cert_revoked_ancestor);
  P0_DIGEST_TEXT(hostname); P0_DIGEST_TEXT(domain); P0_DIGEST_TEXT(desktop_session);
  P0_DIGEST_U64(desktop_session_id); P0_DIGEST_TEXT(current_directory); P0_DIGEST_TEXT(logon_guid);
  P0_DIGEST_U64(logon_time_ns); P0_DIGEST_TEXT(integrity_level); P0_DIGEST_U64(token_elevation);
  P0_DIGEST_TEXT(process_path_hash); P0_DIGEST_TEXT(parent_cmdline); P0_DIGEST_U64(grandparent_pid);
  P0_DIGEST_TEXT(grandparent_name); P0_DIGEST_TEXT(grandparent_path); P0_DIGEST_TEXT(sibling_names);
  P0_DIGEST_TEXT(child_pids); P0_DIGEST_TEXT(network_isolation_level);
  P0_DIGEST_TEXT(process_creation_time); P0_DIGEST_U64(process_start_key);
  P0_DIGEST_U64(process_creation_filetime_100ns); P0_DIGEST_TEXT(process_generation_source);
  P0_DIGEST_TEXT(parent_creation_time); P0_DIGEST_TEXT(command_line_origin);
  P0_DIGEST_TEXT(encoded_command_type); P0_DIGEST_TEXT(powershell_script_block);
  P0_DIGEST_TEXT(wmi_filter); P0_DIGEST_TEXT(scheduled_task_path);
  P0_DIGEST_U64(mitre_ttp_count);
  for (size_t i = 0u; i < EDR_BR_MAX_MITRE; ++i) {
    p0_dedup_digest_text(&ctx, br->mitre_ttps[i]);
  }
#undef P0_DIGEST_TEXT
#undef P0_DIGEST_U64
  edr_sha256_final(&ctx, digest);
  for (size_t i = 0u; i < sizeof(digest); ++i) {
    out[i * 2u] = hex[digest[i] >> 4u];
    out[i * 2u + 1u] = hex[digest[i] & 0x0fu];
  }
  out[64] = '\0';
  return 1;
}

/* Defined with the terminal JSON helpers below. */
static int p0_context_file_identity(const char *context, char *out, size_t out_cap);

static void p0_terminal_commit_text(EdrSha256Ctx *ctx, const char *text) {
  uint32_t length = 0u;
  uint8_t length_le[sizeof(length)];
  const uint8_t separator = 0u;
  if (text) length = (uint32_t)strlen(text);
  /* The terminal key crosses the Agent/backend boundary.  Commit lengths in
   * explicit little-endian order rather than the host representation. */
  length_le[0] = (uint8_t)(length & 0xffu);
  length_le[1] = (uint8_t)((length >> 8u) & 0xffu);
  length_le[2] = (uint8_t)((length >> 16u) & 0xffu);
  length_le[3] = (uint8_t)((length >> 24u) & 0xffu);
  edr_sha256_update(ctx, length_le, sizeof(length_le));
  if (length) edr_sha256_update(ctx, (const uint8_t *)text, length);
  edr_sha256_update(ctx, &separator, sizeof(separator));
}

static int p0_terminal_identity(const EdrBehaviorRecord *br, const char *rule_id,
                                char *idempotency_key, size_t idempotency_key_cap,
                                char *source_event_key, size_t source_event_key_cap,
                                char *process_generation_key, size_t process_generation_key_cap) {
  char file_identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  char pid_text[16];
  char start_key_text[32];
  char creation_text[32];
  char digest_hex[65];
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  EdrSha256Ctx ctx;
  const char *canonical_path;
  if (!br || !rule_id || !rule_id[0] || !idempotency_key || !source_event_key ||
      !process_generation_key || idempotency_key_cap < 80u || source_event_key_cap < EDR_BR_ID_LEN ||
      process_generation_key_cap < sizeof("startkey-") + 16u) {
    return 0;
  }
  canonical_path = br->image_path_canonical[0] ? br->image_path_canonical : br->exe_path;
  if (!br->event_id[0] || !br->pid || !br->process_start_key ||
      !br->process_creation_filetime_100ns || !canonical_path[0] ||
      !p0_context_file_identity(br->detection_context, file_identity, sizeof(file_identity))) {
    return 0;
  }
  snprintf(pid_text, sizeof(pid_text), "%u", br->pid);
  snprintf(start_key_text, sizeof(start_key_text), "%016llx",
           (unsigned long long)br->process_start_key);
  snprintf(creation_text, sizeof(creation_text), "%016llx",
           (unsigned long long)br->process_creation_filetime_100ns);
  /* This key is a collision-resistant commitment over every pre-action
   * process authority field.  FNV is retained only for non-security dedup
   * buckets; it is never an enforcement/journal identity. */
  edr_sha256_init(&ctx);
  p0_terminal_commit_text(&ctx, "edr-p0-enforcement-terminal-v1");
  p0_terminal_commit_text(&ctx, br->tenant_id);
  p0_terminal_commit_text(&ctx, br->endpoint_id);
  p0_terminal_commit_text(&ctx, rule_id);
  p0_terminal_commit_text(&ctx, br->event_id);
  p0_terminal_commit_text(&ctx, pid_text);
  p0_terminal_commit_text(&ctx, start_key_text);
  p0_terminal_commit_text(&ctx, creation_text);
  p0_terminal_commit_text(&ctx, canonical_path);
  p0_terminal_commit_text(&ctx, file_identity);
  edr_sha256_final(&ctx, digest);
  for (size_t i = 0u; i < sizeof(digest); ++i) {
    static const char hex[] = "0123456789abcdef";
    digest_hex[i * 2u] = hex[digest[i] >> 4u];
    digest_hex[i * 2u + 1u] = hex[digest[i] & 0x0fu];
  }
  digest_hex[64] = '\0';
  snprintf(source_event_key, source_event_key_cap, "%s", br->event_id);
  /* `start_key_text` is exactly 16 hexadecimal bytes, so form this terminal
   * authority field without a bounded formatter that could silently shorten
   * it.  The capacity guard above includes the trailing NUL. */
  memcpy(process_generation_key, "startkey-", sizeof("startkey-") - 1u);
  memcpy(process_generation_key + sizeof("startkey-") - 1u, start_key_text,
         sizeof(start_key_text));
  snprintf(idempotency_key, idempotency_key_cap, "p0-enforcement-%s", digest_hex);
  return 1;
}

/* 全进程滑动 60s 内 BehaviorAlert 直出条数上限（B2.3）；未设置或 0=不限制 */
static uint64_t s_p0_gwin_start_ms;
static uint32_t s_p0_gcount;
/* Every rolled global window and every reusable tenant/endpoint slot gets a
 * fresh generation.  A delayed failure may only return the exact token it
 * reserved; it must never decrement a newer window or a reused slot. */
static uint64_t s_p0_gwin_epoch;
static uint64_t s_p0_rate_generation;

/* 每 tenant_id 独立滑动 60s 内直出条数（B2.3）；与全局上限叠加；未设置时默认 60/分；0=不限制 */
#define P0_TENANT_RATE_SLOTS 32u
struct p0_tenant_rate_slot {
  char tenant[64];
  uint64_t win_start_ms;
  uint64_t generation;
  uint32_t count;
};
static struct p0_tenant_rate_slot s_tenant_rate[P0_TENANT_RATE_SLOTS];
static uint32_t s_tenant_rate_next;

/* 每 endpoint_id 独立滑动 60s 内直出条数；未设置时默认 0=不限制（B2.3 可选，与全局限流/tenant 叠加） */
#define P0_EP_RATE_SLOTS 64u
struct p0_ep_rate_slot {
  char ep[EDR_BR_ID_LEN];
  uint64_t win_start_ms;
  uint64_t generation;
  uint32_t count;
};
static struct p0_ep_rate_slot s_ep_rate[P0_EP_RATE_SLOTS];
static uint32_t s_ep_rate_next;

static uint64_t p0_next_rate_generation_locked(void) {
  s_p0_rate_generation++;
  if (s_p0_rate_generation == 0u) s_p0_rate_generation++;
  return s_p0_rate_generation;
}

#ifdef EDR_P0_DIRECT_EMIT_TESTING
static void p0_reset_rate_state_locked(void) {
  s_p0_gwin_start_ms = 0u;
  s_p0_gcount = 0u;
  /* Invalidate a reservation that was still held while a test/runtime reset
   * happened.  Slot generations are assigned again when their owner/window
   * is next established. */
  s_p0_gwin_epoch = p0_next_rate_generation_locked();
  memset(s_tenant_rate, 0, sizeof(s_tenant_rate));
  s_tenant_rate_next = 0u;
  memset(s_ep_rate, 0, sizeof(s_ep_rate));
  s_ep_rate_next = 0u;
}
#endif

static int p0_debug_enabled(void) {
  static int cached = -1;
  if (cached < 0) {
    cached = (getenv("EDR_P0_DEBUG") != NULL) ? 1 : 0;
  }
  return cached;
}

static int p0_debug_all_enabled(void) {
  static int cached = -1;
  if (cached < 0) {
    const char *e = getenv("EDR_P0_DEBUG_ALL");
    cached = (e && e[0] && strcmp(e, "0") != 0) ? 1 : 0;
  }
  return cached;
}

static void p0_debug_event(const char *prefix, const EdrBehaviorRecord *br,
                           const char *pn, const char *detail) {
  if (!br) {
    return;
  }
  fprintf(stderr, "[P0 DEBUG] %s: type=%d pid=%u process=%s %s=%s\n",
          prefix ? prefix : "event", br->type, br->pid, pn ? pn : "",
          br->cmdline[0] ? "cmdline" : "detail", detail ? detail : "");
}

static int p0_should_log_dedup(uint32_t suppressed_count) {
  if (!p0_debug_enabled()) {
    return 0;
  }
  return (suppressed_count == 1u || suppressed_count == 2u || suppressed_count == 4u ||
          suppressed_count == 8u || suppressed_count == 16u || (suppressed_count % 64u) == 0u)
             ? 1
             : 0;
}

static int p0_contains_ci(const char *hay, const char *needle) {
  if (!needle || !needle[0]) {
    return 1;
  }
  if (!hay || !hay[0]) {
    return 0;
  }
  size_t nn = strlen(needle);
  for (const char *p = hay; *p; p++) {
    size_t i = 0u;
    while (i < nn && p[i]) {
      char a = p[i];
      char b = needle[i];
      if (a == '\\') {
        a = '/';
      }
      if (b == '\\') {
        b = '/';
      }
      if (a >= 'A' && a <= 'Z') {
        a = (char)(a - 'A' + 'a');
      }
      if (b >= 'A' && b <= 'Z') {
        b = (char)(b - 'A' + 'a');
      }
      if (a != b) {
        break;
      }
      i++;
    }
    if (i == nn) {
      return 1;
    }
  }
  return 0;
}

static int p0_equals_ci(const char *a, const char *b) {
  if (!a || !b) {
    return 0;
  }
  while (*a && *b) {
    char ca = *a++;
    char cb = *b++;
    if (ca == '\\') ca = '/';
    if (cb == '\\') cb = '/';
    if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
    if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
    if (ca != cb) {
      return 0;
    }
  }
  return *a == '\0' && *b == '\0';
}

static int p0_path_ends_with_ci(const char *value, const char *suffix) {
  size_t nv;
  size_t ns;
  if (!value || !suffix) {
    return 0;
  }
  nv = strlen(value);
  ns = strlen(suffix);
  return nv >= ns && p0_equals_ci(value + nv - ns, suffix);
}

static int p0_is_sha256_hex(const char *value) {
  if (!value || strlen(value) != 64u) {
    return 0;
  }
  for (size_t i = 0u; i < 64u; i++) {
    char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
      return 0;
    }
  }
  return 1;
}

/* 仅用于维护基线匹配：统一大小写、路径分隔符、引号和连续空白，
 * 避免同一签名命令因转义/空格差异形成重复基线。 */
static int p0_has_trusted_signature_evidence(const EdrBehaviorRecord *br, const char *signer_fragment) {
  int trusted;
  int signer_ok;
  if (!br || !signer_fragment || !signer_fragment[0]) {
    return 0;
  }
  /* Trust decisions must come from the background Authenticode result bound
   * to this image identity.  Script text is untrusted input, never evidence. */
  trusted = p0_contains_ci(br->detection_context, "\"signature\":{\"status\":\"verified\"") ||
            p0_contains_ci(br->detection_context, "\"signature_trust\":{\"status\":\"verified\"");
  signer_ok = p0_contains_ci(br->detection_context, "\"signer\":") &&
              p0_contains_ci(br->detection_context, signer_fragment);
  return trusted && signer_ok;
}

static int p0_has_maintenance_hard_blocker(const EdrBehaviorRecord *br, const char *normalized_cmd) {
  static const char *blocked[] = {
      "-enc ", "-encodedcommand", "frombase64string", "downloadstring", "invoke-expression",
      "iex ", "invoke-webrequest", "invoke-restmethod", "http://", "https://", "ftp://",
      "mimikatz", "sekurlsa", "lsass", "vssadmin", "delete shadows", "set-mppreference",
      "add-mppreference", "regsvr32", "rundll32", "mshta", "certutil -urlcache"};
  if (!br) {
    return 1;
  }
  for (size_t i = 0u; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
    if (p0_contains_ci(normalized_cmd, blocked[i]) || p0_contains_ci(br->script_snippet, blocked[i]) ||
        p0_contains_ci(br->detection_context, blocked[i])) {
      return 1;
    }
  }
  if (br->net_dst[0] || br->dns_query[0] || br->cert_revoked_ancestor) {
    return 1;
  }
  return 0;
}

static int p0_is_agent_internal_command(const EdrBehaviorRecord *br) {
  const char *cmd = br ? br->cmdline : NULL;
  if (!br) {
    return 0;
  }
  if ((cmd && cmd[0] && (p0_contains_ci(cmd, "\\edr_forensic\\") ||
                         p0_contains_ci(cmd, "/edr_forensic/") ||
                         p0_contains_ci(cmd, "cmd_forensic_") ||
                         p0_contains_ci(cmd, "auto-forensic-"))) ||
      p0_contains_ci(br->file_path, "\\edr_forensic\\") ||
      p0_contains_ci(br->file_path, "/edr_forensic/") ||
      p0_contains_ci(br->file_path, "cmd_forensic_") ||
      p0_contains_ci(br->file_path, "auto-forensic-") ||
      p0_contains_ci(br->script_snippet, "forensic_bundle") ||
      p0_contains_ci(br->detection_context, "\"edr_internal\":true") ||
      p0_contains_ci(br->detection_context, "\"source\":\"agent_internal\"")) {
    return 1;
  }
  if (!cmd || !cmd[0]) {
    return 0;
  }
  if (p0_contains_ci(cmd, "/api/v1/agent/sensor-interest.json") ||
      p0_contains_ci(cmd, "/agent/sensor-interest.json") ||
      p0_contains_ci(cmd, "edr_sensor_interest_") ||
      p0_contains_ci(cmd, "/api/v1/agent/rules.toml") ||
      p0_contains_ci(cmd, "/agent/rules.toml") ||
      p0_contains_ci(cmd, "/api/v1/agent/p0-bundle.enc") ||
      p0_contains_ci(cmd, "/agent/p0-bundle.enc") ||
      p0_contains_ci(cmd, "/api/v1/agent/version/latest") ||
      p0_contains_ci(cmd, "/agent/version/latest") ||
      p0_contains_ci(cmd, "/api/v1/agent/download/latest") ||
      p0_contains_ci(cmd, "/agent/download/latest") ||
      p0_contains_ci(cmd, "edr_remote_")) {
    return 1;
  }
  return 0;
}

static int p0_parent_is_windows_service_host(const EdrBehaviorRecord *br) {
  const char *parent = br ? br->parent_name : NULL;
  const char *path = br ? br->parent_path : NULL;
  if ((parent && (p0_contains_ci(parent, "svchost.exe") ||
                  p0_contains_ci(parent, "services.exe") ||
                  p0_contains_ci(parent, "ngentask.exe") ||
                  p0_contains_ci(parent, "ngen.exe"))) ||
      (path && (p0_contains_ci(path, "\\windows\\system32\\svchost.exe") ||
                p0_contains_ci(path, "\\windows\\system32\\services.exe")))) {
    return 1;
  }
  return 0;
}

static int p0_is_sdbinst_maintenance_baseline(const EdrBehaviorRecord *br) {
  const char *cmd = br ? br->cmdline : NULL;
  const char *pn = br ? br->process_name : NULL;
  const char *path = br ? br->exe_path : NULL;
  if (!br || br->type != EDR_EVENT_PROCESS_CREATE || !cmd || !cmd[0]) {
    return 0;
  }
  if (!((pn && p0_contains_ci(pn, "sdbinst.exe")) ||
        (path && p0_contains_ci(path, "\\windows\\system32\\sdbinst.exe")) ||
        p0_contains_ci(cmd, "sdbinst.exe"))) {
    return 0;
  }
  if (!(p0_contains_ci(cmd, " -m") && p0_contains_ci(cmd, " -bg"))) {
    return 0;
  }
  if (!p0_parent_is_windows_service_host(br)) {
    return 0;
  }
  if (path && path[0] && !p0_contains_ci(path, "\\windows\\system32\\sdbinst.exe")) {
    return 0;
  }
  return 1;
}

static int p0_is_known_smoke_command(const EdrBehaviorRecord *br, const char *detail) {
  const char *cmd = (detail && detail[0]) ? detail : (br ? br->cmdline : NULL);
  if (!cmd || !cmd[0]) {
    return 0;
  }
  if (p0_contains_ci(cmd, "edr_platform_stack_smoke") ||
      p0_contains_ci(cmd, "r-exec-001-smoke") ||
      p0_contains_ci(cmd, "ZWRyLXNtb2tl") ||
      p0_contains_ci(cmd, "Write-Output ok") ||
      p0_contains_ci(cmd, "Invoke-WebRequest 'https://example.com'") ||
      p0_contains_ci(cmd, "Invoke-WebRequest \"https://example.com\"") ||
      p0_contains_ci(cmd, "Invoke-RestMethod 'https://httpbin.org/get'") ||
      p0_contains_ci(cmd, "Invoke-RestMethod \"https://httpbin.org/get\"") ||
      p0_contains_ci(cmd, "IEX ('Write-Output ok')") ||
      p0_contains_ci(cmd, "IEX (\"Write-Output ok\")")) {
    return 1;
  }
  return 0;
}

static int p0_is_edge_update_temp_baseline(const EdrBehaviorRecord *br, const char *detail) {
  const char *cmd = (detail && detail[0]) ? detail : (br ? br->cmdline : NULL);
  char normalized[EDR_BR_STR_LONG];
  if (!br || br->type != EDR_EVENT_PROCESS_CREATE || !cmd || !cmd[0]) {
    return 0;
  }
  edr_p0_normalize_command_for_evidence(cmd, normalized, sizeof(normalized));
  if (!p0_equals_ci(br->process_name, "MicrosoftEdgeUpdate.exe") ||
      !p0_path_ends_with_ci(br->exe_path, "\\MicrosoftEdgeUpdate.exe") ||
      !p0_contains_ci(br->exe_path, "\\Program Files (x86)\\Microsoft\\Temp\\EU")) {
    return 0;
  }
  if (!p0_contains_ci(br->parent_name, "MicrosoftEdgeUpdateSetup_") ||
      !p0_path_ends_with_ci(br->parent_name, ".exe") ||
      !p0_contains_ci(br->parent_path, "\\Microsoft\\EdgeUpdate\\Install\\")) {
    return 0;
  }
  if (!p0_contains_ci(normalized, " /update ") ||
      !p0_contains_ci(normalized, " /sessionid ") ||
      p0_has_maintenance_hard_blocker(br, normalized)) {
    return 0;
  }
  /* 临时目录中的更新器只有在 Authenticode 信任链、Microsoft 发布者和
   * 当前映像 SHA-256 同时存在时才降噪；缺任一项均保留告警。 */
  return p0_has_trusted_signature_evidence(br, "Microsoft") && p0_is_sha256_hex(br->exe_hash);
}

static int p0_is_sangfor_checknetisolation_baseline(const EdrBehaviorRecord *br, const char *detail) {
  const char *cmd = (detail && detail[0]) ? detail : (br ? br->cmdline : NULL);
  if (!br) {
    return 0;
  }
  if (!(p0_contains_ci(br->parent_name, "ECAgent.exe") ||
        p0_contains_ci(br->parent_path, "\\Sangfor\\SSL\\") ||
        p0_contains_ci(br->grandparent_name, "ECAgent.exe") ||
        p0_contains_ci(br->detection_context, "ECAgent.exe") ||
        p0_contains_ci(br->detection_context, "\\Sangfor\\SSL\\"))) {
    return 0;
  }
  if ((p0_contains_ci(br->process_name, "CheckNetIsolation.exe") ||
       p0_contains_ci(br->exe_path, "\\CheckNetIsolation.exe") ||
       p0_contains_ci(cmd, "CheckNetIsolation.exe")) &&
      p0_contains_ci(cmd, "LoopbackExempt")) {
    return 1;
  }
  if ((p0_contains_ci(br->process_name, "conhost.exe") ||
       p0_contains_ci(br->exe_path, "\\conhost.exe") ||
       p0_contains_ci(cmd, "conhost.exe")) &&
      (p0_contains_ci(br->parent_name, "CheckNetIsolation.exe") ||
       p0_contains_ci(br->parent_path, "\\CheckNetIsolation.exe") ||
       p0_contains_ci(br->detection_context, "CheckNetIsolation.exe"))) {
    return 1;
  }
  return 0;
}

static int p0_record_contains_ci(const EdrBehaviorRecord *br, const char *detail, const char *needle) {
  if (!br || !needle || !needle[0]) {
    return 0;
  }
  return p0_contains_ci(detail, needle) ||
         p0_contains_ci(br->cmdline, needle) ||
         p0_contains_ci(br->exe_path, needle) ||
         p0_contains_ci(br->file_path, needle) ||
         p0_contains_ci(br->parent_path, needle) ||
         p0_contains_ci(br->script_snippet, needle) ||
         p0_contains_ci(br->detection_context, needle) ||
         p0_contains_ci(br->current_directory, needle) ||
         p0_contains_ci(br->scheduled_task_path, needle) ||
         p0_contains_ci(br->network_aux_path, needle) ||
         p0_contains_ci(br->dns_query, needle) ||
         p0_contains_ci(br->net_dst, needle) ||
         p0_contains_ci(br->process_name, needle) ||
         p0_contains_ci(br->parent_name, needle) ||
         p0_contains_ci(br->grandparent_name, needle);
}

static int p0_record_has_fdsecurity_root(const EdrBehaviorRecord *br, const char *detail) {
  return p0_record_contains_ci(br, detail, "\\Program Files\\FDSecurity\\") ||
         p0_record_contains_ci(br, detail, "/Program Files/FDSecurity/") ||
         p0_record_contains_ci(br, detail, "\\ProgramData\\FDSecurity\\") ||
         p0_record_contains_ci(br, detail, "/ProgramData/FDSecurity/");
}

static int p0_is_fdsecurity_self_installer_baseline(const EdrBehaviorRecord *br, const char *detail) {
  if (!br || !p0_record_has_fdsecurity_root(br, detail)) {
    return 0;
  }
  if (p0_record_contains_ci(br, detail, "FDSensorTaskLaunch.ps1")) {
    return 1;
  }
  if ((p0_record_contains_ci(br, detail, "setup-ui\\install-diagnostics.zip") ||
       p0_record_contains_ci(br, detail, "setup-ui/install-diagnostics.zip")) &&
      p0_record_contains_ci(br, detail, "install-diagnostics.zip")) {
    return 1;
  }
  return 0;
}

static int p0_is_local_fixed_disk_desktop_ini_baseline(const EdrBehaviorRecord *br, const char *detail) {
  if (!br || !p0_record_contains_ci(br, detail, "desktop.ini")) {
    return 0;
  }
  if (!(p0_record_contains_ci(br, detail, "\\Device\\HarddiskVolume") ||
        p0_record_contains_ci(br, detail, "C:\\") ||
        p0_record_contains_ci(br, detail, "C:/"))) {
    return 0;
  }
  return p0_record_contains_ci(br, detail, "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\desktop.ini") ||
         p0_record_contains_ci(br, detail, "\\Windows\\System32\\Tasks\\") ||
         p0_record_contains_ci(br, detail, "\\WindowsApps\\") ||
         p0_record_contains_ci(br, detail, "\\D3DSCache\\") ||
         p0_record_contains_ci(br, detail, "\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\") ||
         p0_record_contains_ci(br, detail, "\\desktop.ini");
}

static char p0_fold_path_ci_char(char c) {
  if (c == '\\') {
    c = '/';
  }
  if (c >= 'A' && c <= 'Z') {
    c = (char)(c - 'A' + 'a');
  }
  return c;
}

static int p0_loopback_host_delim(char c) {
  return c == '\0' || c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
         c == ':' || c == '/' || c == '\\' || c == '@' || c == '"' || c == '\'';
}

static int p0_has_ci_token_with_loopback_delim(const char *s, const char *token) {
  size_t nt;
  if (!s || !s[0] || !token || !token[0]) {
    return 0;
  }
  nt = strlen(token);
  for (const char *p = s; *p; p++) {
    size_t i = 0u;
    while (i < nt && p[i]) {
      if (p0_fold_path_ci_char(p[i]) != p0_fold_path_ci_char(token[i])) {
        break;
      }
      i++;
    }
    if (i == nt && p0_loopback_host_delim(p[i])) {
      return 1;
    }
  }
  return 0;
}

static int p0_text_has_loopback_target(const char *s) {
  if (!s || !s[0]) {
    return 0;
  }
  return p0_has_ci_token_with_loopback_delim(s, "http://localhost") ||
         p0_has_ci_token_with_loopback_delim(s, "https://localhost") ||
         p0_has_ci_token_with_loopback_delim(s, "//localhost") ||
         p0_has_ci_token_with_loopback_delim(s, "\\\\localhost") ||
         p0_has_ci_token_with_loopback_delim(s, " localhost") ||
         p0_has_ci_token_with_loopback_delim(s, "http://127.0.0.1") ||
         p0_has_ci_token_with_loopback_delim(s, "https://127.0.0.1") ||
         p0_has_ci_token_with_loopback_delim(s, "//127.0.0.1") ||
         p0_has_ci_token_with_loopback_delim(s, "\\\\127.0.0.1") ||
         p0_has_ci_token_with_loopback_delim(s, " 127.0.0.1");
}

static int p0_is_rundll32_davclnt_loopback_baseline(const EdrBehaviorRecord *br, const char *detail) {
  const char *cmd = (detail && detail[0]) ? detail : (br ? br->cmdline : NULL);
  if (!br) {
    return 0;
  }
  if (!(p0_contains_ci(br->process_name, "rundll32.exe") ||
        p0_contains_ci(br->exe_path, "\\rundll32.exe") ||
        p0_contains_ci(cmd, "rundll32.exe"))) {
    return 0;
  }
  if (!p0_contains_ci(cmd, "davclnt.dll") || !p0_contains_ci(cmd, "DavSetCookie")) {
    return 0;
  }
  return p0_text_has_loopback_target(cmd) || p0_text_has_loopback_target(br->dns_query) ||
         p0_text_has_loopback_target(br->net_dst) || p0_text_has_loopback_target(br->network_aux_path) ||
         p0_text_has_loopback_target(br->script_snippet);
}

static int p0_searchprotocolhost_path_is_system32(const EdrBehaviorRecord *br, const char *detail) {
  const char *cmd = (detail && detail[0]) ? detail : (br ? br->cmdline : NULL);
  if (!br) {
    return 0;
  }
  if (br->exe_path[0]) {
    return p0_contains_ci(br->exe_path, "\\Windows\\System32\\SearchProtocolHost.exe");
  }
  return p0_contains_ci(cmd, "\\Windows\\System32\\SearchProtocolHost.exe") ||
         p0_contains_ci(cmd, "/Windows/System32/SearchProtocolHost.exe");
}

static int p0_is_searchprotocolhost_indexing_baseline(const EdrBehaviorRecord *br, const char *detail) {
  const char *cmd = (detail && detail[0]) ? detail : (br ? br->cmdline : NULL);
  if (!br) {
    return 0;
  }
  if (!(p0_contains_ci(br->process_name, "SearchProtocolHost.exe") ||
        p0_contains_ci(br->exe_path, "\\SearchProtocolHost.exe") ||
        (cmd && p0_contains_ci(cmd, "SearchProtocolHost.exe")))) {
    return 0;
  }
  /* 必须是 System32 真实路径——伪装到其它目录的同名进程不在此豁免。 */
  if (!p0_searchprotocolhost_path_is_system32(br, detail)) {
    return 0;
  }
  if (cmd && cmd[0]) {
    /* 有命令行：要求正常索引管线 token；其它命令行形态保留检测能力（不豁免）。 */
    return p0_contains_ci(cmd, "Global\\UsGthrFltPipe");
  }
  /* 无命令行（告警缺字段，behavior_70 常见）：System32 标准路径 + 进程名即按正常索引降级。
   * 伪装路径已被上面的 System32 检查排除，真实 System32\SearchProtocolHost 无命令行即索引宿主。 */
  return p0_contains_ci(br->exe_path, "\\Windows\\System32\\SearchProtocolHost.exe");
}

static int p0_should_suppress_known_false_positive(const char *rule_id, const EdrBehaviorRecord *br,
                                                   const char *detail, const char **out_reason) {
  if (out_reason) {
    *out_reason = "";
  }
  if (!rule_id || !br) {
    return 0;
  }
  if (strcmp(rule_id, "R-MITRE-WIN-T1138") == 0 && p0_is_sdbinst_maintenance_baseline(br)) {
    if (out_reason) {
      *out_reason = "sdbinst_maintenance_baseline";
    }
    return 1;
  }
  if (strcmp(rule_id, "R-LOLBIN-010") == 0 && p0_is_edge_update_temp_baseline(br, detail)) {
    if (out_reason) {
      *out_reason = "microsoft_edge_update_temp_baseline";
    }
    return 1;
  }
  if (strcmp(rule_id, "R-LOLBIN-010") == 0 && p0_is_sangfor_checknetisolation_baseline(br, detail)) {
    if (out_reason) {
      *out_reason = "sangfor_checknetisolation_baseline";
    }
    return 1;
  }
  if (p0_is_fdsecurity_self_installer_baseline(br, detail)) {
    if (out_reason) {
      *out_reason = "fdsecurity_self_installer_baseline";
    }
    return 1;
  }
  if (strcmp(rule_id, "R-MITRE-WIN-T1091") == 0 &&
      p0_is_local_fixed_disk_desktop_ini_baseline(br, detail)) {
    if (out_reason) {
      *out_reason = "local_fixed_disk_desktop_ini";
    }
    return 1;
  }
  if (p0_is_rundll32_davclnt_loopback_baseline(br, detail)) {
    if (out_reason) {
      *out_reason = "rundll32_davclnt_loopback_baseline";
    }
    return 1;
  }
  if (p0_is_searchprotocolhost_indexing_baseline(br, detail)) {
    if (out_reason) {
      *out_reason = "searchprotocolhost_indexing_baseline";
    }
    return 1;
  }
  if (p0_is_known_smoke_command(br, detail)) {
    if (out_reason) {
      *out_reason = "known_smoke_test";
    }
    return 1;
  }
  return 0;
}

#ifdef EDR_P0_DIRECT_EMIT_TESTING
int edr_p0_test_should_suppress_known_false_positive(const char *rule_id,
                                                     const EdrBehaviorRecord *br,
                                                     const char *detail,
                                                     const char **out_reason) {
  return p0_should_suppress_known_false_positive(rule_id, br, detail, out_reason);
}
#endif

static int p0_ends_with_ci(const char *s, const char *suffix) {
  size_t ns;
  size_t nx;
  if (!s || !suffix) {
    return 0;
  }
  ns = strlen(s);
  nx = strlen(suffix);
  if (ns < nx) {
    return 0;
  }
  s += ns - nx;
  for (size_t i = 0; i < nx; i++) {
    char a = s[i];
    char b = suffix[i];
    if (a >= 'A' && a <= 'Z') {
      a = (char)(a - 'A' + 'a');
    }
    if (b >= 'A' && b <= 'Z') {
      b = (char)(b - 'A' + 'a');
    }
    if (a != b) {
      return 0;
    }
  }
  return 1;
}

static int p0_valid_process_create_record(const EdrBehaviorRecord *br) {
  const char *name;
  int complete_rule_match = 0;
  if (!br) {
    return 1;
  }
  /* Missing source fields are never benign matcher inputs.  The Windows
   * preprocess lane turns a process create into a registered source-only
   * disposition; this guard keeps direct callers from alerting or acting on
   * a record that has already withheld rule-relevant evidence. */
  if (strcmp(br->source_completeness, "TRUNCATED") == 0 ||
      br->source_truncated_fields[0] != '\0') {
    return 0;
  }
  if (br->type == EDR_EVENT_FILE_READ) {
#ifdef _WIN32
    /* Kernel-File Read is P0-eligible only after both the FileKey path and
     * actor generation have survived exact StartKey/creation binding from a
     * live handle or event-time historical generation. A missing extended
     * item or an unbound stale PID is source-only, never a direct alert/action
     * authority. */
    if (!br->file_path[0] || !br->process_start_key ||
        !br->process_creation_filetime_100ns || !br->process_name[0] ||
        !br->exe_path[0] ||
        strcmp(br->image_path_resolution_status, "RESOLVED") != 0 ||
        (strcmp(br->process_generation_source, "etw_start_key_live_telemetry") != 0 &&
         strcmp(br->process_generation_source,
                "file_read_pid_event_time_live_telemetry") != 0 &&
         strcmp(br->process_generation_source,
                "file_read_process_tree_cache_generation") != 0) ||
        strcmp(br->source_completeness, "NOT_EVALUABLE") == 0) {
      return 0;
    }
#endif
    return 1;
  }
  if (br->type != EDR_EVENT_PROCESS_CREATE) {
    return 1;
  }
  /* Security 4688 augments a kernel process generation; it must not create a
   * second P0 alert as an independent lifecycle event. */
  if (br->is_security_4688) {
    return 0;
  }
  /* A raw NT device path cannot establish that an image is outside a system
   * directory, so it is not eligible for path-sensitive P0 evaluation. */
  if (strcmp(br->image_path_resolution_status, "NOT_EVALUABLE") == 0) {
    return 0;
  }
#ifdef _WIN32
  /* The authenticated IR is the authority for predicate completeness.  A
   * short-lived process may exit before optional user/parent/cmd enrichment
   * completes; if the active rule already matched without those fields, keep
   * the detection and declare the missing evidence instead of suppressing it.
   * This never authorizes enforcement, whose generation/file-identity gates
   * are checked separately below the matcher. */
  complete_rule_match = edr_p0_rule_ir_is_ready() &&
                        edr_p0_rule_ir_br_matches_any(br);
  /* P0 path rules require a coalesced Windows process generation.  The
   * preprocess pipeline emits a durable source-only disposition when these
   * fields are unavailable; this guard also protects direct callers. */
  if (!complete_rule_match &&
      ((br->image_path_raw[0] && strcmp(br->image_path_resolution_status, "RESOLVED") != 0) ||
       !br->process_name[0] || !br->exe_path[0] || !br->cmdline[0] || br->ppid == 0u ||
       !br->parent_path[0] || !br->parent_creation_time[0] ||
       (!br->username[0] && !br->user_sid[0]))) {
    return 0;
  }
#else
  (void)complete_rule_match;
#endif
  if (br->pid == 0u) {
    return 0;
  }
  if (!br->process_name[0] && !br->exe_path[0] && !br->cmdline[0]) {
    return 0;
  }
  name = br->process_name[0] ? br->process_name : br->exe_path;
  if (p0_ends_with_ci(name, ".dll") || p0_ends_with_ci(name, ".sys")) {
    return 0;
  }
  return 1;
}

static uint64_t p0_monotonic_ms(void) {
#ifdef EDR_P0_DIRECT_EMIT_TESTING
  if (s_p0_test_monotonic_ms) return s_p0_test_monotonic_ms;
#endif
#if defined(_WIN32)
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
#endif
}

enum {
  P0_SOURCE_ONLY_DURABLE_COMMITTED = 1,
  P0_SOURCE_ONLY_DURABLE_PENDING = 2,
  P0_SOURCE_ONLY_DURABLE_UNHEALTHY = 0
};

static int p0_source_only_retry_has_pending_locked(void) {
  for (uint32_t i = 0u; i < P0_SOURCE_ONLY_RETRY_SLOTS; ++i) {
    if (s_p0_source_only_retry[i].pending) return 1;
  }
  return 0;
}

enum {
  P0_SOURCE_ONLY_FAMILY_PROCESS = 1u << 0,
  P0_SOURCE_ONLY_FAMILY_FILE = 1u << 1,
  P0_SOURCE_ONLY_FAMILY_NETWORK = 1u << 2,
  P0_SOURCE_ONLY_FAMILY_REGISTRY = 1u << 3,
  P0_SOURCE_ONLY_FAMILY_ALL = UINT32_MAX
};

static uint32_t p0_source_only_family_for_event(EdrEventType type) {
  switch (type) {
  case EDR_EVENT_PROCESS_CREATE:
  case EDR_EVENT_PROCESS_TERMINATE:
  case EDR_EVENT_PROCESS_INJECT:
  case EDR_EVENT_DLL_LOAD:
  case EDR_EVENT_THREAD_CREATE_REMOTE:
  case EDR_EVENT_SCRIPT_POWERSHELL:
  case EDR_EVENT_SCRIPT_BASH:
  case EDR_EVENT_SCRIPT_PYTHON:
  case EDR_EVENT_SCRIPT_WMI:
    return P0_SOURCE_ONLY_FAMILY_PROCESS;
  case EDR_EVENT_FILE_READ:
  case EDR_EVENT_FILE_CREATE:
  case EDR_EVENT_FILE_WRITE:
  case EDR_EVENT_FILE_DELETE:
  case EDR_EVENT_FILE_RENAME:
  case EDR_EVENT_FILE_PERMISSION_CHANGE:
    return P0_SOURCE_ONLY_FAMILY_FILE;
  case EDR_EVENT_NET_CONNECT:
  case EDR_EVENT_NET_LISTEN:
  case EDR_EVENT_NET_DNS_QUERY:
  case EDR_EVENT_NET_TLS_HANDSHAKE:
    return P0_SOURCE_ONLY_FAMILY_NETWORK;
  case EDR_EVENT_REG_CREATE_KEY:
  case EDR_EVENT_REG_SET_VALUE:
  case EDR_EVENT_REG_DELETE_KEY:
    return P0_SOURCE_ONLY_FAMILY_REGISTRY;
  default:
    return P0_SOURCE_ONLY_FAMILY_ALL;
  }
}

static void p0_source_only_nonce_hex(const uint8_t nonce[16], char out[33]) {
  static const char hex[] = "0123456789abcdef";
  size_t i;
  if (!out) return;
  if (!nonce) {
    out[0] = '\0';
    return;
  }
  for (i = 0u; i < 16u; ++i) {
    out[i * 2u] = hex[nonce[i] >> 4u];
    out[i * 2u + 1u] = hex[nonce[i] & 0x0fu];
  }
  out[32] = '\0';
}

static void p0_source_only_set_latch_locked(const EdrStorageQueueP0SourceOnlyLatch *latch) {
  if (!latch) return;
  s_p0_source_only_persistent_latch_active = latch->latched ? 1 : 0;
  s_p0_source_only_latch_counter = latch->latch_counter;
  s_p0_source_only_latch_epoch = latch->latch_epoch;
  p0_source_only_nonce_hex(latch->queue_nonce, s_p0_source_only_queue_nonce);
}

static void p0_source_only_mark_unhealthy_locked(const char *reason, int unrecoverable) {
  s_p0_source_only_terminal_unhealthy = 1;
  s_p0_source_only_recovery_verified = 0;
  if (unrecoverable) {
    s_p0_source_only_unrecoverable = 1;
    s_p0_source_only_loss_detected = 1;
    s_p0_source_only_loss_audit_durable = 0;
    /* No exact event remains to retry.  Persist a prepared queue_meta latch
     * before the next recovery audit is even constructed. */
    s_p0_source_only_latch_sync_required = 1;
  }
  if (reason && reason[0]) {
    snprintf(s_p0_source_only_terminal_reason,
             sizeof(s_p0_source_only_terminal_reason), "%s", reason);
  } else if (!s_p0_source_only_terminal_reason[0]) {
    snprintf(s_p0_source_only_terminal_reason,
             sizeof(s_p0_source_only_terminal_reason), "%s",
             "source_only_durable_unavailable");
  }
}

static void p0_source_only_mark_unhealthy_for_event_locked(
    const char *reason, int unrecoverable, EdrEventType type) {
  uint32_t family = p0_source_only_family_for_event(type);
  if (s_p0_source_only_unhealthy_families != P0_SOURCE_ONLY_FAMILY_ALL) {
    s_p0_source_only_unhealthy_families |= family;
  }
  p0_source_only_mark_unhealthy_locked(reason, unrecoverable);
}

/* IR/bootstrap unavailability is not itself a lost source assertion.  Keep
 * the capability fused without manufacturing a persistent latch; a later
 * recovery will use an already-existing latch, if any, as the loss boundary. */
static void p0_source_only_wait_for_recovery_locked(const char *reason) {
  s_p0_source_only_terminal_unhealthy = 1;
  s_p0_source_only_recovery_verified = 0;
  /* Queue/IR/latch recovery is shared infrastructure. Unlike a record-bound
   * failure, its unavailable authority cannot be attributed to one family. */
  s_p0_source_only_unhealthy_families = P0_SOURCE_ONLY_FAMILY_ALL;
  if (reason && reason[0]) {
    snprintf(s_p0_source_only_terminal_reason,
             sizeof(s_p0_source_only_terminal_reason), "%s", reason);
  }
}

/* `queue_meta` is cleared only by the central 2xx ACK transaction.  A local
 * event_queue INSERT proves durability, never delivery, so this routine may
 * clear the fuse only after an observed unlatched meta row and an explicit
 * FULL probe. */
static void p0_source_only_note_ack_observed_locked(void) {
  if (s_p0_source_only_recovery_verified && !s_p0_source_only_latch_sync_required &&
      !s_p0_source_only_persistent_latch_active &&
      !s_p0_source_only_unrecoverable && !p0_source_only_retry_has_pending_locked()) {
    s_p0_source_only_terminal_unhealthy = 0;
    s_p0_source_only_unhealthy_families = 0u;
    s_p0_source_only_terminal_reason[0] = '\0';
  }
}

static void p0_source_only_note_delivery_loss_durable_locked(
    const EdrBehaviorRecord *record) {
  if (!p0_source_only_record_is_delivery_loss(record)) return;
  s_p0_source_only_loss_detected = 1;
  s_p0_source_only_loss_audit_durable = 1;
}

/* Do not take the P0 state lock while executing SQLite.  This has no private
 * persistence: it only prepares the one queue_meta latch used by the normal
 * event_queue severity-2 insert path. */
static void p0_source_only_sync_persistent_latch(void) {
  int required;
  EdrStorageQueueP0SourceOnlyLatch latch;
  p0_state_lock();
  required = s_p0_source_only_latch_sync_required;
  p0_state_unlock();
  if (!required) return;
  if (edr_storage_queue_p0_source_only_latch_prepare(&latch) != EDR_OK || !latch.latched) {
    return;
  }
  p0_state_lock();
  s_p0_source_only_latch_sync_required = 0;
  p0_source_only_set_latch_locked(&latch);
  p0_state_unlock();
}

static int p0_source_only_exact_pending_locked(const char *event_id,
                                                const char *semantic_sha256) {
  for (uint32_t i = 0u; i < P0_SOURCE_ONLY_RETRY_SLOTS; ++i) {
    const p0_source_only_retry_slot *slot = &s_p0_source_only_retry[i];
    if (slot->pending && strcmp(slot->source_event_id, event_id) == 0 &&
        strcmp(slot->source_semantic_sha256, semantic_sha256) == 0) {
      return 1;
    }
  }
  return 0;
}

/* The queue itself remains durable replay authority.  This tiny completed
 * cache merely avoids repeatedly re-serializing the same already-committed
 * source assertion inside one process lifetime; a restart still reaches the
 * queue's exact batch-id check rather than trusting volatile memory. */
static int p0_source_only_exact_committed_locked(const char *event_id,
                                                  const char *semantic_sha256) {
  for (uint32_t i = 0u; i < P0_SOURCE_ONLY_COMMITTED_SLOTS; ++i) {
    const p0_source_only_committed_slot *slot = &s_p0_source_only_committed[i];
    if (slot->valid && strcmp(slot->source_event_id, event_id) == 0 &&
        strcmp(slot->source_semantic_sha256, semantic_sha256) == 0) {
      return 1;
    }
  }
  return 0;
}

static void p0_source_only_remember_committed_locked(const char *event_id,
                                                      const char *semantic_sha256) {
  p0_source_only_committed_slot *slot;
  if (!event_id || !event_id[0] || !semantic_sha256 || !semantic_sha256[0]) return;
  if (p0_source_only_exact_committed_locked(event_id, semantic_sha256)) return;
  slot = &s_p0_source_only_committed[
      s_p0_source_only_committed_next++ % P0_SOURCE_ONLY_COMMITTED_SLOTS];
  memset(slot, 0, sizeof(*slot));
  snprintf(slot->source_event_id, sizeof(slot->source_event_id), "%s", event_id);
  snprintf(slot->source_semantic_sha256, sizeof(slot->source_semantic_sha256), "%s",
           semantic_sha256);
  slot->valid = 1u;
}

/* This is intentionally a fixed, non-overwriting handoff, not another queue:
 * SQLite remains the only persistent source of truth.  The slot retains a
 * source record only until the existing queue has accepted its exact BAT1
 * wire.  `queue_meta` then remains latched until the central 2xx ACK deletes
 * that wire and clears the matching batch in the same FULL transaction. */
static int p0_source_only_prepare_record(const EdrBehaviorRecord *record,
                                         EdrBehaviorRecord *durable,
                                         char semantic_sha256[65]) {
  if (!record || !durable || !semantic_sha256 ||
      !edr_p0_source_only_validate_record(record)) return 0;
  *durable = *record;
  p0_source_event_id(record, durable->event_id, sizeof(durable->event_id));
  return durable->event_id[0] &&
         p0_source_semantic_sha256(durable, semantic_sha256, 65u);
}

static int p0_source_only_enqueue_record(const EdrBehaviorRecord *record,
                                         const EdrStorageQueueP0SourceOnlyLatch *latch,
                                         int recovery_audit) {
  uint8_t wire[65536u + 16u];
  char batch_id[EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_BATCH_ID_MAX];
  size_t wire_len;
  if (!record || !latch || !latch->latched) return 0;
  wire_len = edr_behavior_record_encode_durable_wire(record, wire, sizeof(wire));
  if (wire_len == 0u ||
      !edr_behavior_durable_wire_batch_id("p0-source", wire, wire_len,
                                          batch_id, sizeof(batch_id))) {
    return 0;
  }
  return edr_storage_queue_p0_source_only_enqueue_bound(
             latch, record->event_id, batch_id, wire, wire_len, 0, recovery_audit) == EDR_OK;
}

static int p0_source_only_latch_equal(const EdrStorageQueueP0SourceOnlyLatch *left,
                                      const EdrStorageQueueP0SourceOnlyLatch *right) {
  return left && right && left->latched && right->latched &&
         left->latch_counter == right->latch_counter &&
         left->latch_epoch == right->latch_epoch &&
         memcmp(left->queue_nonce, right->queue_nonce, sizeof(left->queue_nonce)) == 0;
}

static int p0_source_only_store_retry(const EdrBehaviorRecord *record,
                                      const char *semantic_sha256,
                                      const EdrStorageQueueP0SourceOnlyLatch *latch,
                                      int latch_valid, int recovery_audit) {
  uint64_t now = p0_monotonic_ms();
  uint32_t free_index = P0_SOURCE_ONLY_RETRY_SLOTS;
  p0_state_lock();
  if (p0_source_only_exact_pending_locked(record->event_id, semantic_sha256)) {
    p0_state_unlock();
    return P0_SOURCE_ONLY_DURABLE_PENDING;
  }
  for (uint32_t offset = 0u; offset < P0_SOURCE_ONLY_RETRY_SLOTS; ++offset) {
    uint32_t candidate = (s_p0_source_only_retry_next + offset) %
                         P0_SOURCE_ONLY_RETRY_SLOTS;
    if (!s_p0_source_only_retry[candidate].pending) {
      free_index = candidate;
      break;
    }
  }
  if (free_index == P0_SOURCE_ONLY_RETRY_SLOTS) {
    s_p0_source_only_retry_capacity_exhausted++;
    p0_source_only_mark_unhealthy_for_event_locked(
        "source_only_retry_capacity_exhausted", 1, record->type);
    p0_state_unlock();
    p0_source_only_sync_persistent_latch();
    return P0_SOURCE_ONLY_DURABLE_UNHEALTHY;
  }
  {
    p0_source_only_retry_slot *slot = &s_p0_source_only_retry[free_index];
    memset(slot, 0, sizeof(*slot));
    slot->record = *record;
    if (latch_valid && latch) slot->latch = *latch;
    slot->latch_valid = latch_valid ? 1u : 0u;
    slot->recovery_audit = recovery_audit ? 1u : 0u;
    snprintf(slot->source_event_id, sizeof(slot->source_event_id), "%s", record->event_id);
    snprintf(slot->source_semantic_sha256, sizeof(slot->source_semantic_sha256), "%s",
             semantic_sha256);
    slot->generation = ++s_p0_source_only_retry_generation;
    slot->next_retry_ms = now == 0u ? 0u : now + P0_SOURCE_ONLY_RETRY_MS;
    slot->pending = 1u;
    s_p0_source_only_retry_next = (free_index + 1u) % P0_SOURCE_ONLY_RETRY_SLOTS;
  }
  p0_source_only_mark_unhealthy_for_event_locked(
      "source_only_durable_unavailable", 0, record->type);
  p0_state_unlock();
  return P0_SOURCE_ONLY_DURABLE_PENDING;
}

static int p0_source_only_submit_record(const EdrBehaviorRecord *record, int recovery_audit) {
  EdrBehaviorRecord durable;
  EdrStorageQueueP0SourceOnlyLatch latch;
  char semantic_sha256[65];
  if (!p0_source_only_prepare_record(record, &durable, semantic_sha256)) {
    p0_state_lock();
    s_p0_emit_source_only_backpressure_failed++;
    p0_source_only_mark_unhealthy_for_event_locked(
        "source_only_identity_unavailable", 1, record ? record->type : 0);
    p0_state_unlock();
    p0_source_only_sync_persistent_latch();
    return P0_SOURCE_ONLY_DURABLE_UNHEALTHY;
  }

  p0_state_lock();
  if (p0_source_only_exact_committed_locked(durable.event_id, semantic_sha256)) {
    p0_state_unlock();
    return P0_SOURCE_ONLY_DURABLE_COMMITTED;
  }
  p0_state_unlock();

  memset(&latch, 0, sizeof(latch));
  if (edr_storage_queue_p0_source_only_latch_prepare(&latch) == EDR_OK && latch.latched) {
    p0_state_lock();
    p0_source_only_set_latch_locked(&latch);
    p0_state_unlock();
    if (p0_source_only_enqueue_record(&durable, &latch, recovery_audit)) {
      p0_state_lock();
      /* Local persistence proves only that this endpoint can replay the
       * source-only assertion.  It does not prove the backend received the
       * immutable disposition.  Keep the P0 capability fused until the
       * matching severity-2 row is centrally ACKed and queue_meta clears it
       * in that same FULL transaction. */
      p0_source_only_set_latch_locked(&latch);
      p0_source_only_mark_unhealthy_for_event_locked(
          "source_only_delivery_pending_ack", 0, durable.type);
      p0_source_only_remember_committed_locked(durable.event_id, semantic_sha256);
      p0_source_only_note_delivery_loss_durable_locked(&durable);
      s_p0_emit_source_only_backpressure_emitted++;
      p0_state_unlock();
      return P0_SOURCE_ONLY_DURABLE_COMMITTED;
    }
    p0_state_lock();
    s_p0_emit_source_only_backpressure_failed++;
    p0_source_only_mark_unhealthy_for_event_locked(
        "source_only_durable_unavailable", 0, durable.type);
    p0_state_unlock();
    return p0_source_only_store_retry(&durable, semantic_sha256, &latch, 1, recovery_audit);
  }

  p0_state_lock();
  s_p0_emit_source_only_backpressure_failed++;
  p0_source_only_mark_unhealthy_for_event_locked(
      "source_only_latch_prepare_failed", 0, durable.type);
  p0_state_unlock();
  return p0_source_only_store_retry(&durable, semantic_sha256, NULL, 0, recovery_audit);
}

static int p0_source_only_submit(const EdrBehaviorRecord *record) {
  return p0_source_only_submit_record(record, 0);
}

int edr_p0_rule_poll_source_only_durable_retry(EdrBehaviorRecord *committed_out) {
  EdrBehaviorRecord record;
  EdrStorageQueueP0SourceOnlyLatch latch;
  uint64_t generation = 0u;
  uint64_t now = p0_monotonic_ms();
  uint32_t selected = P0_SOURCE_ONLY_RETRY_SLOTS;
  int latch_valid = 0;
  int recovery_audit = 0;
  if (committed_out) memset(committed_out, 0, sizeof(*committed_out));

  p0_state_lock();
  for (uint32_t offset = 0u; offset < P0_SOURCE_ONLY_RETRY_SLOTS; ++offset) {
    uint32_t candidate = (s_p0_source_only_retry_next + offset) %
                         P0_SOURCE_ONLY_RETRY_SLOTS;
    p0_source_only_retry_slot *slot = &s_p0_source_only_retry[candidate];
    if (!slot->pending || (slot->next_retry_ms != 0u && now != 0u &&
                           now < slot->next_retry_ms)) {
      continue;
    }
    record = slot->record;
    latch = slot->latch;
    latch_valid = slot->latch_valid ? 1 : 0;
    recovery_audit = slot->recovery_audit ? 1 : 0;
    generation = slot->generation;
    slot->next_retry_ms = now == 0u ? 0u : now + P0_SOURCE_ONLY_RETRY_MS;
    s_p0_source_only_retry_next = (candidate + 1u) % P0_SOURCE_ONLY_RETRY_SLOTS;
    s_p0_source_only_retry_attempts++;
    selected = candidate;
    break;
  }
  p0_state_unlock();
  if (selected == P0_SOURCE_ONLY_RETRY_SLOTS) return 0;

  if (!latch_valid || !latch.latched) {
    if (edr_storage_queue_p0_source_only_latch_prepare(&latch) != EDR_OK || !latch.latched) {
      p0_state_lock();
      if (s_p0_source_only_retry[selected].pending &&
          s_p0_source_only_retry[selected].generation == generation) {
        s_p0_emit_source_only_backpressure_failed++;
        p0_source_only_mark_unhealthy_for_event_locked(
            "source_only_latch_prepare_failed", 0, record.type);
      }
      p0_state_unlock();
      return 0;
    }
    latch_valid = 1;
    p0_state_lock();
    if (s_p0_source_only_retry[selected].pending &&
        s_p0_source_only_retry[selected].generation == generation) {
      s_p0_source_only_retry[selected].latch = latch;
      s_p0_source_only_retry[selected].latch_valid = 1u;
      p0_source_only_set_latch_locked(&latch);
    }
    p0_state_unlock();
  }

  /* A recovery audit may begin after a database recreation, which first
   * yields a fresh prepared latch. Convert that same retained tuple to the
   * recovery state before claiming it as a loss audit; never bind an audit to
   * a normal source assertion. */
  if (recovery_audit && !latch.recovery_required) {
    if (edr_storage_queue_p0_source_only_latch_prepare(&latch) != EDR_OK ||
        !latch.latched || !latch.recovery_required) {
      p0_state_lock();
      if (s_p0_source_only_retry[selected].pending &&
          s_p0_source_only_retry[selected].generation == generation) {
        s_p0_emit_source_only_backpressure_failed++;
        p0_source_only_mark_unhealthy_for_event_locked(
            "source_only_recovery_latch_prepare_failed", 0, record.type);
      }
      p0_state_unlock();
      return 0;
    }
    p0_state_lock();
    if (s_p0_source_only_retry[selected].pending &&
        s_p0_source_only_retry[selected].generation == generation) {
      s_p0_source_only_retry[selected].latch = latch;
      s_p0_source_only_retry[selected].latch_valid = 1u;
      p0_source_only_set_latch_locked(&latch);
    }
    p0_state_unlock();
  }

  if (!p0_source_only_enqueue_record(&record, &latch, recovery_audit)) {
    EdrStorageQueueP0SourceOnlyLatch current;
    /* Another P0 source may have converted the global latch while this slot
     * waited for I/O. Do not retry forever with a stale tuple: turn the
     * current metadata into recovery-required and retain this source for the
     * next exact queue attempt. */
    if (edr_storage_queue_p0_source_only_latch_get(&current) == EDR_OK &&
        current.latched && !p0_source_only_latch_equal(&current, &latch) &&
        edr_storage_queue_p0_source_only_latch_prepare(&current) == EDR_OK &&
        current.latched) {
      p0_state_lock();
      if (s_p0_source_only_retry[selected].pending &&
          s_p0_source_only_retry[selected].generation == generation) {
        s_p0_source_only_retry[selected].latch = current;
        s_p0_source_only_retry[selected].latch_valid = 1u;
        p0_source_only_set_latch_locked(&current);
      }
      p0_state_unlock();
    }
    p0_state_lock();
    if (s_p0_source_only_retry[selected].pending &&
        s_p0_source_only_retry[selected].generation == generation) {
      s_p0_emit_source_only_backpressure_failed++;
      p0_source_only_mark_unhealthy_for_event_locked(
          "source_only_durable_unavailable", 0, record.type);
    }
    p0_state_unlock();
    return 0;
  }

  p0_state_lock();
  if (!s_p0_source_only_retry[selected].pending ||
      s_p0_source_only_retry[selected].generation != generation) {
    p0_state_unlock();
    return 0;
  }
  if (committed_out) *committed_out = s_p0_source_only_retry[selected].record;
  p0_source_only_remember_committed_locked(
      s_p0_source_only_retry[selected].source_event_id,
      s_p0_source_only_retry[selected].source_semantic_sha256);
  p0_source_only_note_delivery_loss_durable_locked(
      &s_p0_source_only_retry[selected].record);
  memset(&s_p0_source_only_retry[selected], 0, sizeof(s_p0_source_only_retry[selected]));
  s_p0_source_only_retry_committed++;
  s_p0_emit_source_only_backpressure_emitted++;
  p0_state_unlock();
  return 1;
}

int edr_p0_rule_source_only_capability_healthy(char *reason, size_t reason_cap) {
  int healthy;
  if (reason && reason_cap > 0u) reason[0] = '\0';
  p0_state_lock();
  healthy = !s_p0_source_only_terminal_unhealthy;
  if (!healthy && reason && reason_cap > 0u) {
    snprintf(reason, reason_cap, "%s", s_p0_source_only_terminal_reason);
  }
  p0_state_unlock();
  return healthy;
}

int edr_p0_rule_source_only_capability_healthy_for_event(
    EdrEventType type, char *reason, size_t reason_cap) {
  int healthy;
  uint32_t family = p0_source_only_family_for_event(type);
  if (reason && reason_cap > 0u) reason[0] = '\0';
  p0_state_lock();
  healthy = !s_p0_source_only_terminal_unhealthy ||
            (s_p0_source_only_unhealthy_families != P0_SOURCE_ONLY_FAMILY_ALL &&
             (s_p0_source_only_unhealthy_families & family) == 0u);
  if (!healthy && reason && reason_cap > 0u) {
    snprintf(reason, reason_cap, "%s", s_p0_source_only_terminal_reason);
  }
  p0_state_unlock();
  return healthy;
}

static int p0_source_only_ir_recovery_healthy(void) {
  char reason[96];
  if (!edr_p0_rule_ir_is_ready()) return 0;
  return edr_p0_rule_ir_artifact_healthy(reason, sizeof(reason));
}

/* This is deliberately callable from startup and from the preprocess retry
 * loop.  The only transition back to healthy follows observation that a
 * central ACK has atomically deleted the matching severity-2 row and cleared
 * queue_meta; no local enqueue, probe, or timeout is allowed to do so. */
int edr_p0_rule_source_only_recover_after_queue_open(void) {
  EdrStorageQueueP0SourceOnlyLatch latch;
  EdrBehaviorRecord audit;
  EdrError status;
  int pending;
  int latch_sync_required;

  if (!edr_storage_queue_is_open()) {
    p0_state_lock();
    p0_source_only_wait_for_recovery_locked("source_only_queue_unavailable");
    p0_state_unlock();
    return 0;
  }

  p0_source_only_sync_persistent_latch();
  p0_state_lock();
  if (s_p0_source_only_recovery_verified && !s_p0_source_only_terminal_unhealthy) {
    p0_state_unlock();
    return 1;
  }
  latch_sync_required = s_p0_source_only_latch_sync_required;
  p0_state_unlock();
  if (latch_sync_required) return 0;

  if (!p0_source_only_ir_recovery_healthy()) {
    p0_state_lock();
    p0_source_only_wait_for_recovery_locked("source_only_recovery_ir_unavailable");
    p0_state_unlock();
    return 0;
  }

  status = edr_storage_queue_p0_source_only_latch_get(&latch);
  if (status != EDR_OK) {
    p0_state_lock();
    p0_source_only_wait_for_recovery_locked("source_only_latch_state_unavailable");
    p0_state_unlock();
    return 0;
  }

  if (!latch.latched) {
    status = edr_storage_queue_p0_source_only_recovery_probe();
    p0_state_lock();
    if (status != EDR_OK || p0_source_only_retry_has_pending_locked() ||
        s_p0_source_only_latch_sync_required) {
      p0_source_only_wait_for_recovery_locked(
          status == EDR_OK ? "source_only_recovery_pending" :
                             "source_only_restart_recovery_failed");
      p0_state_unlock();
      return 0;
    }
    p0_source_only_set_latch_locked(&latch);
    s_p0_source_only_unrecoverable = 0;
    s_p0_source_only_recovery_verified = 1;
    p0_source_only_note_ack_observed_locked();
    p0_state_unlock();
    return !s_p0_source_only_terminal_unhealthy;
  }

  p0_state_lock();
  p0_source_only_set_latch_locked(&latch);
  pending = p0_source_only_retry_has_pending_locked();
  /* A process that reopened with a durable latch has no RAM assertion to
   * replay.  Its replacement must be explicit even if the original fault was
   * an I/O failure rather than an overflow. */
  if (!s_p0_source_only_recovery_verified && !pending &&
      (!latch.recovery_event_id[0] || !latch.recovery_batch_id[0])) {
    s_p0_source_only_loss_detected = 1;
    s_p0_source_only_loss_audit_durable = 0;
    s_p0_source_only_unrecoverable = 1;
  }
  p0_state_unlock();

  /* A locally retained record still owns the exact assertion.  Do not turn
   * it into a capability-loss audit merely because its next retry is later. */
  if (pending) return 0;

  /* A bound latch already has a durable source/audit BAT1.  Only the remote
   * ACK may advance it; re-emitting here would make a second authority. */
  if (!latch.recovery_required && latch.recovery_batch_id[0]) return 0;

  /* A prepared latch with no retained producer means a crash happened between
   * latch prepare and queue insert.  Prepare again converts it to the strict
   * recovery-required state before the capability audit is encoded. */
  if (!latch.recovery_required) {
    if (edr_storage_queue_p0_source_only_latch_prepare(&latch) != EDR_OK ||
        !latch.latched || !latch.recovery_required) {
      p0_state_lock();
      p0_source_only_wait_for_recovery_locked("source_only_recovery_latch_prepare_failed");
      p0_state_unlock();
      return 0;
    }
    p0_state_lock();
    p0_source_only_set_latch_locked(&latch);
    p0_state_unlock();
  }

  if (!p0_build_source_only_delivery_record(&latch, &audit)) {
    p0_state_lock();
    p0_source_only_wait_for_recovery_locked("source_only_loss_audit_identity_unavailable");
    p0_state_unlock();
    return 0;
  }
  (void)p0_source_only_submit_record(&audit, 1);
  return 0;
}

typedef struct p0_dedup_reservation {
  int commit;
  int advance_next;
  uint32_t slot_index;
  uint64_t generation;
  struct p0_dedup_slot previous;
  struct p0_dedup_slot slot;
} p0_dedup_reservation;

static void p0_dedup_claim(p0_dedup_reservation *reservation) {
  if (!reservation || !reservation->commit) return;
  reservation->previous = s_p0_dedup[reservation->slot_index];
  reservation->generation = ++s_p0_dedup_generation;
  reservation->slot.pending = 1u;
  reservation->slot.generation = reservation->generation;
  s_p0_dedup[reservation->slot_index] = reservation->slot;
  if (reservation->advance_next) {
    s_p0_dedup_next++;
    reservation->advance_next = 0;
  }
}

/* A permitted candidate remains only a reservation until EventBatch accepts
 * its combined frame. Suppression state belongs to already accepted frames. */
static int p0_dedup_reserve(const char *rule_id, const EdrBehaviorRecord *br,
                            p0_dedup_reservation *reservation,
                            int *out_pending_backpressure,
                            uint32_t *out_exact_replay_count) {
  const char *v = getenv("EDR_P0_DEDUP_SEC");
  unsigned long window_s;
  uint64_t window_ms;
  if (!reservation) return 0;
  memset(reservation, 0, sizeof(*reservation));
  if (out_pending_backpressure) *out_pending_backpressure = 0;
  if (out_exact_replay_count) *out_exact_replay_count = 0u;
  window_s = (v && v[0]) ? strtoul(v, NULL, 10) : 30u;
  if (window_s == 0u) {
    return 1;
  }
  /* Bound the multiplication explicitly.  An absurd local test/config value
   * must not wrap into a tiny replay window. */
  window_ms = (uint64_t)window_s > (UINT64_MAX / 1000u) ? UINT64_MAX :
              (uint64_t)window_s * 1000u;
  uint64_t generation_key = p0_generation_key(br);
  char source_event_id[EDR_BR_ID_LEN];
  char source_semantic_sha256[65];
  uint64_t now = p0_monotonic_ms();
  p0_source_event_id(br, source_event_id, sizeof(source_event_id));
  if (!p0_source_semantic_sha256(br, source_semantic_sha256,
                                 sizeof(source_semantic_sha256))) {
    return 0;
  }
  if (now == 0) {
    return 1;
  }
  /* This is a replay window, not a PID/timestamp admission gate.  Expire
   * only completed slots: an in-flight owner remains protected until it
   * commits or rolls back. */
  for (uint32_t i = 0; i < P0_DEDUP_SLOTS; ++i) {
    if (!s_p0_dedup[i].pending && s_p0_dedup[i].last_ms != 0u &&
        now >= s_p0_dedup[i].last_ms &&
        now - s_p0_dedup[i].last_ms >= window_ms) {
      memset(&s_p0_dedup[i], 0, sizeof(s_p0_dedup[i]));
    }
  }
  for (uint32_t i = 0; i < P0_DEDUP_SLOTS; i++) {
    if (s_p0_dedup[i].pid == br->pid &&
        ((generation_key != 0u && s_p0_dedup[i].process_generation_key == generation_key) ||
         (generation_key == 0u && s_p0_dedup[i].process_generation_key == 0u)) &&
        strcmp(s_p0_dedup[i].rule_id, rule_id) == 0 &&
        strcmp(s_p0_dedup[i].endpoint_id, br->endpoint_id) == 0 &&
        strcmp(s_p0_dedup[i].source_event_id, source_event_id) == 0 &&
        strcmp(s_p0_dedup[i].source_semantic_sha256, source_semantic_sha256) == 0) {
      if (s_p0_dedup[i].pending) {
        return 0;
      }
      s_p0_dedup[i].suppressed_count++;
      s_p0_dedup_suppressed_total++;
      s_p0_dedup_exact_suppressed++;
      if (out_exact_replay_count) {
        *out_exact_replay_count = s_p0_dedup[i].suppressed_count;
      }
      if (p0_should_log_dedup(s_p0_dedup[i].suppressed_count)) {
        fprintf(stderr,
                "[P0 DEBUG] dedup: skip exact source replay (rule=%s pid=%u event=%s suppressed=%u total=%llu)\n",
                rule_id, br->pid, source_event_id, s_p0_dedup[i].suppressed_count,
                (unsigned long long)s_p0_dedup_suppressed_total);
      }
      return 0;
    }
  }
  /* Never replace another producer's in-flight claim.  A full pending set is
   * explicit backpressure: the caller must leave this evidence uncommitted
   * rather than let an older owner commit into a reused slot. */
  uint32_t slot_index = P0_DEDUP_SLOTS;
  for (uint32_t offset = 0; offset < P0_DEDUP_SLOTS; ++offset) {
    uint32_t candidate = (s_p0_dedup_next + offset) % P0_DEDUP_SLOTS;
    if (!s_p0_dedup[candidate].pending) {
      slot_index = candidate;
      break;
    }
  }
  if (slot_index == P0_DEDUP_SLOTS) {
    s_p0_dedup_pending_backpressure++;
    if (out_pending_backpressure) *out_pending_backpressure = 1;
    return 0;
  }
  reservation->commit = 1;
  reservation->advance_next = 1;
  reservation->slot_index = slot_index;
  snprintf(reservation->slot.rule_id, sizeof(reservation->slot.rule_id), "%s", rule_id ? rule_id : "");
  snprintf(reservation->slot.endpoint_id, sizeof(reservation->slot.endpoint_id), "%s", br->endpoint_id);
  reservation->slot.pid = br->pid;
  reservation->slot.process_generation_key = generation_key;
  snprintf(reservation->slot.source_event_id, sizeof(reservation->slot.source_event_id), "%s",
           source_event_id);
  snprintf(reservation->slot.source_semantic_sha256,
           sizeof(reservation->slot.source_semantic_sha256), "%s", source_semantic_sha256);
  reservation->slot.event_time_ns = br->event_time_ns;
  reservation->slot.last_ms = now;
  reservation->slot.suppressed_count = 0;
  p0_dedup_claim(reservation);
  return 1;
}

static void p0_dedup_commit(const p0_dedup_reservation *reservation) {
  if (!reservation || !reservation->commit) return;
  if (!s_p0_dedup[reservation->slot_index].pending ||
      s_p0_dedup[reservation->slot_index].generation != reservation->generation) return;
  s_p0_dedup[reservation->slot_index] = reservation->slot;
  s_p0_dedup[reservation->slot_index].pending = 0u;
}

static void p0_dedup_rollback(const p0_dedup_reservation *reservation) {
  if (!reservation || !reservation->commit) return;
  if (!s_p0_dedup[reservation->slot_index].pending ||
      s_p0_dedup[reservation->slot_index].generation != reservation->generation) return;
  s_p0_dedup[reservation->slot_index] = reservation->previous;
}

static unsigned long p0_max_emits_per_min(void) {
  const char *e = getenv("EDR_P0_MAX_EMITS_PER_MIN");
  if (!e || !*e) {
    return 0;
  }
  return strtoul(e, NULL, 10);
}

/* 在即将上送前调用：本分钟内是否未超上限（不修改计数，仅滚动窗口） */
static int p0_global_rate_ok(void) {
  unsigned long cap = p0_max_emits_per_min();
  if (cap == 0) {
    return 1;
  }
  uint64_t now = p0_monotonic_ms();
  if (now == 0) {
    return 1;
  }
  if (s_p0_gwin_start_ms == 0u || (now - s_p0_gwin_start_ms) >= 60000ull) {
    s_p0_gwin_start_ms = now;
    s_p0_gcount = 0u;
    s_p0_gwin_epoch = p0_next_rate_generation_locked();
  }
  return (uint64_t)s_p0_gcount < (uint64_t)cap;
}

static int p0_global_rate_bump(void) {
  if (p0_max_emits_per_min() == 0) {
    return 0;
  }
  if (p0_monotonic_ms() == 0u) return 0;
  s_p0_gcount++;
  return 1;
}

static unsigned long p0_tenant_max_emits_per_min(void) {
  const char *e = getenv("EDR_P0_MAX_EMITS_PER_MIN_PER_TENANT");
  if (!e || !*e) {
    return 60u;
  }
  return strtoul(e, NULL, 10);
}

/* 返回匹配 tenant 的槽；无则占一轮换槽。tenant 全空时统一按 "" 桶 */
static struct p0_tenant_rate_slot *p0_tenant_rate_slot(const char *tid) {
  const char *t = (tid && tid[0]) ? tid : "";
  for (uint32_t i = 0; i < P0_TENANT_RATE_SLOTS; i++) {
    if (strcmp(s_tenant_rate[i].tenant, t) == 0) {
      return &s_tenant_rate[i];
    }
  }
  struct p0_tenant_rate_slot *s = &s_tenant_rate[s_tenant_rate_next % P0_TENANT_RATE_SLOTS];
  s_tenant_rate_next++;
  memset(s, 0, sizeof(*s));
  snprintf(s->tenant, sizeof(s->tenant), "%s", t);
  s->generation = p0_next_rate_generation_locked();
  return s;
}

static int p0_tenant_rate_ok(const char *tid) {
  unsigned long cap = p0_tenant_max_emits_per_min();
  if (cap == 0) {
    return 1;
  }
  uint64_t now = p0_monotonic_ms();
  if (now == 0) {
    return 1;
  }
  struct p0_tenant_rate_slot *s = p0_tenant_rate_slot(tid);
  if (s->win_start_ms == 0u || (now - s->win_start_ms) >= 60000ull) {
    s->win_start_ms = now;
    s->count = 0u;
    s->generation = p0_next_rate_generation_locked();
  }
  return (uint64_t)s->count < (uint64_t)cap;
}

static struct p0_tenant_rate_slot *p0_tenant_rate_bump(const char *tid) {
  if (p0_tenant_max_emits_per_min() == 0) {
    return NULL;
  }
  uint64_t now = p0_monotonic_ms();
  if (now == 0) {
    return NULL;
  }
  struct p0_tenant_rate_slot *s = p0_tenant_rate_slot(tid);
  if (s->win_start_ms == 0u || (now - s->win_start_ms) >= 60000ull) {
    s->win_start_ms = now;
    s->count = 0u;
    s->generation = p0_next_rate_generation_locked();
  }
  s->count++;
  return s;
}

static unsigned long p0_ep_max_emits_per_min(void) {
  const char *e = getenv("EDR_P0_MAX_EMITS_PER_MIN_PER_ENDPOINT");
  if (!e || !*e) {
    return 0u;
  }
  return strtoul(e, NULL, 10);
}

static struct p0_ep_rate_slot *p0_ep_rate_slot(const char *ep) {
  const char *e = (ep && ep[0]) ? ep : "";
  for (uint32_t i = 0; i < P0_EP_RATE_SLOTS; i++) {
    if (strcmp(s_ep_rate[i].ep, e) == 0) {
      return &s_ep_rate[i];
    }
  }
  struct p0_ep_rate_slot *s = &s_ep_rate[s_ep_rate_next % P0_EP_RATE_SLOTS];
  s_ep_rate_next++;
  memset(s, 0, sizeof(*s));
  snprintf(s->ep, sizeof(s->ep), "%s", e);
  s->generation = p0_next_rate_generation_locked();
  return s;
}

static int p0_ep_rate_ok(const char *ep) {
  unsigned long cap = p0_ep_max_emits_per_min();
  if (cap == 0) {
    return 1;
  }
  uint64_t now = p0_monotonic_ms();
  if (now == 0) {
    return 1;
  }
  struct p0_ep_rate_slot *s = p0_ep_rate_slot(ep);
  if (s->win_start_ms == 0u || (now - s->win_start_ms) >= 60000ull) {
    s->win_start_ms = now;
    s->count = 0u;
    s->generation = p0_next_rate_generation_locked();
  }
  return (uint64_t)s->count < (uint64_t)cap;
}

static struct p0_ep_rate_slot *p0_ep_rate_bump(const char *ep) {
  if (p0_ep_max_emits_per_min() == 0) {
    return NULL;
  }
  uint64_t now = p0_monotonic_ms();
  if (now == 0) {
    return NULL;
  }
  struct p0_ep_rate_slot *s = p0_ep_rate_slot(ep);
  if (s->win_start_ms == 0u || (now - s->win_start_ms) >= 60000ull) {
    s->win_start_ms = now;
    s->count = 0u;
    s->generation = p0_next_rate_generation_locked();
  }
  s->count++;
  return s;
}

typedef struct {
  int global_reserved;
  uint64_t global_win_start_ms;
  uint64_t global_epoch;
  int tenant_reserved;
  uint32_t tenant_slot_index;
  uint64_t tenant_win_start_ms;
  uint64_t tenant_slot_generation;
  char tenant[sizeof(s_tenant_rate[0].tenant)];
  int endpoint_reserved;
  uint32_t endpoint_slot_index;
  uint64_t endpoint_win_start_ms;
  uint64_t endpoint_slot_generation;
  char endpoint[sizeof(s_ep_rate[0].ep)];
} p0_rate_reservation;

/* Caller holds s_p0_state_lock.  Reserve all three limits together so two
 * producers cannot both observe the last free token.  A queue failure rolls
 * the reservation back before its dedup claim is released. */
static int p0_rate_reserve(const char *tenant, const char *endpoint,
                           p0_rate_reservation *reservation) {
  if (!reservation || !p0_global_rate_ok() || !p0_tenant_rate_ok(tenant) ||
      !p0_ep_rate_ok(endpoint)) return 0;
  memset(reservation, 0, sizeof(*reservation));
  if (p0_global_rate_bump()) {
    reservation->global_reserved = 1;
    reservation->global_win_start_ms = s_p0_gwin_start_ms;
    reservation->global_epoch = s_p0_gwin_epoch;
  }
  {
    struct p0_tenant_rate_slot *slot = p0_tenant_rate_bump(tenant);
    if (slot) {
      reservation->tenant_reserved = 1;
      reservation->tenant_slot_index = (uint32_t)(slot - s_tenant_rate);
      reservation->tenant_win_start_ms = slot->win_start_ms;
      reservation->tenant_slot_generation = slot->generation;
      snprintf(reservation->tenant, sizeof(reservation->tenant), "%s", slot->tenant);
    }
  }
  {
    struct p0_ep_rate_slot *slot = p0_ep_rate_bump(endpoint);
    if (slot) {
      reservation->endpoint_reserved = 1;
      reservation->endpoint_slot_index = (uint32_t)(slot - s_ep_rate);
      reservation->endpoint_win_start_ms = slot->win_start_ms;
      reservation->endpoint_slot_generation = slot->generation;
      snprintf(reservation->endpoint, sizeof(reservation->endpoint), "%s", slot->ep);
    }
  }
  return 1;
}

static void p0_rate_rollback(const p0_rate_reservation *reservation) {
  if (!reservation) return;
  if (reservation->global_reserved && reservation->global_epoch == s_p0_gwin_epoch &&
      reservation->global_win_start_ms == s_p0_gwin_start_ms && s_p0_gcount > 0u) {
    s_p0_gcount--;
  }
  if (reservation->tenant_reserved && reservation->tenant_slot_index < P0_TENANT_RATE_SLOTS) {
    struct p0_tenant_rate_slot *slot = &s_tenant_rate[reservation->tenant_slot_index];
    if (slot->generation == reservation->tenant_slot_generation &&
        slot->win_start_ms == reservation->tenant_win_start_ms &&
        strcmp(slot->tenant, reservation->tenant) == 0 && slot->count > 0u) {
      slot->count--;
    }
  }
  if (reservation->endpoint_reserved && reservation->endpoint_slot_index < P0_EP_RATE_SLOTS) {
    struct p0_ep_rate_slot *slot = &s_ep_rate[reservation->endpoint_slot_index];
    if (slot->generation == reservation->endpoint_slot_generation &&
        slot->win_start_ms == reservation->endpoint_win_start_ms &&
        strcmp(slot->ep, reservation->endpoint) == 0 && slot->count > 0u) {
      slot->count--;
    }
  }
}

static int getenv_int01_disabled_on_zero(const char *k) {
  const char *v = getenv(k);
  if (!v || v[0] == '\0') {
    return 1;
  }
  if ((v[0] == '0' || v[0] == 'O' || v[0] == 'o') && (v[1] == '\0' || v[1] == ' ' || v[1] == '\n')) {
    return 0;
  }
  if ((v[0] == '1' || v[0] == 'I' || v[0] == 'i') && (v[1] == '\0' || v[1] == ' ' || v[1] == '\n')) {
    return 1;
  }
  if (v[0] == 'N' || v[0] == 'n') {
    return 0;
  }
  return 1;
}

static float p0_anomaly_for_severity(int severity) {
  if (severity <= 1) {
    return 0.35f;
  }
  if (severity == 2) {
    return 0.50f;
  }
  if (severity >= 4) {
    return 0.85f;
  }
  return 0.70f;
}

/**
 * RFC 8259 JSON string escape into out. max_in caps raw input bytes (0 = use full C string until NUL).
 * Returns 1 on success; 0 if output buffer too small — caller should treat as empty string.
 */
static int p0_json_escape(const char *in, char *out, size_t out_cap, size_t max_in) {
  if (!out || out_cap < 2u) {
    return 0;
  }
  if (!in) {
    in = "";
  }
  size_t lim = max_in > 0 ? max_in : strlen(in);
  size_t w = 0;
  for (size_t n = 0; n < lim && in[n]; n++) {
    if (w + 8u >= out_cap) {
      return 0;
    }
    unsigned char c = (unsigned char)in[n];
    switch (c) {
      case '"':
        out[w++] = '\\';
        out[w++] = '"';
        break;
      case '\\':
        out[w++] = '\\';
        out[w++] = '\\';
        break;
      case '\b':
        memcpy(out + w, "\\b", 2u);
        w += 2u;
        break;
      case '\f':
        memcpy(out + w, "\\f", 2u);
        w += 2u;
        break;
      case '\n':
        memcpy(out + w, "\\n", 2u);
        w += 2u;
        break;
      case '\r':
        memcpy(out + w, "\\r", 2u);
        w += 2u;
        break;
      case '\t':
        memcpy(out + w, "\\t", 2u);
        w += 2u;
        break;
      default:
        if (c < 0x20u) {
          int k = snprintf((char *)out + w, out_cap - w, "\\u%04x", (unsigned)c);
          if (k < 0 || (size_t)k >= out_cap - w) {
            return 0;
          }
          w += (size_t)k;
        } else {
          out[w++] = (char)c;
        }
        break;
    }
  }
  out[w] = '\0';
  return 1;
}

static void p0_json_escape_or_empty_impl(const char *in, char *out, size_t out_cap, size_t max_in,
                                         unsigned *values_capped, unsigned *escape_overflows) {
  if (in && in[0] && max_in > 0u && strlen(in) > max_in && values_capped) (*values_capped)++;
  if (!p0_json_escape(in, out, out_cap, max_in)) {
    out[0] = '\0';
    if (in && in[0] && escape_overflows) (*escape_overflows)++;
  }
}

/* emit_for_rule keeps these counters local until it chooses full/compact output.
 * Compact reconstruction intentionally does not recount a full-pass cap. */
#define p0_json_escape_or_empty(in, out, out_cap, max_in) \
  p0_json_escape_or_empty_impl((in), (out), (out_cap), (max_in), &full_values_capped, &full_escape_overflows)

static int p0_json_escape_compact(const char *in, char *out, size_t out_cap, size_t max_in) {
  return p0_json_escape(in, out, out_cap, max_in);
}

static int p0_valid_sha256_hex(const char *value) {
  size_t i;
  if (!value || strlen(value) != 64u) {
    return 0;
  }
  for (i = 0u; i < 64u; i++) {
    const char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F'))) {
      return 0;
    }
  }
  return 1;
}

/* Fixture builders also acquire one complete runtime binding; production
 * emission instead receives the binding captured by evaluate_record(). */
#ifdef EDR_P0_DIRECT_EMIT_TESTING
static int p0_capture_bundle_binding(EdrP0RuleIrBinding *out_binding) {
  if (!out_binding || !edr_p0_rule_ir_get_binding(out_binding) ||
      !out_binding->rules_bundle_version[0] ||
      !p0_valid_sha256_hex(out_binding->artifact_sha256) ||
      out_binding->snapshot_epoch == 0u || out_binding->rule_count == 0u) {
    if (out_binding) {
      memset(out_binding, 0, sizeof(*out_binding));
    }
    return 0;
  }
  return 1;
}
#endif

/* Detection context carries independently collected evidence (signature,
 * hashes, identity quality and suppression rationale). A terminal action is
 * additive metadata, never a replacement for that evidence. */
static int p0_context_is_outer_object(const char *value, size_t first, size_t last) {
  int depth = 0;
  int in_string = 0;
  int escaped = 0;
  if (!value || first >= last || value[first] != '{' || value[last - 1u] != '}') return 0;
  for (size_t i = first; i < last; i++) {
    unsigned char c = (unsigned char)value[i];
    if (in_string) {
      if (escaped) {
        escaped = 0;
      } else if (c == '\\') {
        escaped = 1;
      } else if (c == '"') {
        in_string = 0;
      }
      continue;
    }
    if (c == '"') {
      in_string = 1;
    } else if (c == '{') {
      depth++;
    } else if (c == '}') {
      if (--depth < 0 || (depth == 0 && i + 1u != last)) return 0;
    }
  }
  return !in_string && !escaped && depth == 0;
}

static size_t p0_context_object_extent(const char *value) {
  int depth = 0;
  int in_string = 0;
  int escaped = 0;
  size_t i;
  if (!value || value[0] != '{') return 0u;
  for (i = 0u; value[i]; i++) {
    unsigned char c = (unsigned char)value[i];
    if (in_string) {
      if (escaped) {
        escaped = 0;
      } else if (c == '\\') {
        escaped = 1;
      } else if (c == '"') {
        in_string = 0;
      }
      continue;
    }
    if (c == '"') {
      in_string = 1;
    } else if (c == '{') {
      depth++;
    } else if (c == '}' && --depth == 0) {
      return i + 1u;
    } else if (depth < 0) {
      return 0u;
    }
  }
  return 0u;
}

static int p0_context_merge_terminal(const char *original, const char *terminal,
                                     char *out, size_t out_cap) {
  static const char key[] = "\"enforcement_terminal\":";
  size_t original_len;
  size_t first = 0u;
  size_t last;
  size_t terminal_len;
  size_t used;
  if (!terminal || !terminal[0] || !out || out_cap == 0u) return 0;
  if (!original) original = "";
  original_len = strlen(original);
  last = original_len;
  while (first < last && (original[first] == ' ' || original[first] == '\t' ||
                          original[first] == '\r' || original[first] == '\n')) {
    first++;
  }
  while (last > first && (original[last - 1u] == ' ' || original[last - 1u] == '\t' ||
                          original[last - 1u] == '\r' || original[last - 1u] == '\n')) {
    last--;
  }
  terminal_len = strlen(terminal);
  if (first < last && p0_context_is_outer_object(original, first, last)) {
    size_t body_start = first + 1u;
    size_t body_end = last - 1u;
    int has_existing_member = 0;
    while (body_start < body_end && (original[body_start] == ' ' || original[body_start] == '\t' ||
                                     original[body_start] == '\r' || original[body_start] == '\n')) {
      body_start++;
    }
    has_existing_member = body_start < body_end;
    /* Preserve every original JSON member verbatim and append one typed object. */
    if (body_end + (has_existing_member ? 1u : 0u) + sizeof(key) - 1u + terminal_len + 2u > out_cap) {
      return 0;
    }
    memcpy(out, original, body_end);
    used = body_end;
    if (has_existing_member) out[used++] = ',';
    memcpy(out + used, key, sizeof(key) - 1u);
    used += sizeof(key) - 1u;
    memcpy(out + used, terminal, terminal_len);
    used += terminal_len;
    out[used++] = '}';
    out[used] = '\0';
    return 1;
  }
  if (original_len == 0u) {
    int n = snprintf(out, out_cap, "{%s%s}", key, terminal);
    return n >= 0 && (size_t)n < out_cap;
  }
  {
    char escaped[EDR_BR_STR_LONG * 6u + 8u];
    int n;
    if (!p0_json_escape(original, escaped, sizeof(escaped), 0u)) return 0;
    n = snprintf(out, out_cap, "{\"original_detection_context\":\"%s\",%s%s}",
                 escaped, key, terminal);
    return n >= 0 && (size_t)n < out_cap;
  }
}

/* A producer that cannot take an admission owner must still leave a durable,
 * source-only decision.  It intentionally has no enforcement fields: callers
 * use this only before an irreversible action is allowed to run.  Keep the
 * independently collected evidence object when it is available, otherwise
 * emit a complete minimal JSON object rather than a partial original blob. */
static int p0_build_source_only_direct_record(const EdrBehaviorRecord *record,
                                              const char *rule_id, const char *reason,
                                              const EdrP0RuleIrBinding *binding,
                                              EdrBehaviorRecord *out) {
  const EdrP0SourceOnlyReason *contract;
  char escaped_rule[160];
  char escaped_reason[160];
  char escaped_bundle_version[160];
  char escaped_bundle_sha256[96];
  char preserved[sizeof(out->detection_context)];
  const char *evidence_member;
  size_t evidence_len;
  int written;
  if (!record || !out || !rule_id || !rule_id[0] || !reason || !reason[0] || !binding) {
    return 0;
  }
  contract = edr_p0_source_only_reason_find(reason);
  if (!contract || contract->stage != EDR_P0_SOURCE_ONLY_STAGE_DIRECT ||
      strcmp(rule_id, EDR_P0_PROCESS_EVIDENCE_GATE) == 0 ||
      !binding->rules_bundle_version[0] || !p0_valid_sha256_hex(binding->artifact_sha256) ||
      binding->snapshot_epoch == 0u) {
    return 0;
  }
  if (!p0_json_escape(rule_id, escaped_rule, sizeof(escaped_rule), 64u) ||
      !p0_json_escape(reason, escaped_reason, sizeof(escaped_reason), 96u) ||
      !p0_json_escape(binding->rules_bundle_version, escaped_bundle_version,
                      sizeof(escaped_bundle_version), 128u) ||
      !p0_json_escape(binding->artifact_sha256, escaped_bundle_sha256,
                      sizeof(escaped_bundle_sha256), 64u)) {
    return 0;
  }
  *out = *record;
  evidence_member = strstr(record->detection_context, "\"evidence\":");
  if (evidence_member) {
    evidence_member += strlen("\"evidence\":");
    while (*evidence_member == ' ' || *evidence_member == '\t' ||
           *evidence_member == '\r' || *evidence_member == '\n') {
      evidence_member++;
    }
    evidence_len = p0_context_object_extent(evidence_member);
    if (evidence_len == 0u) {
      evidence_member = NULL;
    } else {
      written = snprintf(preserved, sizeof(preserved),
                         "{\"p0_disposition\":\"NOT_EVALUABLE\",\"reason\":\"%s\","
                         "\"source_contract_version\":\"%s\",\"stage\":\"direct\","
                         "\"rule_id\":\"%s\",\"rules_bundle_version\":\"%s\","
                         "\"rules_bundle_sha256\":\"%s\",\"evidence\":%.*s}",
                         escaped_reason, EDR_P0_SOURCE_ONLY_CONTRACT_VERSION, escaped_rule,
                         escaped_bundle_version, escaped_bundle_sha256,
                         (int)evidence_len, evidence_member);
      if (written >= 0 && (size_t)written < sizeof(preserved)) {
        snprintf(out->detection_context, sizeof(out->detection_context), "%s", preserved);
      } else {
        evidence_member = NULL;
      }
    }
  }
  if (!evidence_member) {
    written = snprintf(out->detection_context, sizeof(out->detection_context),
                       "{\"p0_disposition\":\"NOT_EVALUABLE\",\"reason\":\"%s\","
                       "\"source_contract_version\":\"%s\",\"stage\":\"direct\","
                       "\"rule_id\":\"%s\",\"rules_bundle_version\":\"%s\","
                       "\"rules_bundle_sha256\":\"%s\"}",
                       escaped_reason, EDR_P0_SOURCE_ONLY_CONTRACT_VERSION, escaped_rule,
                       escaped_bundle_version, escaped_bundle_sha256);
    if (written < 0 || (size_t)written >= sizeof(out->detection_context)) {
      return 0;
    }
  }
  return 1;
}

/* This gate records an internal inability to evaluate a source record while
 * a ruleset is present.  It must never borrow a rule ID or re-acquire a live
 * bundle binding: the failed evaluator may not have retained either safely. */
static int p0_build_source_only_ruleset_evaluation_record(const EdrBehaviorRecord *record,
                                                          const char *reason,
                                                          EdrBehaviorRecord *out) {
  const EdrP0SourceOnlyReason *contract;
  char escaped_reason[160];
  char escaped_gate[96];
  char preserved[sizeof(out->detection_context)];
  const char *evidence_member;
  size_t evidence_len;
  int written;
  if (!record || !reason || !reason[0] || !out) {
    return 0;
  }
  contract = edr_p0_source_only_reason_find(reason);
  if (!contract || contract->stage != EDR_P0_SOURCE_ONLY_STAGE_RULESET_EVALUATION ||
      strcmp(contract->gate_id, EDR_P0_RULESET_EVALUATION_GATE) != 0 ||
      !p0_json_escape(reason, escaped_reason, sizeof(escaped_reason), 96u) ||
      !p0_json_escape(contract->gate_id, escaped_gate, sizeof(escaped_gate), 64u)) {
    return 0;
  }
  *out = *record;
  evidence_member = strstr(record->detection_context, "\"evidence\":");
  if (evidence_member) {
    evidence_member += strlen("\"evidence\":");
    while (*evidence_member == ' ' || *evidence_member == '\t' ||
           *evidence_member == '\r' || *evidence_member == '\n') {
      evidence_member++;
    }
    evidence_len = p0_context_object_extent(evidence_member);
    if (evidence_len != 0u) {
      written = snprintf(preserved, sizeof(preserved),
                         "{\"p0_disposition\":\"NOT_EVALUABLE\",\"reason\":\"%s\","
                         "\"source_contract_version\":\"%s\",\"stage\":\"ruleset_evaluation\","
                         "\"gate_id\":\"%s\",\"evidence\":%.*s}",
                         escaped_reason, EDR_P0_SOURCE_ONLY_CONTRACT_VERSION, escaped_gate,
                         (int)evidence_len, evidence_member);
      if (written >= 0 && (size_t)written < sizeof(preserved)) {
        snprintf(out->detection_context, sizeof(out->detection_context), "%s", preserved);
        return 1;
      }
    }
  }
  written = snprintf(out->detection_context, sizeof(out->detection_context),
                     "{\"p0_disposition\":\"NOT_EVALUABLE\",\"reason\":\"%s\","
                     "\"source_contract_version\":\"%s\",\"stage\":\"ruleset_evaluation\","
                     "\"gate_id\":\"%s\"}",
                     escaped_reason, EDR_P0_SOURCE_ONLY_CONTRACT_VERSION, escaped_gate);
  return written >= 0 && (size_t)written < sizeof(out->detection_context);
}

/* A Kernel-File NameCreate capacity fault is a collector capability
 * disposition, not a later FILE_READ rule hit.  Its source record contains
 * only the fields observed before the cache admission failed; null StartKey
 * and pid values are preserved as missing rather than invented. */
static int p0_build_source_only_collector_evidence_record(const EdrBehaviorRecord *record,
                                                          EdrBehaviorRecord *out) {
  const EdrP0SourceOnlyReason *contract;
  char escaped_reason[192];
  char escaped_gate[96];
  char escaped_rejected_field[64];
  char escaped_path[sizeof(record->file_path) * 2u + 1u];
  char canonical_path_json[sizeof(escaped_path) + 3u];
  char file_key[32];
  char pid[16];
  char process_start_key[32];
  char event_time_ns[32];
  const char *file_key_json = "null";
  const char *pid_json = "null";
  const char *start_key_json = "null";
  int written;
  if (!record || !out || record->type != EDR_EVENT_FILE_READ ||
      strcmp(record->collector_evidence_gate, EDR_P0_FILE_READ_METADATA_GATE) != 0 ||
      !record->collector_evidence_reason[0]) {
    return 0;
  }
  contract = edr_p0_source_only_reason_find(record->collector_evidence_reason);
  if (!contract || contract->stage != EDR_P0_SOURCE_ONLY_STAGE_COLLECTOR_EVIDENCE_GATE ||
      strcmp(contract->gate_id, EDR_P0_FILE_READ_METADATA_GATE) != 0 ||
      !contract->rejected_field || !contract->rejected_field[0] ||
      !p0_json_escape(record->collector_evidence_reason, escaped_reason,
                      sizeof(escaped_reason), 96u) ||
      !p0_json_escape(contract->gate_id, escaped_gate, sizeof(escaped_gate), 64u) ||
      !p0_json_escape(contract->rejected_field, escaped_rejected_field,
                      sizeof(escaped_rejected_field), 48u)) {
    return 0;
  }
  if (record->file_path[0]) {
    int n;
    if (!p0_json_escape(record->file_path, escaped_path, sizeof(escaped_path),
                         sizeof(record->file_path) - 1u)) {
      return 0;
    }
    n = snprintf(canonical_path_json, sizeof(canonical_path_json), "\"%s\"", escaped_path);
    if (n < 0 || (size_t)n >= sizeof(canonical_path_json)) return 0;
  } else if (strcmp(record->collector_evidence_reason,
                    EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED) == 0 ||
             strcmp(record->collector_evidence_reason,
                    EDR_P0_FILE_READ_REASON_PAYLOAD_UNAVAILABLE) == 0 ||
             strcmp(record->collector_evidence_reason,
                    EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE) == 0) {
    snprintf(canonical_path_json, sizeof(canonical_path_json), "%s", "null");
  } else {
    return 0;
  }
  if (record->file_key != 0u) {
    snprintf(file_key, sizeof(file_key), "\"0x%016llx\"",
             (unsigned long long)record->file_key);
    file_key_json = file_key;
  }
  if (record->pid != 0u) {
    snprintf(pid, sizeof(pid), "%u", record->pid);
    pid_json = pid;
  }
  if (record->process_start_key != 0u) {
    snprintf(process_start_key, sizeof(process_start_key), "\"%llu\"",
             (unsigned long long)record->process_start_key);
    start_key_json = process_start_key;
  }
  snprintf(event_time_ns, sizeof(event_time_ns), "\"%lld\"",
           (long long)record->event_time_ns);
  *out = *record;
  written = snprintf(out->detection_context, sizeof(out->detection_context),
                     "{\"p0_disposition\":\"NOT_EVALUABLE\",\"reason\":\"%s\","
                     "\"source_contract_version\":\"%s\","
                     "\"stage\":\"collector_evidence_gate\",\"gate_id\":\"%s\","
                     "\"collector_metadata\":{\"canonical_path\":%s,"
                     "\"file_key\":%s,\"pid\":%s,\"process_start_key\":%s,"
                     "\"event_time_ns\":%s,\"rejected_field\":\"%s\"}}",
                     escaped_reason, EDR_P0_SOURCE_ONLY_CONTRACT_VERSION, escaped_gate,
                     canonical_path_json, file_key_json, pid_json, start_key_json,
                     event_time_ns, escaped_rejected_field);
  return written >= 0 && (size_t)written < sizeof(out->detection_context);
}

/* The original in-memory source assertion is unavailable after a restart (or
 * retry-lane overflow), so this is deliberately a capability event rather
 * than a fabricated process/file event.  The persistent queue generation and
 * latch epoch make its source identity replay-stable without borrowing a rule
 * or bundle authority. */
static int p0_build_source_only_delivery_record(
    const EdrStorageQueueP0SourceOnlyLatch *latch, EdrBehaviorRecord *out) {
  const EdrP0SourceOnlyReason *contract;
  char tenant[sizeof(s_p0_source_only_runtime_tenant)];
  char endpoint[sizeof(s_p0_source_only_runtime_endpoint)];
  char escaped_reason[160];
  char escaped_gate[96];
  char nonce_hex[33];
  char commitment[65];
  EdrSha256Ctx commitment_ctx;
  uint8_t commitment_bytes[EDR_SHA256_DIGEST_LEN];
  static const char hex[] = "0123456789abcdef";
  int written;
  if (!latch || !out || !latch->latched || !latch->latch_counter ||
      !latch->latch_epoch) {
    return 0;
  }
  contract = edr_p0_source_only_reason_find("pending_assertion_lost_on_restart");
  if (!contract || contract->stage != EDR_P0_SOURCE_ONLY_STAGE_SOURCE_ONLY_DELIVERY ||
      strcmp(contract->gate_id, EDR_P0_SOURCE_ONLY_DURABILITY_GATE) != 0 ||
      !p0_json_escape(contract->reason, escaped_reason, sizeof(escaped_reason), 96u) ||
      !p0_json_escape(contract->gate_id, escaped_gate, sizeof(escaped_gate), 64u)) {
    return 0;
  }
  p0_state_lock();
  snprintf(tenant, sizeof(tenant), "%s", s_p0_source_only_runtime_tenant);
  snprintf(endpoint, sizeof(endpoint), "%s", s_p0_source_only_runtime_endpoint);
  p0_state_unlock();
  if (!tenant[0] || !endpoint[0] || strcmp(endpoint, "auto") == 0) return 0;

  /* Stable source identity is a domain-separated SHA-256 commitment over the
   * persistent CSPRNG queue nonce and two signed 64-bit queue_meta counters.
   * The short event_id is only an index; the full commitment stays on wire. */
  edr_sha256_init(&commitment_ctx);
  p0_dedup_digest_text(&commitment_ctx, "edr-p0-source-only-delivery-v2");
  edr_sha256_update(&commitment_ctx, latch->queue_nonce, sizeof(latch->queue_nonce));
  p0_dedup_digest_u64(&commitment_ctx, latch->latch_counter);
  p0_dedup_digest_u64(&commitment_ctx, latch->latch_epoch);
  edr_sha256_final(&commitment_ctx, commitment_bytes);
  for (size_t i = 0u; i < sizeof(commitment_bytes); ++i) {
    commitment[i * 2u] = hex[commitment_bytes[i] >> 4u];
    commitment[i * 2u + 1u] = hex[commitment_bytes[i] & 0x0fu];
  }
  commitment[64] = '\0';
  p0_source_only_nonce_hex(latch->queue_nonce, nonce_hex);

  memset(out, 0, sizeof(*out));
  snprintf(out->event_id, sizeof(out->event_id), "p0sl-%.40s", commitment);
  snprintf(out->tenant_id, sizeof(out->tenant_id), "%s", tenant);
  snprintf(out->endpoint_id, sizeof(out->endpoint_id), "%s", endpoint);
  /* No truthful wall-clock source event exists. Keep zero fixed so an
   * interrupted `emit_durable` retries byte-identically for this latch. */
  out->event_time_ns = 0;
  out->type = EDR_EVENT_CAPABILITY_AUDIT;
  out->priority = 0u;
  snprintf(out->source_completeness, sizeof(out->source_completeness), "%s",
           "NOT_EVALUABLE");
  snprintf(out->identity_source, sizeof(out->identity_source), "%s",
           "source_only_delivery");
  snprintf(out->identity_quality, sizeof(out->identity_quality), "%s", "unknown");
  written = snprintf(
      out->detection_context, sizeof(out->detection_context),
      "{\"p0_disposition\":\"NOT_EVALUABLE\",\"reason\":\"%s\","
      "\"source_contract_version\":\"%s\",\"stage\":\"source_only_delivery\","
      "\"gate_id\":\"%s\",\"loss_detected\":true,"
      "\"source_only_delivery\":{\"queue_nonce\":\"%s\","
      "\"latch_counter\":\"%llu\",\"latch_epoch\":\"%llu\","
      "\"commitment_sha256\":\"%s\",\"latch_id\":\"p0sl-%.40s\"}}",
      escaped_reason, EDR_P0_SOURCE_ONLY_CONTRACT_VERSION, escaped_gate,
      nonce_hex, (unsigned long long)latch->latch_counter,
      (unsigned long long)latch->latch_epoch, commitment, commitment);
  return written >= 0 && (size_t)written < sizeof(out->detection_context);
}

static int p0_source_only_record_is_delivery_loss(const EdrBehaviorRecord *record) {
  return record && record->type == EDR_EVENT_CAPABILITY_AUDIT &&
         strstr(record->detection_context, "\"stage\":\"source_only_delivery\"") != NULL &&
         strstr(record->detection_context,
                "\"gate_id\":\"P0_SOURCE_ONLY_DURABILITY_GATE\"") != NULL &&
         strstr(record->detection_context, "\"loss_detected\":true") != NULL;
}

/* A producer that cannot take an admission owner must still leave a durable,
 * source-only decision.  It intentionally has no enforcement fields: callers
 * use this only before an irreversible action is allowed to run. */
static int p0_emit_source_only_not_evaluable(const EdrBehaviorRecord *record,
                                             const char *rule_id,
                                             const char *reason,
                                             const EdrP0RuleIrBinding *binding) {
  EdrBehaviorRecord evidence;
  int accepted;
  if (!p0_build_source_only_direct_record(record, rule_id, reason, binding, &evidence)) {
    return 0;
  }
  accepted = p0_source_only_submit(&evidence);
  if (accepted == P0_SOURCE_ONLY_DURABLE_UNHEALTHY) {
    fprintf(stderr,
            "[P0] source-only NOT_EVALUABLE retry lane unhealthy rule=%s pid=%u reason=%s\n",
            rule_id, record->pid, reason);
  }
  return accepted != P0_SOURCE_ONLY_DURABLE_UNHEALTHY;
}

#ifdef EDR_P0_DIRECT_EMIT_TESTING
int edr_p0_rule_test_build_source_only_direct_record(const EdrBehaviorRecord *record,
                                                      const char *rule_id,
                                                      const char *reason,
                                                      EdrBehaviorRecord *out) {
  EdrP0RuleIrBinding binding;
  return p0_capture_bundle_binding(&binding) &&
         p0_build_source_only_direct_record(record, rule_id, reason, &binding, out);
}

int edr_p0_rule_test_build_source_only_ruleset_evaluation_record(
    const EdrBehaviorRecord *record, const char *reason, EdrBehaviorRecord *out) {
  return p0_build_source_only_ruleset_evaluation_record(record, reason, out);
}

int edr_p0_rule_test_build_source_only_collector_evidence_record(
    const EdrBehaviorRecord *record, EdrBehaviorRecord *out) {
  return p0_build_source_only_collector_evidence_record(record, out);
}

int edr_p0_rule_test_build_source_only_delivery_record(
    const uint8_t queue_nonce[16], uint64_t latch_counter, uint64_t latch_epoch,
    EdrBehaviorRecord *out) {
  EdrStorageQueueP0SourceOnlyLatch latch;
  if (!queue_nonce) return 0;
  memset(&latch, 0, sizeof(latch));
  memcpy(latch.queue_nonce, queue_nonce, sizeof(latch.queue_nonce));
  latch.latch_counter = latch_counter;
  latch.latch_epoch = latch_epoch;
  latch.latched = 1;
  return p0_build_source_only_delivery_record(&latch, out);
}
#endif

static int p0_context_file_identity(const char *context, char *out, size_t out_cap) {
  static const char field[] = "\"file_identity\":\"";
  const char *value;
  const char *end;
  size_t len;
  if (out && out_cap > 0u) out[0] = '\0';
  if (!context || !out || out_cap < EDR_WINDOWS_FILE_IDENTITY_V1_CAP) return 0;
  if (!edr_p0_artifact_identity_is_action_authoritative(context)) return 0;
  value = strstr(context, field);
  if (!value) return 0;
  value += sizeof(field) - 1u;
  end = strchr(value, '\"');
  if (!end) return 0;
  len = (size_t)(end - value);
  if (len + 1u > out_cap) return 0;
  memcpy(out, value, len);
  out[len] = '\0';
  return edr_windows_file_identity_valid(out);
}

typedef struct p0_enforcement_prepare {
  const EdrBehaviorRecord *record;
  const char *rule_id;
  EdrPolicyEnforcementResult *result;
  int executed;
  int journal_precreated;
  char idempotency_key[96];
  /* `source_event_key` deliberately has the outer BehaviorRecord.event_id
   * value, not a local storage hash.  The backend binds this exact source
   * event and PID before accepting a result. */
  char source_event_key[EDR_BR_ID_LEN];
  char process_generation_key[32];
  /* Captured once with the terminal identity.  The intent, result, and
   * combined alert must use this exact canonical path, while the outer
   * BehaviorRecord deliberately retains its raw source path. */
  char canonical_image_path[EDR_BR_STR_LONG];
  char file_identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  EdrP0RuleIrBinding binding;
  char rules_bundle_version[128];
  char rules_bundle_sha256[65];
  char failure_reason[64];
} p0_enforcement_prepare;

/* The terminal intent and result must derive their authority from the same
 * immutable record snapshot and published bundle.  Keeping this setup shared
 * also lets the durable-wire contract exercise the exact production builders
 * without admitting a journal row or executing an action. */
static int p0_fill_terminal_authority(p0_enforcement_prepare *prepare) {
  const char *canonical_path;
  if (!prepare || !prepare->record || !prepare->result || !prepare->rule_id ||
      !prepare->rule_id[0]) {
    return 0;
  }
  if (!p0_terminal_identity(prepare->record, prepare->rule_id, prepare->idempotency_key,
                            sizeof(prepare->idempotency_key), prepare->source_event_key,
                            sizeof(prepare->source_event_key), prepare->process_generation_key,
                            sizeof(prepare->process_generation_key)) ||
      !p0_context_file_identity(prepare->record->detection_context, prepare->file_identity,
                                sizeof(prepare->file_identity)) ||
      !prepare->binding.rules_bundle_version[0] ||
      !p0_valid_sha256_hex(prepare->binding.artifact_sha256) ||
      prepare->binding.snapshot_epoch == 0u) {
    return 0;
  }
  canonical_path = prepare->record->image_path_canonical[0] ?
      prepare->record->image_path_canonical : prepare->record->exe_path;
  if (!canonical_path[0] ||
      snprintf(prepare->canonical_image_path, sizeof(prepare->canonical_image_path), "%s",
               canonical_path) < 0 ||
      strlen(canonical_path) >= sizeof(prepare->canonical_image_path)) {
    return 0;
  }
  snprintf(prepare->rules_bundle_version, sizeof(prepare->rules_bundle_version), "%s",
           prepare->binding.rules_bundle_version);
  snprintf(prepare->rules_bundle_sha256, sizeof(prepare->rules_bundle_sha256), "%s",
           prepare->binding.artifact_sha256);
  return 1;
}

static int p0_build_terminal_intent_record(const p0_enforcement_prepare *prepare,
                                           EdrBehaviorRecord *out) {
  char rule[128];
  char terminal_key[128];
  char source_event[EDR_BR_ID_LEN * 6u + 8u];
  char bundle_version[768];
  char bundle_sha256[80];
  char planned_action[128];
  char generation_key[96];
  char canonical_path[EDR_BR_STR_LONG * 6u + 8u];
  char file_identity[128];
  char terminal[EDR_BR_STR_LONG * 6u + 1024u];
  int n;
  if (!prepare || !prepare->record || !prepare->result || !out) return 0;
  if (!p0_json_escape(prepare->idempotency_key, terminal_key, sizeof(terminal_key), 0u) ||
      !p0_json_escape(prepare->rule_id, rule, sizeof(rule), 48u) ||
      !p0_json_escape(prepare->source_event_key, source_event, sizeof(source_event), 0u) ||
      !p0_json_escape(prepare->rules_bundle_version, bundle_version, sizeof(bundle_version), 0u) ||
      !p0_json_escape(prepare->rules_bundle_sha256, bundle_sha256, sizeof(bundle_sha256), 0u) ||
      !p0_json_escape(prepare->result->planned_action, planned_action, sizeof(planned_action), 0u) ||
      !p0_json_escape(prepare->process_generation_key, generation_key, sizeof(generation_key), 0u) ||
      !prepare->canonical_image_path[0] ||
      !p0_json_escape(prepare->canonical_image_path, canonical_path,
                      sizeof(canonical_path), 0u) ||
      !p0_json_escape(prepare->file_identity, file_identity, sizeof(file_identity), 0u) ||
      !planned_action[0] || strcmp(planned_action, "none") == 0) {
    return 0;
  }
  n = snprintf(terminal, sizeof(terminal),
               "{\"phase\":\"intent\",\"terminal_key\":\"%s\",\"rule_id\":\"%s\","
               "\"rules_bundle_version\":\"%s\",\"rules_bundle_sha256\":\"%s\","
               "\"source_event_key\":\"%s\",\"source_event_id\":\"%s\",\"process_pid\":%u,"
               "\"requested\":true,\"planned_action\":\"%s\",\"process\":{\"generation_key\":\"%s\","
               "\"creation_filetime_100ns\":%llu,\"canonical_image_path\":\"%s\","
               "\"file_identity\":\"%s\",\"file_identity_available\":true}}",
               terminal_key, rule, bundle_version, bundle_sha256, source_event, source_event,
               prepare->record->pid, planned_action, generation_key,
               (unsigned long long)prepare->record->process_creation_filetime_100ns,
               canonical_path, file_identity);
  if (n < 0 || (size_t)n >= sizeof(terminal)) return 0;
  *out = *prepare->record;
  return p0_context_merge_terminal(prepare->record->detection_context, terminal,
                                   out->detection_context, sizeof(out->detection_context));
}

static int p0_prepare_enforcement(void *opaque) {
  p0_enforcement_prepare *prepare = opaque;
  EdrEnforcementTerminalPrecreate precreate;
  EdrBehaviorRecord intent;
  uint8_t intent_wire[65536u + 16u];
  char intent_batch_id[128];
  size_t intent_wire_len;
  if (!prepare || !prepare->record || !prepare->result || !prepare->result->requested) {
    return 1;
  }
  if (!p0_fill_terminal_authority(prepare)) {
    fprintf(stderr, "[P0] terminal authority incomplete; enforcement skipped rule=%s pid=%u\n",
            prepare->rule_id, prepare->record->pid);
    snprintf(prepare->failure_reason, sizeof(prepare->failure_reason), "%s",
             "terminal_authority_unavailable");
    return 0;
  }
  if (!p0_build_terminal_intent_record(prepare, &intent)) {
    fprintf(stderr, "[P0] terminal intent evidence merge failed; enforcement skipped rule=%s pid=%u\n",
            prepare->rule_id, prepare->record->pid);
    snprintf(prepare->failure_reason, sizeof(prepare->failure_reason), "%s",
             "terminal_context_merge_failed");
    return 0;
  }
  intent_wire_len = edr_behavior_record_encode_durable_wire(&intent, intent_wire, sizeof(intent_wire));
  if (intent_wire_len == 0u ||
      !edr_behavior_durable_wire_batch_id("p0-enforcement-intent", intent_wire, intent_wire_len,
                                          intent_batch_id, sizeof(intent_batch_id))) {
    fprintf(stderr, "[P0] terminal intent encoding failed; enforcement skipped rule=%s pid=%u\n",
            prepare->rule_id, prepare->record->pid);
    snprintf(prepare->failure_reason, sizeof(prepare->failure_reason), "%s",
             "terminal_intent_encoding_failed");
    return 0;
  }
  precreate = edr_storage_queue_enforcement_terminal_precreate(
      prepare->idempotency_key, prepare->source_event_key, prepare->rule_id,
      prepare->process_generation_key, intent_batch_id, intent_wire, intent_wire_len);
  if (precreate != EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED) {
    fprintf(stderr,
            "[P0] terminal intent %s; enforcement skipped rule=%s pid=%u key=%s\n",
            precreate == EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING ? "already exists" :
            (precreate == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT ? "semantic conflict" :
                                                                        "storage failure"),
            prepare->rule_id, prepare->record->pid, prepare->idempotency_key);
    snprintf(prepare->failure_reason, sizeof(prepare->failure_reason), "%s",
             precreate == EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING ?
                 "terminal_intent_existing" :
                 (precreate == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT ?
                      "terminal_intent_conflict" : "terminal_journal_unavailable"));
    return 0;
  }
  prepare->journal_precreated = 1;
  if (edr_storage_queue_enqueue(intent_batch_id, intent_wire, intent_wire_len, 0, 1) != EDR_OK) {
    fprintf(stderr,
            "[P0] terminal intent retained in journal after ordinary enqueue failure rule=%s pid=%u key=%s\n",
            prepare->rule_id, prepare->record->pid, prepare->idempotency_key);
  }
  /* The executor independently validates the live PID creation generation
   * before action.  A failure to precreate above is fail-closed. */
  edr_policy_enforcement_execute(prepare->record, prepare->result);
  prepare->executed = 1;
  return 1;
}

static int p0_build_terminal_result_record(const p0_enforcement_prepare *prepare,
                                           EdrBehaviorRecord *out) {
  char rule[128];
  char terminal_key[128];
  char source_event[EDR_BR_ID_LEN * 6u + 8u];
  char bundle_version[768];
  char bundle_sha256[80];
  char planned_action[128];
  char generation_key[96];
  char canonical_path[EDR_BR_STR_LONG * 6u + 8u];
  char file_identity[128];
  char action[128];
  char message[320];
  char terminal[EDR_BR_STR_LONG * 6u + 1280u];
  int n;
  if (!prepare || !prepare->record || !prepare->result || !out) return 0;
  *out = *prepare->record;
  if (!p0_json_escape(prepare->idempotency_key, terminal_key, sizeof(terminal_key), 0u) ||
      !p0_json_escape(prepare->rule_id, rule, sizeof(rule), 48u) ||
      !p0_json_escape(prepare->source_event_key, source_event, sizeof(source_event), 0u) ||
      !p0_json_escape(prepare->rules_bundle_version, bundle_version, sizeof(bundle_version), 0u) ||
      !p0_json_escape(prepare->rules_bundle_sha256, bundle_sha256, sizeof(bundle_sha256), 0u) ||
      !p0_json_escape(prepare->result->planned_action, planned_action, sizeof(planned_action), 0u) ||
      !p0_json_escape(prepare->process_generation_key, generation_key, sizeof(generation_key), 0u) ||
      !prepare->canonical_image_path[0] ||
      !p0_json_escape(prepare->canonical_image_path, canonical_path,
                      sizeof(canonical_path), 0u) ||
      !p0_json_escape(prepare->file_identity, file_identity, sizeof(file_identity), 0u) ||
      !p0_json_escape(prepare->result->action, action, sizeof(action), 64u) ||
      !p0_json_escape(prepare->result->message, message, sizeof(message), 160u)) {
    return 0;
  }
  n = snprintf(terminal, sizeof(terminal),
               "{\"phase\":\"result\",\"terminal_key\":\"%s\",\"rule_id\":\"%s\","
               "\"rules_bundle_version\":\"%s\",\"rules_bundle_sha256\":\"%s\","
               "\"source_event_key\":\"%s\",\"source_event_id\":\"%s\",\"process_pid\":%u,"
               "\"planned_action\":\"%s\",\"process\":{\"generation_key\":\"%s\","
               "\"creation_filetime_100ns\":%llu,\"canonical_image_path\":\"%s\","
               "\"file_identity\":\"%s\",\"file_identity_available\":true},"
               "\"attempted\":%s,\"succeeded\":%s,"
               "\"action\":\"%s\",\"error_code\":%u,"
               "\"message\":\"%s\"}",
               terminal_key, rule, bundle_version, bundle_sha256, source_event, source_event,
               prepare->record->pid, planned_action, generation_key,
               (unsigned long long)prepare->record->process_creation_filetime_100ns,
               canonical_path, file_identity,
               prepare->result->attempted ? "true" : "false",
               prepare->result->succeeded ? "true" : "false", action,
               prepare->result->error_code, message);
  if (n < 0 || (size_t)n >= sizeof(terminal)) return 0;
  return p0_context_merge_terminal(prepare->record->detection_context, terminal,
                                   out->detection_context, sizeof(out->detection_context));
}

#ifdef EDR_P0_DIRECT_EMIT_TESTING
int edr_p0_rule_test_build_terminal_authority_records(
    const EdrBehaviorRecord *record, const char *rule_id,
    const EdrPolicyEnforcementResult *result,
    EdrBehaviorRecord *intent_out, EdrBehaviorRecord *result_out) {
  p0_enforcement_prepare prepare;
  EdrPolicyEnforcementResult result_copy;
  if (!record || !rule_id || !rule_id[0] || !result || !result->requested ||
      !intent_out || !result_out || intent_out == result_out) {
    return 0;
  }
  memset(&prepare, 0, sizeof(prepare));
  result_copy = *result;
  prepare.record = record;
  prepare.rule_id = rule_id;
  prepare.result = &result_copy;
  return p0_capture_bundle_binding(&prepare.binding) &&
         p0_fill_terminal_authority(&prepare) &&
         p0_build_terminal_intent_record(&prepare, intent_out) &&
         p0_build_terminal_result_record(&prepare, result_out);
}
#endif

/* The journal is the recovery owner.  The normal queue is only an immediate
 * delivery path; either ordinary enqueue may fail after the journal update
 * without losing its final frame. */
static int p0_finish_enforcement_terminal(const p0_enforcement_prepare *prepare,
                                          const AVEBehaviorAlert *alert) {
  EdrBehaviorRecord evidence;
  uint8_t source_wire[65536u + 16u];
  uint8_t combined_wire[65536u + 16u];
  char source_batch_id[128];
  char combined_batch_id[128];
  size_t source_wire_len;
  size_t combined_wire_len;
  int source_enqueued;
  int combined_enqueued;
  if (!prepare || !prepare->record || !prepare->result || !prepare->journal_precreated ||
      !prepare->executed || !alert) {
    return 0;
  }
  if (!p0_build_terminal_result_record(prepare, &evidence)) {
    fprintf(stderr,
            "[P0] terminal audit storage failure: final evidence merge failed rule=%s pid=%u key=%s\n",
            prepare->rule_id, prepare->record->pid, prepare->idempotency_key);
    return 0;
  }
  source_wire_len = edr_behavior_record_encode_durable_wire(&evidence, source_wire,
                                                              sizeof(source_wire));
  combined_wire_len = edr_behavior_record_alert_encode_durable_wire(
      &evidence, alert, combined_wire, sizeof(combined_wire));
  if (source_wire_len == 0u || combined_wire_len == 0u ||
      !edr_behavior_durable_wire_batch_id("p0-enforcement-source", source_wire, source_wire_len,
                                          source_batch_id, sizeof(source_batch_id)) ||
      !edr_behavior_durable_wire_batch_id("p0-enforcement-combined", combined_wire,
                                          combined_wire_len, combined_batch_id,
                                          sizeof(combined_batch_id))) {
    fprintf(stderr,
            "[P0] terminal audit storage failure: final frame encoding failed rule=%s pid=%u key=%s\n",
            prepare->rule_id, prepare->record->pid, prepare->idempotency_key);
    return 0;
  }
  if (edr_storage_queue_enforcement_terminal_update(
          prepare->idempotency_key, source_batch_id, source_wire, source_wire_len,
          combined_batch_id, combined_wire, combined_wire_len) != EDR_OK) {
    fprintf(stderr,
            "[P0] terminal audit storage failure: result journal update failed rule=%s pid=%u key=%s\n",
            prepare->rule_id, prepare->record->pid, prepare->idempotency_key);
    return 0;
  }
  source_enqueued = edr_storage_queue_enqueue(source_batch_id, source_wire, source_wire_len, 0, 1) == EDR_OK;
  combined_enqueued =
      edr_storage_queue_enqueue(combined_batch_id, combined_wire, combined_wire_len, 0, 1) == EDR_OK;
  if (!source_enqueued || !combined_enqueued) {
    fprintf(stderr,
            "[P0] terminal journal retained after ordinary enqueue failure rule=%s pid=%u source=%d combined=%d\n",
            prepare->rule_id, prepare->record->pid, source_enqueued, combined_enqueued);
    return 0;
  }
  return 1;
}

static const char *p0_find_ci(const char *haystack, const char *needle) {
  size_t needle_len;
  if (!haystack || !needle || !needle[0]) return NULL;
  needle_len = strlen(needle);
  for (const char *p = haystack; *p; ++p) {
    size_t i = 0u;
    while (i < needle_len && p[i]) {
      char a = p[i];
      char b = needle[i];
      if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
      if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
      if (a != b) break;
      ++i;
    }
    if (i == needle_len) return p;
  }
  return NULL;
}

static void p0_copy_marker_token(const char *start, char *out, size_t out_cap) {
  size_t used = 0u;
  if (!start || !out || out_cap == 0u) return;
  while (*start && used + 1u < out_cap) {
    unsigned char c = (unsigned char)*start++;
    if (!(c == '-' || c == '_' || c == '.' ||
          (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
          (c >= 'a' && c <= 'z'))) break;
    out[used++] = (char)c;
  }
  out[used] = '\0';
}

static void p0_disposition_marker(const EdrBehaviorRecord *br, char *out,
                                  size_t out_cap) {
  static const char *keys[] = {"-Marker", "--edr-p0-case"};
  const char *cmdline = br ? br->cmdline : NULL;
  if (!out || out_cap == 0u) return;
  out[0] = '\0';
  for (size_t i = 0u; i < sizeof(keys) / sizeof(keys[0]); ++i) {
    const char *p = p0_find_ci(cmdline, keys[i]);
    if (!p) continue;
    p += strlen(keys[i]);
    while (*p == ' ' || *p == '\t' || *p == '=' || *p == ':' || *p == '"' || *p == '\'') ++p;
    p0_copy_marker_token(p, out, out_cap);
    if (out[0]) return;
  }
  /* The ARM64 acceptance harness embeds P0CASE-* in the copied image path
   * and command line without a dedicated flag. Recognize only this fixed
   * test prefix; arbitrary production arguments must never enable logging. */
  {
    const char *texts[] = {
        br ? br->cmdline : NULL,
        br ? br->image_path_canonical : NULL,
        br ? br->exe_path : NULL,
    };
    for (size_t i = 0u; i < sizeof(texts) / sizeof(texts[0]); ++i) {
      const char *p = p0_find_ci(texts[i], "P0CASE-");
      if (!p) continue;
      p0_copy_marker_token(p, out, out_cap);
      if (out[0]) return;
    }
  }
}

static int p0_copy_marker_rule_id(const char *candidate, char *rule_id,
                                  size_t rule_id_cap) {
  const char *category_end;
  const char *number_end;
  size_t rule_len;
  if (!candidate || candidate[0] != 'R' || candidate[1] != '-' ||
      !rule_id || rule_id_cap == 0u) {
    return 0;
  }
  category_end = strchr(candidate + 2u, '-');
  if (!category_end || category_end == candidate + 2u) return 0;
  number_end = category_end + 1u;
  if (*number_end < '0' || *number_end > '9') return 0;
  while (*number_end >= '0' && *number_end <= '9') ++number_end;
  if (*number_end != '\0' && *number_end != '-') return 0;
  rule_len = (size_t)(number_end - candidate);
  if (rule_len >= rule_id_cap) return 0;
  memcpy(rule_id, candidate, rule_len);
  rule_id[rule_len] = '\0';
  return 1;
}

static int p0_validation_target_rule(const EdrBehaviorRecord *br,
                                     char *rule_id, size_t rule_id_cap,
                                     char *marker, size_t marker_cap) {
  int count;
  size_t best = 0u;
  const char *candidate;
  if (!rule_id || rule_id_cap == 0u || !marker || marker_cap == 0u) return 0;
  rule_id[0] = '\0';
  p0_disposition_marker(br, marker, marker_cap);
  candidate = strncmp(marker, "P0CASE-", 7u) == 0 ? marker + 7u : marker;
  if (candidate[0] != 'R' || candidate[1] != '-') return 0;
  count = edr_p0_rule_ir_rule_count();
  for (int i = 0; i < count; ++i) {
    const char *loaded = NULL;
    size_t n;
    if (!edr_p0_rule_ir_rule_id_at(i, &loaded) || !loaded || !loaded[0]) continue;
    n = strlen(loaded);
    if (n <= best || strncmp(candidate, loaded, n) != 0 ||
        (candidate[n] != '\0' && candidate[n] != '-')) continue;
    if (n >= rule_id_cap) continue;
    memcpy(rule_id, loaded, n + 1u);
    best = n;
  }
  if (best > 0u) return 1;
  /* When the authenticated IR is unavailable, the loaded rule list is empty.
   * Retain a bounded target in the failure observation by accepting only the
   * canonical R-<family>-<number> prefix from an explicit test marker. */
  return p0_copy_marker_rule_id(candidate, rule_id, rule_id_cap);
}

void edr_p0_rule_observe_validation_stage(const EdrBehaviorRecord *br,
                                          const char *stage,
                                          const char *reason) {
  char marker[96];
  char rule_id[64];
  if (!p0_validation_target_rule(br, rule_id, sizeof(rule_id), marker, sizeof(marker))) {
    return;
  }
  fprintf(stderr,
          "[p0_rule_stage] target_rule=%s stage=%s reason=%s pid=%u "
          "process_start_key=%llu source_event_id=%s marker=%s\n",
          rule_id, stage && stage[0] ? stage : "unknown",
          reason && reason[0] ? reason : "unknown", br ? br->pid : 0u,
          (unsigned long long)(br ? br->process_start_key : 0u),
          br && br->event_id[0] ? br->event_id : "none", marker);
}

static int p0_validation_target_matched(const EdrBehaviorRecord *br,
                                        const EdrP0RuleIrEvaluation *evaluation) {
  char marker[96];
  char target[64];
  if (!evaluation ||
      !p0_validation_target_rule(br, target, sizeof(target), marker, sizeof(marker))) {
    return 0;
  }
  for (uint32_t i = 0u; i < evaluation->match_count; ++i) {
    EdrP0RuleIrMatch match;
    if (edr_p0_rule_ir_evaluation_get_match(evaluation, i, &match) &&
        strcmp(match.rule_id, target) == 0) {
      return 1;
    }
  }
  return 0;
}

/* A grep-stable, bounded observation is emitted for every marked validation
 * event and every non-replay disposition. Unmarked exact replays use a
 * logarithmic sample because aggregate replay counters remain authoritative
 * and per-replay stderr would itself become endpoint noise. It intentionally
 * excludes command lines and user data; the source event id is the durable
 * candidate join. */
static void p0_observe_rule_disposition(const EdrBehaviorRecord *br,
                                        const char *rule_id,
                                        const char *disposition,
                                        const char *reason,
                                        const char *known_fp_reason,
                                        uint32_t repetition) {
  char marker[96];
  p0_disposition_marker(br, marker, sizeof(marker));
  if (repetition > 0u && !marker[0] &&
      !(repetition == 1u || repetition == 2u || repetition == 4u ||
        repetition == 8u || repetition == 16u || (repetition % 64u) == 0u)) {
    return;
  }
  fprintf(stderr,
          "[p0_rule_disposition] rule_id=%s disposition=%s reason=%s "
          "pid=%u process_start_key=%llu source_event_id=%s marker=%s "
          "known_fp_hint=%s repetition=%u\n",
          rule_id && rule_id[0] ? rule_id : "none",
          disposition && disposition[0] ? disposition : "unknown",
          reason && reason[0] ? reason : "unknown", br ? br->pid : 0u,
          (unsigned long long)(br ? br->process_start_key : 0u),
          br && br->event_id[0] ? br->event_id : "none",
          marker[0] ? marker : "none",
          known_fp_reason && known_fp_reason[0] ? known_fp_reason : "none",
          repetition);
}

static int emit_for_rule(const EdrBehaviorRecord *br, const char *rule_id, int severity, const char *title,
                        const char *mitre_comma, const EdrP0RuleIrBinding *binding,
                        const char *known_fp_reason) {
  EdrPolicyEnforcementResult enforcement;
  EdrP0EmitMetrics emitted_metrics = {0};
  p0_dedup_reservation dedup_reservation = {0};
  p0_rate_reservation rate_reservation = {0};
  int dedup_pending_backpressure = 0;
  uint32_t exact_replay_count = 0u;
  unsigned alert_abi_value_omissions = 0u;
  static int s_debug_enabled = -1;
  if (s_debug_enabled < 0) {
    s_debug_enabled = (getenv("EDR_P0_DEBUG") != NULL) ? 1 : 0;
  }

  /* 拒绝空 process_name 且 cmdline 含 forensic 痕迹的事件（Agent 内部取证命令，非真实攻击进程） */
  char resolved_pn[64];
  resolved_pn[0] = '\0';
  const char *pn = br->process_name;
  if (!pn || !pn[0]) {
    const char *cl = br->cmdline;
    if (cl && cl[0]) {
      if (strstr(cl, "edr_forensic") != NULL) {
        if (s_debug_enabled)
          fprintf(stderr, "[P0 DEBUG] emit blocked: cmdline contains forensic path (pid=%u)\n", br->pid);
        p0_observe_rule_disposition(br, rule_id, "rejected",
                                    "agent_forensic_command", known_fp_reason, 0u);
        return 0;
      }
      while (*cl == ' ' || *cl == '"') cl++;
      const char *end = cl;
      while (*end && *end != ' ' && *end != '"') end++;
      size_t name_len = (size_t)(end - cl);
      if (name_len > 0 && name_len < sizeof(resolved_pn)) {
        memcpy(resolved_pn, cl, name_len);
        resolved_pn[name_len] = '\0';
        const char *dot = strrchr(resolved_pn, '.');
        if (dot && (strcmp(dot, ".exe") == 0 || strcmp(dot, ".EXE") == 0 || strcmp(dot, ".bat") == 0 ||
                    strcmp(dot, ".cmd") == 0 || strcmp(dot, ".ps1") == 0 || strcmp(dot, ".vbs") == 0)) {
          pn = resolved_pn;
        } else if (strncmp(cl, "tar ", 4) == 0 || strncmp(cl, "tar.exe ", 7) == 0 ||
                   strncmp(cl, "tar\x00", 3) == 0) {
          snprintf(resolved_pn, sizeof(resolved_pn), "tar.exe");
          pn = resolved_pn;
        }
      }
    }
  }

  if (edr_policy_v2_mode_for_alert(mitre_comma, rule_id) < EDR_POLICY_MODE_ALERT) {
    p0_observe_rule_disposition(br, rule_id, "rejected", "policy_below_alert",
                                known_fp_reason, 0u);
    return 0;
  }
  if (!binding || !binding->rules_bundle_version[0] ||
      !p0_valid_sha256_hex(binding->artifact_sha256) || binding->snapshot_epoch == 0u) {
    if (s_debug_enabled) {
      fprintf(stderr, "[P0 DEBUG] emit blocked: loaded IR plaintext SHA-256 is unavailable or invalid\n");
    }
    p0_observe_rule_disposition(br, rule_id, "rejected",
                                "invalid_ir_binding", known_fp_reason, 0u);
    return 0;
  }
  /* Planning has no side effect.  The owner claim and durable intent below
   * must happen before a block policy is allowed to touch the process. */
  edr_policy_enforcement_plan(br, mitre_comma, rule_id, &enforcement);
  if (enforcement.requested &&
      !edr_p0_artifact_identity_is_action_authoritative(br->detection_context)) {
    /* The current evidence worker starts from a pathname only after the
     * ProcessCreate event.  Its result may describe B after A has started,
     * so block execution is NOT_EVALUABLE while the chain/cmd/user rule match
     * remains a valid alert.  Terminal construction and policy execution
     * perform the same check as defense in depth. */
    enforcement.requested = 0;
    snprintf(enforcement.action, sizeof(enforcement.action), "%s",
             "artifact_authority_unavailable");
    snprintf(enforcement.message, sizeof(enforcement.message), "%s",
             "block action withheld: only post-event path snapshot is available");
  }

  p0_state_lock();
  if (enforcement.requested) {
    /* Block policy uses an explicitly metered critical lane.  It has no
     * suppressing token because a decoy ordinary alert must never prevent the
     * durable intent that owns an irreversible action.  Its owner claim is
     * the terminal journal's durable unique precreate below: do not consume
     * a slot from the bounded, ordinary in-memory replay table first. */
    s_p0_emit_critical_reservations++;
    p0_state_unlock();
  } else if (!p0_rate_reserve(br->tenant_id, br->endpoint_id, &rate_reservation)) {
    p0_state_unlock();
    if (s_debug_enabled) fprintf(stderr, "[P0 DEBUG] emit blocked: rate limit\n");
    p0_observe_rule_disposition(br, rule_id, "rejected", "rate_limit",
                                known_fp_reason, 0u);
    return 0;
  } else if (!p0_dedup_reserve(rule_id, br, &dedup_reservation,
                               &dedup_pending_backpressure, &exact_replay_count)) {
    if (!enforcement.requested) {
      p0_rate_rollback(&rate_reservation);
    }
    p0_state_unlock();
    if (dedup_pending_backpressure) {
      (void)p0_emit_source_only_not_evaluable(br, rule_id,
                                               "p0_dedup_pending_backpressure", binding);
    }
    if (s_debug_enabled) fprintf(stderr, "[P0 DEBUG] emit blocked: dedup (rule=%s pid=%u)\n", rule_id, br->pid);
    p0_observe_rule_disposition(
        br, rule_id, dedup_pending_backpressure ? "source_only" : "rejected",
        dedup_pending_backpressure ? "p0_dedup_pending_backpressure" : "exact_replay_dedup",
        known_fp_reason, exact_replay_count);
    return 0;
  } else {
    p0_state_unlock();
  }

  /* The intent must be durable before an irreversible action.  Execute it
   * here, before building the combined protobuf, so the source event and
   * alert carry the same final enforcement result. */
  p0_enforcement_prepare enforcement_prepare;
  memset(&enforcement_prepare, 0, sizeof(enforcement_prepare));
  enforcement_prepare.record = br;
  enforcement_prepare.rule_id = rule_id;
  enforcement_prepare.result = &enforcement;
  enforcement_prepare.binding = *binding;
  if (enforcement.requested && !p0_prepare_enforcement(&enforcement_prepare)) {
    p0_state_lock();
    p0_dedup_rollback(&dedup_reservation);
    p0_rate_rollback(&rate_reservation);
    p0_state_unlock();
    if (strcmp(enforcement_prepare.failure_reason, "terminal_intent_existing") != 0) {
      (void)p0_emit_source_only_not_evaluable(
          br, rule_id, enforcement_prepare.failure_reason[0] ?
              enforcement_prepare.failure_reason : "terminal_journal_unavailable", binding);
    }
    p0_observe_rule_disposition(
        br, rule_id,
        strcmp(enforcement_prepare.failure_reason, "terminal_intent_existing") == 0
            ? "rejected"
            : "source_only",
        enforcement_prepare.failure_reason[0]
            ? enforcement_prepare.failure_reason
            : "terminal_journal_unavailable",
        known_fp_reason, 0u);
    return 0;
  }

  AVEBehaviorAlert a;
  const char *alert_process_path = enforcement.requested ?
      enforcement_prepare.canonical_image_path : br->exe_path;
  memset(&a, 0, sizeof(a));
  a.pid = br->pid;
  a.ppid = br->ppid;
  a.timestamp_ns = br->event_time_ns;
  snprintf(a.process_name, sizeof(a.process_name), "%s", pn && pn[0] ? pn : "");
  /* The legacy AVE ABI has smaller display fields than BehaviorRecord.  A
   * prefix here is unsafe: it looks complete while changing the process
   * identity presented to downstream consumers.  The complete record is
   * emitted separately in the durable combined frame; expose an explicit
   * omission marker in this legacy projection and count it below. */
  if (strlen(alert_process_path) < sizeof(a.process_path)) {
    memcpy(a.process_path, alert_process_path, strlen(alert_process_path) + 1u);
  } else {
    memcpy(a.process_path, "[omitted: exceeds ABI field]",
           sizeof("[omitted: exceeds ABI field]"));
    alert_abi_value_omissions++;
  }
  if (strlen(br->cmdline) < sizeof(a.cmdline)) {
    memcpy(a.cmdline, br->cmdline, strlen(br->cmdline) + 1u);
  } else {
    memcpy(a.cmdline, "[omitted: exceeds ABI field]",
           sizeof("[omitted: exceeds ABI field]"));
    alert_abi_value_omissions++;
  }
  a.anomaly_score = p0_anomaly_for_severity(severity);
  snprintf(a.triggered_tactics, sizeof(a.triggered_tactics), "%s", mitre_comma ? mitre_comma : "");
  a.skip_ai_analysis = false;
  a.needs_l2_review = false;

  /* user_subject_json：所有嵌入字符串必须 JSON 转义，否则 \\ 未写成 \\\\ 会导致非法 JSON，ingest 不入库、标题退回默认。 */
  {
    unsigned full_values_capped = 0u;
    unsigned full_escape_overflows = 0u;
    char esc_rule_id[80];
    char esc_bundle[160];
    char esc_bundle_sha256[80];
    char esc_title[640];
    char esc_proc[384];
    char esc_exe[1024];
    char cmdline_esc[2048];
    char esc_exe_hash[160];
    char esc_path_hash[160];
    char parent_name_esc[384];
    char parent_path_esc[1024];
    char esc_parent_cmdline[2048];
    char esc_gp[256];
    char username_esc[512];
    char esc_ep[96];
    char esc_tenant[96];
    char esc_host[256];
    char esc_domain[256];
    char esc_cwd[512];
    char esc_il[96];
    char esc_pct[192];
    char esc_ppt[192];
    char esc_child[384];
    char esc_psb[1024];
    char esc_clo[256];
    char esc_ect[96];
    char esc_registry_source[96];
    char esc_registry_attribution[64];
    char esc_registry_detail_status[96];
    char esc_registry_old_data[512];
    char registry_context_json[900];
    char esc_enforcement_action[96];
    char esc_enforcement_message[320];
    char esc_user_sid[320], esc_logon_id[96], esc_creator_user[320], esc_creator_domain[320];
    char esc_creator_sid[320], esc_creator_logon[96], esc_identity_source[64], esc_identity_quality[64], esc_event_id[96];
    char parent_name_buf[sizeof(br->parent_name)];
    char parent_path_buf[sizeof(br->parent_path)];

    snprintf(parent_name_buf, sizeof(parent_name_buf), "%s", br->parent_name);
    snprintf(parent_path_buf, sizeof(parent_path_buf), "%s", br->parent_path);

    /* Fill parent metadata before JSON escaping when the ETW record lacks it. */
    if (!parent_name_buf[0] && br->ppid > 0) {
      enrich_parent_info_by_pid(br->ppid, parent_name_buf, sizeof(parent_name_buf), parent_path_buf,
                                sizeof(parent_path_buf));
    }

    p0_json_escape_or_empty(rule_id, esc_rule_id, sizeof(esc_rule_id), 48);
    p0_json_escape_or_empty(binding->rules_bundle_version, esc_bundle, sizeof(esc_bundle), 128);
    p0_json_escape_or_empty(binding->artifact_sha256, esc_bundle_sha256, sizeof(esc_bundle_sha256), 64);
    p0_json_escape_or_empty(title ? title : "", esc_title, sizeof(esc_title), 240);
    p0_json_escape_or_empty(pn && pn[0] ? pn : "", esc_proc, sizeof(esc_proc), 160);
    p0_json_escape_or_empty(alert_process_path[0] ? alert_process_path : "", esc_exe, sizeof(esc_exe), 400);
    p0_json_escape_or_empty(br->cmdline, cmdline_esc, sizeof(cmdline_esc), 480);
    p0_json_escape_or_empty(br->exe_hash[0] ? br->exe_hash : "", esc_exe_hash, sizeof(esc_exe_hash), 96);
    p0_json_escape_or_empty(br->process_path_hash[0] ? br->process_path_hash : "", esc_path_hash,
                            sizeof(esc_path_hash), 96);
    p0_json_escape_or_empty(parent_name_buf[0] ? parent_name_buf : "", parent_name_esc, sizeof(parent_name_esc),
                            160);
    p0_json_escape_or_empty(parent_path_buf[0] ? parent_path_buf : "", parent_path_esc, sizeof(parent_path_esc),
                            400);
    p0_json_escape_or_empty(br->parent_cmdline[0] ? br->parent_cmdline : "", esc_parent_cmdline,
                            sizeof(esc_parent_cmdline), 480);
    p0_json_escape_or_empty(br->grandparent_name[0] ? br->grandparent_name : "", esc_gp, sizeof(esc_gp), 128);
    p0_json_escape_or_empty(br->username[0] ? br->username : "", username_esc, sizeof(username_esc), 160);
    p0_json_escape_or_empty(br->endpoint_id[0] ? br->endpoint_id : "", esc_ep, sizeof(esc_ep), 80);
    p0_json_escape_or_empty(br->tenant_id[0] ? br->tenant_id : "", esc_tenant, sizeof(esc_tenant), 64);
    p0_json_escape_or_empty(br->hostname[0] ? br->hostname : "", esc_host, sizeof(esc_host), 128);
    p0_json_escape_or_empty(br->domain[0] ? br->domain : "", esc_domain, sizeof(esc_domain), 128);
    p0_json_escape_or_empty(br->user_sid, esc_user_sid, sizeof(esc_user_sid), 256);
    p0_json_escape_or_empty(br->logon_id, esc_logon_id, sizeof(esc_logon_id), 64);
    p0_json_escape_or_empty(br->creator_username, esc_creator_user, sizeof(esc_creator_user), 160);
    p0_json_escape_or_empty(br->creator_domain, esc_creator_domain, sizeof(esc_creator_domain), 160);
    p0_json_escape_or_empty(br->creator_sid, esc_creator_sid, sizeof(esc_creator_sid), 256);
    p0_json_escape_or_empty(br->creator_logon_id, esc_creator_logon, sizeof(esc_creator_logon), 64);
    p0_json_escape_or_empty(br->identity_source, esc_identity_source, sizeof(esc_identity_source), 32);
    p0_json_escape_or_empty(br->identity_quality, esc_identity_quality, sizeof(esc_identity_quality), 32);
    p0_json_escape_or_empty(br->event_id, esc_event_id, sizeof(esc_event_id), 48);
    p0_json_escape_or_empty(br->current_directory[0] ? br->current_directory : "", esc_cwd, sizeof(esc_cwd), 240);
    p0_json_escape_or_empty(br->integrity_level[0] ? br->integrity_level : "Unknown", esc_il, sizeof(esc_il), 48);
    p0_json_escape_or_empty(br->process_creation_time[0] ? br->process_creation_time : "", esc_pct, sizeof(esc_pct),
                            96);
    p0_json_escape_or_empty(br->parent_creation_time[0] ? br->parent_creation_time : "", esc_ppt, sizeof(esc_ppt),
                            96);
    p0_json_escape_or_empty(br->child_pids[0] ? br->child_pids : "", esc_child, sizeof(esc_child), 160);
    p0_json_escape_or_empty(br->powershell_script_block[0] ? br->powershell_script_block : "", esc_psb,
                            sizeof(esc_psb), 360);
    p0_json_escape_or_empty(br->command_line_origin[0] ? br->command_line_origin : "", esc_clo, sizeof(esc_clo),
                            96);
    p0_json_escape_or_empty(br->encoded_command_type[0] ? br->encoded_command_type : "", esc_ect, sizeof(esc_ect),
                            64);
    p0_json_escape_or_empty(br->reg_source, esc_registry_source, sizeof(esc_registry_source), 48);
    p0_json_escape_or_empty(br->reg_attribution, esc_registry_attribution,
                            sizeof(esc_registry_attribution), 32);
    p0_json_escape_or_empty(br->reg_detail_status, esc_registry_detail_status,
                            sizeof(esc_registry_detail_status), 48);
    p0_json_escape_or_empty(br->reg_old_value_data, esc_registry_old_data,
                            sizeof(esc_registry_old_data), 220);
    registry_context_json[0] = '\0';
    if (br->reg_key_path[0] || br->reg_source[0] || br->reg_op[0]) {
      snprintf(registry_context_json, sizeof(registry_context_json),
               ",\"registry_source\":\"%s\",\"registry_attribution\":\"%s\","
               "\"registry_detail_status\":\"%s\",\"registry_old_data\":\"%s\"",
               esc_registry_source, esc_registry_attribution,
               esc_registry_detail_status, esc_registry_old_data);
    }
    p0_json_escape_or_empty(enforcement.action, esc_enforcement_action,
                            sizeof(esc_enforcement_action), 64);
    p0_json_escape_or_empty(enforcement.message, esc_enforcement_message,
                            sizeof(esc_enforcement_message), 160);

    int n = snprintf(
        a.user_subject_json, sizeof(a.user_subject_json),
        "{"
        "\"subject_type\":\"edr_dynamic_rule\","
        "\"rule_id\":\"%s\","
        "\"rules_bundle_version\":\"%s\","
        "\"rules_bundle_sha256\":\"%s\","
        "\"display_title\":\"%s\","
        "\"context\":{"
          "\"pid\":%u,"
          "\"ppid\":%u,"
          "\"process_name\":\"%s\","
          "\"process_path\":\"%s\","
          "\"cmdline\":\"%s\","
          "\"exe_hash\":\"%s\","
          "\"exe_path_hash\":\"%s\","
          "\"parent_name\":\"%s\","
          "\"parent_path\":\"%s\","
          "\"parent_cmdline\":\"%s\","
          "\"grandparent_pid\":%u,"
          "\"grandparent_name\":\"%s\","
          "\"username\":\"%s\","
          "\"process_chain_depth\":%u,"
          "\"endpoint_id\":\"%s\","
          "\"tenant_id\":\"%s\","
          "\"event_type\":%d,"
          "\"hostname\":\"%s\","
          "\"domain\":\"%s\","
          "\"user_sid\":\"%s\",\"logon_id\":\"%s\",\"creator_username\":\"%s\",\"creator_domain\":\"%s\",\"creator_sid\":\"%s\",\"creator_logon_id\":\"%s\",\"identity_source\":\"%s\",\"identity_quality\":\"%s\",\"source_event_id\":\"%s\","
          "\"current_directory\":\"%s\","
          "\"logon_time_ns\":%llu,"
          "\"integrity_level\":\"%s\","
          "\"token_elevation\":%u,"
          "\"process_creation_time\":\"%s\","
          "\"parent_creation_time\":\"%s\","
          "\"child_pids\":\"%s\","
          "\"powershell_script_block\":\"%s\","
          "\"command_line_origin\":\"%s\","
          "\"encoded_command_type\":\"%s\"%s"
        "},"
        "\"enforcement\":{"
          "\"requested\":%s,"
          "\"attempted\":%s,"
          "\"succeeded\":%s,"
          "\"action\":\"%s\","
          "\"error_code\":%u,"
          "\"message\":\"%s\""
        "}"
        "}",
        esc_rule_id,
        esc_bundle,
        esc_bundle_sha256,
        esc_title,
        br->pid,
        br->ppid,
        esc_proc,
        esc_exe,
        cmdline_esc,
        esc_exe_hash,
        esc_path_hash,
        parent_name_esc,
        parent_path_esc,
        esc_parent_cmdline,
        br->grandparent_pid,
        esc_gp,
        username_esc,
        br->process_chain_depth,
        esc_ep,
        esc_tenant,
        (int)br->type,
        esc_host,
        esc_domain,
        esc_user_sid, esc_logon_id, esc_creator_user, esc_creator_domain, esc_creator_sid,
        esc_creator_logon, esc_identity_source, esc_identity_quality, esc_event_id,
        esc_cwd,
        (unsigned long long)br->logon_time_ns,
        esc_il,
        br->token_elevation,
        esc_pct,
        esc_ppt,
        esc_child,
        esc_psb,
        esc_clo,
        esc_ect,
        registry_context_json,
        enforcement.requested ? "true" : "false",
        enforcement.attempted ? "true" : "false",
        enforcement.succeeded ? "true" : "false",
        esc_enforcement_action,
        enforcement.error_code,
        esc_enforcement_message);
    /* Count both JSON field caps and ABI-field omissions.  The latter retain
     * no partial prefix, so this counter is the operational signal that the
     * full value must be read from the durable record. */
    emitted_metrics.values_truncated += full_values_capped + alert_abi_value_omissions;
    emitted_metrics.escape_overflow_values += full_escape_overflows;
    if (full_escape_overflows != 0u || n < 0 || (size_t)n >= sizeof(a.user_subject_json)) {
      /* Rebuild from scratch.  Do not emit snprintf's partial JSON. */
      char crule[128], cbundle[192], cbundle_sha256[80], cproc[384], cpath[768], cep[128], ctenant[128], cevent[192];
      char cuser[384], csid[384], csource[128], cquality[128], caction[192], cmessage[384], identity[1152];
      int compact_ok =
          p0_json_escape_compact(rule_id, crule, sizeof(crule), 24) &&
          p0_json_escape_compact(binding->rules_bundle_version, cbundle, sizeof(cbundle), 48) &&
          p0_json_escape_compact(binding->artifact_sha256, cbundle_sha256, sizeof(cbundle_sha256), 64) &&
          p0_json_escape_compact(pn ? pn : "", cproc, sizeof(cproc), 96) &&
          p0_json_escape_compact(alert_process_path, cpath, sizeof(cpath), 180) &&
          p0_json_escape_compact(br->endpoint_id, cep, sizeof(cep), 48) &&
          p0_json_escape_compact(br->tenant_id, ctenant, sizeof(ctenant), 48) &&
          p0_json_escape_compact(br->event_id, cevent, sizeof(cevent), 48) &&
          p0_json_escape_compact(br->username, cuser, sizeof(cuser), 96) &&
          p0_json_escape_compact(br->user_sid, csid, sizeof(csid), 96) &&
          p0_json_escape_compact(br->identity_source, csource, sizeof(csource), 24) &&
          p0_json_escape_compact(br->identity_quality, cquality, sizeof(cquality), 24) &&
          p0_json_escape_compact(enforcement.action, caction, sizeof(caction), 48) &&
          p0_json_escape_compact(enforcement.message, cmessage, sizeof(cmessage), 96);
      identity[0] = '\0';
      if (compact_ok) {
        if (cuser[0]) snprintf(identity + strlen(identity), sizeof(identity) - strlen(identity), ",\"username\":\"%s\"", cuser);
        if (csid[0]) snprintf(identity + strlen(identity), sizeof(identity) - strlen(identity), ",\"user_sid\":\"%s\"", csid);
        if (csource[0]) snprintf(identity + strlen(identity), sizeof(identity) - strlen(identity), ",\"identity_source\":\"%s\"", csource);
        if (cquality[0]) snprintf(identity + strlen(identity), sizeof(identity) - strlen(identity), ",\"identity_quality\":\"%s\"", cquality);
      }
      emitted_metrics.user_subject_degraded++;
      emitted_metrics.alerts_with_optional_omission++;
      if (compact_ok) {
        n = snprintf(a.user_subject_json, sizeof(a.user_subject_json),
          "{\"subject_type\":\"edr_dynamic_rule\",\"rule_id\":\"%s\",\"rules_bundle_version\":\"%s\",\"rules_bundle_sha256\":\"%s\",\"context\":{\"context_degraded\":true,\"pid\":%u,\"ppid\":%u,\"event_type\":%d,\"process_name\":\"%s\",\"process_path\":\"%s\",\"endpoint_id\":\"%s\",\"tenant_id\":\"%s\",\"source_event_id\":\"%s\"%s},\"enforcement\":{\"requested\":%s,\"attempted\":%s,\"succeeded\":%s,\"action\":\"%s\",\"error_code\":%u,\"message\":\"%s\"}}",
          crule, cbundle, cbundle_sha256, br->pid, br->ppid, (int)br->type, cproc, cpath, cep, ctenant, cevent, identity,
          enforcement.requested ? "true" : "false", enforcement.attempted ? "true" : "false",
          enforcement.succeeded ? "true" : "false", caction, enforcement.error_code, cmessage);
      }
      if (!compact_ok || n < 0 || (size_t)n >= sizeof(a.user_subject_json)) {
        snprintf(a.user_subject_json, sizeof(a.user_subject_json),
                 "{\"subject_type\":\"edr_dynamic_rule\",\"context\":{\"context_degraded\":true},\"enforcement\":{\"requested\":false,\"attempted\":false,\"succeeded\":false}}");
        emitted_metrics.minimal_failures++;
      }
      emitted_metrics.emitted_without_full_context++;
    } else {
      emitted_metrics.user_subject_full++;
    }
  }
  EdrBehaviorRecordAlertEmitOutcome emit_outcome = enforcement.requested
      ? (p0_finish_enforcement_terminal(&enforcement_prepare, &a)
             ? EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED
             : EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED)
      : edr_behavior_record_alert_emit_to_batch_with_prepare_outcome(br, &a, NULL, NULL);
  if (emit_outcome != EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED) {
    p0_state_lock();
    /* A requested enforcement already has a durable intent and may have
     * completed an irreversible side effect.  Do not roll its owner claim
     * back into a second terminate attempt if recording the result frame
     * fails; the intent remains replayable/auditable in the offline queue. */
    if (emit_outcome == EDR_BEHAVIOR_RECORD_ALERT_EMIT_GOVERNOR_SUPPRESSED) {
      /* Governor suppression is an expected, aggregated alert-volume result.
       * Preserve the P0 reservations so the same source cannot re-enter the
       * direct path and masquerade as a queue failure on every replay. */
      p0_dedup_commit(&dedup_reservation);
      s_p0_emit_governor_suppressed++;
    } else {
      if (enforcement_prepare.executed) p0_dedup_commit(&dedup_reservation);
      else p0_dedup_rollback(&dedup_reservation);
      if (!enforcement_prepare.executed) p0_rate_rollback(&rate_reservation);
    }
    p0_state_unlock();
    if (enforcement_prepare.executed) {
      fprintf(stderr, "[P0] enforcement terminal frame not fully enqueued after durable intent; retained owner claim rule=%s pid=%u\n",
              rule_id, br->pid);
    } else if (!enforcement.requested &&
               emit_outcome == EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED) {
      (void)p0_emit_source_only_not_evaluable(br, rule_id, "p0_alert_queue_backpressure", binding);
    }
    p0_observe_rule_disposition(
        br, rule_id,
        emit_outcome == EDR_BEHAVIOR_RECORD_ALERT_EMIT_GOVERNOR_SUPPRESSED
            ? "governor_suppressed"
            : "source_only",
        emit_outcome == EDR_BEHAVIOR_RECORD_ALERT_EMIT_GOVERNOR_SUPPRESSED
            ? "alert_governor"
            : "p0_alert_queue_backpressure",
        known_fp_reason, 0u);
    return 0;
  }
  p0_state_lock();
  p0_dedup_commit(&dedup_reservation);
  s_p0_emit_user_subject_full += emitted_metrics.user_subject_full;
  s_p0_emit_user_subject_degraded += emitted_metrics.user_subject_degraded;
  s_p0_emit_alerts_with_optional_omission += emitted_metrics.alerts_with_optional_omission;
  s_p0_emit_values_truncated += emitted_metrics.values_truncated;
  s_p0_emit_escape_overflow_values += emitted_metrics.escape_overflow_values;
  s_p0_emit_minimal_failures += emitted_metrics.minimal_failures;
  s_p0_emit_emitted_without_full_context += emitted_metrics.emitted_without_full_context;
  p0_state_unlock();
  p0_observe_rule_disposition(br, rule_id, "emitted", "queue_accepted",
                              known_fp_reason, 0u);
  return 1;
}

/* A present IR whose evaluation cannot complete is not permission to fall
 * back to a local heuristic or to claim any rule.  Persist the registered
 * ruleset-evaluation gate once, with the source identity intact and no
 * alert/action authority. */
static int p0_is_ruleset_evaluation_event(EdrEventType type) {
  switch (type) {
  case EDR_EVENT_PROCESS_CREATE:
  case EDR_EVENT_FILE_READ:
  case EDR_EVENT_FILE_CREATE:
  case EDR_EVENT_FILE_WRITE:
  case EDR_EVENT_FILE_DELETE:
  case EDR_EVENT_FILE_RENAME:
  case EDR_EVENT_FILE_PERMISSION_CHANGE:
  case EDR_EVENT_NET_CONNECT:
  case EDR_EVENT_NET_LISTEN:
  case EDR_EVENT_REG_CREATE_KEY:
  case EDR_EVENT_REG_SET_VALUE:
    return 1;
  default:
    return 0;
  }
}

static int emit_ruleset_evaluation_gate(const EdrBehaviorRecord *br,
                                        const char *reason) {
  EdrBehaviorRecord evidence;
  if (!br || !reason || !reason[0]) return 0;
  if (!p0_build_source_only_ruleset_evaluation_record(br, reason, &evidence)) return 0;
  return p0_source_only_submit(&evidence);
}

int edr_p0_rule_emit_pre_evaluation_gate(const EdrBehaviorRecord *record,
                                         const char *reason) {
  const EdrP0SourceOnlyReason *contract;
  char reason_member[192];
  if (!record || !reason || !reason[0]) return 0;
  contract = edr_p0_source_only_reason_find(reason);
  if (!contract || contract->stage != EDR_P0_SOURCE_ONLY_STAGE_PRE_EVALUATION ||
      strcmp(contract->gate_id, EDR_P0_PROCESS_EVIDENCE_GATE) != 0) {
    return 0;
  }
  if (!edr_p0_source_only_validate_record(record) ||
      snprintf(reason_member, sizeof(reason_member), "\"reason\":\"%s\"", reason) < 0 ||
      !strstr(record->detection_context, "\"p0_disposition\":\"NOT_EVALUABLE\"") ||
      !strstr(record->detection_context, "\"stage\":\"pre_evaluation\"") ||
      !strstr(record->detection_context, "\"gate_id\":\"P0_PROCESS_EVIDENCE_GATE\"") ||
      !strstr(record->detection_context, reason_member)) {
    return 0;
  }
  return p0_source_only_submit(record);
}

int edr_p0_rule_emit_collector_evidence_gate(const EdrBehaviorRecord *record) {
  EdrBehaviorRecord evidence;
  if (!record || !p0_build_source_only_collector_evidence_record(record, &evidence)) {
    p0_state_lock();
    p0_source_only_mark_unhealthy_for_event_locked(
        "source_only_collector_record_invalid", 1, record ? record->type : 0);
    p0_state_unlock();
    p0_source_only_sync_persistent_latch();
    return 0;
  }
  /* A FileKey-capacity source can be durable immediately, but it still proves
   * an unknown handle existed. Persist a restart latch before its source is
   * accepted; the collector owns the stricter session-reset fuse. */
  p0_state_lock();
  p0_source_only_mark_unhealthy_for_event_locked(
      "source_only_collector_gate_pending", 0, record->type);
  p0_state_unlock();
  return p0_source_only_submit(&evidence);
}

#undef p0_json_escape_or_empty

int edr_p0_rule_try_emit(const EdrBehaviorRecord *br) {
  int emitted_count = 0;
  if (!br) {
    return 0;
  }
  const char *p0_env = getenv("EDR_P0_DIRECT_EMIT");
  if (!getenv_int01_disabled_on_zero("EDR_P0_DIRECT_EMIT")) {
    static int s_logged_once = 0;
    if (!s_logged_once) {
      fprintf(stderr, "[P0] INFO: EDR_P0_DIRECT_EMIT=%s, P0 rule engine disabled\n", p0_env ? p0_env : "(not set)");
      s_logged_once = 1;
    }
    return 0;
  }
  edr_p0_rule_observe_validation_stage(br, "direct_enter", "accepted");

  /* No active authenticated IR is a capability failure for every collector
   * event group the P0 bundle can evaluate.  This gate deliberately runs
   * before source-completeness and attribution filters: those filters may
   * normally shed telemetry, but cannot erase the fact that the current P0
   * authority was unavailable. */
  if (p0_is_ruleset_evaluation_event(br->type) && !edr_p0_rule_ir_is_ready()) {
    edr_p0_rule_observe_validation_stage(br, "ruleset", "p0_ir_not_ready");
    (void)emit_ruleset_evaluation_gate(br, "p0_ir_not_ready");
    return 0;
  }

  if (!p0_valid_process_create_record(br)) {
    edr_p0_rule_observe_validation_stage(br, "precondition", "invalid_process_create");
    static uint64_t s_invalid_process_create;
    s_invalid_process_create++;
    if (p0_debug_enabled() &&
        (s_invalid_process_create == 1u || (s_invalid_process_create & 1023u) == 0u)) {
      fprintf(stderr,
              "[P0 DEBUG] invalid process_create skipped: count=%llu pid=%u process=%s cmdline=%s\n",
              (unsigned long long)s_invalid_process_create, br->pid,
              br->process_name[0] ? br->process_name : "", br->cmdline[0] ? br->cmdline : "");
    }
    return 0;
  }

  /* RegNotifyChangeKeyValue snapshot diffs prove that a value changed, but do
   * not identify the writer.  Keep those events as telemetry and require an
   * attributed source (Security 4657 / kernel provider) for direct P0 alerts.
   * This prevents a pid=0 snapshot from being presented as a process-backed
   * persistence detection. */
  if ((br->type == EDR_EVENT_REG_SET_VALUE || br->type == EDR_EVENT_REG_CREATE_KEY ||
       br->type == EDR_EVENT_REG_DELETE_KEY) &&
      (strcmp(br->reg_attribution, "unavailable") == 0 || br->pid == 0u)) {
    static uint64_t s_unattributed_registry_skipped;
    s_unattributed_registry_skipped++;
    if (p0_debug_enabled() &&
        (s_unattributed_registry_skipped == 1u ||
         (s_unattributed_registry_skipped & 1023u) == 0u)) {
      fprintf(stderr,
              "[P0 DEBUG] unattributed registry event kept as telemetry: count=%llu source=%s op=%s\n",
              (unsigned long long)s_unattributed_registry_skipped,
              br->reg_source[0] ? br->reg_source : "unknown",
              br->reg_op[0] ? br->reg_op : "unknown");
    }
    return 0;
  }

  const char *detail = br->cmdline[0] ? br->cmdline : br->script_snippet;
  const char *pn = br->process_name;
  if ((!pn || !pn[0]) && br->type == EDR_EVENT_SCRIPT_POWERSHELL) {
    pn = "powershell.exe";
  } else if ((!pn || !pn[0]) && br->type == EDR_EVENT_SCRIPT_WMI) {
    pn = "wmiprvse.exe";
  }
  if (p0_is_agent_internal_command(br)) {
    if (p0_debug_all_enabled()) {
      p0_debug_event("internal-skip", br, pn, detail);
    }
    return 0;
  }

  /* Debug default prints matches only. Use EDR_P0_DEBUG_ALL=1 to dump every candidate. */
  static uint64_t s_debug_empty_count;
  if (p0_debug_all_enabled()) {
    int has_data = ((pn && pn[0]) || (detail && detail[0]));
    if (has_data) {
      p0_debug_event("candidate", br, pn, detail);
    } else {
      s_debug_empty_count++;
      if (s_debug_empty_count == 1u || (s_debug_empty_count & 1023u) == 0u) {
        fprintf(stderr, "[P0 DEBUG] empty events skipped (no img/cmd): count=%llu (last: type=%d pid=%u)\n",
                (unsigned long long)s_debug_empty_count, br->type, br->pid);
      }
    }
  }

  {
    EdrP0RuleIrEvaluation evaluation;
    int i;
    int descriptor_failure = 0;
    int registry_best_index = -1;
    int registry_best_severity = -1;
    memset(&evaluation, 0, sizeof(evaluation));
    if (edr_p0_rule_ir_evaluate_record(br, &evaluation)) {
      edr_p0_rule_observe_validation_stage(
          br, "matcher",
          p0_validation_target_matched(br, &evaluation) ? "target_match" : "target_no_match");
      /* A previously-retained source-only assertion has not crossed the
       * durable boundary yet. It is still safe (and necessary) to build a
       * ruleset-evaluation gate below on a new evaluator failure, but a
       * successfully evaluated rule may not create an alert or action while
       * a source-only fault in the same event family remains unresolved. */
      if (p0_is_ruleset_evaluation_event(br->type) &&
          !edr_p0_rule_source_only_capability_healthy_for_event(br->type, NULL, 0u)) {
        edr_p0_rule_observe_validation_stage(br, "family_gate", "source_only_pending");
        edr_p0_rule_ir_evaluation_free(&evaluation);
        return 0;
      }
      if (br->type == EDR_EVENT_REG_SET_VALUE || br->type == EDR_EVENT_REG_CREATE_KEY) {
        /* A single registry write can match both a canonical persistence rule
         * and an older ATT&CK compatibility rule.  Emit the strongest match
         * once instead of creating two alerts for the same evidence frame. */
        for (i = 0; i < (int)evaluation.match_count; ++i) {
          EdrP0RuleIrMatch match;
          if (!edr_p0_rule_ir_evaluation_get_match(&evaluation, (uint32_t)i, &match)) {
            descriptor_failure = 1;
            break;
          }
          if (match.severity > registry_best_severity) {
            registry_best_index = i;
            registry_best_severity = match.severity;
          }
        }
      }
      for (i = 0; !descriptor_failure && i < (int)evaluation.match_count; ++i) {
        EdrP0RuleIrMatch match;
        const char *rid;
        if (!edr_p0_rule_ir_evaluation_get_match(&evaluation, (uint32_t)i, &match)) {
          descriptor_failure = 1;
          break;
        }
        rid = match.rule_id;
        if (registry_best_index >= 0 && i != registry_best_index) {
          continue;
        }
        const char *known_fp_reason = "";
        if (!p0_should_suppress_known_false_positive(
                rid, br, detail, &known_fp_reason)) {
          known_fp_reason = "";
        }
        if (p0_debug_enabled()) {
          p0_debug_event(rid, br, pn, detail);
        }
        if (emit_for_rule(br, rid, match.severity,
                          match.title[0] ? match.title : rid,
                          match.mitre_csv, &evaluation.binding,
                          known_fp_reason)) {
          emitted_count++;
          edr_adaptive_collection_raise(match.severity, rid, br->pid, br->ppid,
                                        (pn && pn[0]) ? pn : br->process_name);
          fprintf(stderr, "[P0] IR rule emitted: rid=%s\n", rid);
        }
      }
      edr_p0_rule_ir_evaluation_free(&evaluation);
      if (!descriptor_failure) {
        return emitted_count;
      }
    }
    /* A currently-ready IR which could not be copied (for example, memory
     * pressure) is fail-closed: never mix a legacy rule with unknown active
     * authority.  Record the registered source-only gate before returning;
     * it intentionally has no rule/bundle/action claim. */
    if (p0_is_ruleset_evaluation_event(br->type) && edr_p0_rule_ir_is_ready()) {
      edr_p0_rule_observe_validation_stage(br, "matcher", "p0_ir_evaluation_unavailable");
      (void)emit_ruleset_evaluation_gate(br, "p0_ir_evaluation_unavailable");
      return 0;
    }
    if (p0_is_ruleset_evaluation_event(br->type)) {
      (void)emit_ruleset_evaluation_gate(br, "p0_ir_not_ready");
      return 0;
    }
  }
  return emitted_count;
}
