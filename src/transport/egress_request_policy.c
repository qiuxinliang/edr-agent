#include <stdatomic.h>
#include "edr/egress_request_policy.h"
#include "edr/egress_batch_policy.h"
#include "edr/p0_source_only_contract.h"
#include "cJSON.h"

#include <math.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef EDR_HAVE_ZSTD
#include <zstd.h>
#endif

/* Registered once by command ownership before workers start. Tests use the same
 * boundary to isolate durable authority from network I/O. */
static _Atomic(EdrEgressTaskScopeLookup) task_scope_lookup;
static _Atomic(EdrEgressUpgradeLogValidator) upgrade_log_validator;
void edr_egress_set_task_scope_lookup(EdrEgressTaskScopeLookup lookup) { atomic_store(&task_scope_lookup,lookup); }
void edr_egress_set_upgrade_log_validator(EdrEgressUpgradeLogValidator validator) { atomic_store(&upgrade_log_validator,validator); }
int edr_egress_is_policy_hold(int rc) {
  return rc == EDR_EGRESS_REQUEST_DENIED || rc == EDR_EGRESS_AUTHORIZATION_EXPIRED || rc == EDR_EGRESS_PAYLOAD_POLICY_HELD;
}
int edr_egress_task_preflight(EdrEgressPurpose purpose, const char *command_id,
                              EdrEgressTaskScope *out) {
  EdrEgressTaskScope scope = {0};
  if (out) memset(out, 0, sizeof(*out));
  if (purpose != EDR_EGRESS_UPGRADE_EVENT && purpose != EDR_EGRESS_UPGRADE_LOG &&
      purpose != EDR_EGRESS_UPGRADE_DOWNLOAD)
    return EDR_EGRESS_REQUEST_DENIED;
  EdrEgressTaskScopeLookup lookup=atomic_load(&task_scope_lookup);
  if (!command_id || !command_id[0] || !lookup) return EDR_EGRESS_REQUEST_DENIED;
  int rc = lookup(command_id, &scope);
  if (rc) return edr_egress_is_policy_hold(rc) ? rc : EDR_EGRESS_LOCAL_STATE_FAILURE;
  if (!scope.tenant_id[0] || !scope.endpoint_id[0] || !scope.task_id[0] ||
      strcmp(scope.command_id, command_id) || !scope.artifact_id[0] ||
      strlen(scope.artifact_sha256) != 64u || !scope.target_version[0] ||
      (strcmp(scope.operation, "upgrade") && strcmp(scope.operation, "rollback")) ||
      (purpose == EDR_EGRESS_UPGRADE_LOG && strcmp(scope.upgrade_class, "installer_required")))
    return EDR_EGRESS_REQUEST_DENIED;
  if (purpose == EDR_EGRESS_UPGRADE_DOWNLOAD && scope.execution_authorized != 1)
    return EDR_EGRESS_AUTHORIZATION_EXPIRED;
  if (out) *out = scope;
  return 0;
}
int edr_egress_upload_preflight(const char *command_id, const char *upload_id,
    const char *path, const char *sha256, uint64_t *expected_size) {
  if (expected_size) *expected_size = 0;
  EdrEgressTaskScope scope;
  int rc = edr_egress_task_preflight(EDR_EGRESS_UPGRADE_LOG, command_id, &scope);
  if (rc) return rc;
  EdrEgressUpgradeLogValidator validator=atomic_load(&upgrade_log_validator);
  if (!validator || !upload_id || !path || !sha256 || strlen(sha256) != 64u)
    return EDR_EGRESS_REQUEST_DENIED;
  uint64_t size = 0;
  rc = validator(&scope, upload_id, path, sha256, &size);
  if (rc) return edr_egress_is_policy_hold(rc) ? rc : EDR_EGRESS_LOCAL_STATE_FAILURE;
  if (!size || size > 1024u * 1024u) return EDR_EGRESS_REQUEST_DENIED;
  if (expected_size) *expected_size = size;
  return 0;
}

typedef enum { H_NUMBER, H_BOOL, H_TOKEN, H_STATUS, H_REASON, H_PROFILE,
  H_PROTOCOL, H_UINT, H_UPDATE_PROTOCOL, H_UPDATE_SOURCE, H_UPDATE_VERSION,
  H_SHA256, H_UPDATE_ERROR, H_INSTALLER_REASON } HealthType;
typedef struct { const char *path; HealthType type; } HealthField;
#define N(p) {"engine_health." p, H_NUMBER}
#define B(p) {"engine_health." p, H_BOOL}
#define T(p) {"engine_health." p, H_TOKEN}
#define S(p) {"engine_health." p, H_STATUS}
#define R(p) {"engine_health." p, H_REASON}
/* This is the authoritative health field list. Full and delta payloads use the
 * same paths. Paths, command lines, usernames, URLs and free-text errors are
 * deliberately absent. Diagnostic detail remains in the existing local owner. */
static const HealthField health_fields[] = {
  N("reported_at_unix_ms"),
  B("config_recovery.active"), B("config_recovery.safe_mode"),
  B("config_recovery.last_good_used"), B("config_recovery.auto_repaired"),
  N("config_recovery.fields_extracted"), S("config_recovery.mode"), R("config_recovery.reason"),
  {"engine_health.monitor.profile", H_PROFILE},
  B("monitor.enabled"), N("monitor.interval_s"), N("monitor.expires_at_unix_ms"),
  T("monitor.request_id"),
  B("communication.http_fallback"), N("communication.http_ok"), N("communication.http_fail"),
  N("communication.offline_queue_pending"), N("communication.last_success_unix_ms"),
  N("communication.last_failure_unix_ms"), R("communication.last_failure_reason"),
  N("communication.control_ack.ok"), N("communication.control_ack.fail"),
  N("communication.control_ack.pending"), B("communication.control_ack.pending_count_complete"),
  N("communication.control_ack.retry_attempt"), N("communication.control_ack.retry_ok"),
  N("communication.control_ack.retry_fail"), N("communication.control_ack.outbox_persist_fail"),
  N("communication.control_ack.last_failure_unix_ms"), N("communication.control_ack.next_retry_unix_ms"),
  B("communication.enterprise.mtls_configured"), S("communication.enterprise.mtls_status"),
  B("communication.enterprise.circuit_open"), N("communication.enterprise.circuit_until_unix_ms"),
  R("communication.enterprise.circuit_reason"), N("communication.enterprise.pending_upload_queue"),
  N("communication.enterprise.poll_backoff_ms"), N("communication.enterprise.ws_backoff_ms"),
  B("communication.enterprise.protocol.http2_enabled"), B("communication.enterprise.protocol.http2_required"),
  B("communication.enterprise.protocol.control_stream_enabled"),
  B("communication.enterprise.protocol.control_stream_ready"),
  B("communication.enterprise.protocol.control_stream_lease_valid"),
  N("communication.enterprise.protocol.control_stream_last_activity_unix_ms"),
  N("communication.enterprise.protocol.control_stream_lease_deadline_unix_ms"),
  N("communication.enterprise.protocol.control_stream_lease_expired"),
  S("communication.enterprise.protocol.control_stream_status"),
  {"engine_health.communication.enterprise.protocol.negotiated_protocol", H_PROTOCOL},
  B("communication.enterprise.protocol.long_poll_ready"),
  N("communication.enterprise.protocol.long_poll_last_success_unix_ms"),
  N("communication.enterprise.protocol.long_poll_last_failure_unix_ms"),
  B("command_delivery.executor.started"), B("command_delivery.executor.accepting"),
  {"engine_health.command_delivery.executor.live_workers", H_UINT},
  N("event_delivery.post_ok_count"), N("event_delivery.post_ok_body_bytes"),
  N("event_delivery.post_attempt_body_bytes"),
  N("event_bus.capacity"), N("event_bus.used"), N("event_bus.p0_reserved"),
  N("event_bus.ordinary_reserve_rejected"), N("event_bus.p0_reserve_rejected"),
  N("event_bus.pushed"), N("event_bus.dropped"), N("event_bus.high_water_hits"),
  N("resource.cpu_budget_percent"), N("resource.memory_budget_mb"),
  N("resource.behavior_infer_per_min"), N("resource.pmfe_scans_per_min"),
  N("resource.cpu_percent"), N("resource.cpu_percent_x100"),
  N("resource.cpu_avg_10s_x100"), N("resource.cpu_avg_60s_x100"),
  N("resource.rss_mb"), N("resource.current_rss_mb"), N("resource.thread_count"),
  N("resource.handle_count"), B("resource.throttle_active"), B("resource.pressure"),
  N("resource.pressure_level"), R("resource.pressure_reason"),
  B("p0_rule.enabled"), B("p0_rule.ready"), B("p0_rule.artifact_healthy"),
  T("p0_rule.rule_version"), N("p0_rule.rules_count"), T("p0_rule.artifact_sha256"),
  N("p0_rule.snapshot_epoch"), R("p0_rule.last_degrade_reason"),
  B("preprocessing_rules.enabled"), T("preprocessing_rules.rule_version"),
  N("preprocessing_rules.rules_count"), R("preprocessing_rules.last_degrade_reason"),
  B("p0_acceptance.source_only.terminal_unhealthy"),
  N("p0_acceptance.source_only.unhealthy_families_mask"), B("p0_acceptance.source_only.loss_detected"),
  N("p0_acceptance.source_only.retry_pending"), N("p0_acceptance.source_only.retry_committed"),
  R("p0_acceptance.source_only.reason"),
  N("p0_acceptance.dedup.suppressed_total"), N("p0_acceptance.dedup.exact_suppressed"),
  N("p0_acceptance.dedup.pre_rule_event_duplicates"), N("p0_acceptance.dedup.pending_backpressure"),
  B("p0_acceptance.evidence_cache.db_open"), N("p0_acceptance.evidence_cache.storage_format"),
  N("p0_acceptance.evidence_cache.utilization_bps"), N("p0_acceptance.evidence_cache.db_bytes"),
  N("p0_acceptance.evidence_cache.physical_bytes"), N("p0_acceptance.evidence_cache.max_db_mb"),
  N("p0_acceptance.evidence_cache.candidate_requests"),
  N("p0_acceptance.evidence_cache.candidate_admitted"), N("p0_acceptance.evidence_cache.candidate_rejected"),
  N("p0_acceptance.evidence_cache.accounting.pmfe_followup.scheduled"),
  N("p0_acceptance.evidence_cache.accounting.pmfe_followup.running"),
  N("p0_acceptance.evidence_cache.accounting.pmfe_followup.result_bound"),
  N("p0_acceptance.evidence_cache.accounting.pmfe_followup.result_acked_await_queue"),
  N("p0_acceptance.evidence_cache.accounting.pmfe_followup.active"),
  N("p0_acceptance.evidence_cache.accounting.pmfe_followup.expired"),
  N("p0_acceptance.evidence_cache.accounting.pmfe_followup.capacity"),
  N("p0_acceptance.evidence_cache.accounting.pmfe_followup.failures"),
  N("p0_acceptance.evidence_cache.accounting.pmfe_followup.cause_code"),
  N("p0_acceptance.evidence_cache.maintenance.metric_write_failures"),
  N("p0_acceptance.evidence_cache.maintenance.metric_unrecorded"),
  B("p0_acceptance.offline_queue.accounting_available"), N("p0_acceptance.offline_queue.utilization_bps"),
  N("p0_acceptance.offline_queue.used_bytes"), N("p0_acceptance.offline_queue.max_bytes"),
  N("p0_acceptance.offline_queue.pending_rows"), N("p0_acceptance.offline_queue.p0_source_only_rejected"),
  N("p0_acceptance.offline_queue.deferred_pending"), N("p0_acceptance.offline_queue.deferred_failed"),
  N("p0_acceptance.offline_queue.deferred_storage_failures"),
  B("p0_acceptance.offline_queue.deferred_retry_degraded"),
  N("p0_offline_queue_capacity.local_evidence_rows"),
  N("p0_offline_queue_capacity.policy_held_rows"),
  N("p0_offline_queue_capacity.used_bytes"), N("p0_offline_queue_capacity.retained_nonpending_bytes"),
  N("p0_offline_queue_capacity.max_bytes"), N("p0_offline_queue_capacity.utilization_bps"),
  N("p0_offline_queue_capacity.ordinary_rejected"), N("p0_offline_queue_capacity.high_priority_rejected"),
  N("p0_offline_queue_capacity.p0_source_only_rejected"),
  N("p0_offline_queue_capacity.event_queue_metadata_corruption_failures"),
  N("p0_offline_queue_capacity.pending_rows"), N("p0_offline_queue_capacity.accounting_available"),
  N("p0_offline_queue_capacity.enqueue.requests"), N("p0_offline_queue_capacity.enqueue.reused"),
  N("p0_offline_queue_capacity.enqueue.conflicts"), N("p0_offline_queue_capacity.enqueue.admitted"),
  N("p0_offline_queue_capacity.enqueue.capacity_rejected"),
  N("p0_offline_queue_capacity.enqueue.transaction_failures"),
  N("p0_offline_queue_capacity.enqueue.commit_failures"),
  N("p0_offline_queue_capacity.delivery.receipt_failures"),
  N("p0_offline_queue_capacity.delivery.selected"), N("p0_offline_queue_capacity.delivery.sent"),
  N("p0_offline_queue_capacity.delivery.acked"), N("p0_offline_queue_capacity.delivery.requeued"),
  N("p0_offline_queue_capacity.delivery.failed"), N("p0_offline_queue_capacity.delivery.resource_deferred"),
  N("p0_source_only_durability.retry_pending"), N("p0_source_only_durability.retry_attempts"),
  N("p0_source_only_durability.retry_committed"), N("p0_source_only_durability.retry_capacity_exhausted"),
  B("p0_source_only_durability.terminal_unhealthy"), N("p0_source_only_durability.unhealthy_families_mask"),
  R("p0_source_only_durability.reason"), B("p0_artifact_recovery.healthy"), R("p0_artifact_recovery.reason"),
  N("p0_queue_dead_letter"), N("p0_dedup.suppressed_total"), N("p0_dedup.exact_suppressed"),
  N("p0_dedup.pre_rule_event_duplicates"), N("p0_dedup.pending_backpressure"),
  N("p0_enforcement_admission.critical_reservations"), N("p0_enforcement_admission.governor_suppressed"),
  N("p0_enforcement_admission.source_only_backpressure_emitted"),
  N("p0_enforcement_admission.source_only_backpressure_failed"),
  N("p0_enforcement_terminal_journal.pending"), N("p0_enforcement_terminal_journal.backpressure"),
  N("p0_enforcement_terminal_journal.failed"), N("p0_enforcement_terminal_journal.outcome_unknown"),
  N("p0_enforcement_terminal_journal.replay_selection_transient_failures"),
  N("p0_enforcement_terminal_journal.replay_metadata_corruption_failures"),
  N("p0_enforcement_terminal_journal.precreate_metadata_corruption_failures"),
  N("p0_enforcement_terminal_journal.owner_metadata_unresolved"),
  N("process_evidence_worker.backpressure"), N("process_evidence_worker.misses"),
  N("process_evidence_worker.wait_timeouts"), N("process_evidence_worker.queue_deadlines"),
  N("process_evidence_worker.terminal_unhealthy"), N("process_evidence_worker.worker_stalled"),
  N("correlation.enabled"), N("correlation.loaded"), T("correlation.bundle"), N("correlation.rules"),
  N("correlation.active_states"), N("correlation.observed"), N("correlation.evaluated"),
  N("correlation.fired"), N("correlation.suppressed"), N("correlation.evicted"),
  N("correlation.inject_fed"), N("correlation.inject_dropped"), N("correlation.rate_dropped"),
  T("egress.policy_version"), B("egress.task_results_supported"), B("egress.result_delivery_renewal_supported"), N("egress.denied_requests"),
  B("egress.capacity_limit_defaulted"),
  N("egress.policy_held_rows"), N("egress.local_evidence_rows"), R("egress.last_reason"),
  N("egress.terminal_policy_held_frames"), N("egress.terminal_local_retained"), N("egress.legacy_owner_unacknowledged"),
  N("egress.retained_unresolved_rows"), N("egress.projection_pending_rows"), N("egress.projection_acked_rows"),
  B("sensor_health.etw_or_inotify_enabled"), B("sensor_health.powershell_visible"),
  B("sensor_health.amsi_visible"), B("sensor_health.security_audit_visible"),
  B("sensor_health.security_subscription_ready"),
  /* Runtime commitments support diagnostic-lease acceptance without sending
   * rule selectors, paths, command lines or collected event detail. */
  B("sensor_health.sensor_interest.enabled"), B("sensor_health.sensor_interest.loaded"),
  T("sensor_health.sensor_interest.version"), T("sensor_health.sensor_interest.rules_version"),
  B("sensor_health.sensor_interest.full_admission.file_read"),
  B("sensor_health.sensor_interest.full_admission.file_write"),
  B("sensor_health.sensor_interest.full_admission.registry_set"),
  B("sensor_health.sensor_interest.full_admission.contract_valid"),
  B("sensor_health.sensor_interest.full_admission.p0_binding_valid"),
  {"engine_health.sensor_health.sensor_interest.p0_artifact_sha256", H_SHA256},
  {"engine_health.sensor_health.sensor_interest.p0_rule_coverage_sha256", H_SHA256},
  {"engine_health.sensor_health.sensor_interest.manifest_sha256", H_SHA256},
  T("sensor_health.sensor_interest.manifest_hash_mode"),
  {"engine_health.sensor_health.sensor_interest.p0_artifact_rule_count", H_UINT},
  N("sensor_health.sensor_interest.snapshot_epoch"),
  N("sensor_health.etw_callbacks.total"), N("sensor_health.etw_callbacks.process"),
  N("sensor_health.etw_callbacks.file"), N("sensor_health.etw_callbacks.network"),
  N("sensor_health.etw_callbacks.registry"), N("sensor_health.etw_callbacks.prefilter_dropped"),
  N("sensor_health.file_read_collection.name_bindings"),
  N("sensor_health.file_read_collection.name_cache_misses"),
  N("sensor_health.file_read_collection.critical_binding_capacity_exhausted"),
  N("sensor_health.file_read_collection.generation_unavailable"),
  N("sensor_health.file_read_collection.actor_generation_unavailable"),
  B("sensor_health.file_read_collection.metadata_gate.healthy"),
  R("sensor_health.file_read_collection.metadata_gate.reason"),
  N("sensor_health.file_read_collection.metadata_gate.staged"),
  N("sensor_health.file_read_collection.metadata_gate.coalesced"),
  N("sensor_health.file_read_collection.metadata_gate.enqueue_attempts"),
  N("sensor_health.file_read_collection.metadata_gate.queue_rejected"),
  N("sensor_health.file_read_collection.metadata_gate.durable_successes"),
  N("sensor_health.file_read_collection.metadata_gate.durable_failures"),
  N("sensor_health.file_read_collection.metadata_gate.retry_attempts"),
  N("sensor_health.file_read_collection.metadata_gate.paused_events"),
  N("sensor_health.file_read_collection.metadata_gate.epoch_restart_attempts"),
  N("sensor_health.file_read_collection.metadata_gate.epoch_restart_successes"),
  N("sensor_health.file_read_collection.metadata_gate.epoch_restart_failures"),
  N("sensor_health.file_read_collection.metadata_gate.recovery_episodes"),
  N("sensor_health.file_read_collection.metadata_gate.post_reset_recovery.bindings"),
  N("sensor_health.file_read_collection.metadata_gate.post_reset_recovery.failures"),
  R("sensor_health.file_read_collection.metadata_gate.post_reset_recovery.reason"),
  N("sensor_health.process_identity.missing_create"),
  N("sensor_health.process_identity.collector_cache_hits"),
  N("sensor_health.process_identity.collector_cache_misses"),
  N("sensor_health.process_identity.snapshot_hits"), N("sensor_health.process_identity.snapshot_misses"),
  N("sensor_health.process_identity.snapshot_rejects"),
  B("ave.enabled"), N("ave.queue_depth"), N("ave.queue_capacity"),
  N("ave.infer_ok"), N("ave.infer_fail"), N("ave.infer_budget_dropped"),
  R("ave.last_degrade_reason"),
  B("detection_readiness.behavior_monitor_enabled"), B("detection_readiness.behavior_monitor_running"),
  B("detection_readiness.ioc_precheck_enabled"), B("detection_readiness.ioc_db_configured"),
  T("detection_readiness.ioc_rules_version"), B("detection_readiness.pmfe_budget_configured"),
  B("detection_readiness.shellcode_configured"), B("detection_readiness.webshell_configured"),
  B("pmfe.enabled"), N("pmfe.queue_depth"), N("pmfe.submitted"), N("pmfe.completed"),
  N("pmfe.dropped"), N("pmfe.active"), N("pmfe.failed"), R("pmfe.last_degrade_reason"),
  B("shellcode.configured"), B("shellcode.enabled"), S("shellcode.runtime_status"),
  N("shellcode.receive_errors"), N("shellcode.scan_queue_dropped"), R("shellcode.last_degrade_reason"),
  B("webshell.configured"), B("webshell.enabled"), B("webshell.policy_enabled"),
  B("webshell.code_supported"), B("webshell.build_supported"), S("webshell.runtime_status"),
  R("webshell.last_degrade_reason"),
  N("health_upload.full_count"), N("health_upload.delta_count"), N("health_upload.resync_count"),
  N("health_upload.attempt_body_bytes"), N("health_upload.equivalent_full_body_bytes"),
  T("capability_manifest.schema"), T("capability_manifest.platform"),
  T("capability_manifest.architecture"), T("capability_manifest.native_architecture"),
  B("capability_manifest.emulated"),
  N("capability_manifest.telemetry.alert_governor.admitted"),
  N("capability_manifest.telemetry.alert_governor.suppressed"),
  N("capability_manifest.telemetry.alert_governor.summaries"),
  N("capability_manifest.telemetry.alert_governor.critical_bypassed")
};
#undef N
#undef B
#undef T
#undef S
#undef R

static _Atomic(EdrEgressCommandResultValidator) command_result_validator;
void edr_egress_set_command_result_validator(EdrEgressCommandResultValidator validator) {
  atomic_store_explicit(&command_result_validator, validator, memory_order_release);
}

static int deny(char *reason, size_t cap, const char *cause) {
  if (reason && cap) snprintf(reason, cap, "%s", cause);
  return EDR_EGRESS_REQUEST_DENIED;
}
static int token_string(const char *value, size_t max) {
  if (!value || strlen(value) > max) return 0;
  const unsigned char *p = (const unsigned char *)value;
  for (; *p; ++p) if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                        (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')) return 0;
  return 1;
}
static int token(const cJSON *v, size_t max) {
  return cJSON_IsString(v) && token_string(v->valuestring, max);
}
static int listed(const char *s, const char *const *values, size_t count) {
  for (size_t i = 0; i < count; ++i) if (strcmp(s, values[i]) == 0) return 1;
  return 0;
}
static int health_reason(const char *value) {
  /* Reuse the source-only owner's closed cause contract. Merely containing a
   * cause word does not qualify: arbitrary detail is retained locally. */
  static const char *const causes[] = {
    "", "detail_available_locally", "artifact_journal_recovery_failed",
    "source_only_restart_recovery_required", "source_only_durable_unavailable",
    "source_only_identity_unavailable", "source_only_latch_prepare_failed",
    "source_only_latch_state_unavailable", "source_only_legacy_ack_compatibility_pending",
    "source_only_local_recovery_probe_pending", "source_only_loss_audit_identity_unavailable",
    "source_only_pending", "source_only_queue_unavailable", "source_only_recovery_ir_unavailable",
    "source_only_recovery_latch_prepare_failed", "source_only_recovery_pending",
    "source_only_restart_recovery_failed", "source_only_retry_capacity_exhausted",
    "source_only_collector_gate_pending", "source_only_collector_record_invalid",
    "source_only_assertion_unresolved", "source_only_delivery_unresolved",
    "source_only_corrupt_wire", "source_only_invalid_wire_header",
    "source_only_invalid_batch_id_metadata", "source_only_corrupt_payload",
    "legacy_owner_digest_unrecoverable", "queue_capacity_exhausted",
    "logical_capacity_accounting_unavailable", "governor_suppressed",
    "alert_governor", "policy_denied", "rate_limited", "rules_unavailable",
    "file_read_metadata_subject_unavailable", "file_read_metadata_reason_unavailable",
    "file_read_metadata_path_commitment_unavailable", "file_read_metadata_event_identity_unavailable",
    "file_read_metadata_slot_capacity", "file_read_metadata_event_bus_unavailable",
    "file_read_metadata_durable_unavailable", "file_read_metadata_epoch_restart_limit_reached",
    "file_read_metadata_epoch_restart_failed", "file_read_metadata_epoch_restart_join_timeout",
    "file_read_metadata_consumer_open_trace_failed", "file_read_metadata_consumer_terminated",
    "file_read_metadata_session_allocation_failed", "file_read_metadata_start_trace_failed",
    "file_read_metadata_provider_enable_failed", "file_read_metadata_consumer_ready_event_failed",
    "file_read_metadata_consumer_thread_failed", "file_read_metadata_consumer_not_ready",
    "file_read_metadata_new_session_degraded", "file_read_metadata_session_reset_required",
    "file_read_metadata_post_reset_degraded", "file_read_metadata_post_reset_exact_binding_pending",
    "file_read_critical_binding_capacity_recovery_pending", "file_read_metadata_durable_pending",
    "alert_provenance_unavailable", "source_only_requires_local_owner_v3",
    "p0_pair_durable_alert_owner_unavailable",
    "unknown_or_invalid_event_schema", "event_purpose_unknown", "event_decode_failed",
    "detection_context_invalid", "frame_size_invalid", "unknown_outbound_purpose"
  };
  return value && (edr_p0_source_only_reason_find(value) != NULL ||
      listed(value, causes, sizeof(causes) / sizeof(causes[0])));
}
static int valid_value(const cJSON *v, HealthType type) {
  static const char *const statuses[] = {"", "normal", "last_good", "safe_mode", "recovered", "healthy",
    "degraded", "disabled", "unavailable", "idle", "unknown", "unsupported", "not_configured",
    "configured", "ready", "pending", "connected", "connected_pending_hello", "disconnected",
    "connecting_h2", "h2_failed", "h2_unavailable", "h2_unavailable_no_http1_fallback", "ok"};
  if (type == H_PROFILE) return cJSON_IsString(v) && v->valuestring &&
      (!strcmp(v->valuestring, "basic") || !strcmp(v->valuestring, "diagnostic"));
  if (type == H_BOOL) return cJSON_IsBool(v);
  if (type == H_NUMBER || type == H_UINT || type == H_UPDATE_PROTOCOL) {
    double max = type == H_UINT ? (double)UINT_MAX :
        type == H_UPDATE_PROTOCOL ? (double)INT_MAX : 9007199254740991.0;
    return cJSON_IsNumber(v) && isfinite(v->valuedouble) && v->valuedouble >= 0 &&
        v->valuedouble <= max && floor(v->valuedouble) == v->valuedouble;
  }
  if (type == H_TOKEN) return token(v, 160u);
  if (type == H_UPDATE_VERSION) return token(v, 64u);
  if (!cJSON_IsString(v) || !v->valuestring) return 0;
  if (type == H_PROTOCOL) return !strcmp(v->valuestring, "h2") ||
      !strcmp(v->valuestring, "http/1.1") || !strcmp(v->valuestring, "");
  if (type == H_SHA256) {
    size_t len = strlen(v->valuestring);
    if (!len) return 1; /* Unavailable owners report an empty commitment. */
    if (len != 64u) return 0;
    for (size_t i = 0; i < len; ++i)
      if (!isxdigit((unsigned char)v->valuestring[i])) return 0;
    return 1;
  }
  if (type == H_UPDATE_SOURCE) {
    static const char *const sources[] = {"", "embedded", "installed_sidecar",
      "configured_sidecar", "unavailable", "unsupported"};
    return listed(v->valuestring, sources, sizeof(sources) / sizeof(sources[0]));
  }
  if (type == H_UPDATE_ERROR || type == H_INSTALLER_REASON) {
    /* Closed causes emitted by agent_update_command/full_installer_readiness.
     * Unknown diagnostics must remain nonempty: the consumer treats empty
     * updater_error_code as success and one exact baseline cause as repairable. */
    static const char *const errors[] = {"", "detail_available_locally", "non_windows",
      "updater_unavailable", "embedded_module_unavailable", "embedded_resource_lookup_failed",
      "embedded_resource_read_failed", "embedded_resource_hash_failed", "embedded_module_path_failed",
      "embedded_module_directory_failed", "embedded_materialized_path_too_long",
      "embedded_temporary_path_too_long", "embedded_output_path_too_long",
      "embedded_materialize_open_failed", "embedded_materialize_commit_failed",
      "embedded_materialized_hash_mismatch", "installed_sidecar_unreadable",
      "configured_sidecar_unreadable", "embedded_and_sidecar_missing"};
    static const char *const baseline[] = {"ready", "platform_unsupported",
      "updater_protocol_below_full_installer_baseline", "installation_directory_unavailable",
      "probe_dependencies_unavailable", "installation_baseline_missing_FDSensor.exe",
      "installation_baseline_missing_agent.toml", "installation_baseline_missing_unins000.exe",
      "installation_baseline_missing_unins000.dat", "agent_config_unreadable",
      "uninstaller_provenance_missing_or_mismatch", "current_module_identity_mismatch",
      "installation_identity_mismatch", "installation_identity_conflict"};
    return listed(v->valuestring, errors, sizeof(errors) / sizeof(errors[0])) ||
        (type == H_INSTALLER_REASON && listed(v->valuestring, baseline, sizeof(baseline) / sizeof(baseline[0])));
  }
  if (type == H_REASON) return health_reason(v->valuestring);
  return listed(v->valuestring, statuses, sizeof(statuses) / sizeof(statuses[0]));
}

/* Capability names and leaf fields are both closed sets. They describe local
 * runtime availability, not a permission to send command results/artifacts. */
static int capability_field(const char *path, HealthType *type) {
  /* The upgrade dispatcher and completion owner consume these attestations.
   * They do not authorize result payloads or apply to other command manifests. */
  static const HealthField upgrade_fields[] = {
    {"updater_source", H_UPDATE_SOURCE}, {"updater_version", H_UPDATE_VERSION},
    {"updater_sha256", H_SHA256}, {"updater_protocol_version", H_UPDATE_PROTOCOL},
    {"updater_materialized", H_BOOL}, {"updater_error_code", H_UPDATE_ERROR},
    {"runtime_identity_sha256", H_SHA256}, {"full_installer_ready", H_BOOL},
    {"full_installer_reason", H_INSTALLER_REASON}
  };
  static const char *const features[] = {"pcre2", "yara", "shellcode_network", "webshell", "pmfe",
    "onnxruntime", "sqlite", "http2", "zstd", "velociraptor", "artifact_upload", "command_signing"};
  static const char *const commands[] = {"isolate_host", "restore_host", "kill_process", "rtq_execute",
    "rtq_registry", "rtq_eventlog", "yara_scan", "memory_dump", "targeted_forensic", "targeted_forensic_file",
    "targeted_forensic_process", "targeted_forensic_registry", "targeted_forensic_memory", "agent_update_v1",
    "endpoint_lifecycle_v1", "endpoint_uninstall_attestation_v1", "velociraptor_query", "result_delivery_renewal"};
  const char *p = NULL;
  const char *prefix = "engine_health.capability_manifest.features.";
  const char *const *names = features;
  size_t count = sizeof(features) / sizeof(features[0]);
  if (strncmp(path, prefix, strlen(prefix)) == 0) p = path + strlen(prefix);
  else {
    prefix = "engine_health.capability_manifest.commands.";
    if (strncmp(path, prefix, strlen(prefix)) != 0) return 0;
    p = path + strlen(prefix); names = commands; count = sizeof(commands) / sizeof(commands[0]);
  }
  const char *dot = strchr(p, '.');
  if (!dot || (size_t)(dot - p) >= 64u) return 0;
  char name[64]; memcpy(name, p, (size_t)(dot - p)); name[dot - p] = 0;
  if (!listed(name, names, count)) return 0;
  ++dot;
  if (names == commands && !strcmp(name, "agent_update_v1")) {
    for (size_t i = 0; i < sizeof(upgrade_fields) / sizeof(upgrade_fields[0]); ++i)
      if (!strcmp(dot, upgrade_fields[i].path)) { *type = upgrade_fields[i].type; return 1; }
  }
  if (strcmp(dot, "code_supported") == 0 || strcmp(dot, "build_supported") == 0 ||
      strcmp(dot, "policy_enabled") == 0 || strcmp(dot, "rules_ready") == 0 ||
      strcmp(dot, "artifact_upload_required") == 0 || strcmp(dot, "request_signing_configured") == 0) {
    *type = H_BOOL; return 1;
  }
  if (strcmp(dot, "runtime_status") == 0) { *type = H_STATUS; return 1; }
  if (strcmp(dot, "rules_count") == 0) { *type = H_NUMBER; return 1; }
  return 0;
}
static int field_type(const char *path, HealthType *type) {
  for (size_t i = 0; i < sizeof(health_fields) / sizeof(health_fields[0]); ++i) {
    if (strcmp(path, health_fields[i].path) == 0) { *type = health_fields[i].type; return 1; }
  }
  return capability_field(path, type);
}
static int validate_health_node(const cJSON *v, const char *path, unsigned depth) {
  if (depth > 10u) return 0;
  if (cJSON_IsObject(v)) {
    const cJSON *child;
    if (!v->child) return 0;
    cJSON_ArrayForEach(child, v) {
      char next[256];
      int n = snprintf(next, sizeof(next), "%s.%s", path, child->string ? child->string : "");
      if (n < 0 || (size_t)n >= sizeof(next) || !validate_health_node(child, next, depth + 1u)) return 0;
    }
    return 1;
  }
  HealthType type;
  return field_type(path, &type) && valid_value(v, type);
}
static cJSON *project_node(const cJSON *v, const char *path, unsigned depth, int *allocation_failed) {
  if (depth > 10u) return NULL;
  HealthType type;
  if (field_type(path, &type) && (type == H_UPDATE_ERROR || type == H_INSTALLER_REASON)) {
    cJSON *out = cJSON_CreateString(valid_value(v, type) ? v->valuestring : "detail_available_locally");
    if (!out) *allocation_failed = 1;
    return out;
  }
  if (cJSON_IsObject(v)) {
    cJSON *out = cJSON_CreateObject();
    if (!out) { *allocation_failed = 1; return NULL; }
    const cJSON *child;
    cJSON_ArrayForEach(child, v) {
      char next[256];
      int n = snprintf(next, sizeof(next), "%s.%s", path, child->string ? child->string : "");
      if (n < 0 || (size_t)n >= sizeof(next)) continue;
      cJSON *copy = project_node(child, next, depth + 1u, allocation_failed);
      if (*allocation_failed || (copy && !cJSON_AddItemToObject(out, child->string, copy))) {
        *allocation_failed = 1; cJSON_Delete(copy); cJSON_Delete(out); return NULL;
      }
    }
    if (!out->child) { cJSON_Delete(out); return NULL; }
    return out;
  }
  if (!field_type(path, &type)) return NULL;
  cJSON *out = NULL;
  if (type == H_REASON && cJSON_IsString(v))
    out = cJSON_CreateString(health_reason(v->valuestring) ? v->valuestring : "detail_available_locally");
  else if (type == H_STATUS && cJSON_IsString(v) && !valid_value(v, type)) out = cJSON_CreateString("unknown");
  else if (valid_value(v, type)) out = cJSON_Duplicate(v, 1);
  else return NULL;
  if (!out) *allocation_failed = 1;
  return out;
}
static int identities(const cJSON *root) {
  const char *const keys[] = {"endpoint_id", "agent_version", "policy_version"};
  for (size_t i = 0; i < 3u; ++i) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, keys[i]);
    if (!token(v, 160u) || !v->valuestring[0]) return 0;
  }
  return 1;
}
static int health_json_valid(const cJSON *root, int delta) {
  if (!identities(root)) return 0;
  const cJSON *v;
  cJSON_ArrayForEach(v, root) {
    if (strcmp(v->string, "endpoint_id") && strcmp(v->string, "agent_version") &&
        strcmp(v->string, "policy_version") && strcmp(v->string, "engine_health") &&
        (!delta || strcmp(v->string, "engine_health_update"))) return 0;
  }
  const cJSON *health = cJSON_GetObjectItemCaseSensitive(root, "engine_health");
  if (!cJSON_IsObject(health) || (health->child && !validate_health_node(health, "engine_health", 0u))) return 0;
  const cJSON *update = cJSON_GetObjectItemCaseSensitive(root, "engine_health_update");
  if (!delta) return health->child && update == NULL;
  if (!cJSON_IsObject(update)) return 0;
  const cJSON *version = cJSON_GetObjectItemCaseSensitive(update, "version");
  const cJSON *base = cJSON_GetObjectItemCaseSensitive(update, "base");
  const cJSON *removed = cJSON_GetObjectItemCaseSensitive(update, "removed");
  if (!cJSON_IsNumber(version) || (version->valuedouble != 1.0 && version->valuedouble != 2.0) || !token(base, 64u) ||
      !base->valuestring[0] || !cJSON_IsArray(removed) || cJSON_GetArraySize(removed) > 64) return 0;
  if (!health->child && !removed->child) return 0;
  cJSON_ArrayForEach(v, update)
    if (strcmp(v->string, "version") && strcmp(v->string, "base") && strcmp(v->string, "removed")) return 0;
  cJSON_ArrayForEach(v, removed) {
    if (version->valuedouble==2.0) {
      if (!cJSON_IsString(v) || !v->valuestring || v->valuestring[0]!='/' || strlen(v->valuestring)>240u) return 0;
      /* Current health keys are closed ASCII identifiers. No escaped or
       * arbitrary dictionary keys are admitted by the health schema. */
      char path[256]="engine_health"; size_t used=strlen(path);unsigned depth=0;
      const cJSON *change=health; const char *cursor=v->valuestring;
      while (*cursor) {
        if (*cursor++!='/' || ++depth>10u) return 0;
        char key[96];size_t n=0;
        while (*cursor && *cursor!='/') {
          if (!( (*cursor>='a'&&*cursor<='z') || (*cursor>='A'&&*cursor<='Z') ||
              (*cursor>='0'&&*cursor<='9') || *cursor=='_') || n+1>=sizeof(key)) return 0;
          key[n++]=*cursor++;
        }
        if (!n || used+n+2>=sizeof(path)) return 0;
        key[n]=0;path[used++]='.';memcpy(path+used,key,n+1);used+=n;
        if (change) {
          if (!cJSON_IsObject(change) || (depth>1u && !change->child)) return 0;
          change=cJSON_GetObjectItemCaseSensitive(change,key);
        }
      }
      if (change) return 0; /* changed and removed paths must not overlap */
      int known=0;HealthType ignored;
      if (field_type(path,&ignored)) known=1;
      for(size_t i=0;i<sizeof(health_fields)/sizeof(health_fields[0]);i++)
        if (!strncmp(health_fields[i].path,path,used) && health_fields[i].path[used]=='.') known=1;
      if (!known) return 0;
      for(const cJSON *other=v->next;other;other=other->next) {
        if(!cJSON_IsString(other)||!other->valuestring)return 0;
        size_t a=strlen(v->valuestring),b=strlen(other->valuestring),n=a<b?a:b;
        if(!strncmp(v->valuestring,other->valuestring,n) && (a==b || v->valuestring[n]=='/' || other->valuestring[n]=='/')) return 0;
      }
      continue;
    }
    if (!token(v, 64u) || !v->valuestring[0]) return 0;
    char path[100]; snprintf(path, sizeof(path), "engine_health.%s.", v->valuestring);
    int known = 0;
    for (size_t i = 0; i < sizeof(health_fields) / sizeof(health_fields[0]); ++i)
      if (strncmp(health_fields[i].path, path, strlen(path)) == 0) known = 1;
    HealthType ignored;
    snprintf(path, sizeof(path), "engine_health.%s", v->valuestring);
    if (!known && !field_type(path, &ignored)) return 0;
  }
  return 1;
}
char *edr_egress_health_project(const char *body, char *reason, size_t cap) {
  int allocation_failed = 0;
  if (reason && cap) reason[0] = 0;
  if (!body || strlen(body) > 131072u) { deny(reason, cap, "health_input_limit"); return NULL; }
  cJSON *root = edr_egress_parse_purpose_object(body, strlen(body));
  cJSON *out = cJSON_CreateObject();
  if (!out) allocation_failed = 1;
  if (!root || !out || !identities(root) || cJSON_GetObjectItemCaseSensitive(root, "engine_health_update")) goto fail;
  const cJSON *health = cJSON_GetObjectItemCaseSensitive(root, "engine_health");
  if (!cJSON_IsObject(health)) goto fail;
  const char *const keys[] = {"endpoint_id", "agent_version", "policy_version"};
  for (size_t i = 0; i < 3u; ++i) {
    cJSON *copy = cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(root, keys[i]), 1);
    if (!copy || !cJSON_AddItemToObject(out, keys[i], copy)) { allocation_failed = 1; cJSON_Delete(copy); goto fail; }
  }
  cJSON *copy = project_node(health, "engine_health", 0u, &allocation_failed);
  if (!copy || !cJSON_AddItemToObject(out, "engine_health", copy)) { if (copy) allocation_failed = 1; cJSON_Delete(copy); goto fail; }
  char *wire = cJSON_PrintUnformatted(out);
  cJSON_Delete(root); cJSON_Delete(out);
  if (!wire || strlen(wire) > EDR_EGRESS_HEALTH_MAX_BYTES) { deny(reason, cap, wire ? "health_output_limit" : "health_projection_allocation_failed"); free(wire); return NULL; }
  return wire;
fail:
  cJSON_Delete(root); cJSON_Delete(out); deny(reason, cap, allocation_failed ? "health_projection_allocation_failed" : "health_schema_or_identity_invalid"); return NULL;
}

static int b64_value(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}
static uint8_t *decode_base64(const char *s, size_t *len) {
  size_t n = strlen(s);
  if (!n || n % 4u || n > EDR_EGRESS_BATCH_WIRE_MAX_BYTES) return NULL;
  uint8_t *out = malloc(n / 4u * 3u);
  if (!out) return NULL;
  size_t used = 0;
  for (size_t i = 0; i < n; i += 4u) {
    int a = b64_value((unsigned char)s[i]), b = b64_value((unsigned char)s[i + 1u]);
    int c = s[i + 2u] == '=' ? 0 : b64_value((unsigned char)s[i + 2u]);
    int d = s[i + 3u] == '=' ? 0 : b64_value((unsigned char)s[i + 3u]);
    int pad = s[i + 2u] == '=' ? 2 : s[i + 3u] == '=' ? 1 : 0;
    if (a < 0 || b < 0 || c < 0 || d < 0 || (pad && i + 4u != n) ||
        (pad == 2 && s[i + 3u] != '=') || (pad == 2 && (b & 15)) || (pad == 1 && (c & 3))) {
      free(out); return NULL;
    }
    out[used++] = (uint8_t)((a << 2) | (b >> 4));
    if (pad < 2) out[used++] = (uint8_t)((b << 4) | (c >> 2));
    if (pad < 1) out[used++] = (uint8_t)((c << 6) | d);
  }
  *len = used; return out;
}
static int validate_raw_batch(const uint8_t *raw, size_t len,const char *tenant,
    const char *endpoint,char *reason, size_t cap) {
  if (!raw || len <= 12u) return deny(reason, cap, "batch_envelope_invalid");
  int valid=(tenant || endpoint)?edr_egress_batch_validate_scope(raw,12u,raw+12u,len-12u,
      tenant,endpoint,reason,cap):edr_egress_batch_validate(raw,12u,raw+12u,len-12u,reason,cap);
  return valid
      ? 0 : EDR_EGRESS_REQUEST_DENIED;
}
static int validate_json_batch(const cJSON *root,const char *tenant,const char *endpoint,
    char *reason, size_t cap) {
  const cJSON *v;
  cJSON_ArrayForEach(v, root)
    if (strcmp(v->string, "endpoint_id") && strcmp(v->string, "batch_id") &&
        strcmp(v->string, "agent_version") && strcmp(v->string, "payload"))
      return deny(reason, cap, "batch_envelope_field_denied");
  const char *const keys[] = {"endpoint_id", "batch_id", "agent_version"};
  for (size_t i = 0; i < 3u; ++i) {
    v = cJSON_GetObjectItemCaseSensitive(root, keys[i]);
    if (!token(v, 160u) || !v->valuestring[0]) return deny(reason, cap, "batch_envelope_identity_invalid");
  }
  if (endpoint && strcmp(cJSON_GetObjectItemCaseSensitive(root,"endpoint_id")->valuestring,endpoint))
    return deny(reason,cap,"batch_envelope_scope_mismatch");
  v = cJSON_GetObjectItemCaseSensitive(root, "payload");
  if (!cJSON_IsString(v) || !v->valuestring) return deny(reason, cap, "batch_envelope_invalid");
  size_t len = 0;
  uint8_t *raw = decode_base64(v->valuestring, &len);
  int rc = validate_raw_batch(raw, len,tenant,endpoint, reason, cap);
  free(raw); return rc;
}
static int varint(const uint8_t *data, size_t len, size_t *off, uint64_t *value) {
  *value = 0;
  for (unsigned shift = 0; shift < 64u && *off < len; shift += 7u) {
    uint8_t b = data[(*off)++];
    if (shift == 63u && (b & 0xfeu)) return 0;
    *value |= (uint64_t)(b & 0x7fu) << shift;
    if (!(b & 0x80u)) return 1;
  }
  return 0;
}
static int validate_proto_batch(const void *body, size_t len,const char *tenant,const char *endpoint,
    char *reason, size_t cap) {
  const uint8_t *data = body, *fields[10] = {0};
  size_t sizes[10] = {0}, off = 0;
  unsigned seen = 0;
  while (off < len) {
    uint64_t key, size;
    if (!varint(data, len, &off, &key) || (key & 7u) != 2u || key >> 3u < 1u || key >> 3u > 9u ||
        !varint(data, len, &off, &size) || size > len - off) return deny(reason, cap, "batch_envelope_invalid");
    unsigned field = (unsigned)(key >> 3u);
    if (seen & (1u << field)) return deny(reason, cap, "batch_envelope_duplicate_field");
    seen |= 1u << field; fields[field] = data + off; sizes[field] = (size_t)size; off += (size_t)size;
  }
  if (!fields[1] || sizes[1] != strlen("edr.transport.envelope.v1") ||
      memcmp(fields[1], "edr.transport.envelope.v1", sizes[1]) || !fields[2] || !sizes[2] ||
      !fields[3] || !sizes[3] || !fields[4] || !sizes[4] || !fields[8] || !fields[9])
    return deny(reason, cap, "batch_envelope_version_or_identity_invalid");
  for (unsigned i = 2; i <= 7u; ++i) {
    if (sizes[i] > 160u) return deny(reason, cap, "batch_envelope_identity_invalid");
    for (size_t j = 0; j < sizes[i]; ++j) {
      unsigned char c = fields[i][j];
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
          c == '_' || c == '-' || c == '.')) return deny(reason, cap, "batch_envelope_identity_invalid");
    }
  }
  if (endpoint && (sizes[2]!=strlen(endpoint) || memcmp(fields[2],endpoint,sizes[2])))
    return deny(reason,cap,"batch_envelope_scope_mismatch");
  if (sizes[8] == 8u && !memcmp(fields[8], "identity", 8u))
    return validate_raw_batch(fields[9], sizes[9],tenant,endpoint, reason, cap);
  if (sizes[8] != 4u || memcmp(fields[8], "zstd", 4u)) return deny(reason, cap, "batch_envelope_codec_unknown");
#ifdef EDR_HAVE_ZSTD
  unsigned long long raw_len = ZSTD_getFrameContentSize(fields[9], sizes[9]);
  if (raw_len == ZSTD_CONTENTSIZE_ERROR || raw_len == ZSTD_CONTENTSIZE_UNKNOWN ||
      raw_len > 4u * 1024u * 1024u + 12u) return deny(reason, cap, "batch_envelope_compression_limit");
  uint8_t *raw = malloc((size_t)raw_len);
  if (!raw) return deny(reason, cap, "batch_envelope_allocation_failed");
  size_t got = ZSTD_decompress(raw, (size_t)raw_len, fields[9], sizes[9]);
  int rc = ZSTD_isError(got) || got != raw_len ? deny(reason, cap, "batch_envelope_compression_invalid") :
      validate_raw_batch(raw, got,tenant,endpoint, reason, cap);
  free(raw); return rc;
#else
  return deny(reason, cap, "batch_envelope_compression_unavailable");
#endif
}

static int control_query_valid(const char *query, const char *const *allowed, size_t count) {
  if (!query || !query[0]) return 1;
  char copy[1600];
  if (strlen(query) >= sizeof(copy)) return 0;
  snprintf(copy, sizeof(copy), "%s", query);
  unsigned seen = 0u;
  char *part = copy;
  while (part && part[0]) {
    char *next = strchr(part, '&'); if (next) *next++ = 0;
    char *equal = strchr(part, '=');
    if (!equal || equal == part) return 0;
    *equal++ = 0;
    size_t index;
    for (index = 0; index < count; ++index) if (!strcmp(part, allowed[index])) break;
    if (index == count || index >= 32u || (seen & (1u << index)) || strlen(equal) > 160u) return 0;
    seen |= 1u << index;
    for (const unsigned char *p = (const unsigned char *)equal; *p; ++p)
      if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
            *p == '.' || *p == '_' || *p == '-')) return 0;
    if ((!strcmp(part, "h2") || !strcmp(part, "zstd")) && strcmp(equal, "0") && strcmp(equal, "1")) return 0;
    if (!strcmp(part, "limit") && strcmp(equal, "8")) return 0;
    if (!strcmp(part, "wait_s")) {
      char *end; long value = strtol(equal, &end, 10);
      if (!equal[0] || *end || value < 1 || value > 30) return 0;
    }
    if (!strcmp(part, "kind") && strcmp(equal, "velociraptor") && strcmp(equal, "adapter")) return 0;
    if (!strcmp(part, "os") && strcmp(equal, "windows") && strcmp(equal, "linux") && strcmp(equal, "darwin")) return 0;
    if (!strcmp(part, "arch") && strcmp(equal, "amd64") && strcmp(equal, "arm64")) return 0;
    if (next && !next[0]) return 0;
    part = next;
  }
  return 1;
}
static int control_get_valid(const char *path) {
  static const char *const identity_keys[] = {"endpoint_id", "tenant_id"};
  static const char *const stream_keys[] = {"endpoint_id", "agent_version", "policy_version", "dict_ver", "schema_ver", "profile_id", "h2", "zstd"};
  static const char *const poll_keys[] = {"endpoint_id", "limit", "wait_s", "agent_version", "dict_ver", "schema_ver", "profile_id", "h2", "zstd"};
  static const char *const collector_keys[] = {"kind", "os", "arch"};
  const char *query = strchr(path, '?');
  size_t n = query ? (size_t)(query - path) : strlen(path);
  char route[160];
  if (!n || n >= sizeof(route)) return 0;
  memcpy(route, path, n); route[n] = 0;
  if (query) ++query;
  if (!strcmp(route, "ingest/control/stream")) return control_query_valid(query, stream_keys, 8u);
  if (!strcmp(route, "ingest/poll-commands")) return control_query_valid(query, poll_keys, 9u);
  if (!strcmp(route, "agent/comms-route-profile")) return control_query_valid(query, identity_keys, 2u);
  if (!strcmp(route, "agent/forensic-collector/manifest") || !strcmp(route, "agent/forensic-collector/download"))
    return control_query_valid(query, collector_keys, 3u);
  if (!strcmp(route, "agent/runtime-policy.toml") || !strcmp(route, "agent/rules.toml") ||
      !strcmp(route, "agent/p0-bundle.enc") || !strcmp(route, "agent/sensor-interest.json") ||
      !strcmp(route, "agent/version/latest")) return !query;
  const char *prefix = "agent/download/";
  if (!strncmp(route, prefix, strlen(prefix)) && !query) {
    cJSON *v = cJSON_CreateString(route + strlen(prefix));
    int ok = v && v->valuestring[0] && token(v, 96u); cJSON_Delete(v); return ok;
  }
  return 0;
}

int edr_egress_upgrade_download_validate(const char *command_id, const char *url,
    const char *tenant_id, const char *endpoint_id, char *reason, size_t reason_cap) {
  if (reason && reason_cap) reason[0] = 0;
  EdrEgressTaskScope scope;
  int rc = edr_egress_task_preflight(EDR_EGRESS_UPGRADE_DOWNLOAD, command_id, &scope);
  if (rc) {
    if (reason && reason_cap) snprintf(reason, reason_cap, "%s",
        rc == EDR_EGRESS_AUTHORIZATION_EXPIRED ? "task_authorization_expired" :
        rc == EDR_EGRESS_LOCAL_STATE_FAILURE ? "task_authority_unavailable" : "upgrade_download_task_denied");
    return rc;
  }
  if (!tenant_id || strcmp(tenant_id, scope.tenant_id) || !endpoint_id ||
      strcmp(endpoint_id, scope.endpoint_id) || !url || strlen(url) > 2048u)
    return deny(reason, reason_cap, "upgrade_download_scope_denied");
  int runtime = scope.runtime_manifest_url[0] && !strcmp(url, scope.runtime_manifest_url);
  if ((!runtime && (!scope.artifact_url[0] || strcmp(url, scope.artifact_url))) ||
      (runtime && strcmp(scope.upgrade_class, "runtime_bundle") && strcmp(scope.upgrade_class, "installer_required")))
    return deny(reason, reason_cap, "upgrade_download_url_not_pinned");
  /* The signed URL pins the origin as well as every query byte. Reject URL
   * forms that could reinterpret that origin or escape the fixed API route. */
  if (strncmp(url, "https://", 8u)) return deny(reason, reason_cap, "upgrade_download_url_invalid");
  const char *path = strchr(url + 8u, '/');
  if (!path || path == url + 8u || (size_t)(path - (url + 8u)) > 255u)
    return deny(reason, reason_cap, "upgrade_download_url_invalid");
  for (const char *p = url + 8u; p < path; ++p)
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
          (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == ':'))
      return deny(reason, reason_cap, "upgrade_download_url_invalid");
  const char *port = memchr(url + 8u, ':', (size_t)(path - (url + 8u)));
  const char *host_end = port ? port : path;
  if (host_end == url + 8u || !isalnum((unsigned char)url[8]) ||
      !isalnum((unsigned char)host_end[-1]))
    return deny(reason, reason_cap, "upgrade_download_url_invalid");
  if (port) {
    unsigned number = 0u;
    if (path - port < 2 || path - port > 6)
      return deny(reason, reason_cap, "upgrade_download_url_invalid");
    for (const char *p = port + 1; p < path; ++p) {
      if (*p < '0' || *p > '9') return deny(reason, reason_cap, "upgrade_download_url_invalid");
      number = number * 10u + (unsigned)(*p - '0');
    }
    if (!number || number > 65535u) return deny(reason, reason_cap, "upgrade_download_url_invalid");
  }
  char expected[160];
  if (!token_string(scope.target_version, 64u) || !strcmp(scope.target_version, ".") ||
      !strcmp(scope.target_version, ".."))
    return deny(reason, reason_cap, "upgrade_download_version_denied");
  int length = snprintf(expected, sizeof(expected), "/api/v1/agent/%s/%s?",
                        runtime ? "runtime" : "download", scope.target_version);
  if (length < 0 || (size_t)length >= sizeof(expected) || strncmp(path, expected, (size_t)length))
    return deny(reason, reason_cap, "upgrade_download_route_denied");
  const char *query = path + length;
  static const char *const keys[] = {"platform", "arch", "task_id", "artifact_id", "package_id"};
  size_t count = runtime ? 5u : 4u;
  if (!query[0] || !control_query_valid(query, keys, count))
    return deny(reason, reason_cap, "upgrade_download_query_denied");
  const char *architecture = !strcmp(scope.architecture, "x64") ? "amd64" :
                             !strcmp(scope.architecture, "arm64") ? "arm64" : NULL;
  if (!architecture) return deny(reason, reason_cap, "upgrade_download_architecture_denied");
  char copy[1600];
  snprintf(copy, sizeof(copy), "%s", query);
  size_t fields = 0u;
  for (char *part = copy; part && part[0]; ++fields) {
    char *next = strchr(part, '&'); if (next) *next++ = 0;
    char *value = strchr(part, '='); *value++ = 0;
    int matches = !strcmp(part, "platform") ? !strcmp(value, "windows") :
                  !strcmp(part, "arch") ? !strcmp(value, architecture) :
                  !strcmp(part, "task_id") ? !strcmp(value, scope.task_id) :
                  !strcmp(part, "artifact_id") ? !strcmp(value, scope.artifact_id) : 1;
    if (!matches) return deny(reason, reason_cap, "upgrade_download_query_scope_denied");
    if (!strcmp(part, "package_id")) {
      size_t n = strlen(value);
      if (!n || value[0] < '1' || value[0] > '9' || n > 19u ||
          (n == 19u && strcmp(value, "9223372036854775807") > 0))
        return deny(reason, reason_cap, "upgrade_download_package_denied");
      for (const char *p = value; *p; ++p) if (*p < '0' || *p > '9')
        return deny(reason, reason_cap, "upgrade_download_package_denied");
    }
    part = next;
  }
  if (fields != count) return deny(reason, reason_cap, "upgrade_download_query_incomplete");
  return 0;
}
typedef struct { const char *path; char kind; } ControlField;
static const ControlField hello_fields[] = {
  {"type", 't'}, {"endpoint_id", 'i'}, {"agent_version", 'i'}, {"policy_version", 'i'},
  {"h2", 'b'}, {"zstd", 'b'}, {"dict_ver", 'i'}, {"schema_ver", 'i'}, {"profile_id", 'i'},
  {"capabilities.h2", 'b'}, {"capabilities.zstd", 'b'}, {"capabilities.dict_ver", 'i'},
  {"capabilities.schema_ver", 'i'}, {"capabilities.profile_id", 'i'}, {"capabilities.agent_update_v1", 'b'},
  {"supported_schema", 'a'}, {"supported_dicts", 'a'}, {"profiles", 'a'}
};
static const ControlField ack_fields[] = {
  {"endpoint_id", 'i'}, {"command_id", 'i'}, {"status", 's'}, {"reason", 'r'},
  {"transport", 'p'}, {"last_seq", 'n'}
};
static const ControlField config_fields[] = {
  {"tenant_id", 'i'}, {"endpoint_id", 'i'}, {"agent_version", 'i'}, {"policy_version", 'i'},
  {"config_hash", 'i'}, {"config_sequence", 'n'}, {"config_nonce", 'x'},
  {"config_signature", 'x'}, {"signing_key_id", 'i'}, {"verified", 'b'},
  {"reject_reason", 'r'}, {"desired_version", 'i'}, {"desired_hash", 'i'},
  {"apply_status", 's'}, {"restart_required", 'b'}, {"payload.source", 't'}, {"payload.verified", 'b'}
};
static const ControlField attestation_fields[] = {
  {"schema", 't'}, {"task_id", 'i'}, {"endpoint_id", 'i'}, {"service_removed", 'b'},
  {"process_stopped", 'b'}, {"install_dir_removed", 'b'}, {"completed_at", 'd'}
};
static int control_leaf_valid(const cJSON *v, char kind) {
  if (kind == 'b') return cJSON_IsBool(v);
  if (kind == 'n') return valid_value(v, H_NUMBER);
  if (kind == 'i') return token(v, 160u);
  if (kind == 'a') {
    if (!cJSON_IsArray(v) || cJSON_GetArraySize(v) < 1 || cJSON_GetArraySize(v) > 4) return 0;
    const cJSON *item; cJSON_ArrayForEach(item, v) if (!token(item, 96u) || !item->valuestring[0]) return 0;
    return 1;
  }
  if (!cJSON_IsString(v) || !v->valuestring) return 0;
  const char *s = v->valuestring;
  if (kind == 'x') {
    if (strlen(s) > 2048u) return 0;
    for (; *s; ++s) if (!(b64_value((unsigned char)*s) >= 0 || *s == '=' || *s == '_' || *s == '-')) return 0;
    return 1;
  }
  if (kind == 'r') return !s[0] || !strcmp(s, "control_validation_failed") || !strcmp(s, "config_validation_failed") || !strcmp(s, "command_id_conflict");
  /* ACKs echo the existing server CommandEnvelope transport, including durable
   * retries. Keep a closed set; a protocol name never permits result fields. */
  if (kind == 'p') return !strcmp(s, "https_control") || !strcmp(s, "https_control_stream") ||
      !strcmp(s, "https_long_poll") || !strcmp(s, "https_h2_server_stream") ||
      !strcmp(s, "https_http1_stream") || !strcmp(s, "https_h2_long_poll") ||
      !strcmp(s, "https_http1_long_poll") || !strcmp(s, "https_transport_v2");
  if (kind == 's') return !strcmp(s, "received") || !strcmp(s, "rejected") || !strcmp(s, "reported") ||
      !strcmp(s, "applied") || !strcmp(s, "failed") || !strcmp(s, "unchanged") || !strcmp(s, "restart_required");
  if (kind == 'd') {
    if (strlen(s) != 24u) return 0;
    for (size_t i = 0; i < 24u; ++i) {
      char expected = i == 4u || i == 7u ? '-' : i == 10u ? 'T' : i == 13u || i == 16u ? ':' : i == 19u ? '.' : i == 23u ? 'Z' : 0;
      if (expected ? s[i] != expected : s[i] < '0' || s[i] > '9') return 0;
    }
    return 1;
  }
  return !strcmp(s, "client_hello") || !strcmp(s, "agent-runtime-policy") || !strcmp(s, "edr.endpoint.uninstall.attestation.v1");
}
static int control_object_valid(const cJSON *root, const char *path, const ControlField *fields, size_t count, unsigned depth) {
  if (depth > 3u) return 0;
  if (cJSON_IsObject(root)) {
    const cJSON *v;
    if (!root->child) return 0;
    cJSON_ArrayForEach(v, root) {
      char next[128]; int n = snprintf(next, sizeof(next), "%s%s%s", path, path[0] ? "." : "", v->string ? v->string : "");
      if (n < 0 || (size_t)n >= sizeof(next) || !control_object_valid(v, next, fields, count, depth + 1u)) return 0;
    }
    return 1;
  }
  for (size_t i = 0; i < count; ++i) if (!strcmp(path, fields[i].path)) return control_leaf_valid(root, fields[i].kind);
  return 0;
}
static int control_post_valid(const char *path, const cJSON *root) {
  const ControlField *fields;
  size_t count;
  const char *required[4]; size_t required_count;
  if (!strcmp(path, "ingest/control/hello")) {
    fields = hello_fields; count = sizeof(hello_fields) / sizeof(hello_fields[0]);
    required[0] = "endpoint_id"; required[1] = "agent_version"; required[2] = "policy_version"; required[3] = "type"; required_count = 4u;
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "type");
    if (!cJSON_IsString(type) || strcmp(type->valuestring, "client_hello")) return 0;
  } else if (!strcmp(path, "ingest/control/ack")) {
    fields = ack_fields; count = sizeof(ack_fields) / sizeof(ack_fields[0]);
    required[0] = "endpoint_id"; required[1] = "command_id"; required[2] = "status"; required_count = 3u;
  } else if (!strcmp(path, "ingest/config-status")) {
    fields = config_fields; count = sizeof(config_fields) / sizeof(config_fields[0]);
    required[0] = "endpoint_id"; required[1] = "agent_version"; required[2] = "policy_version"; required_count = 3u;
  } else if (!strcmp(path, "agent/lifecycle/uninstall-attest")) {
    fields = attestation_fields; count = sizeof(attestation_fields) / sizeof(attestation_fields[0]);
    required[0] = "endpoint_id"; required[1] = "task_id"; required[2] = "schema"; required[3] = "completed_at"; required_count = 4u;
    const cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schema");
    if (!cJSON_IsString(schema) || strcmp(schema->valuestring, "edr.endpoint.uninstall.attestation.v1")) return 0;
    const char *const flags[] = {"service_removed", "process_stopped", "install_dir_removed"};
    for (size_t i = 0; i < 3u; ++i) if (!cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, flags[i]))) return 0;
  } else return 0;
  for (size_t i = 0; i < required_count; ++i) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, required[i]);
    if (!cJSON_IsString(v) || !v->valuestring[0]) return 0;
  }
  return control_object_valid(root, "", fields, count, 0u);
}

static int upgrade_string(const cJSON *root, const char *key, const char *expected) {
  const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, key);
  return cJSON_IsString(v) && v->valuestring && !strcmp(v->valuestring, expected);
}
const char *edr_egress_upgrade_failure_value(const char *field,const char *candidate) {
  const char *const stages[]={"agent_reported_failure","staging_directory","artifact_download","runtime_manifest_download","launcher_persist","launcher_start","full_installer_rollback_completed","full_installer_rollback_failed","full_installer_rollback_backup_missing","rollback_completed","rollback_failed","recovery_completed","recovery_failed","failed_before_stop"};
  const char *const errors[]={"upgrade_failed","INSTALL_BASELINE_CORRUPT","INSTALL_BASELINE_REPAIR_INCOMPLETE","INSTALL_BASELINE_UNSUPPORTED","INSTALL_EXIT_NONZERO","INSTALL_LOG_TOO_LARGE","INSTALL_LOG_UNAVAILABLE","INSTALL_LOG_UNSAFE_PATH","INSTALL_REPAIR_BACKUP_INCOMPLETE"};
  int stage=field && !strcmp(field,"stage");
  const char *const *values=stage?stages:errors;
  size_t count=stage?sizeof(stages)/sizeof(stages[0]):sizeof(errors)/sizeof(errors[0]);
  for(size_t i=0;candidate && i<count;i++)if(!strcmp(candidate,values[i]))return values[i];
  return values[0];
}
char *edr_egress_upgrade_event_project(const char *body, int *result) {
  int rc = EDR_EGRESS_REQUEST_DENIED;
  cJSON *root = cJSON_Parse(body ? body : ""), *out = NULL, *detail = NULL;
  char *wire = NULL;
  const cJSON *command = cJSON_GetObjectItemCaseSensitive(root, "command_id");
  if (!cJSON_IsString(command) || !command->valuestring) goto done;
  EdrEgressTaskScope scope;
  rc = edr_egress_task_preflight(EDR_EGRESS_UPGRADE_EVENT, command->valuestring, &scope);
  if (rc) goto done;
  rc = EDR_EGRESS_PAYLOAD_POLICY_HELD;
  const cJSON *source = cJSON_GetObjectItemCaseSensitive(root, "detail");
  const cJSON *status = cJSON_GetObjectItemCaseSensitive(root, "status");
  const cJSON *seq = cJSON_GetObjectItemCaseSensitive(root, "event_seq");
  const cJSON *progress = cJSON_GetObjectItemCaseSensitive(root, "progress");
  const char *const statuses[] = {"downloading", "downloaded", "verified", "installing", "restarting", "health_check", "completed", "failed", "cancelled", "rolling_back", "rollback_health_check", "rolled_back"};
  if (!upgrade_string(root,"task_id",scope.task_id) || !cJSON_IsObject(source) ||
      !upgrade_string(source,"artifact_id",scope.artifact_id) ||
      !upgrade_string(source,"sha256",scope.artifact_sha256) ||
      !upgrade_string(source,"version",scope.target_version) ||
      !upgrade_string(source,"operation",scope.operation) ||
      !cJSON_IsString(status) || !listed(status->valuestring,statuses,sizeof(statuses)/sizeof(statuses[0])) ||
      !cJSON_IsNumber(seq) || seq->valuedouble < 1 || seq->valuedouble >= 9007199254740992.0 || floor(seq->valuedouble) != seq->valuedouble ||
      !cJSON_IsNumber(progress) || progress->valuedouble < 0 || progress->valuedouble > 100 || floor(progress->valuedouble) != progress->valuedouble) goto done;
  char event_id[320],safe_command[sizeof(scope.command_id)];
  size_t id_len=strlen(scope.command_id);
  for(size_t i=0;i<id_len;i++){unsigned char c=(unsigned char)scope.command_id[i];safe_command[i]=(isalnum(c)||c=='.'||c=='_'||c=='-')?(char)c:'_';}
  safe_command[id_len]=0;
  snprintf(event_id,sizeof(event_id),"%s-%020llu",safe_command,(unsigned long long)seq->valuedouble);
  if (!upgrade_string(root,"event_id",event_id)) goto done;
  out=cJSON_CreateObject(); detail=cJSON_CreateObject();
  if (!out || !detail) { rc=EDR_EGRESS_LOCAL_STATE_FAILURE; goto done; }
  const char *const keys[]={"task_id","command_id","event_id","status","event_seq","progress"};
  for (size_t i=0;i<sizeof(keys)/sizeof(keys[0]);i++) {
    cJSON *copy=cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(root,keys[i]),1);
    if (!copy || !cJSON_AddItemToObject(out,keys[i],copy)) { cJSON_Delete(copy);rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto done; }
  }
  if (!cJSON_AddStringToObject(detail,"artifact_id",scope.artifact_id) ||
      !cJSON_AddStringToObject(detail,"sha256",scope.artifact_sha256) ||
      !cJSON_AddStringToObject(detail,"version",scope.target_version) ||
      !cJSON_AddStringToObject(detail,"operation",scope.operation)) {rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto done;}
  if(!strcmp(status->valuestring,"failed")) {
    const char *names[]={"stage","error"};
    for(size_t i=0;i<2u;i++) {
      const cJSON *v=cJSON_GetObjectItemCaseSensitive(source,names[i]);
      if(!cJSON_AddStringToObject(detail,names[i],edr_egress_upgrade_failure_value(names[i],cJSON_IsString(v)?v->valuestring:NULL))) {rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto done;}
    }
  }
  /* The backend consumes the task transition and pinned artifact identity.
   * Arbitrary updater detail remains in the local event and journal. */
  if (!cJSON_AddItemToObject(out,"detail",detail)) {rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto done;}
  detail=NULL; wire=cJSON_PrintUnformatted(out); rc=wire?0:EDR_EGRESS_LOCAL_STATE_FAILURE;
done:
  cJSON_Delete(root);cJSON_Delete(out);cJSON_Delete(detail);
  if (result) *result=rc;
  return wire;
}
static int validate_upgrade_event(const void *body,size_t len,const char *tenant,const char *endpoint,char *reason,size_t cap) {
  cJSON *root=edr_egress_parse_purpose_object(body,len);
  const cJSON *command=cJSON_GetObjectItemCaseSensitive(root,"command_id");
  EdrEgressTaskScope scope;
  int rc=cJSON_IsString(command)?edr_egress_task_preflight(EDR_EGRESS_UPGRADE_EVENT,command->valuestring,&scope):EDR_EGRESS_REQUEST_DENIED;
  if (!rc && ((!tenant || strcmp(tenant,scope.tenant_id)) || (!endpoint || strcmp(endpoint,scope.endpoint_id)))) rc=EDR_EGRESS_REQUEST_DENIED;
  char *raw=root?cJSON_PrintUnformatted(root):NULL,*minimal=NULL;
  if (!rc && !raw)rc=EDR_EGRESS_LOCAL_STATE_FAILURE;
  if (!rc) minimal=edr_egress_upgrade_event_project(raw,&rc);
  cJSON *projected=minimal?cJSON_Parse(minimal):NULL;
  if (!rc && !projected)rc=EDR_EGRESS_LOCAL_STATE_FAILURE;
  if (!rc && !cJSON_Compare(root,projected,1))rc=EDR_EGRESS_PAYLOAD_POLICY_HELD;
  free(raw);free(minimal);cJSON_Delete(root);cJSON_Delete(projected);
  if (rc && reason && cap) snprintf(reason,cap,"%s",rc==EDR_EGRESS_AUTHORIZATION_EXPIRED?"task_authorization_expired":"upgrade_event_scope_or_fields_denied");
  return rc;
}

static int command_result_schema_valid(const cJSON *root) {
  static const char *const keys[] = {"command_id", "command_type", "endpoint_id", "agent_version",
    "status", "exit_code", "detail_utf8", "finished_unix_ms", "soar_correlation_id",
    "playbook_run_id", "playbook_step_id"};
  const cJSON *v;
  cJSON_ArrayForEach(v, root)
    if (strcmp(v->string, "endpoint_id") && strcmp(v->string, "result")) return 0;
  const cJSON *r = cJSON_GetObjectItemCaseSensitive(root, "result");
  if (!cJSON_IsObject(r) || cJSON_GetArraySize(r) != 11) return 0;
  cJSON_ArrayForEach(v, r) {
    if (!listed(v->string, keys, sizeof(keys) / sizeof(keys[0]))) return 0;
    if (!strcmp(v->string, "status")) {
      if (!cJSON_IsNumber(v) || v->valuedouble < 1 || v->valuedouble > 4 ||
          floor(v->valuedouble) != v->valuedouble) return 0;
    } else if (!strcmp(v->string, "exit_code")) {
      if (!cJSON_IsNumber(v) || v->valuedouble < -2147483648.0 || v->valuedouble > 2147483647.0 ||
          floor(v->valuedouble) != v->valuedouble) return 0;
    } else if (!strcmp(v->string, "finished_unix_ms")) {
      if (!valid_value(v, H_NUMBER) || v->valuedouble < 1) return 0;
    } else if (!strcmp(v->string, "detail_utf8")) {
      if (!cJSON_IsString(v) || !v->valuestring || strlen(v->valuestring) >= 16384u) return 0;
    } else if (!token(v, 127u)) return 0;
  }
  return 1;
}

int edr_egress_request_validate_for_scope(const char *method, const char *suffix_or_url,
                                const char *content_type, const void *body,
                                size_t len,const char *tenant,const char *endpoint,
                                char *reason, size_t cap) {
  if (reason && cap) reason[0] = 0;
  if (!method || !suffix_or_url || !suffix_or_url[0]) return deny(reason, cap, "egress_purpose_unknown");
  const char *path = suffix_or_url;
  const char *scheme = strstr(path, "://");
  if (scheme) { path = strchr(scheme + 3u, '/'); if (!path) return deny(reason, cap, "egress_purpose_unknown"); }
  if (strncmp(path, "/api/v1/", 8u) == 0) path += 8u;
  else if (*path == '/') ++path;
  if (!strcmp(method,"POST") && !strcmp(path,"ingest/agent-upgrade-event")) {
    if (!content_type || strcmp(content_type,"application/json") || !body || !len || len>8192u)
      return deny(reason,cap,"upgrade_event_body_invalid");
    return validate_upgrade_event(body,len,tenant,endpoint,reason,cap);
  }
  /* Explicitly authorized minimum controls: fixed routes/fields only, never
   * inventory, artifacts or diagnostic events. Task results require their durable owner. */
  if (!strcmp(method, "GET")) return !body && !len && control_get_valid(path) ? 0 : deny(reason, cap, "egress_control_field_or_route_denied");
  if (strcmp(method, "POST")) return deny(reason, cap, "egress_method_denied");
  int command_result = !strcmp(path, "ingest/report-command-result");
  int batch = strcmp(path, "ingest/report-events") == 0;
  int heartbeat = strcmp(path, "ingest/heartbeat") == 0;
  int health = strcmp(path, "ingest/engine-health") == 0;
  int delta = strcmp(path, "ingest/engine-health/delta") == 0;
  int control = !strcmp(path, "ingest/control/hello") || !strcmp(path, "ingest/control/ack") ||
      !strcmp(path, "ingest/config-status") || !strcmp(path, "agent/lifecycle/uninstall-attest");
  if (!batch && !heartbeat && !health && !delta && !control && !command_result) return deny(reason, cap, "egress_purpose_not_allowed");
  if (!body || !len || len > (batch ? EDR_EGRESS_BATCH_WIRE_MAX_BYTES :
      heartbeat ? 1024u : control ? 8192u : command_result ? EDR_EGRESS_COMMAND_RESULT_MAX_BYTES : EDR_EGRESS_HEALTH_MAX_BYTES)) return deny(reason, cap, "egress_body_limit");
  if (batch && content_type && strcmp(content_type, "application/x-protobuf") == 0)
    return validate_proto_batch(body, len,tenant,endpoint, reason, cap);
  if (!content_type || strcmp(content_type, "application/json")) return deny(reason, cap, "egress_content_type_denied");
  cJSON *root = edr_egress_parse_purpose_object(body, len);
  if (!root) return deny(reason, cap, "egress_json_invalid");
  const cJSON *request_endpoint=cJSON_GetObjectItemCaseSensitive(root,"endpoint_id");
  const cJSON *request_tenant=cJSON_GetObjectItemCaseSensitive(root,"tenant_id");
  if ((endpoint && (!endpoint[0] || !cJSON_IsString(request_endpoint) ||
      strcmp(request_endpoint->valuestring,endpoint))) ||
      (tenant && request_tenant && (!tenant[0] || !cJSON_IsString(request_tenant) ||
      strcmp(request_tenant->valuestring,tenant)))) {
    cJSON_Delete(root); return deny(reason,cap,"egress_scope_mismatch");
  }
  int rc = 0;
  if (command_result) {
    EdrEgressCommandResultValidator owner = atomic_load_explicit(&command_result_validator, memory_order_acquire);
    if (!command_result_schema_valid(root)) rc = deny(reason, cap, "command_result_schema_invalid");
    else {
      int owned = owner && tenant && endpoint ? owner(tenant, endpoint, body, len) : 0;
      if (owned == EDR_EGRESS_AUTHORIZATION_EXPIRED || owned == EDR_EGRESS_LOCAL_STATE_FAILURE) {
        rc = owned;
        if(reason && cap)snprintf(reason,cap,"%s",owned == EDR_EGRESS_AUTHORIZATION_EXPIRED ? "command_result_authorization_expired" : "command_result_owner_io_failure");
      } else if (owned != 1) rc = deny(reason, cap, "command_result_owner_unavailable");
    }
  }
  else if (control) { if (!control_post_valid(path, root)) rc = deny(reason, cap, "egress_control_field_or_type_denied"); }
  else if (batch) rc = validate_json_batch(root,tenant,endpoint, reason, cap);
  else if (heartbeat) {
    const cJSON *v;
    if (!identities(root)) rc = deny(reason, cap, "heartbeat_identity_invalid");
    cJSON_ArrayForEach(v, root) {
      if (strcmp(v->string, "endpoint_id") && strcmp(v->string, "agent_version") && strcmp(v->string, "policy_version"))
        rc = deny(reason, cap, "heartbeat_field_denied");
    }
  } else if (!health_json_valid(root, delta)) rc = deny(reason, cap, "health_field_or_type_denied");
  cJSON_Delete(root); return rc;
}
int edr_egress_request_validate(const char *method,const char *suffix_or_url,
    const char *content_type,const void *body,size_t len,char *reason,size_t cap) {
  return edr_egress_request_validate_for_scope(method,suffix_or_url,content_type,body,len,
    NULL,NULL,reason,cap);
}
