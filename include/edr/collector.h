/**
 * 采集层入口（§3）— Windows：ETW 实时订阅；Linux：collector_linux（演进中）；其余 POSIX：stub。
 */
#ifndef EDR_COLLECTOR_H
#define EDR_COLLECTOR_H

#include "edr/error.h"
#include <stdint.h>

struct EdrEventBus;
struct EdrConfig;

#define EDR_COLLECTOR_MAX_EVENTID_FILTER 64
#define EDR_COLLECTOR_MAX_EVENTID_RANGES 16

typedef enum {
    EDR_EVENT_FILTER_MODE_NONE = 0,
    EDR_EVENT_FILTER_MODE_WHITELIST = 1,
    EDR_EVENT_FILTER_MODE_BLACKLIST = 2,
} EdrEventFilterMode;

typedef struct {
    uint16_t start;
    uint16_t end;
} EdrEventIdRange;

typedef struct {
    EdrEventFilterMode mode;
    uint16_t event_ids[EDR_COLLECTOR_MAX_EVENTID_FILTER];
    uint32_t event_id_count;
    EdrEventIdRange ranges[EDR_COLLECTOR_MAX_EVENTID_RANGES];
    uint32_t range_count;
} EdrEventIdFilter;

typedef struct {
    EdrEventIdFilter dns_client;
    EdrEventIdFilter powershell;
    EdrEventIdFilter tcpip;
    EdrEventIdFilter wmi_activity;
    EdrEventIdFilter service_ctrl_mgr;
    int filtering_enabled;
} EdrCollectorEventFilterConfig;

typedef struct {
    uint64_t dns_client_filtered;
    uint64_t powershell_filtered;
    uint64_t tcpip_filtered;
    uint64_t wmi_activity_filtered;
    uint64_t total_filtered;
} EdrCollectorFilterStats;

typedef struct {
    int etw_or_inotify_enabled;
    int powershell_visible;
    int amsi_visible;
    int security_audit_visible;
    int security_subscription_ready;
    int auditd_enabled;
    int auditd_running;
    int ebpf_enabled;
    int ebpf_loaded;
    uint64_t auditd_events;
    uint64_t ebpf_events;
    uint32_t collector_thread_id;
    uint64_t registry_provider_events;
    uint64_t registry_provider_unmapped;
    uint64_t registry_payload_missing;
    uint64_t registry_events_admitted;
    uint64_t security_4688_received;
    uint64_t security_4657_received;
    uint64_t security_4688_payload_full;
    uint64_t security_4688_payload_degraded;
    uint64_t security_4688_values_rejected;
    uint64_t security_4688_identity_capacity_omitted_fields;
    uint64_t security_4688_identity_none_events;
    uint64_t security_4688_effective_identity_present_events;
    uint64_t security_4688_creator_identity_present_events;
    uint64_t security_4688_required_overflow_dropped;
    uint64_t registry_attributed_events;
    uint64_t registry_unattributed_events;
    uint64_t etw_callbacks_total;
    uint64_t etw_callbacks_process;
    uint64_t etw_callbacks_file;
    uint64_t etw_callbacks_network;
    uint64_t etw_callbacks_registry;
    uint64_t etw_prefilter_dropped;
    uint64_t collector_dropped;
    uint64_t queue_dropped;
    uint64_t agent_self_suppressed;
    uint64_t agent_self_direct_pid_suppressed;
    uint64_t agent_self_security_event_suppressed;
    uint64_t agent_self_record_suppressed;
    uint64_t agent_self_interest_suppressed;
    uint64_t agent_self_fuse_provider_suppressed;
    int agent_self_fuse_active;
    int agent_self_fuse_provider_degraded;
    int agent_self_fuse_fast_drop;
    uint64_t agent_self_fuse_until_unix_ms;
    uint64_t agent_self_fuse_trips;
    uint64_t agent_self_fuse_suppressed;
    uint64_t agent_self_fuse_current_minute_count;
    uint64_t agent_self_fuse_threshold_per_min;
    uint64_t agent_self_fuse_cooldown_s;
    uint64_t lifecycle_dropped;
    uint64_t auth_dropped;
    uint64_t invalid_process_dropped;
    uint64_t process_create_missing_identity;
    uint64_t process_identity_cache_hits;
    uint64_t process_identity_cache_misses;
    int process_start_key_requested;
    int process_start_key_enabled;
    uint64_t process_start_key_enable_failures;
    uint64_t process_start_key_missing_events;
    char process_start_key_reason[96];
    /* Kernel-File Id/Task 15 read path: FileKey→NameCreate binding plus
     * exact ProcessStartKey actor generation.  Misses are fail-closed. */
    uint64_t file_read_name_bindings;
    uint64_t file_read_name_cache_misses;
    uint64_t file_read_critical_binding_capacity_exhausted;
    uint64_t file_read_file_key_ambiguities;
    /* A protected FileKey cache failure is held in a single non-overwrite
     * source-only gate slot until the existing SQLite queue accepts it. */
    int file_read_p0_capability_healthy;
    uint64_t file_read_metadata_gate_staged;
    uint64_t file_read_metadata_gate_coalesced;
    uint64_t file_read_metadata_gate_enqueue_attempts;
    uint64_t file_read_metadata_gate_queue_rejected;
    uint64_t file_read_metadata_gate_durable_successes;
    uint64_t file_read_metadata_gate_durable_failures;
    uint64_t file_read_metadata_gate_retry_attempts;
    uint64_t file_read_metadata_gate_paused_events;
    uint64_t file_read_metadata_gate_epoch_restart_attempts;
    uint64_t file_read_metadata_gate_epoch_restart_successes;
    uint64_t file_read_metadata_gate_epoch_restart_failures;
    uint64_t file_read_metadata_gate_recovery_episodes;
    /* Post-reset recovery remains fail-closed until a new-session exact
     * NameCreate->Read binding has been observed.  Keep the failure count and
     * reason distinct from durable delivery failures so an operational queue
     * cannot mask missing attribution. */
    uint64_t file_read_metadata_gate_post_reset_recovery_bindings;
    uint64_t file_read_metadata_gate_post_reset_recovery_failures;
    char file_read_metadata_gate_post_reset_recovery_reason[96];
    char file_read_p0_capability_reason[96];
    uint64_t file_read_generation_unavailable;
    uint64_t file_read_actor_generation_unavailable;
    /* Kernel-File has its own EnableTraceEx2 request; do not infer this from
     * the separate Kernel-Process provider health. */
    int kernel_file_start_key_requested;
    int kernel_file_start_key_enabled;
    uint64_t kernel_file_start_key_enable_failures;
    char kernel_file_start_key_reason[96];
    uint64_t ordinary_file_dropped;
    uint64_t ordinary_registry_dropped;
    uint64_t ordinary_network_dropped;
    uint64_t metadata_dropped;
    int sensor_interest_enabled;
    int sensor_interest_loaded;
    int sensor_interest_file_read_full_admission;
    int sensor_interest_file_write_full_admission;
    int sensor_interest_registry_set_full_admission;
    int sensor_interest_full_admission_contract_valid;
    int sensor_interest_p0_binding_valid;
    char sensor_interest_version[128];
    char sensor_interest_rules_version[128];
    char sensor_interest_p0_artifact_sha256[65];
    char sensor_interest_p0_rule_coverage_sha256[65];
    char sensor_interest_manifest_sha256[65];
    char sensor_interest_manifest_hash_mode[64];
    uint32_t sensor_interest_p0_artifact_rule_count;
    uint64_t sensor_interest_snapshot_epoch;
    uint32_t sensor_interest_process_names;
    uint32_t sensor_interest_process_prefixes;
    uint32_t sensor_interest_ports;
    uint32_t sensor_interest_file_prefixes;
    uint32_t sensor_interest_file_contains;
    uint32_t sensor_interest_registry_prefixes;
    uint32_t sensor_interest_registry_contains;
    uint32_t sensor_interest_cmd_tokens;
    uint32_t sensor_interest_parent_child_pairs;
    uint32_t sensor_interest_required_fields;
    uint64_t sensor_interest_checked;
    uint64_t sensor_interest_matched;
    uint64_t sensor_interest_dropped;
    uint64_t sensor_interest_provider_hits;
    uint64_t sensor_interest_adaptive_hits;
    uint64_t sensor_interest_process_hits;
    uint64_t sensor_interest_port_hits;
    uint64_t sensor_interest_path_hits;
    uint64_t sensor_interest_registry_hits;
    uint64_t sensor_interest_parent_child_hits;
    int adaptive_collection_enabled;
    int adaptive_collection_active;
    uint32_t adaptive_collection_ttl_s;
    uint32_t adaptive_collection_remaining_s;
    uint32_t adaptive_collection_min_severity;
    int adaptive_collection_level;
    uint64_t adaptive_collection_boosts;
    uint64_t adaptive_collection_last_boost_unix_ms;
    char adaptive_collection_last_rule_id[64];
    char auditd_last_error[128];
    char ebpf_last_error[128];
} EdrCollectorHealth;

int edr_collector_get_event_filter_config(EdrCollectorEventFilterConfig *out_config);

int edr_collector_should_filter_event(const char *provider_name, uint16_t event_id);

int edr_collector_get_filter_stats(EdrCollectorFilterStats *out_stats);

int edr_collector_get_health(EdrCollectorHealth *out_health);

/**
 * Register an RTR policy canary root before it executes. Windows uses this
 * short-lived PID grant to let explicitly marked canary descendants traverse
 * the real sensor pipeline without disabling general Agent self-noise filtering.
 */
void edr_collector_register_policy_canary_process(uint32_t pid, const char *command);

#ifdef _WIN32
/* The collector owns the FileKey gate slot.  Preprocess calls retry from its
 * normal loop and reports the existing SQLite durable-write result; neither
 * function creates a new queue or persistent table. `outcome` is 1 for a
 * committed record, 2 for a retained source-only retry owner, and 0 for an
 * unhealthy/lost admission that must keep FileRead P0 disabled. */
void edr_collector_file_read_metadata_gate_retry(void);
void edr_collector_file_read_metadata_gate_delivery_result(const char *event_id,
                                                            int outcome);
/* The Agent lifecycle owns the stop/join/start orchestration.  The collector
 * exposes only the latched requirement and records its outcome so a failed
 * restart cannot make FileRead P0 appear healthy. */
int edr_collector_file_read_metadata_gate_restart_required(void);
void edr_collector_file_read_metadata_gate_restart_attempted(void);
void edr_collector_file_read_metadata_gate_restart_failed(void);
/* A stop/join timeout retains the old ETW/A4.4 resources.  It is terminal for
 * automatic recovery: a later start would otherwise overlap provider epochs. */
void edr_collector_file_read_metadata_gate_restart_timeout(void);
#endif

/**
 * 启动采集：Windows 为 ETW 会话（Kernel-Process / File / Network 等）；Linux（M1）为 inotify 目录监视；其它 POSIX 为 stub。
 * 使用 `cfg->collection.etw_enabled`；Windows 另读 `etw_*_provider` 系列（见 `config.h` 与 §19.10，含 A4.3 四项可选 Provider）。
 * `cfg` 为空视为未启用采集。失败返回 EDR_ERR_ETW_*（常见原因：权限不足、会话名冲突）。
 */
EdrError edr_collector_start(struct EdrEventBus *bus, const struct EdrConfig *cfg);

/**
 * 停止会话并 join 消费线程（可重复调用）。仅在线程和 A4.4 已全部 join
 * 后返回 1；超时返回 0 并保留所有仍被线程引用的资源。
 */
int edr_collector_stop(void);

/**
 * 按固定会话名尝试停止可能残留的 ETW 实时会话（无需本进程曾 StartTrace）。
 * 供卸载 / 运维脚本调用，避免上次异常退出后内核仍占用 `EDR_Agent_RT_001` 等会话。
 * 非 Windows 为 no-op。
 */
void edr_collector_stop_orphan_etw_session(void);

#endif
