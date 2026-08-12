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
    uint64_t ordinary_file_dropped;
    uint64_t ordinary_registry_dropped;
    uint64_t ordinary_network_dropped;
    uint64_t metadata_dropped;
    int sensor_interest_enabled;
    int sensor_interest_loaded;
    char sensor_interest_version[128];
    char sensor_interest_rules_version[128];
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

/**
 * 启动采集：Windows 为 ETW 会话（Kernel-Process / File / Network 等）；Linux（M1）为 inotify 目录监视；其它 POSIX 为 stub。
 * 使用 `cfg->collection.etw_enabled`；Windows 另读 `etw_*_provider` 系列（见 `config.h` 与 §19.10，含 A4.3 四项可选 Provider）。
 * `cfg` 为空视为未启用采集。失败返回 EDR_ERR_ETW_*（常见原因：权限不足、会话名冲突）。
 */
EdrError edr_collector_start(struct EdrEventBus *bus, const struct EdrConfig *cfg);

/** 停止会话并 join 消费线程（可重复调用）。 */
void edr_collector_stop(void);

/**
 * 按固定会话名尝试停止可能残留的 ETW 实时会话（无需本进程曾 StartTrace）。
 * 供卸载 / 运维脚本调用，避免上次异常退出后内核仍占用 `EDR_Agent_RT_001` 等会话。
 * 非 Windows 为 no-op。
 */
void edr_collector_stop_orphan_etw_session(void);

#endif
