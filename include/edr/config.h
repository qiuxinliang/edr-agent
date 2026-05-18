/**
 * §11 配置管理 — 与《EDR 端点详细设计 v1.0》§11.1 字段对齐；
 * 使用 tomlc99（`toml_parse_file`）解析标准 TOML。
 */
#ifndef EDR_CONFIG_H
#define EDR_CONFIG_H

#include "edr/error.h"
#include "edr/emit_rules.h"
#include "edr/forensic_trigger.h"
#include "edr/ave_sdk.h"
#include "edr/collector.h"
#include "edr/shellcode_detector.h"
#include "edr/webshell_detector.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/** T-015：`[fl.frozen_layers]` 逻辑名列表上限（与《10》§5 示例对齐） */
#define EDR_FL_FROZEN_MAX 16
/** 单层逻辑名最大长度（ONNX 子串/模块名） */
#define EDR_FL_FROZEN_NAME_MAX 64

typedef struct {
    bool enabled;
    char coordinator_grpc_addr[256];
    char coordinator_http_url[512];
    char coordinator_secp256r1_pubkey_hex[288];
    uint8_t coordinator_secp256r1_pub[96];
    uint32_t coordinator_secp256r1_pub_len;
    char privacy_budget_db_path[1024];
    char fl_samples_db_path[1024];
    int min_new_samples;
    float idle_cpu_threshold;
    int local_epochs;
    float dp_epsilon;
    float dp_clip_norm;
    int max_participated_rounds;
    int gradient_chunk_size_kb;
    uint32_t mock_round_interval_s;
    char model_target[32];
    size_t frozen_layer_count_static;
    char frozen_layer_static[EDR_FL_FROZEN_MAX][EDR_FL_FROZEN_NAME_MAX];
    size_t frozen_layer_count_behavior;
    char frozen_layer_behavior[EDR_FL_FROZEN_MAX][EDR_FL_FROZEN_NAME_MAX];
} EdrFlConfig;

typedef struct {
    bool enabled;
    uint32_t port_interval_s;
    uint32_t conn_interval_s;
    uint32_t service_interval_s;
    uint32_t policy_interval_s;
    uint32_t full_snapshot_interval_s;
    uint32_t outbound_top_n;
    uint32_t egress_top_n;
    bool outbound_exclude_loopback;
    char geoip_db_path[1024];
    uint32_t firewall_rule_detail_max;
    uint16_t *high_risk_immediate_ports;
    size_t high_risk_immediate_ports_count;
    bool etw_refresh_triggers_snapshot;
    uint32_t etw_refresh_debounce_s;
    uint32_t win_listen_cache_ttl_ms;
} EdrAttackSurfaceConfig;

typedef struct EdrConfig {
  struct {
    char address[256];
    char ca_cert[1024];
    char client_cert[1024];
    char client_key[1024];
    int connect_timeout_s;
    int keepalive_interval_s;
    /** 与 EDR_GRPC_INSECURE=1 等效：连平台明文 gRPC Ingest；生产应 false 并配 mTLS */
    bool grpc_insecure;
  } server;

  struct {
    char endpoint_id[128];
    char tenant_id[128];
  } agent;

  EdrCollectionConfig collection;

  struct {
    uint32_t dedup_window_s;
    uint32_t high_freq_threshold;
    double sampling_rate_whitelist;
    /** 与平台动态规则包版本对齐，如 `edr-dynamic-rules-v1` */
    char rules_version[64];
    /** [[preprocessing.rules]]，堆分配；见 docs/PREPROCESS_RULES.md；销毁 cfg 前调用 edr_config_free_heap */
    EdrEmitRule *rules;
    uint32_t rules_count;
  } preprocessing;

  EdrAveConfig ave;

  struct {
    uint32_t batch_max_events;
    uint32_t batch_max_size_mb;
    int batch_timeout_s;
    uint32_t max_upload_mbps;
  } upload;

  struct {
    char queue_db_path[1024];
    uint32_t max_queue_size_mb;
    uint32_t retention_hours;
  } offline;

  struct {
    uint32_t cpu_limit_percent;
    uint32_t memory_limit_mb;
    uint32_t emergency_cpu_limit;
  } resource_limit;

  struct {
    char level[16];
    char log_dir[1024];
    uint32_t max_log_size_mb;
    uint32_t max_log_files;
  } logging;

  /** §8 远程指令策略（高危：kill / isolate / forensic） */
  struct {
    /**
     * 为 true 时允许执行 kill / isolate / forensic（与 `EDR_CMD_ENABLED=1` 等效，便于生产用 TOML 固定策略）。
     * 环境变量 `EDR_CMD_ENABLED` / `EDR_CMD_DANGEROUS` 仍为最高优先级。
     */
    bool allow_dangerous;
  } command;

  /**
   * §19 平台 REST（攻击面上报）。`rest_base_url` 形如 `http://127.0.0.1:8080/api/v1`（无尾斜杠）。
   * 可被环境变量 `EDR_PLATFORM_REST_BASE` 覆盖；可选 `EDR_PLATFORM_BEARER` 或 `rest_bearer_token`。
   */
  struct {
    char rest_base_url[512];
    char rest_user_id[128];
    char rest_bearer_token[512];
  } platform;

  /**
   * §19.8 攻击面快照 — TOML `[attack_surface]`（与《EDR_端点详细设计》§19.8 对齐）。
   * `high_risk_immediate_ports` 为堆分配 `uint16_t` 数组，由 `edr_config_free_heap` 释放。
   * 周期调度与采集读参在后续迭代接入；当前仅解析与默认值/钳位。
   */
  EdrAttackSurfaceConfig attack_surface;

  /** §9 自保护 */
  struct {
    /** 周期性检测调试器附着（Windows: IsDebuggerPresent/CheckRemoteDebuggerPresent；Linux: TracerPid） */
    bool anti_debug;
    /** Windows：将当前进程纳入 Job Object（句柄保持至退出；失败仅打日志） */
    bool job_object_windows;
    /**
     * 主循环轮询侧日志间隔（秒），0 表示仅当 `EDR_SELF_PROTECT_WATCHDOG=1` 时保留原 tick 行为。
     */
    uint32_t watchdog_log_interval_s;
    /**
     * 事件总线占用 ≥ 该百分比时周期性 stderr 告警；0 表示关闭。
     */
    uint32_t event_bus_pressure_warn_pct;
  } self_protect;

  /** §17 协议层 Shellcode 检测引擎（Windows；其它平台忽略 enabled） */
  EdrShellcodeDetectorConfig shellcode_detector;

  /** §18 Webshell 检测引擎（站点目录增量监控） */
  EdrWebshellDetectorConfig webshell_detector;

  /** §19 检测引擎自适应策略 — TOML `[detection]` */
  struct {
    /** 自适应探测：Agent 启动时根据环境特征自动启用 shellcode/webshell */
    bool auto_profile;
    /** 手工强制 shellcode 检测（覆盖自适应） */
    int shellcode_mode; /* 0=关 1=开 -1=自适应(默认) */
    /** 手工强制 webshell 检测（覆盖自适应） */
    int webshell_mode; /* 0=关 1=开 -1=自适应(默认) */
    /** PMFE 内存取证: 0=关 1=仅空闲扫描 2=告警触发+空闲 (默认0) */
    int pmfe_mode;
  } detection;

  /** §20 PMFE 内存取证空闲扫描 — TOML `[pmfe]` */
  struct {
    bool idle_scan_enabled;
    uint32_t idle_scan_interval_min;
    uint32_t idle_scan_max_procs;
    double idle_cpu_threshold;
    bool idle_skip_on_battery;
  } pmfe;

  /** 取证自动触发策略 — TOML `[forensic_auto]` */
  EdrForensicAutoConfig forensic_auto;

  /** 远程 Shell 配置 — TOML `[shell]` */
  struct {
    uint32_t max_sessions;
    uint32_t session_timeout_s;
    uint32_t max_output_per_command_kb;
    char **shell_allow;
    size_t shell_allow_count;
    char **shell_block;
    size_t shell_block_count;
  } shell;

  /**
   * 联邦学习本地训练（FL §10）；TOML `[fl]`。
   */
  EdrFlConfig fl;

  struct {
    char rules_url[512];
    char p0_bundle_url[512];
    int poll_interval_s;
    char version_url[512];
    char download_url[512];
    bool auto_update;
  } remote;
} EdrConfig;

/** 设计文档默认值（无文件或未指定键时使用） */
void edr_config_apply_defaults(EdrConfig *cfg);

/** 释放 preprocessing.rules、attack_surface.high_risk_immediate_ports 等堆内存；edr_config_load 内部会先调用 */
void edr_config_free_heap(EdrConfig *cfg);

/**
 * 启动/重载后打印与平台联调相关的语义类 WARN（stderr），避免静默误配。
 * 前提：`edr_config_load` 在 `edr_config_clamp` 之后（或等价的 defaults + 已解析的 cfg）调用本函数效果最佳。
 * 见 `docs/WP3_CONFIG_VALIDATION.md`。
 */
void edr_config_log_semantic_warnings(const EdrConfig *cfg);

/**
 * 从 path 加载 TOML（先 apply_defaults，再由解析结果覆盖）。
 * path 为 NULL 或空串：仅 apply_defaults。
 * 文件不可读或解析失败返回 EDR_ERR_CONFIG_PARSE。
 */
EdrError edr_config_load(const char *path, EdrConfig *cfg);

/**
 * §11.2 轻量热更新：若 path 可访问且 mtime 与 *mtime_cache 不同则重新加载并写回 mtime。
 * 初始化：在首次 `edr_config_load` 成功后对配置文件 `stat`，将 `st_mtime` 写入 *mtime_cache。
 * 若 out_reloaded 非空，本次是否发生重新加载写入 *out_reloaded（0/1）。
 */
EdrError edr_config_reload_if_modified(const char *path, EdrConfig *cfg, time_t *mtime_cache,
                                     int *out_reloaded);

/** 配置文件内容 FNV-1a 指纹（十六进制，至少 17 字节缓冲）；不可读时 out_hex[0]='\0' */
void edr_config_fingerprint(const char *path, char *out_hex, size_t cap);

#endif
