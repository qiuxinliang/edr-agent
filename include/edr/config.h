/**
 * §11 配置管理 — 与《EDR 端点详细设计 v1.0》§11.1 字段对齐；
 * 使用 tomlc99（`toml_parse_file`）解析标准 TOML。
 */
#ifndef EDR_CONFIG_H
#define EDR_CONFIG_H

#include "edr/error.h"
#include "edr/emit_rules.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/** T-015：`[fl.frozen_layers]` 逻辑名列表上限（与《10》§5 示例对齐） */
#define EDR_FL_FROZEN_MAX 16
/** 单层逻辑名最大长度（ONNX 子串/模块名） */
#define EDR_FL_FROZEN_NAME_MAX 64

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

  struct {
    bool etw_enabled;
    /** Windows：订阅 Microsoft-Windows-TCPIP（§19.10）；失败时跳过不致命 */
    bool etw_tcpip_provider;
    /** Windows：订阅 WFAS 防火墙 ETW（§19.10）；失败时跳过不致命 */
    bool etw_firewall_provider;
    /** Windows 可选：DNS-Client / PowerShell / Security-Auditing / WMI（A4.3）；**关前须与 P0/字段矩阵对表** */
    bool etw_dns_client_provider;
    bool etw_powershell_provider;
    bool etw_security_audit_provider;
    bool etw_wmi_provider;
    bool ebpf_enabled;
    int poll_interval_s;
    uint32_t max_event_queue_size;
    /**
     * Windows 实时 ETW 会话 `EVENT_TRACE_PROPERTIES`：`BufferSize`（**KB**）、`FlushTimer`（**秒**）。
     * **0** = 在 `edr_config_clamp` 中置默认（64 KB、1s）；亦可用 **`EDR_ETW_BUFFER_KB`** / **`EDR_ETW_FLUSH_TIMER_S`** 覆盖（见 A4.2）。
     */
    uint32_t etw_buffer_kb;
    uint32_t etw_flush_timer_s;
  } collection;

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

  struct {
    char model_dir[1024];
    int scan_threads;
    int max_file_size_mb;
    char sensitivity[16];
    /** 默认 false（需要显式启用）；可由环境变量 EDR_AVE_ENABLED=1 覆盖 */
    bool enabled;
    /** §08 签名白名单 Stage0：Windows 默认 true；见 `ave_sign_whitelist_*` */
    bool cert_whitelist_enabled;
    /** 可选 SQLite（`sign_blacklist` / `sign_whitelist` / `sign_cache` 等，见 08 设计文档） */
    char cert_whitelist_db_path[1024];
    /** L2：文件 SHA256 白名单（表 file_hash_whitelist）；与 IOC 并存时端上优先匹配 IOC（见 AVE_ENGINE_IMPLEMENTATION_PLAN） */
    char file_whitelist_db_path[1024];
    /** L3：已知恶意文件哈希 IOC（表 `ioc_file_hash`） */
    char ioc_db_path[1024];
    /**
     * 为 true（默认）时 ONNX 前做 IOC 预检；为 false 时仅 ONNX 后二次核对 IOC（便于与模型并行或热库后写）。
     */
    bool ioc_precheck_enabled;
    /** L4：不可豁免文件哈希（表 `file_behavior_non_exempt`） */
    char behavior_policy_db_path[1024];
    /** P2：`AVE_StartBehaviorMonitor` 是否拉起消费线程（默认 true） */
    bool behavior_monitor_enabled;
    /**
     * Windows Authenticode：`WinVerifyTrust` 吊销检查（`WTD_REVOKE_WHOLECHAIN`）。
     * 可由环境变量 **`EDR_AVE_CERT_REVOCATION=0/1`** 覆盖（加载后于 clamp 中应用）。
     */
    bool cert_revocation_check;
    /**
     * ONNX 之后：若 **`AVE_ScanFileWithSubject`** 提供 `subject_pid`，且该 PID 行为异常分 ≥ 阈值，则叠加 L4 类覆盖（`rule_name=behavior_realtime`）。
     */
    bool l4_realtime_behavior_link;
    /**
     * 与行为管线 **`anomaly`** 对齐；产品默认等于 **`EDR_AVE_BEH_SCORE_HIGH`**（《11》§7.3，见 `ave_behavior_gates.h`）。
     */
    float l4_realtime_anomaly_threshold;
    /**
     * P2：`AVE_ScanFile` 在已通过 SHA256 后，对 **static ONNX** 推理结果做进程内 LRU；**0**=关闭。
     * 可被 **`EDR_AVE_STATIC_INFER_CACHE_MAX`** 覆盖；实际上限见 `ave_sdk.c`。
     */
    uint32_t static_infer_cache_max_entries;
    /**
     * 缓存条目存活时间（秒）；**0**=不按时间过期（仅 LRU 驱逐）。
     * 可被 **`EDR_AVE_STATIC_INFER_CACHE_TTL_S`** 覆盖。
     */
    uint32_t static_infer_cache_ttl_s;
  } ave;

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
  struct {
    bool enabled;
    uint32_t port_interval_s;
    uint32_t conn_interval_s;
    uint32_t service_interval_s;
    uint32_t policy_interval_s;
    uint32_t full_snapshot_interval_s;
    uint32_t outbound_top_n;
    /** §19 / §18.3.5.4 P2：`egressTop` 条数上限（与 `outbound_top_n` 监听裁剪独立） */
    uint32_t egress_top_n;
    bool outbound_exclude_loopback;
    char geoip_db_path[1024];
    uint32_t firewall_rule_detail_max;
    uint16_t *high_risk_immediate_ports;
    size_t high_risk_immediate_ports_count;
    /**
     * 为 true（默认）时，§19.10 ETW 去抖后触发 `etw_tcpip_wf`；**POST 仍受** `min(port,service,policy,full)` 全局限流。
     */
    bool etw_refresh_triggers_snapshot;
    /** §19.10 去抖窗口（秒，钳 1～300），仅与 ETW 批处理节奏有关，**不能**短于全局限流间隔。 */
    uint32_t etw_refresh_debounce_s;
    /**
     * Windows：`edr_win_listen_collect_rows` 进程内快照缓存 TTL（毫秒）。`0` 表示关闭缓存（每次枚举打 API）。
     * 可被环境变量 **`EDR_WIN_LISTEN_CACHE_TTL_MS`** 覆盖；钳位见 `edr_config_clamp`。
     */
    uint32_t win_listen_cache_ttl_ms;
  } attack_surface;

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
  struct {
    bool enabled;
    int windivert_priority;
    uint32_t max_payload_inspect;
    double alert_threshold;
    double auto_isolate_threshold;
    /**
     * 当分数 ≥ auto_isolate_threshold 且已启用高危策略时，是否执行与 `isolate` 指令相同的落盘 + EDR_ISOLATE_HOOK。
     * 另可用环境变量 **`EDR_SHELLCODE_AUTO_ISOLATE=1`**（优先）。
     * 默认 false；同一进程内最多成功触发一次，防抖动。
     */
    bool auto_isolate_execute;
    /** 启发式分数乘数（0.01–3.0），用于现场压误报/提灵敏度 */
    double heuristic_score_scale;
    /** YARA 规则目录周期性重新编译间隔（秒）；0=仅启动时加载 */
    uint32_t yara_rules_reload_interval_s;
    bool monitor_smb;
    bool monitor_rdp;
    bool monitor_winrm;
    bool monitor_msrpc;
    bool monitor_ldap;
    uint32_t detector_threads;
    char yara_rules_dir[1024];
    char forensic_dir[1024];
    /** 告警时写 PCAP（需 forensic_dir 非空；无环形时单包 raw LINKTYPE 228/229） */
    bool forensic_save_pcap;
    /** 告警 ETW1 中附加证据区 SHA256 后的十六进制预览长度（0=关闭，上限见 config clamp） */
    uint32_t evidence_preview_bytes;
    /** 环形缓冲槽位数（0=关闭，仅写告警触发单包 pcap）；>0 时告警导出最近 N 包为多包 pcap */
    uint32_t forensic_ring_slots;
    /** 环形缓冲单槽最大字节（截断过长 IP 包） */
    uint32_t forensic_ring_max_packet_bytes;
    /**
     * WinDivert 过滤 TCP 端口：逗号分隔，如 `80,443,445`。
     * 空字符串表示使用内置默认（SMB/RDP/WinRM/MSRPC/LDAP 等，与原先硬编码一致）。
     * 非空则完全按该列表生成过滤器，且 `monitor_*` 开关不再按端口类别过滤（仅按列表匹配）。
     */
    char windivert_tcp_ports[512];
    bool windivert_ports_is_custom;
    uint16_t windivert_tcp_ports_parsed[64];
    size_t windivert_tcp_ports_parsed_count;
  } shellcode_detector;

  /** §18 Webshell 检测引擎（站点目录增量监控） */
  struct {
    bool enabled;
    uint32_t discovery_interval_s;
    char iis_config_path[1024];
    uint32_t max_watch_dirs;
    bool monitor_subdirs;
    char webshell_rules_dir[1024];
    uint32_t scan_threads;
    uint32_t max_file_size_mb;
    uint32_t defer_retry_ms;
    double alert_threshold;
    double l2_review_threshold;
    bool upload_webshell_files;
    uint32_t upload_timeout_s;
    uint32_t max_upload_size_mb;
  } webshell_detector;

  /**
   * 联邦学习本地训练（FL §10）；TOML `[fl]`。
   */
  struct {
    bool enabled;
    /** 协调器 gRPC 地址，如 `coordinator.example.com:7443` */
    char coordinator_grpc_addr[256];
    /** C5：HTTP 梯度上传降级（空则仅用占位上传器） */
    char coordinator_http_url[512];
    /**
     * P-256 协调方公钥，**十六进制**（可选 `0x` 前缀），长度 66 或 130 个十六进制字符
     *（对应 33 字节压缩或 65 字节未压缩 SEC1）。与 `EDR_FL_CRYPTO_OPENSSL=1` 配合启用 **FL3**（ECDH+HKDF+GCM）。
     */
    char coordinator_secp256r1_pubkey_hex[288];
    uint8_t coordinator_secp256r1_pub[96];
    uint32_t coordinator_secp256r1_pub_len;
    char privacy_budget_db_path[1024];
    /** C3：`fl_samples.db` 路径（空则不注册特征查找，行为同 C0 全零） */
    char fl_samples_db_path[1024];
    int min_new_samples;
    float idle_cpu_threshold;
    int local_epochs;
    float dp_epsilon;
    float dp_clip_norm;
    int max_participated_rounds;
    int gradient_chunk_size_kb;
    /** C2：>0 时协议线程周期性注入假 Round（联调 / 单测） */
    uint32_t mock_round_interval_s;
    /**
     * 本轮本地训练向量语义：`static`（512 维，与 static ONNX 一致）或 `behavior`（默认 256 维 CLS）。
     * 见 `docs/FL_ROUND_TRAINING_SEMANTICS.md`；`fl_samples.db` 当前仍以 static 枚举为主。
     */
    char model_target[32];
    /**
     * T-015：`[fl.frozen_layers]`，按 `model_target` 选用 static 或 behavior 列表。
     * 名称与 ONNX initializer/模块名子串对齐；HTTP 上传会附带 `frozen_layer_names` JSON 字段供协调端/审计。
     */
    size_t frozen_layer_count_static;
    char frozen_layer_static[EDR_FL_FROZEN_MAX][EDR_FL_FROZEN_NAME_MAX];
    size_t frozen_layer_count_behavior;
    char frozen_layer_behavior[EDR_FL_FROZEN_MAX][EDR_FL_FROZEN_NAME_MAX];
  } fl;

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
