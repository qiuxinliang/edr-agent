/**
 * AVEngine 公共 C API（与《09_AVEngine开发需求文档》§2 对齐）。
 * Phase 1：生命周期、同步文件扫描、状态查询；其余接口见实现与 docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md。
 */
#ifndef EDR_AVE_SDK_H
#define EDR_AVE_SDK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#  if defined(EDR_AVE_BUILD_DLL)
#    define AVE_EXPORT __declspec(dllexport)
#  elif defined(EDR_AVE_USE_DLL)
#    define AVE_EXPORT __declspec(dllimport)
#  else
#    define AVE_EXPORT __declspec(dllexport)
#  endif
#define AVE_CALL __cdecl
#include <wchar.h>
#else
#define AVE_EXPORT __attribute__((visibility("default")))
#define AVE_CALL
#endif

#define AVE_SDK_VERSION_MAJOR 2
#define AVE_SDK_VERSION_MINOR 6
#define AVE_SDK_VERSION_PATCH 5

#define AVE_OK 0
#define AVE_ERR_NOT_INITIALIZED (-1)
#define AVE_ERR_ALREADY_INIT (-2)
#define AVE_ERR_MODEL_LOAD (-3)
#define AVE_ERR_MODEL_VERSION (-4)
#define AVE_ERR_WHITELIST_LOAD (-5)
#define AVE_ERR_IOC_LOAD (-6)
#define AVE_ERR_INVALID_PARAM (-7)
#define AVE_ERR_TIMEOUT (-8)
#define AVE_ERR_FILE_NOT_FOUND (-9)
#define AVE_ERR_ACCESS_DENIED (-10)
#define AVE_ERR_INVALID_HOTFIX (-11)
#define AVE_ERR_PARSE_FAILED (-12)
#define AVE_ERR_CONCURRENT_UPDATE (-13)
#define AVE_ERR_UNKNOWN_HOTFIX (-14)
#define AVE_ERR_QUEUE_FULL (-15)
#define AVE_ERR_INTERNAL (-99)
/** Linux 等平台不支持（如 VerifySignature） */
#define AVE_ERR_NOT_SUPPORTED (-100)
/** 子系统尚未实现（Phase 1 占位） */
#define AVE_ERR_NOT_IMPL (-101)
/** `AVE_ExportModelWeights`：输出缓冲区不足；`*size` 回写所需最小字节数（C0+ 实现） */
#define AVE_ERR_BUFFER_TOO_SMALL (-102)
/** `AVE_ExportFeatureVector`：该 SHA256 在 FL 特征缓存中不存在（C1+ 对接 fl_samples / 缓存） */
#define AVE_ERR_FL_SAMPLE_NOT_FOUND (-103)

typedef enum EDRVerdict {
  VERDICT_CLEAN = 0,
  VERDICT_SUSPICIOUS = 1,
  VERDICT_MALWARE = 2,
  VERDICT_TRUSTED_CERT = 3,
  VERDICT_WHITELISTED = 4,
  VERDICT_IOC_CONFIRMED = 5,
  VERDICT_CERT_REVOKED = 6,
  VERDICT_CERT_TAMPERED = 7,
  VERDICT_TIMEOUT = 8,
  VERDICT_ERROR = 9,
} EDRVerdict;

typedef enum TrustLevel {
  TRUST_MICROSOFT = 0,
  TRUST_OS_VENDOR = 1,
  TRUST_SECURITY = 2,
  TRUST_MAJOR_SW = 3,
  TRUST_ENTERPRISE = 4,
  TRUST_UNKNOWN = 5,
} TrustLevel;

typedef enum SignatureVerifyResult {
  SIG_VALID_MICROSOFT = 0,
  SIG_VALID_KNOWN_VENDOR = 1,
  SIG_VALID_ENTERPRISE = 2,
  SIG_VALID_UNKNOWN = 3,
  SIG_INVALID_REVOKED = 4,
  SIG_INVALID_EXPIRED = 5,
  SIG_INVALID_CHAIN = 6,
  SIG_INVALID_TAMPERED = 7,
  SIG_UNSIGNED = 8,
  SIG_ERROR = 9,
} SignatureVerifyResult;

typedef uint32_t AVEBehaviorFlags;
#define AVE_BEH_INJECT_LSASS (1u << 0)
#define AVE_BEH_ALLOC_EXEC_REMOTE (1u << 1)
#define AVE_BEH_CREATE_REMOTE_THREAD (1u << 2)
#define AVE_BEH_MODULE_STOMP (1u << 3)
#define AVE_BEH_HOLLOW_PROCESS (1u << 4)
#define AVE_BEH_DNS_TUNNEL (1u << 5)
#define AVE_BEH_REFLECTIVE_LOAD (1u << 6)
#define AVE_BEH_LSASS_DUMP (1u << 7)
#define AVE_BEH_NTDS_ACCESS (1u << 8)
#define AVE_BEH_SAM_DUMP (1u << 9)
#define AVE_BEH_SHADOW_COPY_DELETE (1u << 10)
#define AVE_BEH_BOOT_SECTOR_WRITE (1u << 11)
#define AVE_BEH_UNSIGNED_DRIVER (1u << 12)
#define AVE_BEH_WDIGEST_ENABLE (1u << 13)

typedef enum AVEEventType {
  AVE_EVT_PROCESS_CREATE = 0,
  AVE_EVT_PROCESS_INJECT = 1,
  AVE_EVT_FILE_WRITE = 2,
  AVE_EVT_FILE_EXECUTE = 3,
  AVE_EVT_NET_CONNECT = 4,
  AVE_EVT_NET_DNS = 5,
  AVE_EVT_REG_WRITE = 6,
  AVE_EVT_DLL_LOAD = 7,
  AVE_EVT_MEM_ALLOC_EXEC = 8,
  AVE_EVT_LSASS_ACCESS = 9,
  AVE_EVT_AUTH_EVENT = 10,
  /** §12.2 / B3：跨子系统信号事件（与标量字段联用） */
  AVE_EVT_SHELLCODE_SIGNAL = 11,
  AVE_EVT_WEBSHELL_SIGNAL = 12,
  AVE_EVT_PMFE_RESULT = 13,
} AVEEventType;

typedef struct AVEConfig {
  const char *model_dir;
  const char *whitelist_db_path;
  const char *ioc_db_path;
  /** L4：不可豁免哈希库（表 `file_behavior_non_exempt`）；可为 NULL */
  const char *behavior_policy_db_path;
  const char *cert_whitelist_db_path;
  const char *yara_rules_dir;
  const char *fl_samples_db_path;

  int max_concurrent_scans;
  int scan_timeout_ms;
  int async_scan_timeout_ms;
  int memory_limit_mb;
  int async_queue_depth;

  float l3_trigger_threshold;
  float fp_suppression_threshold;

  bool enable_cert_whitelist;
  bool strict_revocation_check;
  bool allow_expired_with_timestamp;
  float cert_adj_microsoft;
  float cert_adj_os_vendor;
  float cert_adj_security;
  float cert_adj_major_sw;
  float cert_adj_enterprise;
  float cert_min_confidence_floor;

  bool behavior_monitor_enabled;
  bool federated_learning_enabled;
  bool yara_scan_enabled;
  bool cert_whitelist_enabled;

  float fl_idle_cpu_threshold;
  int fl_min_samples;

  /** L4×实时行为：`AVE_ScanFileWithSubject` 使用 `subject_pid` 时是否联动行为异常分 */
  bool l4_realtime_behavior_link;
  /** 默认与 **`EDR_AVE_BEH_SCORE_HIGH`**（0.65）一致；与 `AVE_GetProcessAnomalyScore` 同源（`ave_behavior_gates.h`） */
  float l4_realtime_anomaly_threshold;
} AVEConfig;

typedef struct AVEScanResult {
  EDRVerdict raw_ai_verdict;
  float raw_confidence;

  EDRVerdict final_verdict;
  float final_confidence;

  char verification_layer[4];
  char rule_name[64];
  char family_name[64];
  bool is_packed;

  char sha256[65];
  char scanned_path[512];
  int64_t scan_duration_ms;

  SignatureVerifyResult sig_result;
  TrustLevel sig_trust_level;
  char sig_vendor_id[32];
  char sig_vendor_name[128];
  char sig_subject_cn[256];
  bool sig_has_timestamp;
  bool sig_behavior_override;
  float sig_confidence_delta;

  bool skip_ai_analysis;
  bool needs_l2_review;
} AVEScanResult;

typedef struct AVEBehaviorAlert {
  uint32_t pid;
  char process_name[256];
  char process_path[512];
  float anomaly_score;
  float tactic_probs[14];
  char triggered_tactics[512];
  AVEBehaviorFlags behavior_flags;
  bool skip_ai_analysis;
  bool needs_l2_review;
  int64_t timestamp_ns;
} AVEBehaviorAlert;

typedef struct AVEBehaviorEvent {
  uint32_t pid;
  uint32_t ppid;
  AVEEventType event_type;
  uint8_t severity_hint;
  int64_t timestamp_ns;
  char target_path[512];
  char target_ip[46];
  char target_domain[256];
  uint16_t target_port;
  float ave_confidence;
  /** §12.2 / 《11》§5.5 E 组：WinDivert / Webshell / PMFE → behavior.onnx（未接入时为 0） */
  float shellcode_score;
  float webshell_score;
  float pmfe_confidence;
  float pmfe_dns_tunnel;
  uint8_t pmfe_pe_found;
  /** 可选：预处理/缓存已算出的文件 SHA256（64 hex + `\\0`），供 `ioc_file_hash` 匹配 */
  char file_sha256_hex[65];
  /** §5.5 E 组 48–50：TIP/IOC 库在本事件上的命中（0/1）；由 `AVE_FillBehaviorEventIocHits` 或上游填写 */
  uint8_t ioc_ip_hit;
  uint8_t ioc_domain_hit;
  uint8_t ioc_sha256_hit;
  AVEBehaviorFlags behavior_flags;
  /** 《11》§5.3 维 35 `target_has_motw`：文件类事件由预处理/采集填 0/1；未填为 0 */
  uint8_t target_has_motw;
  /**
   * 《11》§5.5 **维 56**：**事件步**上的证书吊销祖先信号（0/1），与 **`EdrAveBehaviorFeatExtra.cert_revoked_ancestor`**
   *（PidHistory 粘性 / `merge_static_scan`）**独立**；编码时二者 **OR** 进入 `feat[56]`，便于预处理或证书子系统直写本字段而不依赖槽位粘性。
   */
  uint8_t cert_revoked_ancestor;
} AVEBehaviorEvent;

typedef void(AVE_CALL *AVEThreatCallback)(const AVEScanResult *result, void *user_data);
typedef void(AVE_CALL *AVEBehaviorCallback)(const AVEBehaviorAlert *alert, void *user_data);
typedef void(AVE_CALL *AVEWhitelistHitCallback)(const char *sha256, const char *file_path,
                                                  EDRVerdict raw_ai_verdict, float raw_confidence,
                                                  const char *whitelist_reason, void *user_data);
typedef void(AVE_CALL *AVEHotfixAppliedCallback)(const char *hotfix_id, bool success,
                                                 const char *error_message, void *user_data);

typedef struct AVECallbacks {
  AVEThreatCallback on_threat_detected;
  AVEBehaviorCallback on_behavior_alert;
  AVEWhitelistHitCallback on_whitelist_hit;
  AVEHotfixAppliedCallback on_hotfix_applied;
  void *user_data;
} AVECallbacks;

typedef struct AVEStatus {
  bool initialized;
  bool behavior_monitor_running;
  int active_scan_count;
  int async_queue_size;
  /** MPMC **近似**深度（多生产者下为估计值）；与 **`behavior_queue_capacity`** 对照可观测背压 */
  int behavior_event_queue_size;
  char static_model_version[32];
  char behavior_model_version[32];
  char whitelist_version[32];
  char cert_whitelist_version[32];
  char yara_version[32];
  int cert_whitelist_entry_count;
  int ioc_entry_count;
  float fl_samples_count;
  /** `ioc_db_path` 库内 `ave_db_meta.rules_version`（无表或键则为空） */
  char ioc_rules_version[32];
  /** `edr_ave_bp_feed` 非 NULL 调用累计（多线程安全计数） */
  uint64_t behavior_feed_total;
  /** MPMC **`ave_mpmc_try_push`** 成功次数 */
  uint64_t behavior_queue_enqueued;
  /** 队列满时 **同步降级** `process_one_event` 次数（背压指标） */
  uint64_t behavior_queue_full_sync_fallback;
  /** 未起监控线程或队列未建时，**直接同步**处理次数 */
  uint64_t behavior_feed_sync_bypass;
  /** 消费线程从 MPMC **成功 pop** 次数（与 enqueued+当前深度大致守恒） */
  uint64_t behavior_worker_dequeued;
  /** **`edr_onnx_behavior_infer`** 成功 / 非 **EDR_OK** 次数 */
  uint64_t behavior_infer_ok;
  uint64_t behavior_infer_fail;
  /** 行为 MPMC 容量（当前实现为 **4096**） */
  uint32_t behavior_queue_capacity;
} AVEStatus;

AVE_EXPORT int AVE_CALL AVE_Init(const AVEConfig *config);
struct EdrConfig;
/**
 * 使用 Agent 已加载的 `EdrConfig` 初始化 ONNX/模型子系统（与 `AVE_Init` 二选一）。
 * `cfg` 在 `AVE_Shutdown` 之前必须保持有效；典型调用点为 `edr_agent_init` 在 TOML 加载成功后。
 */
AVE_EXPORT int AVE_CALL AVE_InitFromEdrConfig(const struct EdrConfig *cfg);
/**
 * 配置热载（`edr_config_reload_if_modified` / 远程 TOML）成功后调用：按当前 `EdrConfig` 从 `model_dir` 重载 static / behavior ONNX。
 * 其它 `[ave]` 项（吊销、L4、SQLite 路径等）在扫描路径上每次从 `cfg` 读取；与 `AVE_InitFromEdrConfig` 使用**同一** `EdrConfig` 指针并原地更新时无需再调本接口，但重载 ONNX 仍需本调用。
 * 若 AVE 未初始化则返回 `AVE_ERR_NOT_INITIALIZED`。
 */
AVE_EXPORT int AVE_CALL AVE_SyncFromEdrConfig(const struct EdrConfig *cfg);
AVE_EXPORT int AVE_CALL AVE_RegisterCallbacks(const AVECallbacks *callbacks);
AVE_EXPORT int AVE_CALL AVE_StartBehaviorMonitor(void);
AVE_EXPORT void AVE_CALL AVE_Shutdown(void);
AVE_EXPORT const char *AVE_CALL AVE_GetVersion(void);
AVE_EXPORT int AVE_CALL AVE_GetStatus(AVEStatus *status_out);

/**
 * 可选扫描主体 PID（如发起读写的进程）。与 `[ave] l4_realtime_behavior_link` 配合，在 ONNX 之后按行为分叠加 L4（`behavior_realtime`）。
 */
typedef struct AVEScanSubject {
  uint32_t subject_pid;
} AVEScanSubject;

AVE_EXPORT int AVE_CALL AVE_ScanFile(const char *file_path, AVEScanResult *result_out);
AVE_EXPORT int AVE_CALL AVE_ScanFileWithSubject(const char *file_path, const AVEScanSubject *subject,
                                              AVEScanResult *result_out);
AVE_EXPORT int64_t AVE_CALL AVE_ScanFileAsync(const char *file_path);
AVE_EXPORT int AVE_CALL AVE_ScanMemory(const uint8_t *buffer, size_t size, const char *hint_name,
                                       AVEScanResult *result_out);
AVE_EXPORT int AVE_CALL AVE_CancelScan(int64_t scan_id);

AVE_EXPORT void AVE_CALL AVE_FeedEvent(const AVEBehaviorEvent *event);
AVE_EXPORT int AVE_CALL AVE_GetProcessAnomalyScore(uint32_t pid, float *score_out);
AVE_EXPORT int AVE_CALL AVE_GetProcessBehaviorFlags(uint32_t pid, AVEBehaviorFlags *flags_out);
AVE_EXPORT void AVE_CALL AVE_NotifyProcessExit(uint32_t pid);

AVE_EXPORT int AVE_CALL AVE_ReportFalsePositive(const char *sha256, const char *file_path);
AVE_EXPORT int AVE_CALL AVE_ReportTruePositive(const char *sha256);
AVE_EXPORT int AVE_CALL AVE_GetFLSampleCount(int *confirmed_malware_count, int *confirmed_clean_count);

/**
 * 联邦学习：按 SHA256 导出 static 模型用 **512 维 float** 特征（见《10_联邦学习FL组件详细设计》§2.9）。
 * 若已注册 `edr_fl_register_feature_lookup` 且命中样本则写库中向量；未注册或未命中时写全零并保持 `AVE_OK`（C0 兼容）。
 * 显式未命中（回调返回「未找到」）时返回 `AVE_ERR_FL_SAMPLE_NOT_FOUND`。
 */
AVE_EXPORT int AVE_CALL AVE_ExportFeatureVector(const char *sha256, float *out_512d);

/** static 联邦特征默认维度（与 static ONNX 嵌入一致） */
#define AVE_FL_FEATURE_DIM_STATIC 512u
/** behavior：与《11_behavior.onnx详细设计》§6.1 **CLS Token** 表征维 **256** 一致（联邦导出默认） */
#define AVE_FL_FEATURE_DIM_BEHAVIOR_DEFAULT 256u
/** 行为序列长度（`features` 张量 `seq_len`，与 §6.1 输入 shape `(1,128,64)` 一致；非 FL 向量维数） */
#define AVE_FL_BEHAVIOR_SEQ_LEN 128u
#define AVE_FL_FEATURE_DIM_MAX 4096u

/**
 * C7：按目标与维度导出特征；`target` 使用 `EDR_FL_TARGET_*`（见 `fl_feature_provider.h`）。
 */
AVE_EXPORT int AVE_CALL AVE_ExportFeatureVectorEx(const char *sha256, float *out, size_t dim, int target);

/**
 * 导出当前 **ONNX 模型原始权重字节**（`target`: `"static"` 或 `"behavior"`）。
 * C0：返回 `AVE_ERR_NOT_IMPL`（占位）；`*size` 行为以实现为准。
 */
AVE_EXPORT int AVE_CALL AVE_ExportModelWeights(const char *target, void *buf, size_t *size);

/**
 * 《11》§9.4：**张量级**导出可联邦训练的 **FP32** 初始值（从 **behavior.onnx** 解析 initializer，排除战术头相关张量）。
 * 与 **`AVE_ExportModelWeights("behavior",…)`**（整文件字节）**并存**；平台按任务选择其一。
 * `out == NULL`：`*out_nelem` ← 所需 float 元素数；`manifest_json` 若非空则写入 JSON 切片说明（`cap` 含 NUL）。
 * `out != NULL`：`*out_nelem` 入参为缓冲可容元素数，成功时回写实际写入数。
 */
AVE_EXPORT int AVE_CALL AVE_ExportBehaviorFlTrainableTensors(float *out, size_t *out_nelem, char *manifest_json,
                                                             size_t manifest_cap);

/**
 * 将权重写回引擎（本地验证 / 回滚；**不**触发线上灰度）。
 * **FL3**（`FL3` + 版本字节 `2`）为加密梯度载荷，非模型权重；返回 `AVE_ERR_NOT_SUPPORTED`。
 * 开发占位：`FLSTUB1` / `FL2` 前缀可返回 `AVE_OK`；其余返回 `AVE_ERR_NOT_IMPL`。
 */
AVE_EXPORT int AVE_CALL AVE_ImportModelWeights(const char *target, const void *buf, size_t size);

AVE_EXPORT int AVE_CALL AVE_ApplyHotfix(const char *hotfix_path);
AVE_EXPORT int AVE_CALL AVE_UpdateModel(const char *model_path, const char *pca_path);
AVE_EXPORT int AVE_CALL AVE_UpdateWhitelist(const char *entries_json);
AVE_EXPORT int AVE_CALL AVE_UpdateIOC(const char *ioc_json);

AVE_EXPORT int AVE_CALL AVE_IsWhitelisted(const char *sha256);

#ifdef _WIN32
AVE_EXPORT int AVE_CALL AVE_VerifySignature(const wchar_t *file_path,
                                            SignatureVerifyResult *sig_result_out,
                                            TrustLevel *trust_level_out, char *vendor_id_out,
                                            char *vendor_name_out);
#endif

#ifdef __cplusplus
}
#endif

#endif /* EDR_AVE_SDK_H */
