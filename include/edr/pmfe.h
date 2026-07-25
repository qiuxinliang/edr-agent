/**
 * §21 PMFE — 进程内存取证引擎（调度 + 扫描线程 + VAD/maps 粗筛；Windows 含 §6 DNS ASCII 分块；扫描命中经事件总线→行为批次→HTTP ingest）
 *
 * **与行为管线（P2 T9）职责边界**：PMFE **工作线程**只产出扫描详情、调用 **`edr_pid_history_pmfe_ingest_scan_detail`**、
 * 并由 **`pmfe_try_emit_scan_result`** 推 **ETW1 槽**；**不写 `AVE_FeedEvent`**。预处理线程在 **`edr_behavior_from_slot`**
 * 之后调用 **`edr_ave_cross_engine_feed_from_record`**，将 PMFE / Shellcode / Webshell 标量统一送入 **`EdrPidHistory`**（E 组 53–54 等）。
 *
 * 开关：`EDR_PMFE_DNS_*`、`EDR_PMFE_EMIT_*`（`EDR_PMFE_EMIT_MZ` 仅 PE MZ；`EDR_PMFE_EMIT_ELF` 仅 Linux ELF，互不影响）、`EDR_PMFE_PID_HISTORY`（=0 关闭按 PID 的 PMFE 摘要写回 `EdrBehaviorRecord.pmfe_snapshot`）
 * Linux：`EDR_PMFE_LINUX_ANON_EXEC_ONLY=1` 时 maps 候选池仅匿名/`[vdso]` 等可执行段；详情含 `vm_read_failures=`；模块完整性/stomp 与 Windows 共用 `EDR_PMFE_STOMP_BYTES`、`EDR_PMFE_DISK_HASH_MAX`。
 * Linux 采集器：可选 **`EDR_LINUX_PROC_CONNECTOR=1`**（见 `collector_linux.c`）用内核 proc connector 驱动 **`edr_pmfe_on_process_lifecycle_hint`**。
 * 宿主筛选与优先级见 ../Cauld Design/07_进程内存取证引擎PMFE设计-1.md §2.2
 */
#ifndef EDR_PMFE_H
#define EDR_PMFE_H

#include "behavior_record.h"
#include "error.h"

#include <stdint.h>

/** 与《PMFE-1》§2.2.4 对齐的扫描宿主档位（用于队列内 ScanScope） */
typedef enum {
  EDR_PMFE_PRIO_IGNORE = 0,
  EDR_PMFE_PRIO_CRITICAL = 1,
  EDR_PMFE_PRIO_HIGH = 2,
  EDR_PMFE_PRIO_MED = 3,
  EDR_PMFE_PRIO_LOW = 4,
} EdrPmfeScanPriority;

typedef enum {
  EDR_PMFE_BAND_P0 = 0,
  EDR_PMFE_BAND_P1 = 1,
  EDR_PMFE_BAND_P2 = 2,
} EdrPmfeTriggerBand;

struct EdrConfig;
struct EdrEventBus;

/* Context retained from a server-triggered scan until the worker reaches a
 * terminal result. */
typedef struct EdrPmfeCommandContext {
  char soar_correlation_id[128];
  char playbook_run_id[96];
  char playbook_step_id[96];
  uint64_t requested_region_base;
  uint64_t requested_region_size;
  uint8_t extract_region;
  uint8_t yara_mode; /* 0=default, 1=enabled, 2=disabled */
} EdrPmfeCommandContext;

#define EDR_PMFE_RESULT_SCHEMA "pmfe_result_v1"
#define EDR_PMFE_MAX_REGIONS 8
#define EDR_PMFE_MAX_YARA_HITS 4
#define EDR_PMFE_MAX_THREAD_STARTS 8

typedef struct EdrPmfeThreadStart {
  uint32_t tid;
  uint64_t start_address;
} EdrPmfeThreadStart;

typedef struct EdrPmfeRegionResult {
  uint64_t base;
  uint64_t allocation_base;
  uint64_t size_bytes;
  uint64_t bytes_sampled;
  uint32_t protection;
  uint32_t memory_type;
  float score;
  float entropy;
  uint8_t read_ok;
  uint8_t mz_found;
  uint8_t yara_hit_count;
  uint8_t thread_start_count;
  char protection_name[48];
  char allocation_protection_name[48];
  char kind[32];
  char mapped_path[1024];
  char reason[160];
  char sha256[65];
  char artifact_path[1024];
  char pe_arch[16];
  uint16_t pe_sections;
  uint32_t pe_timestamp;
  uint32_t pe_entrypoint_rva;
  char entrypoint_preview_hex[129];
  char reconstructed_path[1024];
  char reconstructed_sha256[65];
  char reconstruction_status[32];
  EdrPmfeThreadStart thread_starts[EDR_PMFE_MAX_THREAD_STARTS];
  char yara_hits[EDR_PMFE_MAX_YARA_HITS][128];
} EdrPmfeRegionResult;

/** Structured server-scan result. Region artifacts are written by the PMFE
 * worker but uploaded only by the normal command loop. */
typedef struct EdrPmfeScanResult {
  char schema[24];
  char status[32];
  char verdict[32];
  uint32_t pid;
  char image_path[1024];
  uint64_t started_unix_ms;
  uint64_t finished_unix_ms;
  uint64_t duration_ms;
  uint64_t bytes_sampled;
  uint32_t regions_total;
  uint32_t regions_read;
  uint32_t read_failures;
  uint32_t threads_total;
  uint32_t thread_start_matches;
  uint32_t thread_query_failures;
  uint32_t private_exec;
  uint32_t memfd_exec;
  uint32_t deleted_exec;
  uint32_t stomp_suspicious;
  uint32_t mz_hits;
  uint32_t dns_hits;
  float entropy_max;
  float ave_max_score;
  float dns_best;
  char dns_sample[200];
  char dns_owner[200];
  char module_consistency[24];
  uint8_t injection_observed;
  int64_t injection_event_time_ns;
  int64_t injection_age_ms;
  char injection_technique[32];
  char injection_source[32];
  char cross_process_write_status[32];
  uint8_t truncated;
  uint8_t region_count;
  char warning[256];
  EdrPmfeRegionResult regions[EDR_PMFE_MAX_REGIONS];
} EdrPmfeScanResult;

typedef void (*EdrPmfeServerScanResultCallback)(const char *command_id, uint32_t pid,
                                                int scan_status, const char *detail,
                                                const EdrPmfeScanResult *result,
                                                const EdrPmfeCommandContext *context);

/**
 * 绑定事件总线，使 PMFE 扫描完成后可将 **ETW1 形态** 事件送入预处理线程（与 ETW/Webshell 同源：`edr_event_batch_push` → HTTP ingest）。
 * 须在 `edr_pmfe_init` 之前调用（通常传入 `edr_agent_event_bus(agent)`）。
 */
void edr_pmfe_set_event_bus(struct EdrEventBus *bus);
void edr_pmfe_set_server_scan_result_callback(EdrPmfeServerScanResultCallback callback);

/** 供可选 `AVE_ScanFile` 候选落盘路径使用；在 `edr_pmfe_init` 之前调用一次即可。 */
void edr_pmfe_bind_config(const struct EdrConfig *cfg);
const struct EdrConfig *edr_pmfe_current_config(void);

/**
 * Windows：刷新 TCP/UDP 监听聚合表（与 §19 共用 `edr_win_listen_collect_rows`）；Linux：`ss -ltnp` 聚合；其它 POSIX 空操作。
 * 行数超内部缓冲被截断时默认 `fprintf` 告警；`EDR_PMFE_LISTEN_TRUNC_QUIET=1` 可关闭。
 */
void edr_pmfe_listen_table_refresh(void);

/**
 * 按当前监听表 + 关键进程补集计算宿主档位（`IGNORE`=本进程等）。
 * Windows：**`EDR_PMFE_SERVICE_PRIORITY=0`** 时关闭「运行中的 Win32 服务 + 监听 → HIGH」（§2.2.4 规则 3）。
 */
EdrPmfeScanPriority edr_pmfe_compute_priority(uint32_t pid);

/**
 * 进程创建/退出等生命周期提示（非阻塞）：将监听表刷新**推迟约 1s**（去抖，多次事件合并为「最后一次 +1s」）。
 * Windows：由 ETW Kernel-Process 等路径调用；`EDR_PMFE_LISTEN_REFRESH_ON_PROCESS=0` 可关闭。非 Windows 空操作。
 */
void edr_pmfe_on_process_lifecycle_hint(void);

/** 启动 PMFE 工作线程（幂等）。可通过环境变量 `EDR_PMFE_DISABLED=1` 跳过。 */
EdrError edr_pmfe_init(void);

/** 停止线程并排空队列（幂等）。 */
void edr_pmfe_shutdown(void);

/** 返回 PMFE worker/queue 是否已经启动。 */
int edr_pmfe_is_running(void);

/**
 * 将服务端触发的扫描请求入队（`PMFE_TRIGGER_SERVER_CMD`，设计 P0，不参与同 PID 冷却）。
 * @param command_id 用于审计日志（可为空）
 * @return 0 已入队；-1 未初始化、已 shutdown、队列满或 pid 无效
 */
int edr_pmfe_submit_server_scan(const char *command_id, uint32_t pid);

/** Same as edr_pmfe_submit_server_scan, retaining the SOAR context. */
int edr_pmfe_submit_server_scan_ex(const char *command_id, uint32_t pid,
                                   const EdrPmfeCommandContext *context);

/**
 * ETW / 预处理路径触发的 PMFE 入队（`etw:<reason>`），带 **同 PID 冷却**（`EDR_PMFE_ETW_COOLDOWN_MS`，默认 30000）。
 * 与 `edr_pmfe_submit_server_scan` 区分，便于审计与策略。
 * @return 0 已入队；1 冷却期内跳过；-1 未初始化、shutdown、队列满或 pid 无效
 */
int edr_pmfe_submit_etw_scan(const char *reason, uint32_t pid);

/**
 * 同 `edr_pmfe_submit_etw_scan`，可指定 **触发档位**（影响 `pmfe_task_fill_scope` 中 peek/DNS/full_vad）与 **Windows VAD 精扫 hint**（用户态 VA；仅 Windows 深扫使用，0 表示未指定）。
 */
int edr_pmfe_submit_etw_scan_ex(const char *reason, uint32_t pid, EdrPmfeTriggerBand band, uint64_t vad_hint_va);

/** 预处理线程：在 `edr_behavior_from_slot` 之后调用（Windows：`EDR_PMFE_ETW_AUTO=1` 时按事件入队）。 */
void edr_pmfe_on_preprocess_slot(const EdrEventSlot *slot, const EdrBehaviorRecord *br);

void edr_pmfe_get_stats(unsigned long *out_submitted, unsigned long *out_completed, unsigned long *out_dropped);
void edr_pmfe_get_extended_stats(unsigned long *out_submitted, unsigned long *out_completed,
                                 unsigned long *out_dropped, unsigned long *out_deduped,
                                 unsigned long *out_cooldown_skipped);
unsigned long edr_pmfe_queue_depth(void);

#endif
