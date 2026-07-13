/**
 * §8 响应指令 — HTTPS control stream / long-poll 收到 CommandEnvelope 后转入此入口（隔离/杀进程/取证/PMFE/AVE/自保护状态等）。
 * 高危操作需 **`EDR_CMD_ENABLED=1`** / **`EDR_CMD_DANGEROUS=1`** 或配置 **`[command] allow_dangerous`**。
 * SOAR：编排字段见 `EdrSoarCommandMeta`；执行结果经 HTTPS ingest 回传。
 */
#ifndef EDR_COMMAND_H
#define EDR_COMMAND_H

#include <stddef.h>
#include <stdint.h>

#include "edr/behavior_record.h"

#ifdef __cplusplus
extern "C" {
#endif

struct EdrConfig;
struct EdrPmfeCommandContext;
struct EdrPmfeScanResult;

/**
 * 绑定当前进程配置（main 在 edr_agent_init 成功后调用），供 AVE 等指令使用 `EdrConfig`。
 */
void edr_command_bind_config(const struct EdrConfig *cfg);
void edr_command_set_active_type(const char *command_type);

/**
 * WinDivert shellcode 告警分数 ≥ `auto_isolate_threshold` 时，在显式启用（`EDR_SHELLCODE_AUTO_ISOLATE=1`
 * 或 TOML `auto_isolate_execute`）且高危策略允许时，执行与 `isolate` 相同的标记 + `EDR_ISOLATE_HOOK`。
 * 同一进程至多成功一次。仅 Windows 端实现。
 */
void edr_isolate_auto_from_shellcode_alarm(void);
/**
 * 确诊勒索时执行端侧处置：可选终止归属进程并执行主机隔离。
 * 默认关闭，需 EDR_RANSOM_AUTO_ISOLATE=1 + 高危策略；终止进程另需 EDR_RANSOM_AUTO_TERMINATE=1。
 */
void edr_isolate_auto_from_ransom_alarm(uint32_t pid);

/** 与 CommandEnvelope SOAR 扩展字段对应（定长 UTF-8，截断由控制面写入） */
typedef struct EdrSoarCommandMeta {
  char soar_correlation_id[128];
  char playbook_run_id[96];
  char playbook_step_id[96];
  char idempotency_key[512];
  int64_t issued_at_unix_ms;
  uint32_t deadline_ms;
  /* 命令发起来源(取证 velo 仅允许 "operator" 人工下发;空/其它=自动化,被 gate 拒绝)。 */
  char initiated_by[32];
} EdrSoarCommandMeta;

/** 与 ingest.proto CommandExecutionStatus 枚举值一致 */
typedef enum EdrCommandExecutionStatus {
  EdrCmdExecUnspecified = 0,
  EdrCmdExecOk = 1,
  EdrCmdExecRejected = 2,
  EdrCmdExecFailed = 3,
  EdrCmdExecUnknownType = 4,
} EdrCommandExecutionStatus;

/**
 * 处理服务端下发的指令（来自 HTTPS control stream / long-poll）。
 * command_id / command_type 为 UTF-8 字符串；payload 可为空。
 * soar_meta 为 NULL 表示无非编排扩展（旧服务端或纯本地指令）。
 */
void edr_command_on_envelope(const char *command_id, const char *command_type, const uint8_t *payload,
                             size_t payload_len, const EdrSoarCommandMeta *soar_meta);

/** Trusted in-process automation entry. Never call this with transport-originated data. */
void edr_command_on_internal_envelope(const char *command_id, const char *command_type,
                                      const uint8_t *payload, size_t payload_len,
                                      const EdrSoarCommandMeta *soar_meta);

/**
 * 两阶段控制面入口：先验签/验 deadline/持久化 command_state + 本地执行 inbox。
 * 返回 1 表示应继续执行；返回 0 表示已拒绝、已压制重复或已回放最终结果；
 * 返回 -1 表示尚未可靠接收，HTTPS 控制面不得 ack。
 */
int edr_command_receive_envelope(const char *command_id, const char *command_type, const uint8_t *payload,
                                 size_t payload_len, const EdrSoarCommandMeta *soar_meta);

/** 执行已经通过 edr_command_receive_envelope 持久化接收的命令。 */
void edr_command_execute_received_envelope(const char *command_id, const char *command_type,
                                           const uint8_t *payload, size_t payload_len,
                                           const EdrSoarCommandMeta *soar_meta);

/** 执行已持久化的命令，并在最终结果写入后删除本地执行 inbox。 */
void edr_command_execute_persisted_envelope(const char *command_id, const char *command_type,
                                            const uint8_t *payload, size_t payload_len,
                                            const EdrSoarCommandMeta *soar_meta);

/** Claim and execute at most one durable inbox record. Used only by the command executor. */
int edr_command_replay_persisted_inbox_once(void);
int edr_command_replay_persisted_inbox_once_for_lane(int lane);

/** 周期性刷可靠投递 outbox：取证上传补发、命令执行结果补报、状态库压缩。 */
void edr_command_poll_reliable_delivery(void);
void edr_command_delivery_shutdown(void);

/** Persist a collected forensic artifact for retryable upload. A successful
 * retry emits the command's single terminal result. */
int edr_command_queue_forensic_upload(const char *command_id, const char *command_type,
                                      const EdrSoarCommandMeta *soar_meta,
                                      const char *artifact_path, const char *sha256,
                                      const char *source, int partial);

/** PMFE worker completion is queued and drained by the command poll loop. */
void edr_command_on_pmfe_scan_complete(const char *command_id, uint32_t pid, int scan_status,
                                       const char *detail,
                                       const struct EdrPmfeScanResult *result,
                                       const struct EdrPmfeCommandContext *context);

typedef struct EdrCommandDeliveryHealth {
  uint64_t poll_count;
  int64_t last_poll_unix_ms;
  uint32_t last_total_ms;
  uint32_t max_total_ms;
  uint32_t last_upload_ms;
  uint32_t max_upload_ms;
  uint32_t last_result_ms;
  uint32_t max_result_ms;
  uint32_t last_compact_ms;
  uint32_t max_compact_ms;
  uint32_t upload_pending_seen;
  uint32_t upload_attempted;
  uint32_t upload_succeeded;
  uint32_t upload_failed;
  uint32_t upload_skipped_backoff;
  uint32_t upload_fail_streak;
  int64_t upload_next_retry_unix_ms;
  uint64_t inbox_quarantined;
  uint64_t ack_quarantined;
  uint64_t quarantine_move_failed;
  int64_t last_quarantine_unix_ms;
  char last_quarantine_kind[32];
  char last_quarantine_reason[96];
} EdrCommandDeliveryHealth;

void edr_command_get_delivery_health(EdrCommandDeliveryHealth *out_health);

/**
 * Agent-side automation: map detection_context.recommended_forensics to local
 * response commands. Execution remains gated by command policy.
 */
int edr_command_dispatch_recommended_forensics(const EdrBehaviorRecord *record);

unsigned long edr_command_handled_count(void);
unsigned long edr_command_unknown_count(void);
unsigned long edr_command_rejected_count(void);
unsigned long edr_command_exec_ok_count(void);
unsigned long edr_command_exec_fail_count(void);

#ifdef __cplusplus
}
#endif

#endif
