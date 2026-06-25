/**
 * §8 响应指令 — HTTPS control stream / long-poll 收到 CommandEnvelope 后转入此入口（隔离/杀进程/取证/PMFE/AVE/自保护状态等）。
 * 高危操作需 **`EDR_CMD_ENABLED=1`** / **`EDR_CMD_DANGEROUS=1`** 或配置 **`[command] allow_dangerous`**。
 * SOAR：编排字段见 `EdrSoarCommandMeta`；执行结果优先经 HTTPS ingest 回传，legacy gRPC 仅显式启用时 fallback。
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

/**
 * 绑定当前进程配置（main 在 edr_agent_init 成功后调用），供 AVE 等指令使用 `EdrConfig`。
 */
void edr_command_bind_config(const struct EdrConfig *cfg);

/**
 * WinDivert shellcode 告警分数 ≥ `auto_isolate_threshold` 时，在显式启用（`EDR_SHELLCODE_AUTO_ISOLATE=1`
 * 或 TOML `auto_isolate_execute`）且高危策略允许时，执行与 `isolate` 相同的标记 + `EDR_ISOLATE_HOOK`。
 * 同一进程至多成功一次。仅 Windows 端实现。
 */
void edr_isolate_auto_from_shellcode_alarm(void);
/** 确诊勒索(ENCRYPTION_CONFIRMED)时本机自隔离;默认关,需 EDR_RANSOM_AUTO_ISOLATE=1 + 高危策略,每进程一次。 */
void edr_isolate_auto_from_ransom_alarm(void);

/** 与 ingest.proto CommandEnvelope SOAR 扩展字段对应（定长 UTF-8，截断由 gRPC 层写入） */
typedef struct EdrSoarCommandMeta {
  char soar_correlation_id[128];
  char playbook_run_id[96];
  char playbook_step_id[96];
  char idempotency_key[512];
  int64_t issued_at_unix_ms;
  uint32_t deadline_ms;
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
 * 处理服务端下发的指令（来自 HTTPS control stream / long-poll；legacy gRPC Subscribe 仅兼容期使用）。
 * command_id / command_type 为 UTF-8 字符串；payload 可为空。
 * soar_meta 为 NULL 表示无非编排扩展（旧服务端或纯本地指令）。
 */
void edr_command_on_envelope(const char *command_id, const char *command_type, const uint8_t *payload,
                             size_t payload_len, const EdrSoarCommandMeta *soar_meta);

/** 周期性刷可靠投递 outbox：取证上传补发、命令执行结果补报、状态库压缩。 */
void edr_command_poll_reliable_delivery(void);

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
