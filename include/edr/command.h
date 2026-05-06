/**
 * §8 响应指令 — Subscribe 收到 CommandEnvelope 后转入此入口（隔离/杀进程/取证/PMFE/AVE/自保护状态等）。
 * 高危操作需 **`EDR_CMD_ENABLED=1`** / **`EDR_CMD_DANGEROUS=1`** 或配置 **`[command] allow_dangerous`**。
 * SOAR：编排字段见 `EdrSoarCommandMeta`；执行结果经 gRPC `ReportCommandResult` 回传（见 docs/SOAR_CONTRACT.md）。
 */
#ifndef EDR_COMMAND_H
#define EDR_COMMAND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct EdrConfig;

/**
 * 绑定当前进程配置（main 在 edr_agent_init 成功后调用），供 AVE 等指令使用 `EdrConfig`。
 * 实际由 command_util 模块实现。
 */
void edr_command_bind_config(const struct EdrConfig *cfg);

/** 与 ingest.proto CommandEnvelope SOAR 扩展字段对应（定长 UTF-8，截断由 gRPC 层写入） */
typedef struct EdrSoarCommandMeta {
  char soar_correlation_id[128];
  char playbook_run_id[96];
  char playbook_step_id[96];
  char idempotency_key[128];
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
 * 处理服务端下发的指令（来自 gRPC Subscribe 流）。
 * command_id / command_type 为 UTF-8 字符串；payload 可为空。
 * soar_meta 为 NULL 表示无非编排扩展（旧服务端或纯本地指令）。
 */
void edr_command_on_envelope(const char *command_id, const char *command_type, const uint8_t *payload,
                             size_t payload_len, const EdrSoarCommandMeta *soar_meta);

unsigned long edr_command_handled_count(void);
unsigned long edr_command_unknown_count(void);
unsigned long edr_command_rejected_count(void);
unsigned long edr_command_exec_ok_count(void);
unsigned long edr_command_exec_fail_count(void);

#ifdef __cplusplus
}
#endif

#endif
