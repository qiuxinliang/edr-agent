/**
 * Shell Session — 匿名管道 + PeekNamedPipe 实现远程交互式 Shell。
 * 零新线程，在主循环中 poll；复用现有 gRPC Subscribe 流回传数据。
 */
#ifndef EDR_SHELL_SESSION_H
#define EDR_SHELL_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define EDR_SS_MAX_SESSIONS 10u
#define EDR_SS_ID_LEN 48u
#define EDR_SS_BUF_KB 64u

typedef void (*edr_ss_write_fn)(const char *session_id,
                                const char *data, size_t len,
                                int exit_code, bool closed,
                                void *user);

/**
 * 初始化，注册输出回调。
 * max_sessions: 最大并发 session 数
 * timeout_s: 单个 session 超时（秒）
 * max_output_kb: 单条 stdout 输出最大 KB
 */
void edr_shell_session_init(uint32_t max_sessions,
                            uint32_t timeout_s,
                            uint32_t max_output_kb,
                            edr_ss_write_fn write_fn,
                            void *write_user);

void edr_shell_session_shutdown(void);

/**
 * 打开一个 Shell Session。
 * session_id: 唯一 session ID（由上游生成）
 * shell: "cmd.exe" / "powershell.exe" / "/bin/bash"
 * 返回 0 成功，-1 失败（超过 max 或无法创建进程）
 */
int edr_shell_session_open(const char *session_id, const char *shell);

/**
 * 向 session 的 stdin 写入数据。
 * 返回 0 成功，-1 未找到 session 或写入失败。
 */
int edr_shell_session_input(const char *session_id,
                            const char *data, size_t len);

/** 关闭 session（TerminateProcess + 清理）。 */
void edr_shell_session_close(const char *session_id);

/**
 * 在主循环中调用（200ms 周期）。
 * 轮询所有活跃 session 的 stdout，通过 write_fn 回传。
 */
void edr_shell_session_poll(void);

/** 活跃 session 数量，用于监控。 */
uint32_t edr_shell_session_active_count(void);

#endif
