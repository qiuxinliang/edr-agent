/**
 * 深度取证采集器启动器 — 对标 CrowdStrike Falcon Forensics Collector。
 * Agent 负责：下载 collector 可执行文件 → 验证签名 → CreateProcess(Job+低优) → 监控 → 报告。
 */
#ifndef EDR_DEEP_COLLECTOR_H
#define EDR_DEEP_COLLECTOR_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  EDR_DC_OK = 0,
  EDR_DC_ERR_DOWNLOAD = -1,
  EDR_DC_ERR_SIGNATURE = -2,
  EDR_DC_ERR_SPAWN = -3,
  EDR_DC_ERR_TIMEOUT = -4,
  EDR_DC_ERR_CRASH = -5,
  EDR_DC_ERR_DISABLED = -6,
} EdrDeepCollectorError;

typedef struct {
  const char *download_url;
  const char *expected_sha256;
  const char *output_dir;
  const char *upload_url;
  const char *scope;
  uint32_t timeout_s;
} EdrDeepCollectorParams;

/**
 * 启动深度取证采集器。
 * 返回 EDR_DC_OK 成功（采集器已在后台运行，异步监控）。
 * 其他返回值表示启动阶段失败。
 *
 * 监控：Agent 的主循环应周期性调用 edr_deep_collector_poll()
 *       来收集子进程状态变化。
 */
int edr_deep_collector_launch(const EdrDeepCollectorParams *params);

/**
 * 在 Agent 主循环中周期性调用。
 * 返回：>0 采集器仍在运行，0 采集器已完成，<0 失败。
 * 如果 completed，out_exit_code 和 out_detail 被填充。
 */
int edr_deep_collector_poll(int *out_exit_code, char *out_detail, size_t detail_cap);

/** 强制终止采集器（前端 cancel 或 Agent shutdown）。 */
void edr_deep_collector_kill(void);

/** 判断当前是否有采集器在运行。 */
int edr_deep_collector_is_running(void);

#endif
