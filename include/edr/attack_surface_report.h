/**
 * §19 攻击面快照 — GET_ATTACK_SURFACE 指令：本机采集后 POST 至平台 REST（与 platform POST /endpoints/:id/attack-surface 对齐）。
 */
#ifndef EDR_ATTACK_SURFACE_REPORT_H
#define EDR_ATTACK_SURFACE_REPORT_H

#include <stdint.h>

#include "edr/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * §19.8：整包快照模式下，周期 POST 与 JSON `ttlSeconds` 使用的有效间隔（秒）。
 * 取 `port_interval_s`、`service_interval_s`、`policy_interval_s`、`full_snapshot_interval_s` 的**最小值**（`conn_interval_s` 仅用于 refresh-request 轮询，不参与）。
 * 结果钳在 60～604800。
 */
uint32_t edr_attack_surface_effective_periodic_interval_s(const EdrConfig *cfg);

/**
 * 执行采集并可选上报。detail 为 SOAR/审计短句（如 "stored_http_200" / "skip_no_rest_base"）。
 * @return 0 成功；非 0 为失败码（可映射 CommandExecutionResult）。
 */
int edr_attack_surface_execute(const char *command_id, const EdrConfig *cfg, char *detail, size_t detail_cap);

/**
 * 查询管控是否排队了按需刷新（GET .../attack-surface/refresh-request）。
 * @return 1 需采集；0 否或未配置 REST；负值表示 curl/读响应失败（可忽略，下周期再试）。
 */
int edr_attack_surface_refresh_pending(const EdrConfig *cfg);

/**
 * 由预处理线程调用：标记「因 §19.10 ETW 需刷新攻击面快照」（与主线程 `edr_attack_surface_take_etw_flush` 配对）。
 */
void edr_attack_surface_etw_signal(void);

/**
 * 主线程轮询：若存在 ETW 触发的刷新请求且已超过 `debounce_ns` 单调时钟间隔，则清除请求并返回 1。
 * @param now_monotonic_ns `edr_monotonic_ns()`
 * @param debounce_ns 去抖间隔（如 5s → 5e9）
 */
int edr_attack_surface_take_etw_flush(uint64_t now_monotonic_ns, uint64_t debounce_ns);

#ifdef __cplusplus
}
#endif

#endif
