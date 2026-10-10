/**
 * §19 攻击面快照 — GET_ATTACK_SURFACE 指令：本机采集后 POST 至平台 REST（与 platform POST /endpoints/:id/attack-surface 对齐）。
 */
#ifndef EDR_ATTACK_SURFACE_REPORT_H
#define EDR_ATTACK_SURFACE_REPORT_H

#include <stddef.h>
#include <stdint.h>

#include "edr/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Legacy aggregate ttlSeconds compatibility value; new consumers use each
 * sampled group's groupTTLSeconds and server-derived collection timestamp. */
uint32_t edr_attack_surface_effective_periodic_interval_s(const EdrConfig *cfg);
/** Periods in seconds: full, network(listeners+egress), inventory, policy. */
void edr_attack_surface_periodic_intervals(const EdrConfig *cfg, uint32_t intervals[4]);

/** Defer automatic group scheduling while a collector owns the snapshot lock. */
int edr_attack_surface_collection_running(void);

/** Collect and upload through the internal HTTP stack; nonzero returns an
 * actionable command failure through detail. */
int edr_attack_surface_execute(const char *command_id, const uint8_t *payload,
                               size_t payload_len, const EdrConfig *cfg,
                               char *detail, size_t detail_cap);

/**
 * 查询管控是否排队了按需刷新（GET .../attack-surface/refresh-request）。
 * @return 1 需采集；0 否或未配置 REST；负值表示 HTTP/读响应失败（可忽略，下周期再试）。
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
