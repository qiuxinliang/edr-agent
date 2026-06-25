#ifndef EDR_HEARTBEAT_H
#define EDR_HEARTBEAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * §9 子系统心跳（进程内）—— 抗 worker 线程 hang/死锁。
 *
 * 各关键线程在自己的循环里周期性调用 `edr_health_beat(id)` 写入单调时间戳；
 * 主循环（`edr_self_protect_poll`）调用 `edr_health_stale_mask` 判定哪些子系统
 * 超过 max_age 未上报，从而发现「线程还在但卡死」。进程整体被 kill 的情况由
 * 伴生 watchdog 进程兜底（见 watchdog.h）。
 *
 * 时间戳为 `volatile uint64_t`（x64 对齐 64bit 读写本身原子），无锁、可在
 * 信号/回调上下文安全调用。
 */
typedef enum {
  EDR_HEALTH_COLLECTOR = 0,
  EDR_HEALTH_PREPROCESS = 1,
  EDR_HEALTH_TRANSPORT = 2,
  EDR_HEALTH_MAIN_LOOP = 3,
  EDR_HEALTH_COMPONENT_COUNT = 4
} EdrHealthComponent;

/** 标记某子系统“仍在跳动”。线程未启用的组件永不会被判超期（除非曾 beat 过）。 */
void edr_health_beat(EdrHealthComponent id);

/** 该组件距上次 beat 的纳秒数；从未 beat 过返回 0（视为未启用，不判超期）。 */
uint64_t edr_health_age_ns(EdrHealthComponent id);

/**
 * 返回超期组件位掩码（bit i = 组件 i 距上次 beat ≥ max_age_ns）。
 * 从未 beat 过的组件不计入（避免对未启用子系统误报）。max_age_ns==0 返回 0。
 */
uint32_t edr_health_stale_mask(uint64_t max_age_ns);

/** 组件名（用于日志）。越界返回 "?"。 */
const char *edr_health_component_name(EdrHealthComponent id);

#ifdef __cplusplus
}
#endif

#endif
