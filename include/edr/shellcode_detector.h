/**
 * §17 协议层 Shellcode 检测引擎 — 入口（Windows 启用 WinDivert 捕获；未链接 SDK 时为占位）。
 */
#ifndef EDR_SHELLCODE_DETECTOR_H
#define EDR_SHELLCODE_DETECTOR_H

#include "edr/error.h"

#include <stddef.h>
#include <stdint.h>

struct EdrConfig;
struct EdrEventBus;

/**
 * 初始化 §17 模块。`bus` 供 WinDivert 命中后写入事件总线；可为 NULL（仅打日志、不投递）。
 */
EdrError edr_shellcode_detector_init(const struct EdrConfig *cfg, struct EdrEventBus *bus);
void edr_shellcode_detector_shutdown(void);

/** Shannon 熵（bit/byte），供 Layer 3 与单测使用 */
double edr_shellcode_shannon_entropy_bits(const uint8_t *data, size_t len);

/** 0.0–1.0 启发式分数（熵、NOP sled、简化 GetPC 特征），不含 YARA */
double edr_shellcode_heuristic_score(const uint8_t *data, size_t len);

#ifdef _WIN32
/**
 * WinDivert 线程累计计数（§17 性能 / P2-PERF-2）；未启动捕获时多为 0。
 * 指针可为 NULL（跳过该项）。关机前 **`edr_windivert_capture_stop`** 若 **`EDR_SHELLCODE_WD_STATS=1`** 会 stderr 打一行汇总。
 * **`alert_dedup_suppressed`**（T-SC-041）：同五元组语义键 + 同 rule 在 30s 内被合并丢弃的次数。
 */
void edr_shellcode_windivert_stats_snapshot(unsigned long long *recv_packets, unsigned long long *recv_errors,
                                            unsigned long long *rows_skipped, unsigned long long *monitor_filtered,
                                            unsigned long long *alerts_pushed, unsigned long long *bus_drops,
                                            unsigned long long *alert_dedup_suppressed);
#endif

#endif
