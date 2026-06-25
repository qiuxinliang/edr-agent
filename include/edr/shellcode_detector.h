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
int edr_shellcode_detector_active(void);
uint64_t edr_shellcode_detector_budget_drop_count(void);
/** P1 #4：因深扫速率限制/资源压力而跳过深扫的包数（仅 Windows 捕获路径累计）。 */
uint64_t edr_shellcode_detector_rate_drop_count(void);

/** Shannon 熵（bit/byte），供 Layer 3 与单测使用 */
double edr_shellcode_shannon_entropy_bits(const uint8_t *data, size_t len);

/** 0.0–1.0 启发式分数（熵、NOP sled、简化 GetPC 特征），不含 YARA */
double edr_shellcode_heuristic_score(const uint8_t *data, size_t len);

#endif
