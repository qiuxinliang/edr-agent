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

typedef enum {
  EDR_SHELLCODE_RUNTIME_DISABLED = 0,
  EDR_SHELLCODE_RUNTIME_STARTING = 1,
  EDR_SHELLCODE_RUNTIME_HEALTHY = 2,
  EDR_SHELLCODE_RUNTIME_DEGRADED = 3,
  EDR_SHELLCODE_RUNTIME_STOPPED = 4,
} EdrShellcodeRuntimeState;

typedef struct {
  EdrShellcodeRuntimeState state;
  int code_supported;
  int build_supported;
  int policy_enabled;
  int dll_loaded;
  int driver_open;
  uint32_t capture_threads;
  uint32_t scan_workers;
  uint32_t scan_queue_depth;
  uint32_t scan_queue_capacity;
  uint32_t win32_error;
  uint64_t packets_received;
  uint64_t receive_errors;
  uint64_t scan_queue_dropped;
  uint64_t scan_jobs_processed;
  uint32_t reassembly_active_streams;
  uint64_t reassembly_memory_bytes;
  uint64_t reassembly_out_of_order;
  uint64_t reassembly_evicted;
  uint64_t reassembly_memory_drops;
  char runtime_status[16];
  char windivert_source[16];
  char detail[128];
} EdrShellcodeDetectorRuntime;

/**
 * 初始化 §17 模块。`bus` 供 WinDivert 命中后写入事件总线；可为 NULL（仅打日志、不投递）。
 */
EdrError edr_shellcode_detector_init(const struct EdrConfig *cfg, struct EdrEventBus *bus);
void edr_shellcode_detector_shutdown(void);
int edr_shellcode_detector_active(void);
uint64_t edr_shellcode_detector_budget_drop_count(void);
/** P1 #4：因深扫速率限制/资源压力而跳过深扫的包数（仅 Windows 捕获路径累计）。 */
uint64_t edr_shellcode_detector_rate_drop_count(void);
void edr_shellcode_detector_get_runtime(EdrShellcodeDetectorRuntime *out);

/** Shannon 熵（bit/byte），供 Layer 3 与单测使用 */
double edr_shellcode_shannon_entropy_bits(const uint8_t *data, size_t len);

/** 0.0–1.0 启发式分数（熵、NOP sled、简化 GetPC 特征），不含 YARA */
double edr_shellcode_heuristic_score(const uint8_t *data, size_t len);

#endif
