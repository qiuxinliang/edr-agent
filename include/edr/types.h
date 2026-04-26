/**
 * 与《EDR 端点详细设计 v1.0》附录 16.1 对齐的核心类型。
 */
#ifndef EDR_TYPES_H
#define EDR_TYPES_H

#include <stdbool.h>
#include <stdint.h>

/** 单条事件载荷上限（§2.3） */
#define EDR_MAX_EVENT_PAYLOAD 4096u

/**
 * 环形槽位数量：设计文档 §2.3 为 65536（全量预分配约 256MB 量级载荷区）。
 * 默认先用较小值便于开发机调试；生产通过配置调回目标值或改为堆外缓冲池。
 */
#ifndef EDR_RING_SLOTS
#define EDR_RING_SLOTS 4096u
#endif

typedef enum {
  EDR_EVENT_PROCESS_CREATE = 1,
  EDR_EVENT_PROCESS_TERMINATE = 2,
  EDR_EVENT_PROCESS_INJECT = 3,
  EDR_EVENT_DLL_LOAD = 4,
  EDR_EVENT_THREAD_CREATE_REMOTE = 5,
  /** 文件读（与 `file_read` 动态规则对齐；采集路径可按需映射） */
  EDR_EVENT_FILE_READ = 6,
  EDR_EVENT_FILE_CREATE = 10,
  EDR_EVENT_FILE_WRITE = 11,
  EDR_EVENT_FILE_DELETE = 12,
  EDR_EVENT_FILE_RENAME = 13,
  EDR_EVENT_FILE_PERMISSION_CHANGE = 14,
  EDR_EVENT_NET_CONNECT = 20,
  EDR_EVENT_NET_LISTEN = 21,
  EDR_EVENT_NET_DNS_QUERY = 22,
  EDR_EVENT_NET_TLS_HANDSHAKE = 23,
  EDR_EVENT_REG_CREATE_KEY = 30,
  EDR_EVENT_REG_SET_VALUE = 31,
  EDR_EVENT_REG_DELETE_KEY = 32,
  EDR_EVENT_SCRIPT_POWERSHELL = 40,
  EDR_EVENT_SCRIPT_BASH = 41,
  EDR_EVENT_SCRIPT_PYTHON = 42,
  EDR_EVENT_SCRIPT_WMI = 43,
  EDR_EVENT_AUTH_LOGIN = 50,
  EDR_EVENT_AUTH_LOGOUT = 51,
  EDR_EVENT_AUTH_FAILED = 52,
  EDR_EVENT_AUTH_PRIVILEGE_ESC = 53,
  EDR_EVENT_SERVICE_CREATE = 60,
  EDR_EVENT_SCHEDULED_TASK_CREATE = 61,
  EDR_EVENT_DRIVER_LOAD = 62,
  /** §17 协议层可疑 shellcode（WinDivert 路径） */
  EDR_EVENT_PROTOCOL_SHELLCODE = 63,
  /** §18 Web 服务目录新增/修改脚本命中 webshell 规则 */
  EDR_EVENT_WEBSHELL_DETECTED = 64,
  /** §19.10 Microsoft-Windows-Windows Firewall With Advanced Security（规则增删改等） */
  EDR_EVENT_FIREWALL_RULE_CHANGE = 65,
  /** §21 PMFE 内存扫描结论（经预处理 → 行为批次 → gRPC，与 ETW 路径一致） */
  EDR_EVENT_PMFE_SCAN_RESULT = 66,
  /** behavior.onnx 告警帧（`BehaviorEvent.behavior_alert`，§12.4） */
  EDR_EVENT_BEHAVIOR_ONNX_ALERT = 70,
} EdrEventType;

/** 优先级：0=高 1=中 2=低（§2.3） */
typedef uint8_t EdrEventPriority;

typedef struct {
  uint8_t data[EDR_MAX_EVENT_PAYLOAD];
  uint32_t size;
  uint64_t timestamp_ns;
  EdrEventType type;
  uint8_t priority;
  /** §19.10：来自 Microsoft-Windows-TCPIP / WFAS 的 ETW，供攻击面增量刷新去抖联动 */
  uint8_t attack_surface_hint;
  bool consumed;
} EdrEventSlot;

#endif
