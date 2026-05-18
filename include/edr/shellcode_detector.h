/**
 * §17 协议层 Shellcode 检测引擎 — 入口（Windows 启用 WinDivert 捕获；未链接 SDK 时为占位）。
 */
#ifndef EDR_SHELLCODE_DETECTOR_H
#define EDR_SHELLCODE_DETECTOR_H

#include "edr/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool enabled;
    int windivert_priority;
    uint32_t max_payload_inspect;
    double alert_threshold;
    double auto_isolate_threshold;
    bool auto_isolate_execute;
    double heuristic_score_scale;
    uint32_t yara_rules_reload_interval_s;
    bool monitor_smb;
    bool monitor_rdp;
    bool monitor_winrm;
    bool monitor_msrpc;
    bool monitor_ldap;
    uint32_t detector_threads;
    char yara_rules_dir[1024];
    char forensic_dir[1024];
    bool forensic_save_pcap;
    uint32_t evidence_preview_bytes;
    uint32_t forensic_ring_slots;
    uint32_t forensic_ring_max_packet_bytes;
    char windivert_tcp_ports[512];
    bool windivert_ports_is_custom;
    uint16_t windivert_tcp_ports_parsed[64];
    size_t windivert_tcp_ports_parsed_count;
} EdrShellcodeDetectorConfig;

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

#endif
