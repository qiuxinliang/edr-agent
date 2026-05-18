#ifndef EDR_WEBSHELL_DETECTOR_H
#define EDR_WEBSHELL_DETECTOR_H

#include "edr/error.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool enabled;
    uint32_t discovery_interval_s;
    char iis_config_path[1024];
    uint32_t max_watch_dirs;
    bool monitor_subdirs;
    char webshell_rules_dir[1024];
    uint32_t scan_threads;
    uint32_t max_file_size_mb;
    uint32_t defer_retry_ms;
    double alert_threshold;
    double l2_review_threshold;
    bool upload_webshell_files;
    uint32_t upload_timeout_s;
    uint32_t max_upload_size_mb;
} EdrWebshellDetectorConfig;

struct EdrConfig;
struct EdrEventBus;

/** §18 Webshell 检测引擎：启动目录监控与增量扫描。 */
EdrError edr_webshell_detector_init(const struct EdrConfig *cfg, struct EdrEventBus *bus);

/** 停止监控线程并释放资源。 */
void edr_webshell_detector_shutdown(void);

#endif
