#ifndef EDR_WEBSHELL_DETECTOR_H
#define EDR_WEBSHELL_DETECTOR_H

#include "edr/error.h"

struct EdrConfig;
struct EdrEventBus;

/** §18 Webshell 检测引擎：启动目录监控与增量扫描。 */
EdrError edr_webshell_detector_init(const struct EdrConfig *cfg, struct EdrEventBus *bus);

/** 停止监控线程并释放资源。 */
void edr_webshell_detector_shutdown(void);

#endif
