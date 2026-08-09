#ifndef EDR_WEBSHELL_DETECTOR_H
#define EDR_WEBSHELL_DETECTOR_H

#include "edr/error.h"

#include <stdint.h>

struct EdrConfig;
struct EdrEventBus;

typedef struct {
  int code_supported;
  int build_supported;
  int policy_enabled;
  int started;
  unsigned int root_count;
  unsigned int watch_count;
  char runtime_status[32];
  char detail[128];
} EdrWebshellDetectorRuntime;

/** §18 Webshell 检测引擎：启动目录监控与增量扫描。 */
EdrError edr_webshell_detector_init(const struct EdrConfig *cfg, struct EdrEventBus *bus);

/** 停止监控线程并释放资源。 */
void edr_webshell_detector_shutdown(void);

unsigned int edr_webshell_detector_watch_count(void);
uint64_t edr_webshell_detector_budget_drop_count(void);
void edr_webshell_detector_get_runtime(EdrWebshellDetectorRuntime *out);

#endif
