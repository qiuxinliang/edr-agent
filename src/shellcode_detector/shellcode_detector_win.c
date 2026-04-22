/**
 * §17 Windows：加载 WinDivert、启动捕获线程；停止时关闭句柄并 join。
 */
#if !defined(_WIN32)
#error "shellcode_detector_win.c is Windows-only"
#endif

#include <stdio.h>

#include "edr/config.h"
#include "edr/error.h"
#include "edr/event_bus.h"
#include "edr/shellcode_detector.h"

extern EdrError edr_windivert_capture_start(const EdrConfig *cfg, EdrEventBus *bus);
extern void edr_windivert_capture_stop(void);

static int s_active;

EdrError edr_shellcode_detector_init(const EdrConfig *cfg, EdrEventBus *bus) {
  if (!cfg) {
    return EDR_ERR_INVALID_ARG;
  }
  if (!cfg->shellcode_detector.enabled) {
    return EDR_OK;
  }
  if (s_active) {
    return EDR_OK;
  }

  EdrError e = edr_windivert_capture_start(cfg, bus);
  if (e != EDR_OK) {
    return e;
  }
  s_active = 1;
  return EDR_OK;
}

void edr_shellcode_detector_shutdown(void) {
  if (!s_active) {
    return;
  }
  edr_windivert_capture_stop();
  fprintf(stderr, "[shellcode_detector] 已关闭\n");
  s_active = 0;
}
