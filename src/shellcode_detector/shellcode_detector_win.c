/**
 * §17 Windows：加载 WinDivert、启动捕获线程；停止时关闭句柄并 join。
 */
#if !defined(_WIN32)
#error "shellcode_detector_win.c is Windows-only"
#endif

#include "edr/config.h"
#include "edr/error.h"
#include "edr/event_bus.h"
#include "edr/shellcode_detector.h"

extern EdrError edr_windivert_capture_start(const EdrConfig *cfg, EdrEventBus *bus);
extern void edr_windivert_capture_stop(void);
extern uint64_t edr_windivert_capture_budget_drop_count(void);
extern uint64_t edr_windivert_capture_rate_drop_count(void);
extern void edr_windivert_capture_get_runtime(EdrShellcodeDetectorRuntime *out);

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
  s_active = 0;
}

int edr_shellcode_detector_active(void) { return s_active ? 1 : 0; }

uint64_t edr_shellcode_detector_budget_drop_count(void) {
  return edr_windivert_capture_budget_drop_count();
}

uint64_t edr_shellcode_detector_rate_drop_count(void) {
  return edr_windivert_capture_rate_drop_count();
}

void edr_shellcode_detector_get_runtime(EdrShellcodeDetectorRuntime *out) {
  edr_windivert_capture_get_runtime(out);
}
