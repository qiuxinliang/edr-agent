/* 非 Windows：§17 模块不加载 WinDivert，接口为空操作 */

#include "edr/shellcode_detector.h"

#include "edr/config.h"

#include "edr/event_bus.h"

EdrError edr_shellcode_detector_init(const EdrConfig *cfg, EdrEventBus *bus) {
  (void)cfg;
  (void)bus;
  return EDR_OK;
}

void edr_shellcode_detector_shutdown(void) {}

int edr_shellcode_detector_active(void) { return 0; }

uint64_t edr_shellcode_detector_budget_drop_count(void) { return 0u; }
uint64_t edr_shellcode_detector_rate_drop_count(void) { return 0u; }
