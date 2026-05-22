#include "edr/webshell_detector.h"

#include "edr/config.h"
#include "edr/event_bus.h"

#include <stdint.h>

EdrError edr_webshell_detector_init(const EdrConfig *cfg, EdrEventBus *bus) {
  (void)cfg;
  (void)bus;
  return EDR_OK;
}

void edr_webshell_detector_shutdown(void) {}

unsigned int edr_webshell_detector_watch_count(void) { return 0u; }

uint64_t edr_webshell_detector_budget_drop_count(void) { return 0u; }
