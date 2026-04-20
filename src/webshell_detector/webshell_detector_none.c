#include "edr/webshell_detector.h"

#include "edr/config.h"
#include "edr/event_bus.h"

EdrError edr_webshell_detector_init(const EdrConfig *cfg, EdrEventBus *bus) {
  (void)cfg;
  (void)bus;
  return EDR_OK;
}

void edr_webshell_detector_shutdown(void) {}
