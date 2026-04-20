/* 非 Windows：采集占位 */

#include "edr/collector.h"
#include "edr/config.h"
#include "edr/event_bus.h"

EdrError edr_collector_start(EdrEventBus *bus, const EdrConfig *cfg) {
  (void)bus;
  (void)cfg;
  return EDR_OK;
}

void edr_collector_stop(void) {}
