#include "edr/webshell_detector.h"

#include "edr/config.h"
#include "edr/event_bus.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int s_policy_enabled;

EdrError edr_webshell_detector_init(const EdrConfig *cfg, EdrEventBus *bus) {
  s_policy_enabled = cfg && cfg->webshell_detector.enabled;
  (void)bus;
  return EDR_OK;
}

void edr_webshell_detector_shutdown(void) { s_policy_enabled = 0; }

unsigned int edr_webshell_detector_watch_count(void) { return 0u; }

uint64_t edr_webshell_detector_budget_drop_count(void) { return 0u; }

void edr_webshell_detector_get_runtime(EdrWebshellDetectorRuntime *out) {
  if (!out) return;
  memset(out, 0, sizeof(*out));
  out->policy_enabled = s_policy_enabled;
  snprintf(out->runtime_status, sizeof(out->runtime_status), "%s", "unavailable");
  snprintf(out->detail, sizeof(out->detail), "%s", "unsupported_platform");
}
