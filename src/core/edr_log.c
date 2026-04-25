#include "edr/edr_log.h"

#include <stdlib.h>
#include <string.h>

static int edr_env_is_off(const char *v) {
  if (!v || !v[0]) {
    return 1;
  }
  if (strcmp(v, "0") == 0 || strcmp(v, "false") == 0 || strcmp(v, "off") == 0 || strcmp(v, "no") == 0 ||
      strcmp(v, "FALSE") == 0 || strcmp(v, "NO") == 0) {
    return 1;
  }
  return 0;
}

int edr_log_verbose(void) {
  static int cached = -1;
  if (cached < 0) {
    const char *e = getenv("EDR_AGENT_VERBOSE");
    cached = (!edr_env_is_off(e) && e && e[0]) ? 1 : 0;
  }
  return cached;
}

int edr_log_want_shutdown_stats(void) {
  if (edr_log_verbose()) {
    return 1;
  }
  const char *e = getenv("EDR_AGENT_SHUTDOWN_LOG");
  if (!e || !e[0]) {
    return 0;
  }
  return !edr_env_is_off(e);
}

int edr_log_shelldcode_windivert_verbose(void) {
  if (edr_log_verbose()) {
    return 1;
  }
  const char *e = getenv("EDR_SHELCODE_LOG");
  if (!e || !e[0]) {
    return 0;
  }
  return !edr_env_is_off(e);
}
