#include "edr/detection_mode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifdef _WIN32
static int streq_ci(const char *a, const char *b) {
  if (!a || !b) return 0;
  while (*a && *b) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

static int env_is_on(const char *name) {
  const char *v = getenv(name);
  if (!v || !v[0]) return 0;
  return strcmp(v, "1") == 0 || streq_ci(v, "true") || streq_ci(v, "yes") || streq_ci(v, "on");
}
#endif

static int path_exists(const char *p) {
  if (!p || !p[0]) return 0;
#ifdef _WIN32
  DWORD a = GetFileAttributesA(p);
  return a != INVALID_FILE_ATTRIBUTES;
#else
  struct stat st;
  return stat(p, &st) == 0;
#endif
}

static int auto_webshell_enabled(const EdrConfig *cfg) {
  if (!cfg) return 0;
  if (cfg->webshell_detector.enabled) return 1;
  if (getenv("EDR_WEBSHELL_ROOTS") && getenv("EDR_WEBSHELL_ROOTS")[0]) return 1;
  if (cfg->webshell_detector.iis_config_path[0] && path_exists(cfg->webshell_detector.iis_config_path)) return 1;
#ifdef _WIN32
  return path_exists("C:\\inetpub\\wwwroot");
#else
  return path_exists("/var/www") || path_exists("/usr/share/nginx/html") || path_exists("/srv/www");
#endif
}

static int auto_shellcode_enabled(const EdrConfig *cfg) {
  if (!cfg) return 0;
  if (cfg->shellcode_detector.enabled) return 1;
#ifdef _WIN32
  if (env_is_on("EDR_SHELLCODE_AUTO_PROFILE")) return 1;
  if (cfg->shellcode_detector.windivert_ports_is_custom &&
      cfg->shellcode_detector.windivert_tcp_ports_parsed_count > 0) {
    return 1;
  }
#endif
  return 0;
}

void edr_detection_apply_profile(EdrConfig *cfg) {
  if (!cfg) return;

  switch (cfg->detection.shellcode_mode) {
    case 0:
      cfg->shellcode_detector.enabled = false;
      break;
    case 1:
      cfg->shellcode_detector.enabled = true;
      break;
    case -1:
      if (cfg->detection.auto_profile) {
        cfg->shellcode_detector.enabled = auto_shellcode_enabled(cfg) ? true : false;
      }
      break;
    default:
      cfg->detection.shellcode_mode = 0;
      cfg->shellcode_detector.enabled = false;
      break;
  }

  switch (cfg->detection.webshell_mode) {
    case 0:
      cfg->webshell_detector.enabled = false;
      break;
    case 1:
      cfg->webshell_detector.enabled = true;
      break;
    case -1:
      if (cfg->detection.auto_profile) {
        cfg->webshell_detector.enabled = auto_webshell_enabled(cfg) ? true : false;
      }
      break;
    default:
      cfg->detection.webshell_mode = 0;
      cfg->webshell_detector.enabled = false;
      break;
  }

  switch (cfg->detection.pmfe_mode) {
    case 0:
      break;
    case 1:
      break;
    case 2:
      break;
    case -1:
      break;
    default:
      cfg->detection.pmfe_mode = 0;
      break;
  }
}

int edr_detection_apply_remote_modes(EdrConfig *current, const EdrConfig *remote) {
  int changed;
  if (!current || !remote) return 0;
  changed = current->detection.auto_profile != remote->detection.auto_profile ||
            current->detection.shellcode_mode != remote->detection.shellcode_mode ||
            current->detection.webshell_mode != remote->detection.webshell_mode ||
            current->detection.pmfe_mode != remote->detection.pmfe_mode;
  current->detection = remote->detection;
  edr_detection_apply_profile(current);
  return changed;
}
