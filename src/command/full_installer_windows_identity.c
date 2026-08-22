#include "edr/full_installer_windows_identity.h"

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#define edr_stricmp _stricmp
#else
#include <strings.h>
#define edr_stricmp strcasecmp
#endif

enum {
  EDR_TASK_LOGON_SERVICE_ACCOUNT = 5,
  EDR_TASK_RUNLEVEL_HIGHEST = 1
};

static int is_path_separator(char value) {
  return value == '\\' || value == '/';
}

static void copy_normalized_path(const char *input, char *output, size_t cap) {
  if (!output || cap == 0u) return;
  output[0] = '\0';
  if (!input) return;
  while (isspace((unsigned char)*input)) ++input;
  size_t used = 0u;
  for (; *input && used + 1u < cap; ++input) {
    char value = is_path_separator(*input) ? '\\' : *input;
    if (value == '\\' && used > 0u && output[used - 1u] == '\\') continue;
    output[used++] = value;
  }
  while (used > 3u && (output[used - 1u] == '\\' || isspace((unsigned char)output[used - 1u]))) --used;
  output[used] = '\0';
}

static int path_matches(const char *expected, const char *actual) {
  char expected_path[1024], actual_path[1024];
  copy_normalized_path(expected, expected_path, sizeof(expected_path));
  copy_normalized_path(actual, actual_path, sizeof(actual_path));
  return expected_path[0] && actual_path[0] && edr_stricmp(expected_path, actual_path) == 0;
}

static int read_command_token(const char **cursor, char *output, size_t cap) {
  if (!cursor || !*cursor || !output || cap == 0u) return 0;
  const char *value = *cursor;
  while (isspace((unsigned char)*value)) ++value;
  if (!*value) return 0;
  char quote = 0;
  if (*value == '"' || *value == '\'') quote = *value++;
  size_t used = 0u;
  while (*value) {
    if (quote) {
      if (*value == quote) {
        ++value;
        break;
      }
    } else if (isspace((unsigned char)*value)) {
      break;
    }
    if (used + 1u >= cap) return 0;
    output[used++] = *value++;
  }
  if (quote && value[-1] != quote) return 0;
  output[used] = '\0';
  while (isspace((unsigned char)*value)) ++value;
  *cursor = value;
  return used > 0u;
}

static int string_contains_ci(const char *haystack, const char *needle) {
  if (!haystack || !needle || !*needle) return 0;
  size_t needle_len = strlen(needle);
  for (; *haystack; ++haystack) {
    size_t i = 0u;
    while (i < needle_len && haystack[i] &&
           tolower((unsigned char)haystack[i]) == tolower((unsigned char)needle[i])) ++i;
    if (i == needle_len) return 1;
  }
  return 0;
}

static int code_line_contains_ci(const char *contents, const char *needle) {
  if (!contents || !needle || !needle[0]) return 0;
  const char *line = contents;
  while (*line) {
    while (*line == '\r' || *line == '\n') ++line;
    const char *trimmed = line;
    while (*trimmed == ' ' || *trimmed == '\t') ++trimmed;
    const char *end = trimmed;
    while (*end && *end != '\r' && *end != '\n') ++end;
    if (*trimmed != '#') {
      size_t length = (size_t)(end - trimmed);
      char buffer[4096];
      if (length < sizeof(buffer)) {
        memcpy(buffer, trimmed, length);
        buffer[length] = '\0';
        if (string_contains_ci(buffer, needle)) return 1;
      }
    }
    line = end;
  }
  return 0;
}

static int powershell_assignment(char *out, size_t cap, const char *name, const char *value) {
  if (!out || cap == 0u || !name || !value || strchr(value, '\'')) return 0;
  int written = snprintf(out, cap, "$%s = '%s'", name, value);
  return written > 0 && (size_t)written < cap;
}

int edr_full_installer_uninstall_identity_matches(
    const char *install_directory,
    const EdrFullInstallerUninstallIdentity *identity) {
  if (!install_directory || !install_directory[0] || !identity ||
      !identity->install_location || !identity->uninstall_command ||
      !identity->display_name || !identity->publisher) return 0;
  char expected_uninstaller[1024];
  if (snprintf(expected_uninstaller, sizeof(expected_uninstaller), "%s\\unins000.exe",
               install_directory) <= 0) return 0;
  const char *cursor = identity->uninstall_command;
  char executable[1024];
  if (!read_command_token(&cursor, executable, sizeof(executable))) return 0;
  if (identity->app_id && edr_stricmp(identity->app_id, "{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}") != 0) return 0;
  return path_matches(install_directory, identity->install_location) &&
         path_matches(expected_uninstaller, executable) &&
         edr_stricmp(identity->display_name, "FDSecurity Endpoint Agent") == 0 &&
         edr_stricmp(identity->publisher, "FDSecurity") == 0;
}

int edr_full_installer_task_identity_matches(
    const char *install_directory,
    const char *expected_powershell,
    const EdrFullInstallerTaskIdentity *identity) {
  if (!install_directory || !install_directory[0] || !expected_powershell ||
      !identity || !identity->arguments || !identity->launcher_contents) return 0;
  char expected_launcher[1024];
  char expected_agent[1024];
  char expected_config[1024];
  if (snprintf(expected_launcher, sizeof(expected_launcher), "%s\\FDSensorTaskLaunch.ps1", install_directory) <= 0 ||
      snprintf(expected_agent, sizeof(expected_agent), "%s\\FDSensor.exe", install_directory) <= 0 ||
      snprintf(expected_config, sizeof(expected_config), "%s\\agent.toml", install_directory) <= 0) return 0;
  if (!path_matches(expected_powershell, identity->powershell_path) ||
      !path_matches(install_directory, identity->working_directory) ||
      identity->logon_type != EDR_TASK_LOGON_SERVICE_ACCOUNT ||
      identity->run_level != EDR_TASK_RUNLEVEL_HIGHEST ||
      !(edr_stricmp(identity->principal_user, "SYSTEM") == 0 ||
        edr_stricmp(identity->principal_user, "NT AUTHORITY\\SYSTEM") == 0)) return 0;

  const char *cursor = identity->arguments;
  char token[1024];
  int found_file = 0;
  while (read_command_token(&cursor, token, sizeof(token))) {
    if (edr_stricmp(token, "-File") == 0) {
      if (!read_command_token(&cursor, token, sizeof(token)) ||
          !path_matches(expected_launcher, token)) return 0;
      found_file = 1;
      break;
    }
  }
  if (!found_file) return 0;

  char executable_assignment[1200], config_assignment[1200], workdir_assignment[1200];
  if (!powershell_assignment(executable_assignment, sizeof(executable_assignment), "exe", expected_agent) ||
      !powershell_assignment(config_assignment, sizeof(config_assignment), "cfg", expected_config) ||
      !powershell_assignment(workdir_assignment, sizeof(workdir_assignment), "wd", install_directory)) return 0;

  /*
   * Bind the mutable launcher to the exact executable/config variables and the
   * production Start-Process invocation. Comment-only markers are ignored.
   */
  return code_line_contains_ci(identity->launcher_contents, executable_assignment) &&
         code_line_contains_ci(identity->launcher_contents, config_assignment) &&
         code_line_contains_ci(identity->launcher_contents, workdir_assignment) &&
         code_line_contains_ci(identity->launcher_contents,
                               "$agentArgs = \"--config \" + (Quote-FDNativeArg $cfg)") &&
         code_line_contains_ci(identity->launcher_contents,
                               "Start-Process -FilePath $exe -ArgumentList $agentArgs -WorkingDirectory $wd");
}
