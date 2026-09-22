#include "edr/behavior_record.h"
#include "edr/process_generation.h"

#ifndef _WIN32
int main(void) { return 0; }
#else

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <string.h>
#include <wchar.h>

static int utf8_length(const wchar_t *value) {
  int written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1,
                                   NULL, 0, NULL, NULL);
  return written > 0 ? written - 1 : -1;
}

static int build_command(wchar_t *command, size_t command_cap, int unicode,
                         size_t minimum_utf8, int fill_to_rtq_limit,
                         size_t *out_utf8_length) {
  wchar_t executable[MAX_PATH];
  if (!GetModuleFileNameW(NULL, executable, sizeof(executable) / sizeof(executable[0]))) {
    return 0;
  }
  int prefix = swprintf_s(command, command_cap, L"\"%ls\" --child EDR_RTQ_LONG_COMMAND ", executable);
  if (prefix <= 0) return 0;

  size_t length = (size_t)prefix;
  while (length + 1u < command_cap) {
    wchar_t next = unicode ? L'\x4e2d' : L'x';
    command[length] = next;
    command[length + 1u] = L'\0';
    int current_utf8 = utf8_length(command);
    if (current_utf8 < 0) return 0;
    if (fill_to_rtq_limit && (size_t)current_utf8 > EDR_BR_STR_CMDLINE - 1u) {
      command[length] = L'\0';
      break;
    }
    if (!fill_to_rtq_limit && (size_t)current_utf8 >= minimum_utf8) break;
    length++;
  }
  int final_utf8 = utf8_length(command);
  if (final_utf8 < 0 || (size_t)final_utf8 < minimum_utf8) return 0;
  if (fill_to_rtq_limit && (size_t)final_utf8 > EDR_BR_STR_CMDLINE - 1u) return 0;
  if (out_utf8_length) *out_utf8_length = (size_t)final_utf8;
  return 1;
}

static int query_child(const wchar_t *command, char *output, size_t output_cap,
                       char *reason, size_t reason_cap) {
  wchar_t mutable_command[32768];
  STARTUPINFOW startup = {0};
  PROCESS_INFORMATION child = {0};
  startup.cb = sizeof(startup);
  if (wcslen(command) >= sizeof(mutable_command) / sizeof(mutable_command[0])) return 0;
  wcscpy_s(mutable_command, sizeof(mutable_command) / sizeof(mutable_command[0]), command);
  if (!CreateProcessW(NULL, mutable_command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                      NULL, NULL, &startup, &child)) {
    return 0;
  }
  int ok = edr_process_command_line_query_live(child.hProcess, output, output_cap,
                                               reason, reason_cap);
  TerminateProcess(child.hProcess, 1u);
  WaitForSingleObject(child.hProcess, 5000u);
  CloseHandle(child.hThread);
  CloseHandle(child.hProcess);
  return ok;
}

int main(void) {
  wchar_t command[32768];
  char reason[64];
  char command_line[EDR_BR_STR_CMDLINE];
  size_t command_length = 0;

  /* A command over the historical 2048-byte RTQ buffer must reject that
   * buffer, then succeed with the authoritative 8192-byte bound. */
  if (!build_command(command, sizeof(command) / sizeof(command[0]), 0, 2300u, 0,
                     &command_length) || command_length <= 2048u) return 1;
  reason[0] = '\0';
  if (query_child(command, command_line, 2048u, reason, sizeof(reason)) ||
      strcmp(reason, "command_line_too_long") != 0 || command_line[0] != '\0') {
    fprintf(stderr, "2048-byte rejection contract failed: %s\n", reason);
    return 1;
  }
  reason[0] = '\0';
  if (!query_child(command, command_line, sizeof(command_line), reason, sizeof(reason)) ||
      strlen(command_line) != command_length || strlen(command_line) <= 2048u ||
      strstr(command_line, "EDR_RTQ_LONG_COMMAND") == NULL || strcmp(reason, "ok") != 0) {
    fprintf(stderr, "bounded >2048 command query failed: %s length=%zu expected=%zu\n",
            reason, strlen(command_line), command_length);
    return 1;
  }

  /* Exercise UTF-8 expansion beyond 4096 and as close as possible below the
   * 8191-byte payload limit.  The helper must size in UTF-8 bytes, not UTF-16
   * code units. */
  if (!build_command(command, sizeof(command) / sizeof(command[0]), 1, 4097u, 1,
                     &command_length) || command_length <= 4096u ||
      command_length > EDR_BR_STR_CMDLINE - 1u) return 1;
  reason[0] = '\0';
  if (!query_child(command, command_line, sizeof(command_line), reason, sizeof(reason)) ||
      strlen(command_line) != command_length || strlen(command_line) <= 4096u ||
      strcmp(reason, "ok") != 0) {
    fprintf(stderr, "UTF-8 near-boundary query failed: %s length=%zu expected=%zu\n",
            reason, strlen(command_line), command_length);
    return 1;
  }

  /* A value beyond the authoritative payload capacity must fail closed and
   * report too-long status rather than returning a prefix for matching. */
  if (!build_command(command, sizeof(command) / sizeof(command[0]), 0,
                     EDR_BR_STR_CMDLINE + 8u, 0, &command_length) ||
      command_length <= EDR_BR_STR_CMDLINE - 1u) return 1;
  reason[0] = '\0';
  if (query_child(command, command_line, sizeof(command_line), reason, sizeof(reason)) ||
      strcmp(reason, "command_line_too_long") != 0 || command_line[0] != '\0') {
    fprintf(stderr, "8192-byte rejection contract failed: %s length=%zu\n",
            reason, strlen(command_line));
    return 1;
  }
  return 0;
}

#endif
