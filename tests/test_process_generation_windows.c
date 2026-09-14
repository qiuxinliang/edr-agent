#include "edr/process_generation.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <string.h>
#include "../src/preprocess/process_token_permissions_win.h"

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "--child") == 0) { Sleep(15000); return 0; }
  HANDLE token = NULL;
  char integrity[32], too_small[1];
  uint32_t elevation = 0u;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 1;
  int permissions_ok = edr_token_permissions_query(token, integrity, sizeof(integrity), &elevation) &&
      integrity[0] && elevation >= TokenElevationTypeDefault && elevation <= TokenElevationTypeLimited;
  permissions_ok = permissions_ok &&
      !edr_token_permissions_query(token, too_small, sizeof(too_small), &elevation) &&
      too_small[0] == '\0' && elevation == 0u;
  CloseHandle(token);
  permissions_ok = permissions_ok &&
      !edr_token_permissions_query(NULL, integrity, sizeof(integrity), &elevation) &&
      integrity[0] == '\0' && elevation == 0u;
  if (!permissions_ok) { fprintf(stderr, "same-token permission contract failed\n"); return 1; }
  char command_line[4096];
  char reason[64];
  char tiny[2];

  if (!edr_process_command_line_query_live(GetCurrentProcess(), command_line,
                                           sizeof(command_line), reason,
                                           sizeof(reason))) {
    fprintf(stderr, "same-handle command-line query failed: %s\n", reason);
    return 1;
  }
  if (!strstr(command_line, "test_process_generation_windows")) {
    fprintf(stderr, "unexpected current-process command line: %s\n", command_line);
    return 1;
  }
  if (edr_process_command_line_query_live(GetCurrentProcess(), tiny, sizeof(tiny),
                                          reason, sizeof(reason)) || tiny[0] != '\0' ||
      strcmp(reason, "command_line_too_long") != 0) {
    fprintf(stderr, "bounded output did not fail closed: %s\n", reason);
    return 1;
  }
  char executable[MAX_PATH], child_command[MAX_PATH + 32];
  if (!GetModuleFileNameA(NULL, executable, sizeof(executable))) return 1;
  snprintf(child_command, sizeof(child_command), "\"%s\" --child", executable);
  STARTUPINFOA startup = {0};
  PROCESS_INFORMATION child = {0};
  startup.cb = sizeof(startup);
  if (!CreateProcessA(executable, child_command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) return 1;
  FILETIME created = {0}, exited, kernel, user;
  int ok = GetProcessTimes(child.hProcess, &created, &exited, &kernel, &user) != 0;
  uint64_t identity = ((uint64_t)created.dwHighDateTime << 32u) | created.dwLowDateTime;
  ok = ok && !edr_process_terminate_checked(child.dwProcessId, 0u, 5000, reason, sizeof(reason)) &&
      WaitForSingleObject(child.hProcess, 0) == WAIT_TIMEOUT;
  ok = ok && !edr_process_terminate_checked(4u, identity, 5000, reason, sizeof(reason));
  ok = ok && !edr_process_terminate_checked(child.dwProcessId, identity + 1u, 5000, reason, sizeof(reason)) &&
      strcmp(reason, "process_generation_mismatch") == 0 && WaitForSingleObject(child.hProcess, 0) == WAIT_TIMEOUT;
  ok = ok && !edr_process_terminate_checked(GetCurrentProcessId(), identity, 5000, reason, sizeof(reason));
  ok = ok && edr_process_terminate_checked(child.dwProcessId, identity, 5000, reason, sizeof(reason)) &&
      strcmp(reason, "process_exit_verified") == 0 && WaitForSingleObject(child.hProcess, 0) == WAIT_OBJECT_0;
  ok = ok && edr_process_terminate_checked(child.dwProcessId, identity, 5000, reason, sizeof(reason)) &&
      strcmp(reason, "process_already_gone") == 0;
  if (!ok) {
    fprintf(stderr, "generation-pinned termination failed: %s\n", reason);
    TerminateProcess(child.hProcess, 1); /* Cleanup only our own test child. */
    WaitForSingleObject(child.hProcess, 5000);
  }
  CloseHandle(child.hThread);
  CloseHandle(child.hProcess);
  return ok ? 0 : 1;
}
