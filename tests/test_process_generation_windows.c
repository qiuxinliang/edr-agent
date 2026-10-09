#include "edr/process_generation.h"
#include "edr/behavior_record.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/preprocess/process_token_permissions_win.h"
#include "../src/collector/process_start_token_win.h"
#include "../src/preprocess/process_sid_account_win.h"

static int same_handle_parent_contract(HANDLE child, DWORD pid, uint64_t creation) {
  EdrLiveProcessGeneration live, wrong;
  uint32_t parent_pid = UINT32_MAX;
  uint8_t parent_state = EDR_PARENT_PID_CONFLICT;
  char reason[96];
  if (!edr_process_generation_query_live(child, &live, reason, sizeof(reason)) ||
      live.pid != pid || live.creation_filetime_100ns != creation ||
      !edr_process_parent_pid_query_live(child, &live, &parent_pid, &parent_state,
                                         reason, sizeof(reason)) ||
      parent_pid != GetCurrentProcessId() || parent_state != EDR_PARENT_PID_KNOWN) {
    fprintf(stderr, "same-child-handle parent query failed\n");
    return 0;
  }
  /* The source is this still-open child object, not a new lookup of a PID.
   * An otherwise valid handle must not complete a different actor tuple. */
  for (unsigned i = 0u; i < 6u; ++i) {
    wrong = live;
    if (i == 0u) wrong.pid++;
    else if (i == 1u) wrong.process_start_key++;
    else if (i == 2u) wrong.creation_filetime_100ns++;
    else if (i == 3u) wrong.pid = 0u;
    else if (i == 4u) wrong.process_start_key = 0u;
    else wrong.creation_filetime_100ns = 0u;
    parent_pid = UINT32_MAX; parent_state = EDR_PARENT_PID_CONFLICT;
    if (edr_process_parent_pid_query_live(child, &wrong, &parent_pid, &parent_state,
                                          reason, sizeof(reason)) ||
        parent_pid != 0u || parent_state != EDR_PARENT_PID_UNKNOWN) {
      fprintf(stderr, "wrong actor tuple acquired a parent relationship\n");
      return 0;
    }
  }
  parent_pid = UINT32_MAX; parent_state = EDR_PARENT_PID_CONFLICT;
  if (edr_process_parent_pid_query_live(NULL, &live, &parent_pid, &parent_state,
                                        reason, sizeof(reason)) ||
      parent_pid != 0u || parent_state != EDR_PARENT_PID_UNKNOWN) return 0;
  parent_pid = UINT32_MAX; parent_state = EDR_PARENT_PID_CONFLICT;
  if (edr_process_parent_pid_query_live(child, NULL, &parent_pid, &parent_state,
                                        reason, sizeof(reason)) ||
      parent_pid != 0u || parent_state != EDR_PARENT_PID_UNKNOWN) return 0;
  if (edr_process_parent_pid_query_live(child, &live, NULL, &parent_state,
                                        reason, sizeof(reason)) ||
      edr_process_parent_pid_query_live(child, &live, &parent_pid, NULL,
                                        reason, sizeof(reason))) return 0;
  return 1;
}

static int startup_token_contract(HANDLE child, DWORD pid, uint64_t creation) {
  EdrLiveProcessGeneration live;
  EdrBehaviorRecord source;
  EdrEventSlot captured, attempt;
  HANDLE own_token = NULL;
  char reason[96], expected_logon[32];
  LPSTR expected_sid = NULL;
  DWORD bytes = 0u;
  TOKEN_USER *owner = NULL;
  TOKEN_STATISTICS stats;
  int ok = 0;
  memset(&source, 0, sizeof(source));
  memset(&captured, 0, sizeof(captured));
  if (!edr_process_generation_query_live(child, &live, reason, sizeof(reason)) ||
      !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &own_token)) goto done;
  (void)GetTokenInformation(own_token, TokenUser, NULL, 0u, &bytes);
  if (!bytes || bytes > 65536u) goto done;
  owner = (TOKEN_USER *)malloc(bytes);
  if (!owner || !GetTokenInformation(own_token, TokenUser, owner, bytes, &bytes) ||
      !ConvertSidToStringSidA(owner->User.Sid, &expected_sid) ||
      !GetTokenInformation(own_token, TokenStatistics, &stats, sizeof(stats), &bytes)) goto done;
  snprintf(expected_logon, sizeof(expected_logon), "logon_id=0x%llx\n",
      (unsigned long long)(((uint64_t)(uint32_t)stats.AuthenticationId.HighPart << 32u) |
                           stats.AuthenticationId.LowPart));
  source.type = EDR_EVENT_PROCESS_CREATE;
  source.pid = pid;
  source.process_creation_filetime_100ns = creation;
  if (!edr_windows_process_image_path_utf8(child, source.image_path_canonical,
                                          sizeof(source.image_path_canonical))) goto done;
  captured.type = EDR_EVENT_PROCESS_CREATE;
  memcpy(captured.data, "ETW1\n", 6u);
  captured.size = 6u;
  if (edr_process_start_token_capture(child, &live, &source, &captured) != 1 ||
      captured.process_token_snapshot_pid != pid ||
      captured.process_token_snapshot_start_key != live.process_start_key ||
      captured.process_token_snapshot_creation_filetime_100ns != creation ||
      !strstr((char *)captured.data, expected_sid) ||
      !strstr((char *)captured.data, expected_logon)) goto done;
  /* Wrong actor, generation, path and unavailable handles cannot bind a
   * snapshot, even when the caller passes a valid live process handle. */
  attempt = captured; source.pid++;
  if (edr_process_start_token_capture(child, &live, &source, &attempt) != 0 ||
      attempt.process_token_snapshot_start_key) goto done;
  source.pid--; source.process_creation_filetime_100ns++;
  if (edr_process_start_token_capture(child, &live, &source, &attempt) != 0) goto done;
  source.process_creation_filetime_100ns--; source.process_start_key = live.process_start_key + 1u;
  if (edr_process_start_token_capture(child, &live, &source, &attempt) != 0) goto done;
  source.process_start_key = live.process_start_key;
  source.image_path_canonical[0] = 'X';
  if (edr_process_start_token_capture(child, &live, &source, &attempt) != 0) goto done;
  if (!edr_windows_process_image_path_utf8(child, source.image_path_canonical,
                                          sizeof(source.image_path_canonical))) goto done;
  if (edr_process_start_token_capture(NULL, &live, &source, &attempt) != 0) goto done;
  /* Leave room for the SID alone. Partial publication must roll back and
   * retain a per-event truncation indicator without increasing the envelope. */
  size_t used = sizeof(attempt.data) - (strlen(expected_sid) + strlen("user_sid=\n") + 5u);
  memset(&attempt, 0, sizeof(attempt));
  memset(attempt.data, 'x', used);
  attempt.data[used - 1u] = '\n'; attempt.data[used] = '\0';
  attempt.size = (uint32_t)used + 1u;
  if (edr_process_start_token_capture(child, &live, &source, &attempt) != -1 ||
      !attempt.process_token_snapshot_truncated || attempt.process_token_snapshot_start_key ||
      attempt.size != used + 1u || strlen((char *)attempt.data) != used ||
      strstr((char *)attempt.data, "user_sid=")) goto done;
  /* The process exists under an exact OS handle here. End only this test
   * child, then show why the already-captured tuple must survive queue delay. */
  if (!edr_process_terminate_checked(pid, creation, 5000, reason, sizeof(reason))) goto done;
  memset(&attempt, 0, sizeof(attempt));
  if (edr_process_start_token_capture(child, &live, &source, &attempt) != 0 ||
      !strstr((char *)captured.data, expected_sid) ||
      !strstr((char *)captured.data, expected_logon)) goto done;
  /* Account names are derived from the captured actor SID after exit,
   * independently of the child's PID or a replacement process. */
  {
    EdrBehaviorRecord identity = {0}, before;
    DWORD account_error;
    snprintf(identity.user_sid, sizeof(identity.user_sid), "%s", expected_sid);
    snprintf(identity.logon_id, sizeof(identity.logon_id), "%s", "0x1234");
    snprintf(identity.identity_source, sizeof(identity.identity_source), "%s", "kernel_process_token");
    snprintf(identity.identity_quality, sizeof(identity.identity_quality), "%s", "token_sid");
    identity.pid = pid;
    before = identity;
    if (edr_process_snapshot_account_name(&identity, &account_error) != 1 ||
        !identity.username[0] || strcmp(identity.user_sid, before.user_sid) ||
        strcmp(identity.logon_id, before.logon_id) ||
        strcmp(identity.identity_quality, before.identity_quality)) goto done;
  }
  ok = 1;
done:
  if (expected_sid) LocalFree(expected_sid);
  free(owner);
  if (own_token) CloseHandle(own_token);
  if (!ok) fprintf(stderr, "startup token snapshot contract failed\n");
  return ok;
}

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
  char executable[MAX_PATH];
  char child_command[16384];
  if (!GetModuleFileNameA(NULL, executable, sizeof(executable))) return 1;
  const char *long_marker = "EDR_LONG_COMMAND_TEST";
  const size_t target_command_length = 12717u;
  int prefix_length = snprintf(child_command, sizeof(child_command),
                               "\"%s\" --child %s ", executable, long_marker);
  if (prefix_length <= 0 || (size_t)prefix_length >= target_command_length ||
      (size_t)prefix_length >= sizeof(child_command)) return 1;
  memset(child_command + prefix_length, 'x', target_command_length - (size_t)prefix_length);
  child_command[target_command_length] = '\0';
  STARTUPINFOA startup = {0};
  PROCESS_INFORMATION child = {0};
  startup.cb = sizeof(startup);
  if (!CreateProcessA(executable, child_command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) return 1;
  char long_command[EDR_BR_STR_CMDLINE];
  reason[0] = '\0';
  int long_query_ok = !edr_process_command_line_query_live(
      child.hProcess, long_command, sizeof(long_command), reason, sizeof(reason)) &&
      !long_command[0] && strcmp(reason, "command_line_too_long") == 0;
  char *complete = edr_process_command_line_query_alloc(child.hProcess, reason, sizeof(reason));
  long_query_ok = long_query_ok && complete && strlen(complete) == target_command_length &&
      strcmp(complete, child_command) == 0 && strcmp(reason, "ok") == 0;
  free(complete);
  FILETIME created = {0}, exited, kernel, user;
  int ok = GetProcessTimes(child.hProcess, &created, &exited, &kernel, &user) != 0;
  ok = ok && long_query_ok;
  uint64_t identity = ((uint64_t)created.dwHighDateTime << 32u) | created.dwLowDateTime;
  ok = ok && same_handle_parent_contract(child.hProcess, child.dwProcessId, identity);
  ok = ok && !edr_process_terminate_checked(child.dwProcessId, 0u, 5000, reason, sizeof(reason)) &&
      WaitForSingleObject(child.hProcess, 0) == WAIT_TIMEOUT;
  ok = ok && !edr_process_terminate_checked(4u, identity, 5000, reason, sizeof(reason));
  ok = ok && !edr_process_terminate_checked(child.dwProcessId, identity + 1u, 5000, reason, sizeof(reason)) &&
      strcmp(reason, "process_generation_mismatch") == 0 && WaitForSingleObject(child.hProcess, 0) == WAIT_TIMEOUT;
  ok = ok && !edr_process_terminate_checked(GetCurrentProcessId(), identity, 5000, reason, sizeof(reason));
  ok = ok && startup_token_contract(child.hProcess, child.dwProcessId, identity) &&
      WaitForSingleObject(child.hProcess, 0) == WAIT_OBJECT_0;
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
