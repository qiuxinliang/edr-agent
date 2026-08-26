#ifdef _WIN32

#include "edr/windows_spawn.h"

#include <wchar.h>

int edr_windows_spawn_whitelisted(const wchar_t *command, const wchar_t *directory,
                                  const HANDLE *handles, DWORD handle_count,
                                  PROCESS_INFORMATION *process,
                                  DWORD creation_flags) {
  STARTUPINFOEXW startup;
  SIZE_T attribute_size = 0;
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
  BOOL attributes_initialized = FALSE;
  BOOL inheritable[8] = { FALSE };
  wchar_t mutable_command[32768];
  DWORD index;
  int ok = 0;
  int restore_ok = 1;
  if (!command || !directory || !handles || !handle_count || handle_count > 8 || !process) return 0;
  ZeroMemory(&startup, sizeof(startup));
  ZeroMemory(process, sizeof(*process));
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
  startup.StartupInfo.wShowWindow = SW_HIDE;
  if (wcslen(command) + 1 >= sizeof(mutable_command) / sizeof(mutable_command[0])) return 0;
  wcscpy(mutable_command, command);
  for (index = 0; index < handle_count; ++index) {
    DWORD flags = 0;
    if (!handles[index] || handles[index] == INVALID_HANDLE_VALUE ||
        !GetHandleInformation(handles[index], &flags)) goto cleanup;
    if (!(flags & HANDLE_FLAG_INHERIT)) {
      if (!SetHandleInformation(handles[index], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) goto cleanup;
      inheritable[index] = TRUE;
    }
  }
  InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
  if (!attribute_size) goto cleanup;
  attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attribute_size);
  if (!attributes || !InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size)) goto cleanup;
  attributes_initialized = TRUE;
  if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 (PVOID)handles, handle_count * sizeof(HANDLE), NULL, NULL)) goto cleanup;
  startup.lpAttributeList = attributes;
  if (!CreateProcessW(NULL, mutable_command, NULL, NULL, TRUE,
                      creation_flags | EXTENDED_STARTUPINFO_PRESENT,
                      NULL, directory, &startup.StartupInfo, process)) goto cleanup;
  ok = 1;
cleanup:
  if (attributes) {
    if (attributes_initialized) DeleteProcThreadAttributeList(attributes);
    HeapFree(GetProcessHeap(), 0, attributes);
  }
  for (index = 0; index < handle_count; ++index) {
    if (inheritable[index] &&
        !SetHandleInformation(handles[index], HANDLE_FLAG_INHERIT, 0)) {
      restore_ok = 0;
    }
  }
  if (!restore_ok) {
    if (process->hProcess) {
      TerminateProcess(process->hProcess, ERROR_CANCELLED);
      WaitForSingleObject(process->hProcess, 5000);
    }
    if (process->hThread) CloseHandle(process->hThread);
    if (process->hProcess) CloseHandle(process->hProcess);
    ZeroMemory(process, sizeof(*process));
    ok = 0;
  }
  return ok;
}

#endif
