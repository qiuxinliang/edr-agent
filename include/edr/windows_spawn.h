#ifndef EDR_WINDOWS_SPAWN_H
#define EDR_WINDOWS_SPAWN_H

#ifdef _WIN32

#include <windows.h>

/*
 * The caller must hold the process-local EdrWindowsSpawnLock from before any
 * inheritable handoff handle is created through this call and parent-only
 * inherit-flag cleanup. This helper validates/whitelists handles but does not
 * acquire the lock or close caller-owned handles.
 */
int edr_windows_spawn_whitelisted(const wchar_t *command, const wchar_t *directory,
                                  const HANDLE *handles, DWORD handle_count,
                                  PROCESS_INFORMATION *process,
                                  DWORD creation_flags);

#endif

#endif
