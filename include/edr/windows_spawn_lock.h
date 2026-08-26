#ifndef EDR_WINDOWS_SPAWN_LOCK_H
#define EDR_WINDOWS_SPAWN_LOCK_H

#ifdef _WIN32

#include <windows.h>

typedef struct EdrWindowsSpawnLock {
  HANDLE mutex;
  int held;
} EdrWindowsSpawnLock;

int edr_windows_spawn_lock_acquire(EdrWindowsSpawnLock *lock);
void edr_windows_spawn_lock_release(EdrWindowsSpawnLock *lock);

#endif

#endif
