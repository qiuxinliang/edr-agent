#ifdef _WIN32

#include "edr/windows_spawn_lock.h"

static INIT_ONCE g_spawn_lock_once = INIT_ONCE_STATIC_INIT;
static HANDLE g_spawn_lock_mutex = NULL;

static BOOL CALLBACK edr_windows_spawn_lock_init(PINIT_ONCE once, PVOID parameter,
                                                  PVOID *context) {
  (void)once;
  (void)parameter;
  (void)context;
  g_spawn_lock_mutex = CreateMutexW(NULL, FALSE, NULL);
  return g_spawn_lock_mutex != NULL;
}

int edr_windows_spawn_lock_acquire(EdrWindowsSpawnLock *lock) {
  DWORD wait_result;
  if (!lock || !InitOnceExecuteOnce(&g_spawn_lock_once,
                                    edr_windows_spawn_lock_init, NULL, NULL) ||
      !g_spawn_lock_mutex) return 0;
  lock->mutex = g_spawn_lock_mutex;
  lock->held = 0;
  wait_result = WaitForSingleObject(lock->mutex, 5000);
  if (wait_result != WAIT_OBJECT_0 && wait_result != WAIT_ABANDONED) {
    lock->mutex = NULL;
    return 0;
  }
  lock->held = 1;
  return 1;
}

void edr_windows_spawn_lock_release(EdrWindowsSpawnLock *lock) {
  if (!lock) return;
  if (lock->held && lock->mutex) ReleaseMutex(lock->mutex);
  lock->mutex = NULL;
  lock->held = 0;
}

#endif
