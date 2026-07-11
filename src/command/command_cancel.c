#include "edr/command_cancel.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static SRWLOCK s_cancel_lock = SRWLOCK_INIT;
static void cancel_lock(void) { AcquireSRWLockExclusive(&s_cancel_lock); }
static void cancel_unlock(void) { ReleaseSRWLockExclusive(&s_cancel_lock); }
#else
#include <pthread.h>
static pthread_mutex_t s_cancel_lock = PTHREAD_MUTEX_INITIALIZER;
static void cancel_lock(void) { pthread_mutex_lock(&s_cancel_lock); }
static void cancel_unlock(void) { pthread_mutex_unlock(&s_cancel_lock); }
#endif

enum { EDR_COMMAND_ACTIVE_MAX = 32 };

typedef struct EdrActiveCommand {
  char command_id[128];
  int cancel_requested;
} EdrActiveCommand;

static EdrActiveCommand s_active[EDR_COMMAND_ACTIVE_MAX];

static int active_index(const char *command_id) {
  if (!command_id || !command_id[0]) {
    return -1;
  }
  for (int i = 0; i < EDR_COMMAND_ACTIVE_MAX; i++) {
    if (s_active[i].command_id[0] && strcmp(s_active[i].command_id, command_id) == 0) {
      return i;
    }
  }
  return -1;
}

int edr_command_cancel_begin(const char *command_id) {
  if (!command_id || !command_id[0]) {
    return 0;
  }
  cancel_lock();
  if (active_index(command_id) >= 0) {
    cancel_unlock();
    return 0;
  }
  for (int i = 0; i < EDR_COMMAND_ACTIVE_MAX; i++) {
    if (!s_active[i].command_id[0]) {
      snprintf(s_active[i].command_id, sizeof(s_active[i].command_id), "%s", command_id);
      s_active[i].cancel_requested = 0;
      cancel_unlock();
      return 1;
    }
  }
  cancel_unlock();
  return 0;
}

void edr_command_cancel_end(const char *command_id) {
  cancel_lock();
  int index = active_index(command_id);
  if (index >= 0) {
    memset(&s_active[index], 0, sizeof(s_active[index]));
  }
  cancel_unlock();
}

int edr_command_cancel_request(const char *command_id) {
  cancel_lock();
  int index = active_index(command_id);
  if (index >= 0) {
    s_active[index].cancel_requested = 1;
  }
  cancel_unlock();
  return index >= 0;
}

int edr_command_cancel_requested(const char *command_id) {
  cancel_lock();
  int index = active_index(command_id);
  int requested = index >= 0 ? s_active[index].cancel_requested : 0;
  cancel_unlock();
  return requested;
}
