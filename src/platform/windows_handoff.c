#ifdef _WIN32

#include "edr/windows_handoff.h"

#include <wchar.h>

static int handoff_pipe_available(HANDLE handle, DWORD *available) {
  return PeekNamedPipe(handle, NULL, 0, NULL, available, NULL) != FALSE;
}

static int edr_windows_handoff_write_all(HANDLE handle, const BYTE *data, DWORD length,
                                         DWORD started) {
  DWORD offset = 0;
  if (!handle || handle == INVALID_HANDLE_VALUE || (!data && length)) return 0;
  while (offset < length) {
    DWORD written = 0;
    if (!WriteFile(handle, data + offset, length - offset, &written, NULL) || !written) return 0;
    offset += written;
    if (GetTickCount() - started > EDR_WINDOWS_HANDOFF_TIMEOUT_MS) return 0;
  }
  return 1;
}

int edr_windows_handoff_write_frame(HANDLE handle, const BYTE *payload, DWORD length) {
  DWORD started = GetTickCount();
  if (!payload || !length || length > EDR_WINDOWS_HANDOFF_MAX_FRAME) return 0;
  return edr_windows_handoff_write_all(handle, (const BYTE *)&length, sizeof(length), started) &&
         edr_windows_handoff_write_all(handle, payload, length, started);
}

int edr_windows_handoff_read_frame(HANDLE handle, BYTE *payload, DWORD capacity,
                                   DWORD *length) {
  DWORD expected = 0;
  DWORD read = 0;
  DWORD started = GetTickCount();
  if (length) *length = 0;
  if (!handle || handle == INVALID_HANDLE_VALUE || !payload || !length ||
      capacity < EDR_WINDOWS_HANDOFF_MAX_FRAME) return 0;
  while (read < sizeof(expected)) {
    DWORD available = 0;
    if (!handoff_pipe_available(handle, &available)) return 0;
    if (!available) {
      if (GetTickCount() - started > EDR_WINDOWS_HANDOFF_TIMEOUT_MS) return 0;
      Sleep(10);
      continue;
    }
    {
      DWORD wanted = sizeof(expected) - read;
      DWORD got = 0;
      if (available < wanted) wanted = available;
      if (!ReadFile(handle, ((BYTE *)&expected) + read, wanted, &got, NULL) || !got) return 0;
      read += got;
    }
  }
  if (!expected || expected > EDR_WINDOWS_HANDOFF_MAX_FRAME || expected > capacity) return 0;
  read = 0;
  while (read < expected) {
    DWORD available = 0;
    if (!handoff_pipe_available(handle, &available)) return 0;
    if (!available) {
      if (GetTickCount() - started > EDR_WINDOWS_HANDOFF_TIMEOUT_MS) return 0;
      Sleep(10);
      continue;
    }
    {
      DWORD wanted = expected - read;
      DWORD got = 0;
      if (available < wanted) wanted = available;
      if (!ReadFile(handle, payload + read, wanted, &got, NULL) || !got) return 0;
      read += got;
    }
    if (GetTickCount() - started > EDR_WINDOWS_HANDOFF_TIMEOUT_MS) return 0;
  }
  *length = expected;
  return 1;
}

#endif
