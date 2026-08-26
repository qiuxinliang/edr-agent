#ifndef EDR_WINDOWS_HANDOFF_H
#define EDR_WINDOWS_HANDOFF_H

#ifdef _WIN32

#include <windows.h>

#define EDR_WINDOWS_HANDOFF_MAX_FRAME 256u
#define EDR_WINDOWS_HANDOFF_TIMEOUT_MS 30000u

int edr_windows_handoff_write_frame(HANDLE handle, const BYTE *payload, DWORD length);
int edr_windows_handoff_read_frame(HANDLE handle, BYTE *payload, DWORD capacity,
                                   DWORD *length);

#endif

#endif
