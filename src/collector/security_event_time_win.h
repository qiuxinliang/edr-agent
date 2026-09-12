#ifndef EDR_SECURITY_EVENT_TIME_WIN_H
#define EDR_SECURITY_EVENT_TIME_WIN_H

#include <windows.h>
#include <winevt.h>
#include <stdint.h>
#include <stdlib.h>

/* Private collector I/O boundary, shared with the native Windows regression.
 * EVT_VARIANT[] describes the properties, but EvtRender also stores pointed-to
 * strings/GUIDs/SIDs in the same buffer. sizeof(array) is not the buffer size.
 * System metadata is small; bound even an unexpected required size to 64 KiB.
 * The event is immutable, so one size query and one render suffice. */
static uint64_t edr_security_event_time_ns(EVT_HANDLE event, DWORD *out_error) {
  const uint64_t epoch = UINT64_C(116444736000000000);
  const DWORD max_bytes = 64u * 1024u;
  EVT_HANDLE context = NULL;
  EVT_VARIANT *values = NULL;
  DWORD needed = 0u, used = 0u, count = 0u, error = ERROR_SUCCESS;
  uint64_t result = 0u, filetime;
  if (!event) { error = ERROR_INVALID_HANDLE; goto done; }
  context = EvtCreateRenderContext(0u, NULL, EvtRenderContextSystem);
  if (!context) { error = GetLastError(); goto done; }
  if (EvtRender(context, event, EvtRenderEventValues, 0u, NULL, &needed, &count)) {
    error = ERROR_INVALID_DATA;
    goto done;
  }
  error = GetLastError();
  if (error != ERROR_INSUFFICIENT_BUFFER) goto done;
  if (needed < (EvtSystemTimeCreated + 1u) * sizeof(EVT_VARIANT) ||
      needed > max_bytes) {
    error = ERROR_INVALID_DATA;
    goto done;
  }
  values = (EVT_VARIANT *)malloc(needed);
  if (!values) { error = ERROR_NOT_ENOUGH_MEMORY; goto done; }
  if (!EvtRender(context, event, EvtRenderEventValues, needed, values, &used, &count)) {
    error = GetLastError();
    goto done;
  }
  if (used > needed || count > used / sizeof(EVT_VARIANT) ||
      count <= EvtSystemTimeCreated ||
      values[EvtSystemTimeCreated].Type != EvtVarTypeFileTime) {
    error = ERROR_INVALID_DATA;
    goto done;
  }
  filetime = (uint64_t)values[EvtSystemTimeCreated].FileTimeVal;
  /* Downstream behavior records use signed nanoseconds. Never wrap a corrupt
   * or out-of-range FILETIME into a plausible correlation timestamp. */
  if (filetime <= epoch || filetime - epoch > (uint64_t)INT64_MAX / 100u) {
    error = ERROR_INVALID_DATA;
    goto done;
  }
  result = (filetime - epoch) * 100u;
  error = ERROR_SUCCESS;
done:
  free(values);
  if (context) EvtClose(context);
  if (!result && error == ERROR_SUCCESS) error = ERROR_GEN_FAILURE;
  if (out_error) *out_error = error;
  /* Missing recorded time stays unavailable; never use callback wall time. */
  return result;
}

#endif
