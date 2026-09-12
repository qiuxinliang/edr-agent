#include <windows.h>
#include <winevt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum Mode { OK, CONTEXT_FAIL, QUERY_FAIL, QUERY_SUCCESS, SMALL, HUGE, NO_MEMORY,
            RENDER_FAIL, SIZE_CHANGED, SHORT_COUNT, BAD_USED, SHORT_USED,
            WRONG_TYPE, ARRAY_TYPE, EPOCH, OVERFLOW };
static enum Mode mode;
static DWORD required;
static unsigned renders, closes, allocations, frees;
static const uint64_t valid_time = UINT64_C(134337262942457197);

static EVT_HANDLE WINAPI fake_context(DWORD count, LPCWSTR *paths, DWORD flags) {
  if (count || paths || flags != EvtRenderContextSystem) abort();
  if (mode == CONTEXT_FAIL) { SetLastError(ERROR_ACCESS_DENIED); return NULL; }
  return (EVT_HANDLE)(uintptr_t)2;
}
static BOOL WINAPI fake_close(EVT_HANDLE handle) {
  if (handle != (EVT_HANDLE)(uintptr_t)2) abort();
  ++closes;
  SetLastError(ERROR_SUCCESS); /* Cleanup must not erase the reported error. */
  return TRUE;
}
static BOOL WINAPI fake_render(EVT_HANDLE context, EVT_HANDLE event, DWORD flags,
                               DWORD size, PVOID buffer, PDWORD used, PDWORD count) {
  if (context != (EVT_HANDLE)(uintptr_t)2 || event != (EVT_HANDLE)(uintptr_t)1 ||
      flags != EvtRenderEventValues) abort();
  ++renders;
  *count = EvtSystemPropertyIdEND;
  if (!buffer) {
    if (size) abort();
    *used = mode == SMALL ? 16u : mode == HUGE ? 65537u : required;
    SetLastError(mode == QUERY_FAIL ? ERROR_INVALID_HANDLE : ERROR_INSUFFICIENT_BUFFER);
    return mode == QUERY_SUCCESS;
  }
  if (size != required || renders != 2u) abort();
  if (mode == RENDER_FAIL || mode == SIZE_CHANGED) {
    *used = size + 16u;
    SetLastError(mode == SIZE_CHANGED ? ERROR_INSUFFICIENT_BUFFER : ERROR_ACCESS_DENIED);
    return FALSE;
  }
  memset(buffer, 0, size);
  EVT_VARIANT *values = (EVT_VARIANT *)buffer;
  values[EvtSystemTimeCreated].Type = mode == WRONG_TYPE ? EvtVarTypeString :
      mode == ARRAY_TYPE ? EvtVarTypeFileTime | EVT_VARIANT_TYPE_ARRAY : EvtVarTypeFileTime;
  values[EvtSystemTimeCreated].FileTimeVal = mode == EPOCH ? UINT64_C(116444736000000000) :
      mode == OVERFLOW ? UINT64_C(116444736000000000) + (uint64_t)INT64_MAX / 100u + 1u : valid_time;
  if (mode == SHORT_COUNT) *count = EvtSystemTimeCreated;
  *used = mode == BAD_USED ? size + 1u : mode == SHORT_USED ? 16u : size;
  return TRUE;
}
static void *fake_malloc(size_t size) {
  ++allocations;
  return mode == NO_MEMORY ? NULL : malloc(size);
}
static void fake_free(void *p) { if (p) ++frees; free(p); }

/* Compile the production I/O implementation; substitute only external APIs.
 * The native companion invokes the same helper with real Windows APIs. */
#define EvtCreateRenderContext fake_context
#define EvtRender fake_render
#define EvtClose fake_close
#define malloc fake_malloc
#define free fake_free
#include "../src/collector/security_event_time_win.h"
#undef EvtCreateRenderContext
#undef EvtRender
#undef EvtClose
#undef malloc
#undef free

static int check(enum Mode next, DWORD bytes, DWORD expected_error,
                 unsigned expected_renders, unsigned expected_allocations) {
  DWORD error = 999u;
  mode = next; required = bytes;
  renders = closes = allocations = frees = 0u;
  uint64_t time = edr_security_event_time_ns((EVT_HANDLE)(uintptr_t)1, &error);
  uint64_t expected_time = next == OK ? UINT64_C(1789252694245719700) : 0u;
  if (time != expected_time || error != expected_error || renders != expected_renders ||
      allocations != expected_allocations || closes != (next == CONTEXT_FAIL ? 0u : 1u) ||
      frees != (next == NO_MEMORY ? 0u : expected_allocations)) {
    fprintf(stderr, "mode=%d time=%llu error=%lu renders=%u alloc=%u free=%u close=%u\n",
            next, (unsigned long long)time, (unsigned long)error, renders, allocations, frees, closes);
    return 0;
  }
  return 1;
}

int main(void) {
  int ok = 1;
  DWORD error = 0u;
  if (edr_security_event_time_ns(NULL, &error) != 0u || error != ERROR_INVALID_HANDLE) return 1;
  ok &= check(OK, 432u, ERROR_SUCCESS, 2u, 1u);
  ok &= check(OK, 1024u, ERROR_SUCCESS, 2u, 1u);
  ok &= check(OK, 65536u, ERROR_SUCCESS, 2u, 1u);
  ok &= check(CONTEXT_FAIL, 432u, ERROR_ACCESS_DENIED, 0u, 0u);
  ok &= check(QUERY_FAIL, 432u, ERROR_INVALID_HANDLE, 1u, 0u);
  ok &= check(QUERY_SUCCESS, 432u, ERROR_INVALID_DATA, 1u, 0u);
  ok &= check(SMALL, 432u, ERROR_INVALID_DATA, 1u, 0u);
  ok &= check(HUGE, 432u, ERROR_INVALID_DATA, 1u, 0u);
  ok &= check(NO_MEMORY, 432u, ERROR_NOT_ENOUGH_MEMORY, 1u, 1u);
  ok &= check(RENDER_FAIL, 432u, ERROR_ACCESS_DENIED, 2u, 1u);
  ok &= check(SIZE_CHANGED, 432u, ERROR_INSUFFICIENT_BUFFER, 2u, 1u);
  ok &= check(SHORT_COUNT, 432u, ERROR_INVALID_DATA, 2u, 1u);
  ok &= check(BAD_USED, 432u, ERROR_INVALID_DATA, 2u, 1u);
  ok &= check(SHORT_USED, 432u, ERROR_INVALID_DATA, 2u, 1u);
  ok &= check(WRONG_TYPE, 432u, ERROR_INVALID_DATA, 2u, 1u);
  ok &= check(ARRAY_TYPE, 432u, ERROR_INVALID_DATA, 2u, 1u);
  ok &= check(EPOCH, 432u, ERROR_INVALID_DATA, 2u, 1u);
  ok &= check(OVERFLOW, 432u, ERROR_INVALID_DATA, 2u, 1u);
  if (ok) puts("PASS security event time: sizing, failures, cleanup, type and timestamp bounds");
  return ok ? 0 : 1;
}
