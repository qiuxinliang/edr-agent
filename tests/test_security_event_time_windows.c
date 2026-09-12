#include "../src/collector/security_event_time_win.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/* Read-only native regression: System is readable without audit policy setup.
 * The optional Security PID query supports replay of an actual lab sample. */
int main(int argc, char **argv) {
  const wchar_t *channel = L"System";
  wchar_t query[192] = L"*";
  EVT_HANDLE query_handle = NULL, event = NULL, context = NULL;
  EVT_VARIANT *expected = NULL;
  DWORD returned = 0u, used = 0u, count = 0u, error = 0u;
  int result = 1;
  if (argc == 3 && strcmp(argv[1], "--security-pid") == 0) {
    char *end = NULL;
    unsigned long pid = strtoul(argv[2], &end, 10);
    if (!pid || !end || *end) return 2;
    channel = L"Security";
    swprintf(query, sizeof(query) / sizeof(query[0]),
             L"*[System[EventID=4688] and EventData[Data[@Name='NewProcessId']='0x%lx']]", pid);
  } else if (argc != 1) return 2;
  query_handle = EvtQuery(NULL, channel, query, EvtQueryChannelPath | EvtQueryReverseDirection);
  if (!query_handle || !EvtNext(query_handle, 1u, &event, 5000u, 0u, &returned) || returned != 1u) {
    error = GetLastError(); goto done;
  }
  context = EvtCreateRenderContext(0u, NULL, EvtRenderContextSystem);
  if (!context) { error = GetLastError(); goto done; }
  EVT_VARIANT old_buffer[EvtSystemPropertyIdEND];
  BOOL old_ok = EvtRender(context, event, EvtRenderEventValues, sizeof(old_buffer), old_buffer, &used, &count);
  DWORD old_error = old_ok ? ERROR_SUCCESS : GetLastError();
  if (old_ok || old_error != ERROR_INSUFFICIENT_BUFFER || used <= sizeof(old_buffer) || used > 65536u) {
    fprintf(stderr, "Native fixture did not exercise variable-size system metadata\n");
    goto done;
  }
  DWORD needed = used;
  expected = (EVT_VARIANT *)malloc(needed);
  if (!expected) { error = ERROR_NOT_ENOUGH_MEMORY; goto done; }
  if (!EvtRender(context, event, EvtRenderEventValues, needed, expected, &used, &count)) {
    error = GetLastError(); goto done;
  }
  if (count <= EvtSystemTimeCreated || expected[EvtSystemTimeCreated].Type != EvtVarTypeFileTime) goto done;
  uint64_t expected_ns = ((uint64_t)expected[EvtSystemTimeCreated].FileTimeVal - UINT64_C(116444736000000000)) * 100u;
  uint64_t actual_ns = edr_security_event_time_ns(event, &error);
  if (error != ERROR_SUCCESS || !actual_ns || actual_ns != expected_ns) goto done;
  printf("PASS old_buffer=%lu required=%lu old_error=%lu timestamp_ns=%llu\n",
         (unsigned long)sizeof(old_buffer), (unsigned long)needed, (unsigned long)old_error,
         (unsigned long long)actual_ns);
  result = 0;
done:
  if (result) fprintf(stderr, "security event time native test failed error=%lu\n", (unsigned long)error);
  free(expected);
  if (context) EvtClose(context);
  if (event) EvtClose(event);
  if (query_handle) EvtClose(query_handle);
  return result;
}
