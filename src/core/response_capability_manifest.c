#include "edr/response_capability_manifest.h"

#include <stdio.h>

int edr_response_capability_manifest_json(int platform_supported,
                                          int dangerous_policy,
                                          char *out,
                                          size_t out_cap) {
  if (!out || out_cap == 0u) return -1;
  const char *build = platform_supported ? "true" : "false";
  const char *policy = dangerous_policy ? "true" : "false";
  const char *runtime = !platform_supported ? "unavailable"
                           : !dangerous_policy ? "disabled"
                                               : "idle";
#ifdef _WIN32
  const char *kill_build = build;
  const char *kill_runtime = runtime;
#else
  /* The generation-pinned executor currently uses Windows process handles.
   * Other builds must not advertise the former PID-only action as ready. */
  const char *kill_build = "false";
  const char *kill_runtime = "unavailable";
#endif
  int written = snprintf(
      out, out_cap,
      "\"isolate_host\":{\"code_supported\":true,\"build_supported\":%s,\"policy_enabled\":%s,\"runtime_status\":\"%s\"},"
      "\"restore_host\":{\"code_supported\":true,\"build_supported\":%s,\"policy_enabled\":%s,\"runtime_status\":\"%s\"},"
      "\"kill_process\":{\"code_supported\":true,\"build_supported\":%s,\"policy_enabled\":%s,\"runtime_status\":\"%s\"},",
      build, policy, runtime, build, policy, runtime, kill_build, policy, kill_runtime);
  if (written < 0 || (size_t)written >= out_cap) {
    out[0] = '\0';
    return -1;
  }
  return written;
}
