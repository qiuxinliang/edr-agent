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
                                               : "healthy";
  int written = snprintf(
      out, out_cap,
      "\"isolate_host\":{\"code_supported\":true,\"build_supported\":%s,\"policy_enabled\":%s,\"runtime_status\":\"%s\"},"
      "\"restore_host\":{\"code_supported\":true,\"build_supported\":%s,\"policy_enabled\":%s,\"runtime_status\":\"%s\"},"
      "\"kill_process\":{\"code_supported\":true,\"build_supported\":%s,\"policy_enabled\":%s,\"runtime_status\":\"%s\"},",
      build, policy, runtime, build, policy, runtime, build, policy, runtime);
  if (written < 0 || (size_t)written >= out_cap) {
    out[0] = '\0';
    return -1;
  }
  return written;
}
