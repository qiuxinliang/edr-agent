#include "edr/agent_update_manifest.h"
#include <stdio.h>

int edr_agent_update_manifest_fragment(const EdrAgentUpdateRuntimeInfo *info, char *out, size_t cap) {
  if (!info || !out || cap == 0) return -1;
  int n = snprintf(out, cap,
    "\"agent_update_v1\":{\"code_supported\":true,\"build_supported\":%s,\"policy_enabled\":true,\"runtime_status\":\"%s\","
    "\"updater_source\":\"%s\",\"updater_version\":\"%s\",\"updater_sha256\":\"%s\","
    "\"updater_protocol_version\":%d,\"updater_materialized\":%s,\"updater_error_code\":\"%s\","
    "\"runtime_identity_sha256\":\"%s\",\"full_installer_ready\":%s,\"full_installer_reason\":\"%s\","
    "\"installation_family\":\"%s\",\"installation_baseline\":\"%s\"},",
    info->ready ? "true" : "false", info->ready ? "healthy" : "unavailable",
    info->source, info->version, info->sha256, info->protocol_version,
    info->materialized ? "true" : "false", info->error_code, info->runtime_identity_sha256,
    info->full_installer_ready ? "true" : "false", info->full_installer_reason,
    info->installation_family, info->installation_baseline);
  return n > 0 && (size_t)n < cap ? 0 : -1;
}
