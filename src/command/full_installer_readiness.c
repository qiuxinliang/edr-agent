#include "edr/full_installer_readiness.h"

#include <stdio.h>
#include <string.h>

static int fail(char *reason, size_t cap, const char *value) {
  if (reason && cap) snprintf(reason, cap, "%s", value);
  return 0;
}

int edr_full_installer_readiness_probe(const EdrFullInstallerReadinessDeps *deps,
                                       const char *directory, char *reason, size_t reason_cap) {
  if (!deps || !directory || !directory[0] || !deps->regular_file || !deps->readable_config ||
      !deps->uninstall_provenance || !deps->service_identity || !deps->task_identity ||
      !deps->current_module) return fail(reason, reason_cap, "probe_dependencies_unavailable");
  const char *files[] = {"FDSensor.exe", "agent.toml", "unins000.exe", "unins000.dat"};
  char path[512];
  for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
    snprintf(path, sizeof(path), "%s/%s", directory, files[i]);
    if (!deps->regular_file(deps->ctx, path)) {
      char code[128]; snprintf(code, sizeof(code), "installation_baseline_missing_%s", files[i]);
      return fail(reason, reason_cap, code);
    }
  }
  snprintf(path, sizeof(path), "%s/agent.toml", directory);
  if (!deps->readable_config(deps->ctx, path)) return fail(reason, reason_cap, "agent_config_unreadable");
  if (!deps->uninstall_provenance(deps->ctx, directory)) return fail(reason, reason_cap, "uninstaller_provenance_missing_or_mismatch");
  snprintf(path, sizeof(path), "%s/FDSensor.exe", directory);
  if (!deps->current_module(deps->ctx, path)) return fail(reason, reason_cap, "current_module_identity_mismatch");
  int service = deps->service_identity(deps->ctx, path);
  int task = deps->task_identity(deps->ctx, path);
  if (!service && !task) return fail(reason, reason_cap, "installation_identity_mismatch");
  if (service && task) return fail(reason, reason_cap, "installation_identity_conflict");
  if (reason && reason_cap) snprintf(reason, reason_cap, "ready");
  return 1;
}

int edr_full_installer_baseline_ready(const EdrFullInstallerReadinessDeps *deps,
                                      const char *directory, char *reason, size_t reason_cap) {
  return edr_full_installer_readiness_probe(deps, directory, reason, reason_cap);
}
