#include "edr/full_installer_readiness.h"
#include "edr/full_installer_windows_identity.h"

#include <stdio.h>
#include <string.h>

typedef struct {
  unsigned files;
  int config, uninstall, service, task, module;
} Snapshot;

static int regular_file(void *opaque, const char *path) {
  const Snapshot *s = (const Snapshot *)opaque;
  static const char *names[] = {"FDSensor.exe", "agent.toml", "unins000.exe", "unins000.dat"};
  for (unsigned i = 0; i < 4u; ++i) {
    if (strstr(path, names[i]) != NULL) return (s->files & (1u << i)) != 0u;
  }
  return 0;
}
static int config(void *opaque, const char *path) { (void)path; return ((Snapshot *)opaque)->config; }
static int uninstall(void *opaque, const char *path) { (void)path; return ((Snapshot *)opaque)->uninstall; }
static int service(void *opaque, const char *path) { (void)path; return ((Snapshot *)opaque)->service; }
static int task(void *opaque, const char *path) { (void)path; return ((Snapshot *)opaque)->task; }
static int module(void *opaque, const char *path) { (void)path; return ((Snapshot *)opaque)->module; }

static int baseline(Snapshot *snapshot, char *reason, size_t cap) {
  EdrFullInstallerReadinessDeps deps = {
      snapshot, regular_file, config, uninstall, service, task, module};
  return edr_full_installer_baseline_ready(&deps, "C:/Program Files/FDSecurity", reason, cap);
}

static int expect_snapshot(const char *name, Snapshot snapshot, int want_ready, const char *want_reason) {
  char reason[128] = {0};
  int ready = baseline(&snapshot, reason, sizeof(reason));
  if (ready != want_ready || strcmp(reason, want_reason) != 0) {
    fprintf(stderr, "%s: ready=%d reason=%s want=%d/%s\n", name, ready, reason, want_ready, want_reason);
    return 0;
  }
  return 1;
}

static int test_identity_matrix(void) {
  const char *dir = "C:\\Program Files\\FDSecurity";
  const char *powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const char *launcher =
      "$exe = 'C:\\Program Files\\FDSecurity\\FDSensor.exe'\n"
      "$cfg = 'C:\\Program Files\\FDSecurity\\agent.toml'\n"
      "$wd = 'C:\\Program Files\\FDSecurity'\n"
      "$agentArgs = \"--config \" + (Quote-FDNativeArg $cfg)\n"
      "Start-Process -FilePath $exe -ArgumentList $agentArgs -WorkingDirectory $wd";
  EdrFullInstallerUninstallIdentity uninstall_identity = {
      "C:\\Program Files\\FDSecurity\\", "\"C:\\Program Files\\FDSecurity\\unins000.exe\" /SILENT",
      "FDSecurity Endpoint Agent", "FDSecurity",
      "{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}"};
  if (!edr_full_installer_uninstall_identity_matches(dir, &uninstall_identity)) return 0;
  uninstall_identity.publisher = "Other Publisher";
  if (edr_full_installer_uninstall_identity_matches(dir, &uninstall_identity)) return 0;
  uninstall_identity.publisher = "FDSecurity";
  uninstall_identity.app_id = "{WRONG-APP-ID}";
  if (edr_full_installer_uninstall_identity_matches(dir, &uninstall_identity)) return 0;
  uninstall_identity.app_id = "{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}";
  EdrFullInstallerTaskIdentity task_identity = {
      powershell, "-NoProfile -File \"C:\\Program Files\\FDSecurity\\FDSensorTaskLaunch.ps1\"",
      dir, "SYSTEM", 5, 1, launcher};
  if (!edr_full_installer_task_identity_matches(dir, powershell, &task_identity)) return 0;
  task_identity.run_level = 0;
  if (edr_full_installer_task_identity_matches(dir, powershell, &task_identity)) return 0;
  task_identity.run_level = 1;
  task_identity.arguments = "-NoProfile -File \"C:\\Other\\FDSensorTaskLaunch.ps1\"";
  if (edr_full_installer_task_identity_matches(dir, powershell, &task_identity)) return 0;
  return 1;
}

int main(void) {
  Snapshot ready = {15u, 1, 1, 1, 0, 1};
  if (!expect_snapshot("scm-service-ready", ready, 1, "ready")) return 1;
  ready.service = 0; ready.task = 1;
  if (!expect_snapshot("scheduled-task-ready", ready, 1, "ready")) return 2;
  ready.service = 1;
  if (!expect_snapshot("service-task-conflict", ready, 0, "installation_identity_conflict")) return 3;
  ready.service = 0; ready.task = 0;
  if (!expect_snapshot("disabled-or-missing-identities", ready, 0, "installation_identity_mismatch")) return 4;
  ready.task = 1; ready.uninstall = 0;
  if (!expect_snapshot("registry-provenance-missing", ready, 0, "uninstaller_provenance_missing_or_mismatch")) return 5;
  ready.uninstall = 1; ready.files = 14u;
  if (!expect_snapshot("launcher-baseline-drift", ready, 0, "installation_baseline_missing_FDSensor.exe")) return 6;
  if (!test_identity_matrix()) return 7;
  puts("full_installer_windows_adapter: PASS");
  return 0;
}
