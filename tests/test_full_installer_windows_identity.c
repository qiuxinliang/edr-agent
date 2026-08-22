#include "edr/full_installer_windows_identity.h"

#include <assert.h>
#include <stdio.h>

static void test_uninstall_identity(void) {
  const char *directory = "C:\\Program Files\\FDSecurity";
  EdrFullInstallerUninstallIdentity identity = {
      "C:\\Program Files\\FDSecurity\\",
      "\"C:\\Program Files\\FDSecurity\\unins000.exe\" /SILENT",
      "FDSecurity Endpoint Agent",
      "FDSecurity",
      "{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}"};
  assert(edr_full_installer_uninstall_identity_matches(directory, &identity));

  identity.install_location = "C:\\Program Files\\Other";
  assert(!edr_full_installer_uninstall_identity_matches(directory, &identity));
  identity.install_location = directory;
  identity.uninstall_command = "\"C:\\Temp\\unins000.exe\" /SILENT";
  assert(!edr_full_installer_uninstall_identity_matches(directory, &identity));
  identity.uninstall_command = "\"C:\\Program Files\\FDSecurity\\unins000.exe\" /SILENT";
  identity.display_name = "FDSecurity Endpoint Agent (forged)";
  assert(!edr_full_installer_uninstall_identity_matches(directory, &identity));
  identity.display_name = "FDSecurity Endpoint Agent";
  identity.publisher = "Unknown";
  assert(!edr_full_installer_uninstall_identity_matches(directory, &identity));
  identity.publisher = "FDSecurity";
  identity.app_id = "{WRONG-APP-ID}";
  assert(!edr_full_installer_uninstall_identity_matches(directory, &identity));
}

static void test_task_identity(void) {
  const char *directory = "C:\\Program Files\\FDSecurity";
  const char *powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const char *launcher =
      "$exe = 'C:\\Program Files\\FDSecurity\\FDSensor.exe'\n"
      "$cfg = 'C:\\Program Files\\FDSecurity\\agent.toml'\n"
      "$wd = 'C:\\Program Files\\FDSecurity'\n"
      "$agentArgs = \"--config \" + (Quote-FDNativeArg $cfg)\n"
      "$p = Start-Process -FilePath $exe -ArgumentList $agentArgs -WorkingDirectory $wd -PassThru";
  EdrFullInstallerTaskIdentity identity = {
      powershell,
      "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"C:\\Program Files\\FDSecurity\\FDSensorTaskLaunch.ps1\"",
      directory,
      "NT AUTHORITY\\SYSTEM",
      5,
      1,
      launcher};
  assert(edr_full_installer_task_identity_matches(directory, powershell, &identity));

  identity.powershell_path = "C:\\Temp\\powershell.exe";
  assert(!edr_full_installer_task_identity_matches(directory, powershell, &identity));
  identity.powershell_path = powershell;
  identity.arguments = "-NoProfile -File \"C:\\Temp\\FDSensorTaskLaunch.ps1\"";
  assert(!edr_full_installer_task_identity_matches(directory, powershell, &identity));
  identity.arguments = "-NoProfile -File \"C:\\Program Files\\FDSecurity\\FDSensorTaskLaunch.ps1\"";
  identity.principal_user = "Administrator";
  assert(!edr_full_installer_task_identity_matches(directory, powershell, &identity));
  identity.principal_user = "SYSTEM";
  identity.launcher_contents =
      "# $exe = 'C:\\Program Files\\FDSecurity\\FDSensor.exe'\n"
      "# $cfg = 'C:\\Program Files\\FDSecurity\\agent.toml'\n"
      "# $wd = 'C:\\Program Files\\FDSecurity'\n"
      "# $agentArgs = \"--config \" + (Quote-FDNativeArg $cfg)\n"
      "# Start-Process -FilePath $exe -ArgumentList $agentArgs -WorkingDirectory $wd";
  assert(!edr_full_installer_task_identity_matches(directory, powershell, &identity));
}

int main(void) {
  test_uninstall_identity();
  test_task_identity();
  puts("full installer Windows identity contract: PASS");
  return 0;
}
