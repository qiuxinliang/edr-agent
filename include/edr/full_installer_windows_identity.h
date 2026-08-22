#ifndef EDR_FULL_INSTALLER_WINDOWS_IDENTITY_H
#define EDR_FULL_INSTALLER_WINDOWS_IDENTITY_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EdrFullInstallerUninstallIdentity {
  const char *install_location;
  const char *uninstall_command;
  const char *display_name;
  const char *publisher;
  /* The Inno AppId is supplied by the Windows registry adapter when known. */
  const char *app_id;
} EdrFullInstallerUninstallIdentity;

typedef struct EdrFullInstallerTaskIdentity {
  const char *powershell_path;
  const char *arguments;
  const char *working_directory;
  const char *principal_user;
  int logon_type;
  int run_level;
  const char *launcher_contents;
} EdrFullInstallerTaskIdentity;

/* Pure validators shared by the Windows adapter and production-linked tests. */
int edr_full_installer_uninstall_identity_matches(
    const char *install_directory,
    const EdrFullInstallerUninstallIdentity *identity);

int edr_full_installer_task_identity_matches(
    const char *install_directory,
    const char *expected_powershell,
    const EdrFullInstallerTaskIdentity *identity);

#ifdef __cplusplus
}
#endif

#endif
