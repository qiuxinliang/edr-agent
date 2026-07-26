#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long size = ftell(f);
  if (size < 0) {
    fclose(f);
    return NULL;
  }
  rewind(f);
  char *data = (char *)calloc((size_t)size + 1u, 1u);
  if (!data) {
    fclose(f);
    return NULL;
  }
  if (fread(data, 1u, (size_t)size, f) != (size_t)size) {
    free(data);
    fclose(f);
    return NULL;
  }
  fclose(f);
  return data;
}

static int require_contains(const char *text, const char *needle, const char *message) {
  if (text && strstr(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (missing %s)\n", message, needle);
  return 0;
}

static int require_absent(const char *text, const char *needle, const char *message) {
  if (!text || !strstr(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (unexpected %s)\n", message, needle);
  return 0;
}

static char *read_source(const char *root, const char *relative) {
  char path[1400];
  snprintf(path, sizeof(path), "%s/%s", root, relative);
  char *data = read_file(path);
  if (!data) fprintf(stderr, "FAIL: cannot read %s\n", path);
  return data;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  if (!root || !root[0]) root = ".";
  int ok = 1;

  char *errors = read_source(root, "include/edr/error.h");
  if (!errors) return 1;
  ok &= require_contains(errors, "EDR_ERR_QUEUE_PERMISSION = 5005",
                         "queue ACL failures must have a distinct error code");
  free(errors);

  char *queue = read_source(root, "src/storage/queue_sqlite.c");
  if (!queue) return 1;
  ok &= require_contains(queue, "return EDR_ERR_QUEUE_PERMISSION;",
                         "queue lock access denial must not be reported as another instance");
  ok &= require_contains(queue, "err != ERROR_SHARING_VIOLATION && err != ERROR_LOCK_VIOLATION",
                         "only Windows lock-contention errors may enter the lock wait path");
  ok &= require_contains(queue, "sqlite open failed rc=%d extended_rc=%d system_errno=%d",
                         "SQLite queue open failures must retain native diagnostic details");
  ok &= require_contains(queue, "sqlite3_close(s_db);",
                         "failed SQLite queue opens must close the diagnostic handle");
  free(queue);

  char *main_source = read_source(root, "src/main.c");
  if (!main_source) return 1;
  ok &= require_contains(main_source, "queue ACL denies the Agent runtime identity",
                         "Agent startup must diagnose queue ACL failures explicitly");
  ok &= require_contains(main_source, "fatal open failure",
                         "Agent startup must fail closed when the durable queue cannot open");
  free(main_source);

  char *worker = read_source(root, "src/installer_worker/installer_worker_win.c");
  if (!worker) return 1;
  ok &= require_contains(worker, "edr_windows_autorun.ps1",
                         "native worker must delegate task registration to the structured PowerShell task installer");
  ok &= require_contains(worker, "stage=start-autorun begin",
                         "native worker must start and verify the scheduled task");
  ok &= require_contains(worker, "scheduled_task_started_without_agent_process",
                         "scheduled-task startup must fail when no Agent process appears");
  ok &= require_contains(worker, "service_running=%d process_running=%d",
                         "service startup must verify both SCM state and the Agent process");
  ok &= require_contains(worker, "change_service_config_failed",
                         "service reconfiguration failures must stop installation");
  ok &= require_contains(worker, "service_failure_actions_config_failed",
                         "service recovery policy failures must stop installation");
  ok &= require_contains(worker, "takeown.exe",
                         "ACL repair must recover ownership before applying queue permissions");
  ok &= require_absent(worker, "L\"/Create /F /TN %ls /SC ONSTART",
                       "native worker must not build a nested-quoted schtasks action");
  free(worker);

  char *autorun = read_source(root, "install/windows-inno/edr_windows_autorun.ps1");
  if (!autorun) return 1;
  ok &= require_contains(autorun, "`$p.WaitForExit()",
                         "task launcher must remain alive so Task Scheduler supervises the Agent");
  ok &= require_contains(autorun, "-ExecutionTimeLimit ([TimeSpan]::Zero)",
                         "scheduled Agent must not inherit the 72-hour task limit");
  ok &= require_contains(autorun, "-RestartCount 3",
                         "scheduled Agent must be restarted after abnormal exit");
  ok &= require_contains(autorun, "-WorkingDirectory $instDir",
                         "scheduled task must use the installation directory");
  ok &= require_contains(autorun, "Repair-RuntimeFileAcls -Path $path",
                         "scheduled-task installation must repair explicit ACLs on existing runtime files");
  free(autorun);

  char *installer_ps = read_source(root, "scripts/edr_agent_install.ps1");
  if (!installer_ps) return 1;
  ok &= require_contains(installer_ps, "Repair-RuntimeFileAcls -Path $path",
                         "headless enrollment must repair explicit ACLs on existing queue DB sidecars");
  ok &= require_contains(installer_ps, "if ($sub -eq \"queue\") { throw }",
                         "headless enrollment must fail when queue ACL repair fails");
  free(installer_ps);

  char *uninstall_ps = read_source(root, "scripts/edr_agent_uninstall.ps1");
  if (!uninstall_ps) return 1;
  ok &= require_contains(uninstall_ps, "takeown.exe /F $InstallDir /A /R /D Y",
                         "uninstall cleanup must recover ownership recursively");
  ok &= require_contains(uninstall_ps, "/reset /T /C /Q",
                         "uninstall cleanup must remove stale deny and inheritance ACL state");
  ok &= require_contains(uninstall_ps, "[IO.FileAttributes]::Normal",
                         "uninstall cleanup must clear restrictive file attributes before deletion");
  free(uninstall_ps);

  char *headless_uninstaller = read_source(root, "src/installer_worker/headless_uninstaller_win.c");
  if (!headless_uninstaller) return 1;
  ok &= require_contains(headless_uninstaller, "MessageBoxW(",
                         "headless uninstall prompts must use the Unicode Windows API");
  ok &= require_absent(headless_uninstaller, "MessageBoxA(",
                       "headless uninstall prompts must never use the ANSI Windows API");
  free(headless_uninstaller);

  char *cmake = read_source(root, "CMakeLists.txt");
  if (!cmake) return 1;
  ok &= require_contains(cmake, "target_compile_options(fd_headless_uninstaller PRIVATE /utf-8)",
                         "MSVC must decode the UTF-8 Chinese uninstall prompt source explicitly");
  free(cmake);

  char *preflight = read_source(root, "scripts/edr_agent_preflight.ps1");
  if (!preflight) return 1;
  ok &= require_contains(preflight, "repaired ACL and removed $Label",
                         "preflight must retry cleanup after repairing empty file ACLs");
  free(preflight);

  char *inno = read_source(root, "install/windows-inno/EDRAgentSetup.bundled.iss");
  if (!inno) return 1;
  ok &= require_contains(inno, "EdrWorkerStartAutorunParams, True",
                         "headless setup must fail if the scheduled task cannot start the Agent");
  ok &= require_contains(inno, "EdrWorkerBaseParams('start-autorun')",
                         "headless setup must start the registered task instead of a detached process");
  ok &= require_contains(inno, "EdrWorkerStartServiceParams, True",
                         "GUI service mode must fail setup when the service cannot start");
  ok &= require_contains(inno, "EdrStartServicePsParameters, True",
                         "GUI service fallback must remain a critical install stage");
  ok &= require_contains(inno, "EdrWorkerStartRuntimeParams, True",
                         "GUI manual mode must fail setup when the Agent exits early");
  ok &= require_contains(inno, "EdrStartManualPsParameters, True",
                         "GUI manual fallback must remain a critical install stage");
  ok &= require_contains(inno, "service_status=missing",
                         "PowerShell service fallback must verify the service state");
  ok &= require_contains(inno, "process_exited_early exit_code=",
                         "PowerShell manual fallback must reject an early Agent exit");
  ok &= require_contains(inno, "#ifdef EDR_ALLOW_POWERSHELL_FALLBACK",
                         "worker-less bundled installers must require an explicit lab-only build flag");
  free(inno);

  char *setup_ui = read_source(root, "install/windows-setup-ui/MainWindow.xaml.cs");
  if (!setup_ui) return 1;
  ok &= require_contains(setup_ui, "await fallbackSetup.WaitForExitAsync();",
                         "WebView2 fallback must wait for the traditional installer");
  ok &= require_contains(setup_ui, "if (fallbackSetup.ExitCode != 0)",
                         "WebView2 fallback must surface a failed installer exit code");
  ok &= require_contains(setup_ui, "if (!summary.AgentRunning ||",
                         "GUI completion must require a live Agent process");
  ok &= require_contains(setup_ui, "Process.GetProcessesByName(\"FDSensor\")",
                         "GUI health collection must verify live process state directly");
  free(setup_ui);

  char *build_ps = read_source(root, "install/windows-inno/Build-BundledInstaller.ps1");
  if (!build_ps) return 1;
  ok &= require_contains(build_ps, "/DEDR_ALLOW_POWERSHELL_FALLBACK=1",
                         "lab-only PowerShell fallback must be explicit in the Inno build contract");
  free(build_ps);

  char *build_cmd = read_source(root, "install/windows-inno/build_bundled.cmd");
  if (!build_cmd) return 1;
  ok &= require_contains(build_cmd, "Build-BundledInstaller.ps1",
                         "batch build entrypoint must use the worker-enforcing build script");
  ok &= require_absent(build_cmd, "EDRAgentSetup.bundled.iss\"",
                       "batch build entrypoint must not invoke ISCC directly");
  free(build_cmd);

  char *legacy_inno = read_source(root, "install/windows-inno/EDRAgentSetup.iss");
  if (!legacy_inno) return 1;
  ok &= require_contains(legacy_inno, "#ifndef EDR_ALLOW_LEGACY_INSTALLER",
                         "legacy GUI installer must be disabled unless a lab-only flag is explicit");
  free(legacy_inno);

  return ok ? 0 : 1;
}
