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

static int require_utf8_bom(const char *text, const char *message) {
  if (text && (unsigned char)text[0] == 0xef &&
      (unsigned char)text[1] == 0xbb && (unsigned char)text[2] == 0xbf) {
    return 1;
  }
  fprintf(stderr, "FAIL: %s (missing UTF-8 BOM)\n", message);
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

  char *collector = read_source(root, "src/collector/collector_win.c");
  if (!collector) return 1;
  ok &= require_contains(collector, "return edr_agent_self_pid_seen(",
                         "self-noise fuse must be scoped to Agent-owned PIDs");
  ok &= require_contains(collector, "s_health.etw_prefilter_dropped++",
                         "uninteresting ETW schemas must be observable before payload parsing");
  ok &= require_contains(collector, "edr_classify_manifest_semantics",
                         "file and network ETW schemas must be classified by TDH metadata");
  ok &= require_contains(collector, "EDR_ETW_SEMANTIC_CACHE_SIZE",
                         "TDH schema classification must be cached rather than repeated per event");
  ok &= require_absent(collector, "if (op == 10u || op == 11u)",
                       "network send and receive opcodes must not be treated as connections");
  ok &= require_absent(collector, "EVENT_CONTROL_CODE_DISABLE_PROVIDER",
                       "self-noise fuse must not disable mandatory ETW providers");
  ok &= require_contains(collector, "return TRACE_LEVEL_INFORMATION;",
                         "high-volume kernel providers must use the production information level");
  ok &= require_contains(collector, "edr_registry_snapshot_free",
                         "registry snapshots must release exact-sized value allocations");
  free(collector);

  char *agent = read_source(root, "src/core/agent.c");
  if (!agent) return 1;
  ok &= require_contains(agent, "EDR_REMOTE_POLICY_PMFE_LIFECYCLE_CHANGED",
                         "remote PMFE policy changes must participate in engine lifecycle");
  ok &= require_contains(agent, "edr_pmfe_shutdown();",
                         "remote policy must stop PMFE workers when PMFE is disabled");
  ok &= require_contains(agent, "PMFE started by remote policy",
                         "remote policy must restart PMFE when it is re-enabled");
  free(agent);

  char *shellcode = read_source(root, "src/shellcode_detector/shellcode_detector_win.c");
  if (!shellcode) return 1;
  ok &= require_absent(shellcode, "if (!s_active) {\n    return;\n  }",
                       "failed shellcode starts must still be cleaned up on policy disable");
  free(shellcode);

  char *transport = read_source(root, "src/transport/ingest_http.c");
  if (!transport) return 1;
  ok &= require_contains(transport, "EDR_HTTP_CONNECT_TIMEOUT_MS",
                         "maintenance transport must bound TCP connect time");
  ok &= require_contains(transport, "socket_connect_with_timeout",
                         "native HTTP must use non-blocking bounded connect");
  free(transport);

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
  ok &= require_contains(worker, "EDR_FORENSIC_VERSION_CHECK_SEC\", L\"900",
                         "native worker must install the bounded 15-minute forensic version check");
  ok &= require_contains(worker, "EDR_FORENSIC_PREFETCH_RETRY_SEC\", L\"900",
                         "native worker must install the bounded 15-minute forensic prefetch retry");
  ok &= require_contains(worker, "--capability-probe",
                         "native worker must expose a machine-readable release capability probe");
  ok &= require_contains(worker, "\\\"uninstall_attestation\\\":\\\"v2\\\"",
                         "native worker capability probe must declare uninstall attestation v2");
  ok &= require_contains(worker, "lifecycle_attestation_handoff protocol=v2",
                         "native worker must record sanitized token handoff diagnostics");
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
  ok &= require_contains(autorun, "SetEnvironmentVariable(\"EDR_FORENSIC_VERSION_CHECK_SEC\", \"900\"",
                         "scheduled-task installation must preserve the 15-minute forensic version check");
  ok &= require_contains(autorun, "SetEnvironmentVariable(\"EDR_FORENSIC_PREFETCH_RETRY_SEC\", \"900\"",
                         "scheduled-task installation must preserve the 15-minute forensic prefetch retry");
  free(autorun);

  char *service_installer = read_source(root, "scripts/windows_service_install.ps1");
  if (!service_installer) return 1;
  ok &= require_contains(service_installer, "EDR_FORENSIC_VERSION_CHECK_SEC\" \"900",
                         "service installation must preserve the 15-minute forensic version check");
  ok &= require_contains(service_installer, "EDR_FORENSIC_PREFETCH_RETRY_SEC\" \"900",
                         "service installation must preserve the 15-minute forensic prefetch retry");
  ok &= require_contains(service_installer, "\"start=\", \"auto\"",
                         "service installation must pass sc.exe option names and values as separate arguments");
  ok &= require_contains(service_installer, "sc.exe $($Arguments[0]) failed with exit code",
                         "service installation must stop immediately when sc.exe fails");
  ok &= require_absent(service_installer, "\"start= auto\"",
                       "service installation must not use legacy PowerShell native argument flattening");
  ok &= require_absent(service_installer, "\"binPath= $binPath\"",
                       "service installation must keep the sc.exe binPath option separate from its value");
  ok &= require_contains(service_installer, "ETW cleanup returned exit code $exitCode; continuing uninstall",
                         "best-effort ETW cleanup must report but not poison successful uninstall status");
  ok &= require_contains(service_installer, "EDR_FORENSIC_VERSION_CHECK_SEC",
                         "service uninstall must remove the forensic version check setting");
  ok &= require_contains(service_installer, "EDR_FORENSIC_PREFETCH_RETRY_SEC",
                         "service uninstall must remove the forensic prefetch retry setting");
  free(service_installer);

  char *installer_ps = read_source(root, "scripts/edr_agent_install.ps1");
  if (!installer_ps) return 1;
  ok &= require_utf8_bom(installer_ps,
                         "non-ASCII enrollment script must retain a UTF-8 BOM for Windows PowerShell 5.1");
  ok &= require_contains(installer_ps, "Repair-RuntimeFileAcls -Path $path",
                         "headless enrollment must repair explicit ACLs on existing queue DB sidecars");
  ok &= require_contains(installer_ps, "if ($sub -eq \"queue\") { throw }",
                         "headless enrollment must fail when queue ACL repair fails");
  ok &= require_contains(installer_ps, "packaged MSVC runtime missing beside",
                         "headless enrollment must identify an incomplete app-local MSVC runtime");
  ok &= require_contains(installer_ps, "vcruntime140_1.dll",
                         "headless enrollment must validate the extended MSVC runtime dependency");
  ok &= require_contains(installer_ps, "msvcp140.dll",
                         "headless enrollment must validate the C++ runtime dependency");
  free(installer_ps);

  char *uninstall_ps = read_source(root, "scripts/edr_agent_uninstall.ps1");
  if (!uninstall_ps) return 1;
  ok &= require_contains(uninstall_ps, "takeown.exe /F $InstallDir /A /R /D Y",
                         "uninstall cleanup must recover ownership recursively");
  ok &= require_contains(uninstall_ps, "function Disable-AgentServiceRecovery",
                         "uninstall must disable Windows service recovery before teardown");
  ok &= require_contains(uninstall_ps, "failureflag",
                         "uninstall must prevent non-crash failures from restarting the service");
  ok &= require_contains(uninstall_ps, "/reset /T /C /Q",
                         "uninstall cleanup must remove stale deny and inheritance ACL state");
  ok &= require_contains(uninstall_ps, "[IO.FileAttributes]::Normal",
                         "uninstall cleanup must clear restrictive file attributes before deletion");
  ok &= require_contains(uninstall_ps, "EDR_FORENSIC_PREFETCH_RETRY_SEC",
                         "uninstall must remove the forensic prefetch retry machine setting");
  ok &= require_contains(uninstall_ps, "edr.endpoint.uninstall.attestation.v1",
                         "uninstall must attest positive local teardown after deferred cleanup");
  ok &= require_contains(uninstall_ps, "`$bodyFields.token_proof_hmac_sha256 = `$tokenProof",
                         "loopback uninstall attestation must carry a header-independent token proof");
  ok &= require_contains(uninstall_ps, "Security.Cryptography.HMACSHA256",
                         "uninstall attestation body proof must use HMAC-SHA256");
  ok &= require_contains(uninstall_ps, "tcp_loopback_http11",
                         "loopback attestation must use byte-exact HTTP under LocalSystem");
  ok &= require_contains(uninstall_ps, "New-Object Net.Sockets.TcpClient",
                         "loopback attestation must bypass WebRequest rewriting");
  ok &= require_contains(uninstall_ps, "Content-Length: `$(`$bodyBytes.Length)",
                         "loopback attestation must bind the exact UTF-8 body length");
  ok &= require_contains(uninstall_ps, "Skipped unrelated $name process PID",
                         "uninstall must scope process termination to the target installation");
  ok &= require_contains(uninstall_ps, "ETW cleanup exceeded 15 seconds and was terminated; continuing uninstall",
                         "best-effort ETW cleanup must have a bounded execution window");
  ok &= require_contains(uninstall_ps, "ETW cleanup returned exit code $($cleanupProcess.ExitCode); continuing uninstall",
                         "best-effort ETW cleanup must not poison complete uninstall status");
  ok &= require_contains(uninstall_ps, "uninstall-script-last.json",
                         "uninstall must persist the exact synchronous failure stage outside program files");
  ok &= require_contains(uninstall_ps, "function Remove-RuntimePathWithRetry",
                         "runtime data cleanup must retry transient endpoint-security file locks");
  ok &= require_contains(uninstall_ps, "Runtime data remains for verified deferred directory cleanup:",
                         "complete uninstall must hand persistent file locks to verified directory cleanup");
  ok &= require_contains(uninstall_ps, "deferred_runtime_paths = @($script:DeferredRuntimePaths)",
                         "synchronous uninstall receipt must disclose paths handed to deferred cleanup");
  ok &= require_contains(uninstall_ps, "deletion_last_error = `$deleteLastError",
                         "deferred cleanup must retain the final directory deletion error");
  ok &= require_contains(uninstall_ps, "remaining_entries = @(`$remainingEntries)",
                         "deferred cleanup must identify files that survive bounded removal");
  ok &= require_contains(uninstall_ps, "attestation_error = `$attestationError",
                         "deferred cleanup must retain callback transport diagnostics");
  ok &= require_contains(uninstall_ps, "[Net.WebRequest]::DefaultWebProxy = `$null",
                         "loopback callback transport must not inherit a machine proxy under LocalSystem");
  ok &= require_contains(uninstall_ps, "attestation_errors = @(`$attestationErrors)",
                         "cleanup receipt must retain the complete bounded attestation attempt history");
  ok &= require_contains(uninstall_ps, "`$requestHeaders['X-EDR-Uninstall-Token']",
                         "loopback callback must not depend on HTTP.sys exposing Authorization headers");
  ok &= require_contains(uninstall_ps, "`$attestationLastHttpStatus -in @(400, 401, 403)",
                         "deterministic callback authorization failures must not consume the retry window");
  ok &= require_contains(uninstall_ps, "failure_reasons = @(`$failureReasons)",
                         "deferred cleanup must report machine-readable terminal causes");
  ok &= require_contains(uninstall_ps,
                         "status = if (`$overallSucceeded) { 'succeeded' } else { 'failed' }",
                         "terminal cleanup status must include required attestation success");
  ok &= require_contains(uninstall_ps,
                         "local_status = if (`$localSucceeded) { 'succeeded' } else { 'failed' }",
                         "cleanup receipt must retain independent local teardown status");
  ok &= require_contains(uninstall_ps, "Management.Automation.Language.Parser]::ParseInput($cleanup",
                         "generated deferred cleanup must pass the native Windows PowerShell parser before launch");
  ok &= require_contains(uninstall_ps, "uninstall-cleanup-last.stderr.log",
                         "detached cleanup parser and runtime errors must remain observable after program removal");
  ok &= require_contains(uninstall_ps, "elseif ($RemoveProgramFiles)",
                         "runtime data cleanup may defer only when complete program removal is scheduled");
  ok &= require_absent(uninstall_ps,
                       "Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue",
                       "runtime data cleanup must not regress to one-shot silent deletion");
  ok &= require_contains(uninstall_ps, "Add-CleanupWarning (\"Failed to reset install directory ACL:",
                         "ACL repair helper failures must defer to final deletion proof");
  ok &= require_absent(uninstall_ps, "Add-CriticalFailure (\"ETW cleanup failed:",
                       "best-effort ETW cleanup must never become a terminal uninstall failure");
  ok &= require_absent(uninstall_ps, "System.Collections.Generic.HashSet",
                       "Windows PowerShell 5.1 uninstall initialization must not depend on generic type construction");
  ok &= require_contains(uninstall_ps, "PID ${processId}:",
                         "PowerShell variables immediately before a colon must use braced interpolation");
  ok &= require_absent(uninstall_ps, "PID $processId:",
                       "unbraced processId interpolation must not reintroduce a Windows PowerShell parser error");
  free(uninstall_ps);

  char *headless_uninstaller = read_source(root, "src/installer_worker/headless_uninstaller_win.c");
  if (!headless_uninstaller) return 1;
  ok &= require_contains(headless_uninstaller, "MessageBoxW(",
                         "headless uninstall prompts must use the Unicode Windows API");
  ok &= require_absent(headless_uninstaller, "MessageBoxA(",
                       "headless uninstall prompts must never use the ANSI Windows API");
  ok &= require_contains(headless_uninstaller, "uninstall-powershell-last.log",
                         "native uninstall must capture PowerShell output outside the removable install directory");
  ok &= require_contains(headless_uninstaller, "uninstall-powershell-%ls.log",
                         "remote uninstall must preserve task-bound PowerShell diagnostics");
  ok &= require_contains(headless_uninstaller, "uninstall_native_start pid=%lu",
                         "native uninstall must record entry before launching PowerShell");
  ok &= require_contains(headless_uninstaller, "详细诊断日志",
                         "native uninstall dialog must point operators to the captured PowerShell diagnostics");
  ok &= require_contains(headless_uninstaller, "STARTF_USESTDHANDLES",
                         "native uninstall must redirect child stdout and stderr for actionable CI diagnostics");
  ok &= require_contains(headless_uninstaller, "wait_for_process(process.hProcess, 240000)",
                         "native uninstall must bound a stalled PowerShell cleanup");
  ok &= require_contains(headless_uninstaller, "TerminateProcess(process, ERROR_TIMEOUT)",
                         "native uninstall must terminate and report a timed-out PowerShell cleanup");
  ok &= require_contains(headless_uninstaller, "CREATE_BREAKAWAY_FROM_JOB",
                         "PowerShell cleanup must survive parent service Job Object teardown");
  ok &= require_contains(headless_uninstaller, "--capability-probe",
                         "native uninstaller must expose a machine-readable release capability probe");
  ok &= require_contains(headless_uninstaller, "\\\"uninstall_attestation\\\":\\\"v2\\\"",
                         "native uninstaller capability probe must declare uninstall attestation v2");
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
  ok &= require_contains(inno, "#define EDR_SETUP_ARCH \"x64os\"",
                         "AMD64 Setup must be limited to native x64 Windows");
  ok &= require_absent(inno, "#define EDR_SETUP_ARCH \"x64compatible\"",
                       "AMD64 Setup must not bypass the native-only v1 contract through ARM64 emulation");
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
  ok &= require_contains(inno, "Source: \"{#EDR_BIN_DIR}\\uninstall.exe\"",
                         "Setup UI must package the same native uninstaller as the release ZIP");
  ok &= require_contains(inno, "Source: \"{#EDR_BIN_DIR}\\uninstall.ps1\"",
                         "Setup UI must package the release-owned PowerShell uninstaller");
  ok &= require_contains(inno, "INSTALL_FAILURE_ROLLBACK begin",
                         "first-install Setup UI failure must initiate controlled rollback");
  ok &= require_contains(inno, "EdrHadExistingInstallation := FileExists(ExpandConstant('{app}\\unins000.exe'))",
                         "only a completed GUI installation may be preserved during failure rollback");
  ok &= require_contains(inno, "skipped_existing_installation=true",
                         "upgrade failure must preserve the previous installation instead of deleting it");
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
  ok &= require_contains(build_ps, "write_windows_package_capabilities.ps1",
                         "Setup UI and headless packages must use the shared capability contract writer");
  ok &= require_contains(build_ps, "-SignatureStatus $SignatureStatus",
                         "bundled installer capability metadata must bind the Agent signature mode");
  ok &= require_contains(build_ps, "Verified Runtime PE closure",
                         "bundled installer must verify every Runtime EXE and DLL architecture");
  ok &= require_contains(build_ps, "/DEDR_ALLOW_POWERSHELL_FALLBACK=1",
                         "lab-only PowerShell fallback must be explicit in the Inno build contract");
  free(build_ps);

  char *setup_ui_build = read_source(root, "install/windows-setup-ui/Build-SetupUi.ps1");
  if (!setup_ui_build) return 1;
  ok &= require_contains(setup_ui_build, "edr.windows.package-capabilities.v1",
                         "Setup UI manifest uses the canonical package capability schema");
  ok &= require_contains(setup_ui_build, "signature_status = if ($uiSigned -and $setupSigned)",
                         "Setup UI capability metadata records signed versus unsigned state");
  ok &= require_contains(setup_ui_build, "target_arch = $targetArch",
                         "Setup UI capability metadata binds the native target architecture");
  free(setup_ui_build);

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
