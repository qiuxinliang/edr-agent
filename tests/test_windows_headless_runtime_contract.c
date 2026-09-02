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

static int require_true(int condition, const char *message) {
  if (condition) return 1;
  fprintf(stderr, "FAIL: %s\n", message);
  return 0;
}

static int require_count(const char *text, const char *needle, size_t expected,
                         const char *message) {
  size_t count = 0;
  const char *cursor = text;
  size_t needle_length = needle ? strlen(needle) : 0;
  if (!needle || needle_length == 0) return 0;
  while ((cursor = strstr(cursor, needle)) != NULL) {
    ++count;
    cursor += needle_length;
  }
  if (count == expected) return 1;
  fprintf(stderr, "FAIL: %s (expected %zu occurrences, found %zu)\n",
          message, expected, count);
  return 0;
}

static int require_range_absent(const char *text, const char *begin, const char *end,
                                const char *needle, const char *message) {
  const char *start = text ? strstr(text, begin) : NULL;
  const char *finish = start ? strstr(start + strlen(begin), end) : NULL;
  if (start && finish) {
    const char *hit = strstr(start, needle);
    if (!hit || hit >= finish) return 1;
  }
  fprintf(stderr, "FAIL: %s\n", message);
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
  ok &= require_contains(collector, "s_agent_self_start_key_cache[i] != process_start_key",
                         "self-noise ancestry must bind PID entries to an exact process generation");
  ok &= require_contains(collector, "pid == 0u || process_start_key == 0u",
                         "self-noise ancestry must fail open when generation is unavailable");
  ok &= require_contains(collector, "Only discovery of a new, exact descendant generation",
                         "repeated expected Agent events must not keep moving the self-noise fuse");
  ok &= require_contains(collector, "s_health.etw_prefilter_dropped++",
                         "uninteresting ETW schemas must be observable before payload parsing");
  ok &= require_range_absent(collector, "static void edr_agent_self_count_drop_source",
                             "static int edr_agent_self_mark_pid", "s_health.collector_dropped++",
                             "intentional Agent self filtering must not count as collector loss");
  ok &= require_range_absent(collector, "if (!edr_map_type_and_tag(event_record, &ty, &tag))",
                             "if (edr_a44_split_path_enabled())", "s_health.collector_dropped++",
                             "intentional ETW schema prefiltering must not count as collector loss");
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
  ok &= require_contains(agent, "\\\"agent_self_sources\\\":{\\\"direct_pid\\\"",
                         "basic health must expose the source of Agent self filtering");
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
  ok &= require_contains(worker, "(unsigned long)agent_parent_pid",
                         "uninstall worker must forward the Agent owner PID to the native finalizer");
  ok &= require_absent(worker, "(unsigned long)GetCurrentProcessId(), attestation_url",
                       "uninstall worker must not make the finalizer wait on the short-lived worker process");
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
  ok &= require_absent(worker, "--attestation-token",
                       "worker must not pass the token through a command-line argument");
  ok &= require_absent(worker, "INFINITE",
                       "worker lifecycle waits must remain bounded");
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
  ok &= require_contains(installer_ps, "if ($exeMachine -ne \"arm64\")",
                         "headless enrollment must apply architecture-specific runtime requirements");
  ok &= require_contains(installer_ps, "$requiredRuntime += \"vcruntime140_1.dll\"",
                         "headless enrollment must validate the extended MSVC runtime outside native ARM64");
  ok &= require_contains(installer_ps, "msvcp140.dll",
                         "headless enrollment must validate the C++ runtime dependency");
  free(installer_ps);

  char *headless_uninstaller = read_source(root, "src/installer_worker/headless_uninstaller_win.c");
  if (!headless_uninstaller) return 1;
  ok &= require_absent(headless_uninstaller, "uninstall.ps1",
                       "native uninstall must not depend on PowerShell");
  ok &= require_absent(headless_uninstaller, "--attestation-token",
                       "native uninstall must not accept a token command-line argument");
  ok &= require_absent(headless_uninstaller, "powershell.exe",
                       "native uninstall must not launch PowerShell");
  ok &= require_absent(headless_uninstaller, "token_proof_hmac_sha256",
                       "native uninstall must not invent an HMAC protocol");
  ok &= require_absent(headless_uninstaller, "--native-foundation-self-test",
                       "production uninstall must not expose test-only self-test flags");
  ok &= require_absent(headless_uninstaller, "--native-foundation-child",
                       "production uninstall must not expose test-only child flags");
  ok &= require_absent(headless_uninstaller, "INFINITE",
                       "native uninstall waits must remain bounded");
  ok &= require_contains(headless_uninstaller,
                         "wait_result == WAIT_OBJECT_0 || wait_result == WAIT_TIMEOUT",
                         "an expired Agent result-delivery window must continue into SCM cleanup");
  ok &= require_contains(headless_uninstaller,
                         "return edr_windows_native_manifest_validate(install_dir, NULL)",
                         "native uninstall must accept a valid manifest without legacy Inno files");
  ok &= require_contains(headless_uninstaller,
                         "certificate_configured = thumbprint && thumbprint[0]",
                         "local uninstall must permit an unenrolled Agent with no certificate to remove");
  ok &= require_count(headless_uninstaller, "if (certificate_configured) {", 2,
                      "configured certificates must be validated and removed exactly once");
  ok &= require_contains(headless_uninstaller,
                         "!thumbprint || !thumbprint[0] ||",
                         "remote uninstall must still require a certificate thumbprint");
  ok &= require_contains(headless_uninstaller, "CreateNamedPipeW(",
                         "coordinator must keep the finalizer token in a protected memory channel");
  ok &= require_contains(headless_uninstaller, "edr_native_register_finalizer_task(",
                         "finalizer must start outside the Agent scheduled-task job");
  ok &= require_contains(headless_uninstaller,
                         "edr_native_delete_finalizer_task(finalizer_task_name)",
                         "one-shot finalizer task registration must be removed before teardown");
  ok &= require_contains(headless_uninstaller,
                         "error != ERROR_LOCK_VIOLATION",
                         "native uninstall must retry transient file lock errors");
  ok &= require_contains(headless_uninstaller,
                         "error != ERROR_ACCESS_DENIED",
                         "native uninstall must retry transient mapped-image access denial");
  ok &= require_contains(headless_uninstaller,
                         "edr_finalizer_delete_path_with_retry(receipt, 0, &delete_error)",
                         "native uninstall must not silently preserve a stale failure receipt");
  ok &= require_contains(headless_uninstaller,
                         "stage=%s\\nerror=%d\\npath=%s\\n",
                         "native uninstall failure receipt must identify the blocked stage and path");
  ok &= require_absent(headless_uninstaller, "/EDR_NATIVE_COORDINATED=1",
                       "native finalizer must not invoke the legacy Inno coordination path");
  ok &= require_contains(headless_uninstaller, "edr_native_attestation_should_retry(",
                         "attestation retry policy must be explicit and bounded");
  ok &= require_contains(headless_uninstaller, "WINHTTP_OPTION_CLIENT_CERT_CONTEXT",
                         "remote attestation must make the no-client-certificate policy explicit");
  ok &= require_contains(headless_uninstaller, "WINHTTP_NO_CLIENT_CERT_CONTEXT, 0",
                         "remote attestation must explicitly decline optional client-certificate authentication");
  const char *finalizer_body = strstr(headless_uninstaller, "static int edr_native_finalizer(");
  const char *certificate_removal = finalizer_body
                                        ? strstr(finalizer_body, "edr_native_remove_certificate_identity(")
                                        : NULL;
  const char *attestation = finalizer_body
                                ? strstr(finalizer_body, "edr_native_attest(")
                                : NULL;
  ok &= require_true(finalizer_body && certificate_removal && attestation &&
                         certificate_removal < attestation,
                     "remote attestation must remain after local certificate cleanup");
  ok &= require_contains(headless_uninstaller,
                         "deferred_result == ERROR_SUCCESS_REBOOT_REQUIRED",
                         "accepted Windows reboot deletion must be treated as terminal cleanup");
  ok &= require_absent(headless_uninstaller,
                       "edr_native_write_failure_receipt(self_path, \"self-delete\"",
                       "accepted reboot deletion must not leave a false uninstall failure receipt");
  ok &= require_contains(headless_uninstaller, "(void)edr_native_cleanup_stale_finalizers(state_dir)",
                         "historical finalizer cleanup must be best-effort and non-blocking");
  ok &= require_range_absent(headless_uninstaller,
                             "static int edr_native_cleanup_stale_finalizers(",
                             "static int edr_native_stop_sensor(",
                             "edr_finalizer_delete_path_with_retry(",
                             "stale finalizer cleanup must not wait on retry delays");
  ok &= require_contains(headless_uninstaller, "uninstall-finalizer-*.exe",
                         "historical finalizer cleanup must use an exact state-directory filename pattern");
  ok &= require_contains(headless_uninstaller, "edr_native_stale_finalizer_name",
                         "historical finalizer cleanup must require the canonical UUID filename");
  ok &= require_contains(headless_uninstaller, "EDR_FINALIZER_STALE_AGE_100NS",
                         "historical finalizer cleanup must enforce a fixed stale age threshold");
  ok &= require_contains(headless_uninstaller, "edr_native_process_running_at_path(path)",
                         "historical finalizer cleanup must skip any image still running");
  ok &= require_contains(headless_uninstaller, "DWORD *service_pid_out",
                         "native finalizer must retain the SCM-owned service process identity");
  ok &= require_contains(headless_uninstaller, "edr_native_stop_sensor(install_dir, service_pid)",
                         "sensor teardown must target the service PID instead of arbitrary same-name processes");
  ok &= require_contains(headless_uninstaller, "_wcsicmp(canonical_process, canonical_sensor) == 0",
                         "sensor teardown must validate the target PID image path before termination");
  ok &= require_contains(headless_uninstaller, "FILE_ATTRIBUTE_REPARSE_POINT",
                         "historical finalizer cleanup must not follow reparse-point entries");
  ok &= require_contains(headless_uninstaller, "error == 429 || (error >= 500 && error <= 599)",
                         "only HTTP 429 and 5xx responses must be retryable");
  ok &= require_contains(headless_uninstaller, "ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED",
                         "certificate transport failures must not be retried as HTTP statuses");
  ok &= require_contains(headless_uninstaller, "if (error == 429) return 60000u",
                         "HTTP 429 must honor the one-minute retry window");
  ok &= require_contains(headless_uninstaller, "self_delete_error = edr_native_unlink_self",
                         "self-delete failure must be recorded without aborting teardown proof");
  ok &= require_contains(headless_uninstaller, "edr_finalizer_schedule_self_delete(self_path)",
                         "failed self-delete must request deferred reboot cleanup");
  ok &= require_contains(headless_uninstaller, "RegDeleteKeyExW(HKEY_LOCAL_MACHINE, subkey, KEY_WOW64_64KEY",
                         "native uninstall must remove only the 64-bit installer registration view");
  ok &= require_contains(headless_uninstaller,
                         "{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}}_is1",
                         "native uninstall must remove the exact Inno AppId registration");
  ok &= require_contains(headless_uninstaller, "CSIDL_COMMON_PROGRAMS",
                         "native uninstall must resolve the shared Programs folder through Shell APIs");
  ok &= require_contains(headless_uninstaller, "CSIDL_COMMON_DESKTOPDIRECTORY",
                         "native uninstall must resolve the shared Desktop folder through Shell APIs");
  ok &= require_contains(headless_uninstaller, "FDSecurity.lnk",
                         "native uninstall must remove only the product desktop shortcut");
  ok &= require_contains(headless_uninstaller, "DeleteFileW(program_link)",
                         "native uninstall must remove the exact Common Programs shortcut");
  ok &= require_absent(headless_uninstaller, "SHFileOperationW",
                       "native uninstall must not recursively delete a shared Programs directory");
  free(headless_uninstaller);

  char *agent_core = read_source(root, "src/core/agent.c");
  if (!agent_core) return 1;
  ok &= require_contains(agent_core, "lifecycle_attestation_ready",
                         "capability health must gate remote uninstall on finalizer prerequisites");
  ok &= require_contains(agent_core, "schannel_store_ready",
                         "remote uninstall capability must require a ready Schannel certificate store");
  ok &= require_contains(agent_core, "lifecycle_attestation_runtime",
                         "remote uninstall capability must report degraded state when trust prerequisites are absent");
  free(agent_core);

  char *lifecycle = read_source(root, "src/command/agent_lifecycle_command.c");
  if (!lifecycle) return 1;
  ok &= require_absent(lifecycle, "--attestation-token",
                       "Agent lifecycle must not pass tokens through command-line arguments");
  ok &= require_absent(lifecycle, "powershell.exe",
                       "Agent lifecycle must not launch PowerShell");
  ok &= require_absent(lifecycle, "INFINITE",
                       "Agent lifecycle waits must remain bounded");
  ok &= require_contains(lifecycle, "--parent-pid %lu",
                         "Agent lifecycle must identify the process that owns the uninstall handoff");
  ok &= require_contains(lifecycle, "(unsigned long)GetCurrentProcessId()",
                         "Agent lifecycle must pass its own PID through the uninstall handoff");
  free(lifecycle);

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
  ok &= require_contains(inno, "FDSecurityInstallerWorker.exe is required by commercial installers",
                         "commercial Setup fails closed instead of entering the lab PowerShell fallback");
  ok &= require_contains(inno, "(not EdrInstallerWorkerExists) and (not EdrPowerShellFallbackAllowed)",
                         "commercial Setup checks the native worker before any install stage");
  ok &= require_contains(inno, "Source: \"{#EDR_BIN_DIR}\\uninstall.exe\"",
                         "Setup UI must package the same native uninstaller as the release ZIP");
  ok &= require_contains(inno, "AppId={{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}}",
                         "bundled Setup must retain the exact native-owned Inno registration identity");
  ok &= require_contains(inno, "Name: \"{autoprograms}\\{#MyAppName}\"",
                         "bundled Setup Programs entry must remain product-scoped for native cleanup");
  ok &= require_contains(inno, "Name: \"{autodesktop}\\{#MyAppName}\"",
                         "bundled Setup Desktop entry must remain product-scoped for native cleanup");
  ok &= require_absent(inno, "EdrNativeCoordinatedUninstall",
                       "Inno must not retain the removed native coordination branch");
  ok &= require_absent(inno, "EDR_NATIVE_COORDINATED",
                       "Inno must not expose the removed native coordination marker");
  ok &= require_contains(inno, "Type: filesandordirs; Name: \"{app}\\collector\"",
                         "Setup uninstall must remove the worker-created optional collector directory");
  ok &= require_contains(inno, "INSTALL_FAILURE_ROLLBACK begin",
                         "first-install Setup UI failure must initiate controlled rollback");
  ok &= require_contains(inno, "EdrHadExistingInstallation := FileExists(AppDir + '\\unins000.exe')",
                         "only a completed GUI installation may be preserved during failure rollback");
  const char *initialize_setup = strstr(inno, "function InitializeSetup(): Boolean;");
  const char *json_escape = strstr(inno, "function JsonEscape(const S: string): string;");
  const char *early_app_expansion = initialize_setup ? strstr(initialize_setup, "ExpandConstant('{app}") : NULL;
  ok &= require_true(initialize_setup && json_escape &&
                         (!early_app_expansion || early_app_expansion >= json_escape),
                     "InitializeSetup must not expand {app} before Inno initializes the install directory");
  const char *prepare_to_install = strstr(inno, "function PrepareToInstall(var NeedsRestart: Boolean): string;");
  const char *existing_install_probe = strstr(inno, "EdrHadExistingInstallation := FileExists(AppDir + '\\unins000.exe')");
  ok &= require_true(prepare_to_install && existing_install_probe && existing_install_probe > prepare_to_install,
                     "completed-install probing must run from PrepareToInstall after {app} is initialized");
  ok &= require_contains(inno, "/EDR_UPGRADE_EXISTING requires a completed existing Setup installation",
                         "upgrade mode must reject incomplete directories before replacing release files");
  ok &= require_contains(inno, "skipped_existing_installation=true",
                         "upgrade failure must preserve the previous installation instead of deleting it");
  free(inno);

  char *plain_inno = read_source(root, "install/windows-inno/EDRAgentSetup.iss");
  if (!plain_inno) return 1;
  ok &= require_contains(plain_inno, "AppId={{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}}",
                         "plain Setup must retain the exact native-owned Inno registration identity");
  ok &= require_contains(plain_inno, "Name: \"{autoprograms}\\{#MyAppName}\"",
                         "plain Setup Programs entry must remain product-scoped for native cleanup");
  ok &= require_contains(plain_inno, "Name: \"{autodesktop}\\{#MyAppName}\"",
                         "plain Setup Desktop entry must remain product-scoped for native cleanup");
  ok &= require_absent(plain_inno, "EdrNativeCoordinatedUninstall",
                       "plain Inno must not retain the removed native coordination branch");
  ok &= require_absent(plain_inno, "EDR_NATIVE_COORDINATED",
                       "plain Inno must not expose the removed native coordination marker");
  free(plain_inno);

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
  ok &= require_contains(setup_ui, "public string RuntimeMode { get; set; } = \"windows_service\";",
                         "commercial Setup UI defaults to the Windows service");
  ok &= require_contains(setup_ui, "[\"harden_acl\"] = true",
                         "commercial Setup UI makes ACL hardening invariant");
  ok &= require_contains(setup_ui, "[\"strict_health_check\"] = true",
                         "commercial Setup UI makes health validation invariant");
  ok &= require_contains(setup_ui, "return normalizedMode == \"upgrade_keep\";",
                         "commercial Setup UI preserves upgrade data without a checkbox");
  free(setup_ui);

  char *setup_html = read_source(root, "install/windows-setup-ui/Assets/installer.html");
  if (!setup_html) return 1;
  ok &= require_contains(setup_html, "自动安装 / 升级（保留终端身份、队列和证据）",
                         "commercial Setup presents one automatic installation policy");
  ok &= require_contains(setup_html, "正式部署固定使用 Windows Service、ACL 加固和严格健康校验",
                         "commercial Setup explains its fixed safety defaults");
  ok &= require_true(!strstr(setup_html, "<div class=\"tl\">跳过证书校验</div>"),
                     "commercial Setup does not offer a clickable TLS verification bypass");
  free(setup_html);

  char *build_ps = read_source(root, "install/windows-inno/Build-BundledInstaller.ps1");
  if (!build_ps) return 1;
  ok &= require_contains(build_ps, "write_windows_package_capabilities.ps1",
                         "Setup UI and headless packages must use the shared capability contract writer");
  ok &= require_contains(build_ps, "-SignatureStatus $SignatureStatus",
                         "bundled installer capability metadata must bind the Agent signature mode");
  ok &= require_contains(build_ps, "Verified executable signature closure",
                         "bundled installer must verify declared inner executable signing state");
  ok &= require_contains(build_ps, "actualSignatureStatus -ne $SignatureStatus",
                         "bundled installer must reject an inner signature-state mismatch");
  ok &= require_contains(build_ps, "notin @(\"Valid\", \"NotSigned\")",
                         "bundled installer must reject corrupt or unverifiable Authenticode states");
  ok &= require_contains(build_ps, "Verified Runtime PE closure",
                         "bundled installer must verify every Runtime EXE and DLL architecture");
  ok &= require_contains(build_ps, "Verified isolated Velociraptor emulation component",
                         "ARM64 packaging permits only the AMD64 Velociraptor child-process exception");
  ok &= require_contains(build_ps, "-Architecture \"amd64\"",
                         "the Velociraptor exception must still verify an AMD64 PE explicitly");
  ok &= require_contains(build_ps, "Assert-WindowsInstallerBootstrapArchitecture.ps1",
                         "Inno bootstrap architecture must be validated separately from native payload architecture");
  ok &= require_contains(build_ps, "/DEDR_ALLOW_POWERSHELL_FALLBACK=1",
                         "lab-only PowerShell fallback must be explicit in the Inno build contract");
  free(build_ps);

  char *setup_ui_build = read_source(root, "install/windows-setup-ui/Build-SetupUi.ps1");
  if (!setup_ui_build) return 1;
  ok &= require_contains(setup_ui_build, "edr.windows.package-capabilities.v1",
                         "Setup UI manifest uses the canonical package capability schema");
  ok &= require_contains(setup_ui_build, "[string] $ExpectedSignatureStatus",
                         "Setup UI packaging requires an explicit Release signature expectation");
  ok &= require_contains(setup_ui_build, "$actualSignatureStatus -eq \"mixed\"",
                         "Setup UI packaging rejects partially signed executable closures");
  ok &= require_contains(setup_ui_build, "notin @('Valid', 'NotSigned')",
                         "Setup UI packaging rejects corrupt or unverifiable executable signatures");
  ok &= require_contains(setup_ui_build, "signature_status = $actualSignatureStatus",
                         "Setup UI capability metadata records the verified executable closure state");
  ok &= require_contains(setup_ui_build, "target_arch = $targetArch",
                         "Setup UI capability metadata binds the native target architecture");
  ok &= require_contains(setup_ui_build, "windows_x64_emulation",
                         "Setup UI metadata exposes the isolated Velociraptor emulation mode");
  ok &= require_contains(setup_ui_build, "Assert-WindowsInstallerBootstrapArchitecture.ps1",
                         "Setup UI packaging must preserve the explicit Inno bootstrap architecture exception");
  ok &= require_contains(setup_ui_build, "packages.$runtime.lock.json",
                         "Setup UI build must select the immutable NuGet lock for its target RID");
  ok &= require_contains(setup_ui_build, "Restore-SetupUiLocked.ps1",
                         "Setup UI build must run the shared immutable NuGet restore gate before publish");
  ok &= require_contains(setup_ui_build, "-SelfContained $selfContained",
                         "Setup UI restore must receive the same self-contained mode as publish");
  ok &= require_contains(setup_ui_build, "-PublishReadyToRun $readyToRun",
                         "Setup UI restore must receive the same ReadyToRun mode as publish");
  ok &= require_contains(setup_ui_build, "-Configuration $Configuration",
                         "Setup UI restore must receive the same configuration as publish");
  ok &= require_contains(setup_ui_build, "--no-restore",
                         "Setup UI publish must consume the already verified locked restore closure");
  free(setup_ui_build);

  char *setup_ui_restore = read_source(root, "scripts/Restore-SetupUiLocked.ps1");
  if (!setup_ui_restore) return 1;
  ok &= require_contains(setup_ui_restore, "-p:SelfContained=$SelfContained",
                         "locked restore must explicitly resolve self-contained runtime packs");
  ok &= require_contains(setup_ui_restore, "-p:PublishReadyToRun=$PublishReadyToRun",
                         "locked restore must resolve the selected ReadyToRun closure");
  ok &= require_contains(setup_ui_restore, "-p:Configuration=$Configuration",
                         "locked restore must match the selected publish configuration");
  ok &= require_contains(setup_ui_restore, "if ($VerifyPublish)",
                         "locked restore gate must support a real publish smoke");
  ok &= require_contains(setup_ui_restore, "Setup UI publish smoke did not produce FDSecuritySetupUI.exe",
                         "publish smoke must require the product executable");
  free(setup_ui_restore);

  char *dependency_locks = read_source(root, "scripts/Validate-DependencyLocks.ps1");
  if (!dependency_locks) return 1;
  ok &= require_contains(dependency_locks, "packages.win-x64.lock.json",
                         "dependency validation must require the immutable Windows x64 Setup UI lock");
  ok &= require_contains(dependency_locks, "packages.win-arm64.lock.json",
                         "dependency validation must require the immutable Windows ARM64 Setup UI lock");
  ok &= require_contains(dependency_locks, "committed RID lock during MSBuild project evaluation",
                         "dependency validation must reject a project that stops selecting RID-specific locks during evaluation");
  ok &= require_contains(dependency_locks, "preserve packages.lock.json for portable restores",
                         "dependency validation must retain a portable NuGet lock for no-RID restores");
  free(dependency_locks);

  char *bootstrap_arch = read_source(root, "scripts/Assert-WindowsInstallerBootstrapArchitecture.ps1");
  if (!bootstrap_arch) return 1;
  ok &= require_contains(bootstrap_arch, "[ValidateSet(\"amd64\", \"arm64\")]",
                         "installer bootstrap validation must bind a supported native payload architecture");
  ok &= require_contains(bootstrap_arch, "$expectedInno6Bootstrap = [UInt16]0x014c",
                         "Inno Setup 6 bootstrap verification must require the expected x86 PE machine");
  ok &= require_contains(bootstrap_arch, "Do not weaken the separate native Runtime PE checks",
                         "the bootstrap exception must remain isolated from native Runtime PE validation");
  free(bootstrap_arch);

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
