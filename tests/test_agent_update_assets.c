#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require_true(int value, const char *message) {
  if (!value) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}

static char *read_file(const char *path) {
  FILE *file = fopen(path, "rb");
  if (!file) return NULL;
  fseek(file, 0, SEEK_END); long size = ftell(file); rewind(file);
  char *data = (char *)malloc((size_t)size + 1u);
  if (!data || fread(data, 1, (size_t)size, file) != (size_t)size) { free(data); fclose(file); return NULL; }
  data[size] = 0; fclose(file); return data;
}

static void contains(const char *text, const char *needle, const char *message) {
  require_true(text && strstr(text, needle), message);
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  require_true(root && root[0], "EDR_SOURCE_DIR is configured");
  char path[4096];
  snprintf(path, sizeof(path), "%s/scripts/edr_agent_inplace_update.ps1", root);
  char *script = read_file(path);
  require_true(script != NULL, "read Windows updater script without executing it");
  contains(script, "Get-AuthenticodeSignature", "Authenticode validity gate exists");
  contains(script, "TrustedPublisherThumbprint", "trusted publisher thumbprint gate exists");
  contains(script, "TrustedPublisherSubject", "trusted publisher subject gate exists");
  contains(script, "SHA256_ONLY_UNSIGNED", "explicit optional-signing update mode exists");
  contains(script, "already verified task-pinned SHA-256", "unsigned mode remains pinned to the task artifact hash");
  contains(script, "Compare-SemVer", "semantic version direction checks exist");
  contains(script, "Normalize-ProductVersion", "Windows four-part ProductVersion is normalized to release SemVer");
  contains(script, "(?:\\.0)?", "only a zero fourth Windows version component is accepted");
  contains(script, "$Operation -eq 'upgrade' -and $versionDirection -le 0", "upgrade rejects downgrade and same-version targets");
  contains(script, "$Operation -eq 'rollback' -and $versionDirection -ge 0", "rollback requires an older target version");
  contains(script, "InternalName", "PE InternalName check exists");
  contains(script, "ProductVersion", "PE ProductVersion check exists");
  contains(script, "Get-PSDrive", "disk-space preflight exists");
  contains(script, "Resolve-DeploymentMode", "auto deployment mode exists");
  contains(script, "Stop-Service", "service stop path exists");
  contains(script, "Start-ScheduledTask", "scheduled-task start path exists");
  contains(script, "UpdaterTaskName", "temporary updater task identity is explicit");
  contains(script, "Unregister-ScheduledTask", "temporary updater task is cleaned up");
  contains(script, "Clear-StaleUpdateWork", "stale updater tasks and work directories are bounded");
  contains(script, "Remove-CurrentUpdateWork", "terminal update work is removed after durable reporting");
  contains(script, "AgentUpdateUpdaterProtocolVersion = 2", "updater protocol version is explicit in the release script");
  contains(script, "Wait-AgentHealthObservation", "local health watchdog is enforced before updater exit");
  contains(script, "[UInt64]$HealthObserveMs = 30000", "manual updater defaults to the bounded local health gate");
  contains(script, "$stableCheck -lt 3", "startup stability uses consecutive liveness samples");
  require_true(!strstr(script, "Start-Sleep -Seconds 5"), "startup does not impose the old fixed five-second delay");
  contains(script, "[Math]::Min(1000, [Math]::Max(100, $remainingMs))", "health polling cannot overshoot a short observation window by two seconds");
  contains(script, "local_health_observation_passed", "platform health check starts only after the local watchdog passes");
  contains(script, "local_watchdog = 'observing'", "local observation is reported as nonterminal runtime progress");
  contains(script, "$resumeHealthObservation -and -not $running", "Agent exit during recovered health observation forces rollback");
  contains(script, "resume_after_commit", "committed replacement can resume after updater interruption");
  contains(script, "Restore-RuntimePlanFromJournal", "runtime DLL rollback plan survives updater interruption");
  contains(script, "$item.Committed = $false", "runtime rollback checkpoints cannot be applied twice after a crash");
  contains(script, "$journal['replacement_committed'] = $false", "binary rollback completion is durable across updater crashes");
  contains(script, "$currentMatchesBackup -and $replacementMayHaveStarted", "binary rollback is inferred if a crash precedes its journal checkpoint");
  contains(script, "$targetHash -eq (Get-Sha256 -Path $backupPath)", "runtime rollback is inferred from restored file content");
  contains(script, "health_observation_deadline_unix_ms", "health observation deadline is durable");
  contains(script, "replacement_committed", "durable replacement journal exists");
  contains(script, "schema_version = 2", "journal uses strict v2 schema");
  contains(script, "task_id = $TaskId", "journal binds task identity");
  contains(script, "command_id = $CommandId", "journal binds command identity");
  contains(script, "hash = $expectedHash", "journal binds artifact hash");
  contains(script, "version = $TargetVersion", "journal binds target version");
  contains(script, "last_event_seq", "journal persists event sequence");
  contains(script, "Add-UpdateEvent", "PowerShell stages durable update events");
  contains(script, "rollback_health_check", "rollback health event is recorded");
  contains(script, "$env:ProgramData", "journal survives install-directory binary replacement");
  contains(script, "if ([string]$prior.status -eq 'succeeded') { exit 0 }", "only prior success exits successfully");
  contains(script, "Write-AtomicJson", "journal and report use atomic writes");
  free(script);

  snprintf(path, sizeof(path), "%s/src/command/agent_update_command.c", root);
  char *command = read_file(path);
  require_true(command != NULL, "read Agent update command implementation");
  contains(command, "before_download", "update can be cancelled before download");
  contains(command, "artifact_downloaded", "update can be cancelled after artifact download");
  contains(command, "runtime_manifest_downloaded", "update can be cancelled after runtime manifest download");
  contains(command, "before_updater_launch", "update can be cancelled before replacement process starts");
  contains(command, "operator_cancelled_before_replacement", "cancel event records the safe cancellation boundary");
  contains(command, "New-ScheduledTaskPrincipal", "updater runs in an independent SYSTEM scheduled task");
  contains(command, "New-ScheduledTaskTrigger -AtStartup", "updater survives a host restart after replacement begins");
  contains(command, "-RestartCount 5", "updater task retries after an unexpected process exit");
  contains(command, "-MultipleInstances IgnoreNew", "updater task cannot run duplicate replacement instances");
  contains(command, "ShellExecuteExA", "updater bootstrap completion is observed");
  contains(command, "GetModuleFileNameA", "updater resolves from the installed Agent directory");
  contains(command, "FindResourceA", "updater script is loaded from the running Agent resource");
  contains(command, "IDR_EDR_AGENT_UPDATE_SCRIPT", "embedded updater resource identity is explicit");
  contains(command, "MOVEFILE_WRITE_THROUGH", "embedded updater is materialized atomically before use");
  contains(command, "EMBEDDED_UPDATER_FAILED", "embedded updater extraction failure is distinct from resource absence");
  contains(command, "if (embedded == EMBEDDED_UPDATER_FAILED) return 0", "embedded extraction failure cannot fall back to a stale sidecar");
  contains(command, "embedded_materialized_hash_mismatch", "runtime readiness requires the materialized updater bytes to match the embedded resource");
  contains(command, "cleanup_old_materialized_updaters", "old materialized updater scripts receive bounded cleanup");
  contains(command, "cleanup_prelaunch_update_work", "pre-launch failures remove the current staging directory immediately");
  contains(command, "update staging directory path is too long", "staging path truncation fails before download");
  contains(command, "update staging file path is too long", "staging file truncation fails before download");
  contains(command, "temp, safe_id", "staging directory uses the same normalized command identity as cleanup");
  contains(command, "updater_info.error_code", "runtime failure reports the exact updater readiness error before download");
  free(command);

  snprintf(path, sizeof(path), "%s/CMakeLists.txt", root);
  char *cmake = read_file(path);
  contains(cmake, "src/command/agent_update_command.c", "command helper is compiled");
  contains(cmake, "src/command/agent_update_event.c", "durable update event outbox is compiled");
  require_true(!strstr(cmake, "src/core/agent_update.c"), "dormant self-overwrite implementation remains disabled");
  contains(cmake, "edr_agent_inplace_update.ps1", "updater script is staged by CMake");
  require_true(!strstr(cmake, "EDR_AGENT_UPDATE_SCRIPT_PATH=\\\"${CMAKE_CURRENT_SOURCE_DIR}"),
               "runtime updater path is not pinned to the CI source checkout");
  contains(cmake, "shell32", "Windows external updater launch dependency is linked");
  free(cmake);

  snprintf(path, sizeof(path), "%s/src/command/command_stub.c", root);
  char *dispatch = read_file(path);
  contains(dispatch, "EDR_AGENT_UPDATE_EXIT_LAUNCHED", "launch result is handled as nonterminal");
  contains(dispatch, "edr_agent_update_recover", "startup inbox replay consumes update journal");
  contains(dispatch, "awaiting terminal updater journal", "replay-blocked update waits instead of failing or relaunching");
  contains(dispatch, "durable inbox is retained", "launch does not delete durable inbox");
  free(dispatch);

  snprintf(path, sizeof(path), "%s/src/core/agent.c", root);
  char *agent = read_file(path);
  require_true(agent != NULL, "read Agent capability manifest implementation");
  contains(agent, "\\\"agent_update_v1\\\"", "runtime capability manifest advertises agent update");
  contains(agent, "edr_agent_update_get_runtime_info", "capability depends on audited embedded or installed updater readiness");
  contains(agent, "updater_protocol_version", "capability reports updater protocol compatibility");
  contains(agent, "updater_materialized", "capability reports whether the embedded updater was materialized");
  contains(agent, "updater_sha256", "capability reports the resolved updater hash");
  free(agent);

  snprintf(path, sizeof(path), "%s/resources/FDSensor.rc", root);
  char *resource = read_file(path);
  contains(resource, "InternalName", "Windows version resource has InternalName");
  contains(resource, "ProductVersion", "Windows version resource has ProductVersion");
  contains(resource, "IDR_EDR_AGENT_UPDATE_SCRIPT RCDATA", "Windows binary embeds its matching updater script");
  contains(resource, "../scripts/edr_agent_inplace_update.ps1", "embedded updater resource uses the release script");
  free(resource);

  snprintf(path, sizeof(path), "%s/.github/workflows/edr-agent-client-release.yml", root);
  char *workflow = read_file(path);
  contains(workflow, "Authenticode sign release executables", "release requires Authenticode signing");
  contains(workflow, "WINDOWS_SIGNING_THUMBPRINT", "release verifies trusted signing thumbprint");
  contains(workflow, "artifact-manifest.json", "release publishes artifact hash manifest");
  contains(workflow, "workflow_dispatch:", "release supports an explicit manual run");
  contains(workflow, "WINDOWS_RELEASE_MODE", "release signing mode is configuration-driven");
  contains(workflow, "arch: arm64", "release builds an ARM64 matrix target");
  contains(workflow, "triplet: arm64-windows", "release uses native ARM64 vcpkg dependencies");
  contains(workflow, "runtime_identifier: win-arm64", "release builds the ARM64 Setup UI");
  contains(workflow, "Assert-WindowsPeArchitecture.ps1", "release rejects architecture-mismatched PE files");
  contains(workflow, "stage_msvc_runtime_dlls_build_release.ps1", "release stages the app-local MSVC runtime");
  contains(workflow, "vcruntime140_1.dll", "release package gate requires the MSVC runtime dependency closure");
  contains(workflow, "msvcp140.dll", "release package gate requires the C++ runtime used by ONNX Runtime");
  contains(workflow, "EDR_WINDOWS_TARGET_ARCH", "release passes an explicit MSVC target architecture");
  contains(workflow, "ARM64 package must not include unsupported WinDivert binaries",
           "ARM64 release excludes unsupported WinDivert drivers");
  contains(workflow, "gh release upload", "architecture bundles are retained in the draft release before publication");
  contains(workflow, "Verify combined AMD64/ARM64 asset set",
           "combined release is published only after both architecture bundles exist");
  contains(workflow, "Copy-Item -LiteralPath $agentBinary -Destination $agentAsset -Force",
           "signed and unsigned releases both publish the raw update artifact");
  contains(workflow, "optional-signature", "unsigned release documents the integrity-pinned platform path");
  contains(workflow, "SignedCms", "release produces detached signed manifest");
  contains(workflow, "signer_thumbprint", "manifest binds expected signer thumbprint");
  contains(workflow, "CMS signer subject does not match", "release verifies CMS signer identity binding");
  contains(workflow, "edr_agent_inplace_update.ps1", "release package contains updater script");
  contains(workflow, "windows-install-upgrade-rollback.yml", "release completion includes the Windows lifecycle workflow");
  contains(workflow, "      - windows-lifecycle", "release publication waits for the Windows lifecycle gate");
  contains(workflow, "target_tag: ${{ github.event_name == 'workflow_dispatch'", "lifecycle validation receives the exact release tag");
  free(workflow);

  snprintf(path, sizeof(path), "%s/scripts/stage_msvc_runtime_dlls_build_release.ps1", root);
  char *msvc_runtime = read_file(path);
  require_true(msvc_runtime != NULL, "read app-local MSVC runtime staging script");
  contains(msvc_runtime, "VCToolsRedistDir", "MSVC runtime staging uses the selected compiler toolset first");
  contains(msvc_runtime, "vswhere.exe", "MSVC runtime staging has a Visual Studio discovery fallback");
  contains(msvc_runtime, "vcruntime140.dll", "MSVC runtime staging requires the core runtime");
  contains(msvc_runtime, "vcruntime140_1.dll", "MSVC runtime staging requires the extended runtime");
  contains(msvc_runtime, "msvcp140.dll", "MSVC runtime staging requires the C++ standard library runtime");
  free(msvc_runtime);

  snprintf(path, sizeof(path), "%s/.github/workflows/windows-install-upgrade-rollback.yml", root);
  char *lifecycle = read_file(path);
  require_true(lifecycle != NULL, "read Windows release lifecycle workflow");
  contains(lifecycle, "workflow_call:", "release lifecycle is callable with an explicit target");
  contains(lifecycle, "target_tag:", "release lifecycle target tag is an explicit input");
  contains(lifecycle, "gh release list", "blank baseline resolves to the latest lower stable Windows release");
  contains(lifecycle, "edr-agent-$Tag-windows-amd64-exe.zip",
           "release lifecycle selects baseline runtime assets by immutable exact name");
  contains(lifecycle, "contents: write",
           "release lifecycle has the push-level visibility GitHub requires for draft releases");
  contains(lifecycle, "repos/$env:GITHUB_REPOSITORY/releases?per_page=100",
           "release lifecycle resolves target drafts from the authenticated release list");
  contains(lifecycle, "Invoke-WebRequest -Uri $apiUrl",
           "release lifecycle downloads draft and published assets through the authenticated asset API");
  contains(lifecycle, "runtime '$($asset.name)' SHA-256 mismatch",
           "release lifecycle verifies the GitHub asset digest when available");
  require_true(!strstr(lifecycle, "actions/download-artifact"),
               "release lifecycle does not consume GitHub Actions artifact storage");
  require_true(!strstr(lifecycle, "github.event.workflow_run.head_branch"),
               "release lifecycle never guesses a version from a workflow branch name");
  contains(lifecycle, "windows_release_lifecycle_smoke.ps1", "release lifecycle executes the Windows install-upgrade-rollback smoke test");
  free(lifecycle);

  snprintf(path, sizeof(path), "%s/scripts/windows_release_lifecycle_smoke.ps1", root);
  char *lifecycle_smoke = read_file(path);
  require_true(lifecycle_smoke != NULL, "read Windows release lifecycle smoke test");
  contains(lifecycle_smoke, "Wait-EmbeddedUpdaterMaterialized", "lifecycle verifies updater extraction from the installed target binary");
  contains(lifecycle_smoke, "embedded updater hash mismatch", "lifecycle binds the materialized updater to the target release hash");
  contains(lifecycle_smoke, "embedded_updater", "lifecycle summary records embedded updater verification");
  contains(lifecycle_smoke, "$targetInstaller = Find-OneFile -Root $TargetPackageDir",
           "lifecycle uses the current target installer to drive the immutable baseline runtime");
  contains(lifecycle_smoke, "target package service installer hash mismatch",
           "lifecycle binds the packaged service installer to the checked-out release source");
  require_true(!strstr(lifecycle_smoke, "$baselineInstaller"),
               "lifecycle does not execute an immutable baseline installer with obsolete PowerShell argument semantics");
  contains(lifecycle_smoke, "$targetUninstallScript = Find-OneFile -Root $TargetPackageDir -Name \"uninstall.ps1\"",
           "lifecycle selects the current uninstall PowerShell protocol");
  contains(lifecycle_smoke, "Copy-Item -LiteralPath $targetUninstallScript",
           "lifecycle never mixes the current native uninstaller with a baseline uninstall script");
  contains(lifecycle_smoke, "target package uninstall script hash mismatch",
           "lifecycle binds the packaged uninstall protocol to the checked-out release source");
  require_true(!strstr(lifecycle_smoke, "headless uninstall failed with exit code $LASTEXITCODE"),
               "lifecycle does not treat a stale native exit code as the result of a PowerShell installer script");
  contains(lifecycle_smoke, "failed_stage = $stage",
           "lifecycle persists the exact failed stage for actionable CI diagnostics");
  contains(lifecycle_smoke, "function Wait-ServiceDeleted",
           "lifecycle waits for asynchronous Windows service deletion");
  contains(lifecycle_smoke, "exit 0",
           "lifecycle explicitly clears stale native-command status after successful assertions");
  free(lifecycle_smoke);

  snprintf(path, sizeof(path), "%s/src/installer_worker/headless_uninstaller_win.c", root);
  char *uninstaller = read_file(path);
  require_true(uninstaller != NULL, "read headless uninstaller implementation");
  contains(uninstaller, "-PreserveDiagnostics -RemoveProgramFiles",
           "keep-data uninstall archives diagnostics but still removes program files");
  contains(uninstaller, "-RemoveData -RemoveProgramFiles",
           "complete uninstall removes runtime data and program files");
  contains(uninstaller, "current_process_is_elevated",
           "native uninstaller detects LocalSystem or an elevated administrator token");
  contains(uninstaller, "run_powershell_direct",
           "elevated lifecycle uninstall avoids an interactive UAC handoff");
  contains(uninstaller, "exec_info.lpVerb = L\"runas\"",
           "manual non-elevated uninstall retains the UAC elevation path");
  contains(uninstaller, "-ServiceName",
           "native uninstall forwards the exact lifecycle service name");
  free(uninstaller);

  snprintf(path, sizeof(path), "%s/scripts/edr_agent_uninstall.ps1", root);
  char *uninstall_script = read_file(path);
  require_true(uninstall_script != NULL, "read Windows uninstall script");
  contains(uninstall_script, "function Wait-AgentServiceDeleted",
           "uninstall verifies that Windows services disappear");
  contains(uninstall_script, "$service.Dispose()",
           "uninstall releases ServiceController handles before service deletion");
  contains(uninstall_script, "Get-CimInstance Win32_Service",
           "uninstall deletion polling does not retain a new SCM service handle");
  contains(uninstall_script, "$deleteExitCode = $LASTEXITCODE",
           "uninstall checks the service deletion result");
  contains(uninstall_script, "FDSecurity\\UninstallArchive",
           "diagnostic retention uses a directory outside program files");
  contains(uninstall_script, "foreach ($relative in @(\"logs\", \"diagnostics\"))",
           "diagnostic retention excludes credentials and active runtime state");
  contains(uninstall_script, "$attempt -lt 120",
           "deferred program-file removal tolerates bounded endpoint security file locks");
  contains(uninstall_script, "uninstall-cleanup-last.json",
           "deferred cleanup persists a result outside the removed program directory");
  free(uninstall_script);

  snprintf(path, sizeof(path), "%s/src/installer_worker/installer_worker_win.c", root);
  char *installer_worker = read_file(path);
  require_true(installer_worker != NULL, "read Windows installer worker");
  contains(installer_worker, "WaitForSingleObject(process.hProcess, 300000)",
           "remote uninstall observes native uninstaller completion");
  contains(installer_worker, "lifecycle_uninstall_completed",
           "remote uninstall journals verified native completion");
  contains(installer_worker, "--service-name %ls",
           "lifecycle worker binds uninstall to the installed service name");
  free(installer_worker);

  puts("ok (pure source contract; Windows execution intentionally not simulated)");
  return 0;
}
