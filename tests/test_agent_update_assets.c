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
  contains(script, "AgentUpdateUpdaterProtocolVersion = 5", "updater protocol version is explicit in the release script");
  contains(script, "Invoke-FullInstallerUpgrade", "protocol v5 supports the task-pinned full installer path");
  contains(script, "EDR_UPGRADE_EXISTING=1", "full installer preserves the existing endpoint identity");
  contains(script, "full installer modified protected agent.toml identity configuration", "full installer verifies the protected identity was not rewritten");
  contains(script, "full installer completed but installed Runtime component identity does not match the task-pinned release",
           "full installer verifies the complete installed Runtime identity before reporting success");
  contains(script, "runtime_identity_sha256 is required for protocol-5 releases",
           "protocol-5 full installers require a signed Runtime identity");
  contains(script, "Invoke-FullInstallerRuntimeMirror", "full installer has an immutable runtime backup and restore path");
  contains(script, "expected_runtime_identity_sha256", "full installer recovery journal binds the target Runtime identity");
  contains(script, "full_installer_recovery", "interrupted full installer recovery has an explicit durable stage");
  contains(script, "Wait-FullInstallerProcess", "recovery waits for the already launched installer instead of starting a second copy");
  contains(script, "recovered full installer did not complete the task-pinned Agent replacement",
           "incomplete recovered installer execution enters rollback without overwriting the original backup");
  contains(script, "full installer rollback backup is unavailable; refusing to start an unverified mixed Runtime",
           "full installer recovery fails closed when the immutable rollback baseline is missing");
  contains(script, "$verifiedStatus = if ($Operation -eq 'rollback')", "full installer event status is initialized before either upgrade branch uses it");
  contains(script, "rollback_full_installer_started", "full installer failure starts a bounded runtime rollback");
  contains(script, "preserving Agent update work for recovery", "unrecoverable update failure retains the restricted recovery snapshot");
  contains(script, "native-package-integrity.json", "complete runtime package integrity manifest is required");
  contains(script, "runtime package integrity manifest may only add app-local DLLs",
           "complete runtime package limits extended components to app-local DLLs");
  contains(script, "$files += [pscustomobject]@{", "native package integrity manifest joins the transactional runtime plan");
  contains(script, "$integrityInput.CopyTo($integrityOutput)",
           "Runtime identity manifest bytes are preserved exactly during transactional update");
  contains(script, "'FDSecurityInstallerWorker.exe','uninstall.exe','uninstall.ps1','native-package-integrity.json'",
           "complete runtime update requires helpers and their installed integrity manifest");
  contains(script, "A Headless base package can contain optional rules", "runtime update accepts the complete verified Headless package");
  contains(script, "$name.Contains('/')", "runtime update ignores nested Headless package assets instead of extracting them");
  contains(script, "FDSecurityInstallerWorker.exe", "runtime update includes lifecycle worker");
  contains(script, "uninstall.exe", "runtime update includes headless uninstaller");
  contains(script, "uninstall.ps1", "runtime update includes uninstall script");
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

  snprintf(path, sizeof(path), "%s/install/windows-inno/EDRAgentSetup.bundled.iss", root);
  char *inno = read_file(path);
  require_true(inno != NULL, "read Windows bundled installer definition");
  contains(inno, "[InstallDelete]", "full installer has an explicit release-owned Runtime reconciliation stage");
  contains(inno, "Name: \"{app}\\*.dll\"; Check: ShouldReconcileRuntimeDlls",
           "full installer removes obsolete root DLLs only during an identity-preserving upgrade");
  contains(inno, "Result := EdrCmdUpgradeExisting", "Runtime DLL reconciliation is restricted to verified upgrades");
  free(inno);

  snprintf(path, sizeof(path), "%s/src/command/agent_update_command.c", root);
  char *command = read_file(path);
  require_true(command != NULL, "read Agent update command implementation");
  contains(command, "before_download", "update can be cancelled before download");
  contains(command, "artifact_downloaded", "update can be cancelled after artifact download");
  contains(command, "runtime_manifest_downloaded", "update can be cancelled after runtime manifest download");
  contains(command, "runtime-package.zip", "complete runtime ZIP is downloaded into isolated staging");
  contains(command, "EDR_AGENT_UPDATE_MAX_ARTIFACT_BYTES", "runtime package has an explicit download size limit");
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
  contains(command, "describe_http_download_failure", "download failures preserve the bounded transport diagnostic");
  contains(command, "runtime package download failed", "runtime package errors no longer mislabel every failure as authentication");
  free(command);

  snprintf(path, sizeof(path), "%s/tests/test_agent_update_contract.c", root);
  char *update_contract_test = read_file(path);
  require_true(update_contract_test != NULL, "read Agent update contract test");
  contains(update_contract_test, "int edr_command_cancel_requested",
           "Windows update contract target stubs cancellation dependency");
  contains(update_contract_test, "int edr_ingest_http_get_url_to_file",
           "Windows update contract target stubs download dependency");
  contains(update_contract_test, "void edr_ingest_http_get_runtime",
           "Windows update contract target stubs transport diagnostics dependency");
  free(update_contract_test);

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
  contains(agent, "edr_agent_lifecycle_runtime_identity", "lifecycle capability is based on installed native chain integrity and identity");
  free(agent);

  snprintf(path, sizeof(path), "%s/src/command/agent_lifecycle_command.c", root);
  char *lifecycle_identity_command = read_file(path);
  require_true(lifecycle_identity_command != NULL, "read Agent lifecycle Runtime identity implementation");
  contains(lifecycle_identity_command, "cJSON_GetArraySize(files)",
           "lifecycle Runtime identity bounds the full component list");
  contains(lifecycle_identity_command, "lifecycle_runtime_name_valid",
           "lifecycle Runtime identity rejects unsupported component types");
  contains(lifecycle_identity_command, "lifecycle_file_sha256(path, actual)",
           "lifecycle Runtime identity verifies every declared component hash");
  free(lifecycle_identity_command);

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
  contains(workflow, "EDR_UPGRADE_CLASS", "release records a fail-closed upgrade classification");
  contains(workflow, "classify_windows_upgrade.py", "release classifies changed components before manifest signing");
  contains(workflow, "upgrade_class = $env:EDR_UPGRADE_CLASS", "signed artifact metadata binds the upgrade class");
  contains(workflow, "runtime_identity_sha256 = $runtimeIdentitySha256",
           "signed artifact metadata binds the complete runtime identity");
  contains(workflow, "verify_binary_hot_compatibility.py",
           "explicit binary-hot releases prove runtime component identity after build");
  contains(workflow, "Get-ChildItem -LiteralPath $outDir -Filter \"*.dll\"",
           "release Runtime identity binds every root app-local DLL");
  contains(workflow, "$nativeIntegrityFiles.ToArray()",
           "release materializes the Runtime component list before ordered-manifest serialization");
  require_true(!strstr(workflow, "files = @($nativeIntegrityFiles)"),
               "release must not trigger PowerShell generic-list expansion inside an ordered manifest");
  contains(workflow, "arch: arm64", "release builds an ARM64 matrix target");
  contains(workflow, "triplet: arm64-windows", "release uses native ARM64 vcpkg dependencies");
  contains(workflow, "runtime_identifier: win-arm64", "release builds the ARM64 Setup UI");
  contains(workflow, "Assert-WindowsPeArchitecture.ps1", "release rejects architecture-mismatched PE files");
  contains(workflow, "Verified Runtime PE closure",
           "release verifies every Runtime EXE and DLL against the target architecture");
  contains(workflow, "stage_msvc_runtime_dlls_build_release.ps1", "release stages the app-local MSVC runtime");
  contains(workflow, "vcruntime140_1.dll", "release package gate requires the MSVC runtime dependency closure");
  contains(workflow, "msvcp140.dll", "release package gate requires the C++ runtime used by ONNX Runtime");
  contains(workflow, "EDR_WINDOWS_TARGET_ARCH", "release passes an explicit MSVC target architecture");
  contains(workflow, "ARM64 package must not include unsupported WinDivert binaries",
           "ARM64 release excludes unsupported WinDivert drivers");
  contains(workflow, "write_windows_package_capabilities.ps1",
           "release uses the shared Windows package capability contract writer");
  contains(workflow, "test_windows_package_capabilities_contract.ps1",
           "release runs the AMD64 and ARM64 capability round-trip gate");
  contains(workflow, "-SignatureStatus $signatureStatus",
           "release passes signed versus unsigned launch policy context to the contract writer");
  contains(workflow, "package root must contain exactly one package-capabilities.json",
           "release gate verifies the architecture capability manifest is packaged exactly once");
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

  snprintf(path, sizeof(path), "%s/scripts/write_windows_package_capabilities.ps1", root);
  char *package_capabilities = read_file(path);
  require_true(package_capabilities != NULL, "read shared Windows package capability writer");
  contains(package_capabilities, "edr.windows.package-capabilities.v1",
           "package writer declares the strict Windows capability schema");
  contains(package_capabilities, "arm64_emulation_supported = $false",
           "package writer rejects unverified AMD64-on-ARM64 compatibility");
  contains(package_capabilities, "arm64_emulation_network_packet_capture = $false",
           "package writer rejects network capture through AMD64 emulation");
  contains(package_capabilities, "network_packet_capture = $networkPacketCapture",
           "package writer binds native network capture to the target architecture");
  contains(package_capabilities, "windows_firewall_isolation = $true",
           "package writer retains architecture-independent host isolation");
  contains(package_capabilities, "signature_status = $SignatureStatus",
           "package writer records signed versus unsigned launch policy context");
  contains(package_capabilities, "UTF8Encoding]::new($false)",
           "package writer emits UTF-8 JSON without a BOM");
  free(package_capabilities);

  snprintf(path, sizeof(path), "%s/install/windows-inno/package_bundled_layout.sh", root);
  char *legacy_layout = read_file(path);
  require_true(legacy_layout != NULL, "read legacy bundle layout generator");
  contains(legacy_layout, "edr.windows.package-capabilities.v1",
           "legacy bundle layout emits the canonical package capability schema");
  contains(legacy_layout, "package-capabilities.json",
           "legacy bundle layout writes the canonical root capability manifest");
  contains(legacy_layout, "EDR_WINDOWS_SIGNATURE_STATUS",
           "legacy bundle layout records signed versus unsigned state");
  require_true(strstr(legacy_layout, "capabilities/package.json") == NULL,
               "legacy bundle layout no longer emits the incompatible nested capability manifest");
  free(legacy_layout);

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
  contains(lifecycle, "$hasNativeAsset",
           "blank baseline resolves to the latest lower release with a matching native package");
  contains(lifecycle, "$targetRuntime = \"edr-agent-$env:TARGET_TAG-windows-${{ matrix.arch }}-exe.zip\"",
           "release lifecycle selects baseline runtime assets by architecture-specific immutable exact name");
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
  contains(lifecycle, "windows_setup_exe_lifecycle_smoke.ps1",
           "release lifecycle executes the real Setup EXE install-upgrade-rollback-uninstall test");
  contains(lifecycle, "windows-${{ matrix.arch }}-setup.exe",
           "release lifecycle downloads the architecture-matched immutable Setup EXE");
  contains(lifecycle, "runner: windows-2022",
           "AMD64 Setup lifecycle is pinned to the Visual Studio 2022 Windows image");
  contains(lifecycle, "runner: windows-11-arm",
           "release lifecycle executes on a native Windows ARM64 runner");
  contains(lifecycle, "-Architecture '${{ matrix.arch }}'",
           "release lifecycle passes the native target architecture into the smoke test");
  contains(lifecycle, "windows-${{ matrix.arch }}-exe.zip",
           "release lifecycle downloads the architecture-matched immutable package");
  contains(lifecycle, "Deferred uninstall cleanup receipt",
           "failed lifecycle summaries expose the asynchronous cleanup receipt");
  contains(lifecycle, "Uninstall attestation listener",
           "failed lifecycle summaries expose callback listener diagnostics");
  contains(lifecycle, "Uninstall attestation attempts",
           "failed lifecycle summaries expose every callback request observed by the listener");
  contains(lifecycle, "Deferred uninstall cleanup stderr",
           "failed lifecycle summaries expose deferred PowerShell runtime errors");
  free(lifecycle);

  snprintf(path, sizeof(path), "%s/.github/workflows/edr-agent-client-release.yml", root);
  char *client_release = read_file(path);
  require_true(client_release != NULL, "read Windows client release workflow");
  require_true(!strstr(client_release, "Cache CMake build directory"),
               "release workflow must not restore mutable CMake build outputs");
  contains(client_release, "Verify native uninstall attestation capabilities",
           "release workflow probes freshly built native uninstall components");
  contains(client_release, "invoke_windows_native_capability_probe.ps1",
           "release workflow waits for GUI subsystem capability probes through the shared runner");
  contains(client_release, "runner: windows-11-arm",
           "release workflow builds and tests ARM64 on a native Windows runner");
  contains(client_release, "invoke_windows_native_capability_probe.ps1",
           "release workflow executes native lifecycle capability probes on both architectures");
  contains(client_release, "native-package-integrity.json",
           "release workflow packages native component SHA-256 identities");
  contains(client_release, "Required release test was not configured",
           "release workflow rejects a missing lifecycle release gate");
  contains(client_release, "agent_update_packaging_contract",
           "release workflow executes the OTA packaging contract gate");
  contains(client_release, "pmfe_pe_architectures",
           "release workflow executes the ARM64, ARM64EC, and x64 emulation PE recognition test");
  contains(client_release, "'test_pmfe_pe_arch'",
           "release workflow builds the PMFE PE architecture test before CTest executes it");
  contains(client_release, "'test_ave_static_onnx_integration'",
           "release workflow builds the real ONNX fixture test before CTest executes it");
  contains(client_release, "ave_static_onnx_triple_integration",
           "release gate executes real ONNX inference on both native architectures");
  contains(client_release, "ONNX Runtime test DLL is unavailable",
           "release CTest verifies that the official ONNX Runtime DLL is reachable from test executables");
  contains(client_release, "Release CTest ONNX Runtime DLL directory",
           "release CTest explicitly prepends the task-pinned ONNX Runtime DLL directory to PATH");
  contains(client_release, "Release tests failed on native $env:EDR_RELEASE_ARCH runner",
           "release workflow executes the contract suite natively on AMD64 and ARM64");
  contains(client_release, "Windows release native target $nativeTarget failed",
           "release workflow builds native uninstall binaries after gate tests without building unrelated targets");
  contains(client_release, "$releaseTargets = @(",
           "release workflow uses an explicit Windows build target allowlist");
  contains(client_release, "'native-package-integrity\\.json'",
           "release workflow rejects packages missing native component integrity metadata");
  contains(client_release, "Initialize-VS2022Environment.ps1",
           "release workflow pins the Visual Studio compiler generation on both architectures");
  contains(client_release, "bootstrap_pinned_vcpkg.ps1",
           "release workflow bootstraps the manifest-pinned vcpkg commit");
  contains(client_release, "Install-PinnedOnnxRuntime.ps1",
           "release workflow downloads only SHA-256 pinned ONNX Runtime archives");
  contains(client_release, "-DEDR_REQUIRE_ONNXRUNTIME=ON",
           "release configure fails closed when ONNX Runtime is unavailable");
  contains(client_release, "actions/setup-dotnet@v5",
           "release workflow uses the Node 24 setup-dotnet action");
  contains(client_release, "Verify locked Setup UI NuGet closure",
           "release workflow verifies the target RID Setup UI lock before packaging");
  contains(client_release, "packages.{0}.lock.json",
           "release workflow derives the immutable Setup UI lock name from its runtime identifier");
  contains(client_release, "dotnet restore $project -r $env:EDR_RUNTIME_IDENTIFIER --locked-mode",
           "release workflow restores the Setup UI through its immutable target RID lock");
  require_true(!strstr(client_release, "ilammy/msvc-dev-cmd"),
               "release workflow has no Node 20 MSVC action");
  require_true(!strstr(client_release, "mozilla-actions/sccache-action"),
               "release workflow has no Node 20 sccache action");
  free(client_release);

  snprintf(path, sizeof(path), "%s/tests/test_ave_static_onnx_integration.c", root);
  char *static_onnx_integration = read_file(path);
  require_true(static_onnx_integration != NULL,
               "release workflow target has a checked static ONNX integration test source");
  contains(static_onnx_integration, "edr_onnx_runtime_load",
           "static ONNX integration test loads the pinned fixture through the Agent runtime");
  contains(static_onnx_integration, "onnx_layout != 1",
           "static ONNX integration test requires the named triple-output contract");
  contains(static_onnx_integration, "void edr_win_listen_apply_config",
           "static ONNX integration test supplies config.c's Windows-only listener hook");
  contains(static_onnx_integration, "write_deterministic_input",
           "static ONNX integration test uses a cross-platform deterministic feature input");
  contains(static_onnx_integration, "static ONNX result: layout=",
           "static ONNX integration failures include runtime output diagnostics");
  free(static_onnx_integration);

  snprintf(path, sizeof(path), "%s/tests/CMakeLists.txt", root);
  char *tests_cmake = read_file(path);
  require_true(tests_cmake != NULL, "read test target CMake definitions");
  contains(tests_cmake, "Stage task-pinned ONNX Runtime DLL beside static ONNX integration test",
           "Windows static ONNX test stages the pinned runtime DLL next to its executable");
  contains(tests_cmake, "onnxruntime_providers_shared.dll",
           "Windows static ONNX test stages optional ONNX provider DLLs with the core runtime");
  free(tests_cmake);

  snprintf(path, sizeof(path), "%s/.github/workflows/edr-agent-client-build.yml", root);
  char *client_build = read_file(path);
  require_true(client_build != NULL, "read Windows client build workflow");
  require_true(!strstr(client_build, "Cache CMake build directory"),
               "client build workflow must not restore mutable CMake build outputs");
  contains(client_build, "Verify native uninstall attestation capabilities",
           "client build workflow probes freshly built native uninstall components");
  contains(client_build, "native-package-integrity.json",
           "client build workflow packages native component SHA-256 identities");
  contains(client_build, "'native-package-integrity\\.json'",
           "client build workflow rejects packages missing native component integrity metadata");
  contains(client_build, "invoke_windows_native_capability_probe.ps1",
           "client build waits for GUI subsystem capability probes through the shared runner");
  contains(client_build, "actions/setup-dotnet@v5",
           "client build uses the Node 24 setup-dotnet action");
  contains(client_build, "Verify locked Setup UI NuGet closure",
           "client build verifies the AMD64 Setup UI lock before packaging");
  contains(client_build, "packages.{0}.lock.json",
           "client build derives the immutable Setup UI lock name from its runtime identifier");
  contains(client_build, "dotnet restore $project -r $runtime --locked-mode",
           "client build restores the Setup UI through its immutable target RID lock");
  contains(client_build, "actions/upload-artifact@v6",
           "client build uses the Node 24 artifact upload action");
  contains(client_build, "$nativeIntegrityFiles.ToArray()",
           "client build materializes the Runtime component list before ordered-manifest serialization");
  require_true(!strstr(client_build, "files = @(\n              [ordered]@{ name = \"FDSecurityInstallerWorker.exe\""),
               "client build must not use inline generic-list expansion inside an ordered manifest");
  free(client_build);

  snprintf(path, sizeof(path), "%s/.github/workflows/windows-platform-https-lifecycle.yml", root);
  char *platform_https = read_file(path);
  require_true(platform_https != NULL, "read real platform HTTPS lifecycle workflow");
  contains(platform_https, "environment: staging-platform-https",
           "destructive real platform lifecycle is protected by a staging environment approval");
  contains(platform_https, "loopback is forbidden in the real platform HTTPS gate",
           "real platform gate rejects loopback substitutes");
  contains(platform_https, "/admin/ops/agent-rollouts/${campaign_id}/execute",
           "real platform gate executes the production rollout API");
  contains(platform_https, "/lifecycle/uninstall",
           "real platform gate executes the production uninstall API");
  contains(platform_https, "uninstall_attested:true",
           "real platform gate requires the two-phase uninstall attestation to succeed");
  contains(platform_https, "uninstall_verification_failed|uninstall_attestation_timeout",
           "real platform gate keeps polling through the backend's bounded late-attestation repair window");
  require_true(!strstr(platform_https, "--insecure") && !strstr(platform_https, " -k"),
               "real platform HTTPS gate never disables certificate validation");
  free(platform_https);

  snprintf(path, sizeof(path), "%s/dependencies.lock.json", root);
  char *dependency_lock = read_file(path);
  require_true(dependency_lock != NULL, "read native dependency lock");
  contains(dependency_lock, "\"onnxruntime\"", "dependency lock pins ONNX Runtime");
  contains(dependency_lock, "\"sha256\"", "dependency lock binds native archives by SHA-256");
  contains(dependency_lock, "0b38df9af21834e41e73d602d90db5cb06dbd1ca618948b8f1d66d607ac9f3cd",
           "dependency lock binds the official ONNX Runtime x64 asset digest");
  contains(dependency_lock, "1cfe88b6435df3b5fb0e9f6bd7d6f5df1e887b6174de7f6e2a47bab956f3f168",
           "dependency lock binds the official ONNX Runtime ARM64 asset digest");
  free(dependency_lock);

  snprintf(path, sizeof(path), "%s/scripts/Validate-DependencyLocks.ps1", root);
  char *dependency_validator = read_file(path);
  require_true(dependency_validator != NULL, "read dependency lock consistency validator");
  contains(dependency_validator, "global.json SDK version does not match dependencies.lock.json",
           "dependency validation prevents .NET lock drift");
  contains(dependency_validator, "vcpkg builtin-baseline is invalid or inconsistent",
           "dependency validation prevents vcpkg baseline drift");
  contains(dependency_validator, "Setup UI package '$name' is not exactly bound",
           "dependency validation enforces NuGet locked restore inputs");
  free(dependency_validator);

  snprintf(path, sizeof(path), "%s/global.json", root);
  char *dotnet_lock = read_file(path);
  require_true(dotnet_lock != NULL, "read .NET SDK lock");
  contains(dotnet_lock, "\"rollForward\": \"disable\"", ".NET SDK roll-forward is disabled");
  free(dotnet_lock);

  const char *onnx_fixtures[] = {
    "static_triple_minimal.onnx", "behavior_dual_minimal.onnx", "behavior_seq128_dual_minimal.onnx"
  };
  for (size_t i = 0; i < sizeof(onnx_fixtures) / sizeof(onnx_fixtures[0]); ++i) {
    snprintf(path, sizeof(path), "%s/tests/fixtures/%s", root, onnx_fixtures[i]);
    char *fixture = read_file(path);
    require_true(fixture != NULL, "checked ONNX integration fixture exists");
    free(fixture);
  }

  snprintf(path, sizeof(path), "%s/tests/CMakeLists.txt", root);
  char *test_cmake = read_file(path);
  require_true(test_cmake != NULL, "read test CMake configuration");
  contains(test_cmake, "if(NOT MSVC)",
           "C11 atomic stress test is excluded from MSVC builds");
  free(test_cmake);

  snprintf(path, sizeof(path), "%s/CMakeLists.txt", root);
  char *required_onnx_cmake = read_file(path);
  require_true(required_onnx_cmake != NULL, "read top-level required ONNX gate");
  contains(required_onnx_cmake, "EDR_REQUIRE_ONNXRUNTIME=ON requires checked ONNX fixture",
           "missing ONNX fixtures block every required configure, including tests-off builds");
  contains(required_onnx_cmake, "Checked ONNX fixture SHA256 mismatch",
           "required configure binds checked ONNX fixtures by SHA-256");
  free(required_onnx_cmake);

  snprintf(path, sizeof(path), "%s/scripts/windows_release_lifecycle_smoke.ps1", root);
  char *lifecycle_smoke = read_file(path);
  require_true(lifecycle_smoke != NULL, "read Windows release lifecycle smoke test");
  contains(lifecycle_smoke, "-UpgradeClass binary_hot", "binary-only lifecycle smoke explicitly selects the no-package update path");
  contains(lifecycle_smoke, "ValidateSet(\"amd64\", \"arm64\")",
           "lifecycle smoke requires an explicit native architecture");
  contains(lifecycle_smoke, "$expectedUpdateArchitecture",
           "lifecycle smoke passes the correct architecture to the updater");
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
  contains(lifecycle_smoke, "$targetLifecycleWorker = Find-OneFile -Root $TargetPackageDir",
           "lifecycle selects the current detached lifecycle worker");
  contains(lifecycle_smoke, "--stage\", \"lifecycle-uninstall\"",
           "lifecycle smoke exercises the same worker stage used by remote uninstall");
  contains(lifecycle_smoke, "lifecycle uninstall journal reported failure",
           "lifecycle smoke requires the detached worker terminal journal");
  contains(lifecycle_smoke, "agent-lifecycle-$lifecycleCommandId.worker.log",
           "lifecycle smoke preserves task-bound worker diagnostics outside program files");
  contains(lifecycle_smoke, "uninstall-script-$lifecycleTaskId.json",
           "lifecycle smoke reads the exact task-specific synchronous uninstall receipt");
  contains(lifecycle_smoke, "uninstall-cleanup-$lifecycleTaskId.json",
           "lifecycle smoke reads the exact task-specific deferred cleanup receipt");
  contains(lifecycle_smoke, "deferred uninstall cleanup did not write its receipt",
           "lifecycle smoke verifies the asynchronous program-file cleanup result");
  contains(lifecycle_smoke, "uninstall-attestation-callback.json",
           "lifecycle smoke captures the detached cleanup attestation callback");
  contains(lifecycle_smoke, "[IO.Path]::GetFullPath($EvidenceDir)",
           "background attestation jobs receive absolute evidence paths");
  contains(lifecycle_smoke, "function Wait-AttestationListenerReady",
           "lifecycle smoke verifies the callback listener before uninstall starts");
  contains(lifecycle_smoke, "authorization_valid = $authorizationValid",
           "lifecycle callback validates the exact one-time bearer token");
  contains(lifecycle_smoke, "while (-not $accepted)",
           "callback listener survives unrelated or invalid requests until valid teardown proof arrives");
  contains(lifecycle_smoke, "uninstall-attestation-attempts.json",
           "callback listener persists sanitized diagnostics for every observed request");
  contains(lifecycle_smoke, "function Normalize-AttestationToken",
           "callback listener normalizes quoting introduced by Windows command-line handoffs");
  contains(lifecycle_smoke, "X-EDR-Uninstall-Token",
           "loopback lifecycle callback has an HTTP.sys-independent proof-of-token header");
  contains(lifecycle_smoke, "expected_token_sha256",
           "callback diagnostics compare token identities without disclosing token plaintext");
  contains(lifecycle_smoke, "Get-UninstallAttestationProof",
           "lifecycle callback binds a header-independent HMAC proof to the task and endpoint");
  contains(lifecycle_smoke, "body_token_proof_valid",
           "lifecycle callback reports whether the HMAC body proof matched");
  contains(lifecycle_smoke, "token_valid = $tokenValid",
           "lifecycle callback distinguishes overall token proof from the Authorization transport");
  contains(lifecycle_smoke, "[Guid]::NewGuid().ToString(\"N\")",
           "lifecycle uses a fresh one-time attestation token for each run");
  contains(lifecycle_smoke, "attestation_error=$($cleanupResult.attestation_error)",
           "lifecycle failure output reports the exact attestation error");
  contains(lifecycle_smoke, "[int]$Seconds = 120",
           "cleanup receipt wait covers the bounded attestation retry window");
  contains(lifecycle_smoke, "edr.endpoint.uninstall.attestation.v1",
           "lifecycle smoke verifies the positive local teardown proof schema");
  contains(lifecycle_smoke, "Copy-Item -LiteralPath $targetUninstallScript",
           "lifecycle never mixes the current native uninstaller with a baseline uninstall script");
  contains(lifecycle_smoke, "target package uninstall script hash mismatch",
           "lifecycle binds the packaged uninstall protocol to the checked-out release source");
  contains(lifecycle_smoke, "native-package-integrity.json",
           "lifecycle binds native uninstall components to the packaged SHA-256 manifest");
  contains(lifecycle_smoke, "invoke_windows_native_capability_probe.ps1",
           "lifecycle waits for GUI subsystem capability probes before reading evidence");
  contains(lifecycle_smoke, "attestation_token_length",
           "lifecycle failure output identifies token loss without disclosing token plaintext");
  require_true(!strstr(lifecycle_smoke, "headless uninstall failed with exit code $LASTEXITCODE"),
               "lifecycle does not treat a stale native exit code as the result of a PowerShell installer script");
  contains(lifecycle_smoke, "failed_stage = $stage",
           "lifecycle persists the exact failed stage for actionable CI diagnostics");
  contains(lifecycle_smoke, "function Wait-ServiceDeleted",
           "lifecycle waits for asynchronous Windows service deletion");
  contains(lifecycle_smoke, "exit 0",
           "lifecycle explicitly clears stale native-command status after successful assertions");
  contains(lifecycle_smoke, "validate_windows_powershell_syntax.ps1",
           "lifecycle validates release script grammar before mutating Windows services");
  free(lifecycle_smoke);

  snprintf(path, sizeof(path), "%s/scripts/invoke_windows_native_capability_probe.ps1", root);
  char *capability_probe_runner = read_file(path);
  require_true(capability_probe_runner != NULL, "read native capability probe runner");
  contains(capability_probe_runner, "Start-Process", "native capability runner starts GUI executables explicitly");
  contains(capability_probe_runner, "--capability-probe", "native capability runner invokes the required protocol probe");
  contains(capability_probe_runner, "-Wait", "native capability runner waits for GUI executables to exit");
  contains(capability_probe_runner, "could not remove stale result", "native capability runner cannot accept stale evidence");
  contains(capability_probe_runner, "Test-Path", "native capability runner requires a newly generated result file");
  contains(capability_probe_runner, "ConvertFrom-Json", "native capability runner rejects malformed probe output");
  free(capability_probe_runner);

  snprintf(path, sizeof(path), "%s/scripts/validate_windows_powershell_syntax.ps1", root);
  char *powershell_validator = read_file(path);
  require_true(powershell_validator != NULL, "read Windows PowerShell syntax validator");
  contains(powershell_validator, "Management.Automation.Language.Parser]::ParseFile",
           "release validation uses the Windows PowerShell parser");
  contains(powershell_validator, "invoke_windows_native_capability_probe.ps1",
           "release validation parses the shared native capability runner on Windows PowerShell 5.1");
  contains(powershell_validator, "write_windows_package_capabilities.ps1",
           "release validation parses the shared package capability writer on Windows PowerShell 5.1");
  contains(powershell_validator, "Build-BundledInstaller.ps1",
           "release validation parses the complete Setup UI build entrypoint on Windows PowerShell 5.1");
  contains(powershell_validator, "Non-ASCII Windows PowerShell 5.1 script must be UTF-8 with BOM",
           "release validation rejects ambiguous ANSI decoding of non-ASCII runtime scripts");
  free(powershell_validator);

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
  contains(uninstaller, "-AttestationToken",
           "native uninstall forwards the task-pinned one-time attestation secret");
  contains(uninstaller, "uninstall-powershell-last.log",
           "native uninstall preserves PowerShell output outside the removed program directory");
  contains(uninstaller, "uninstall-powershell-%ls.log",
           "remote uninstall preserves task-bound PowerShell diagnostics across reinstall attempts");
  contains(uninstaller, "详细诊断日志",
           "native uninstall dialog exposes the captured PowerShell diagnostic path");
  free(uninstaller);

  snprintf(path, sizeof(path), "%s/scripts/edr_agent_uninstall.ps1", root);
  char *uninstall_script = read_file(path);
  require_true(uninstall_script != NULL, "read Windows uninstall script");
  contains(uninstall_script, "function Wait-AgentServiceDeleted",
           "uninstall verifies that Windows services disappear");
  contains(uninstall_script, "function Disable-AgentServiceRecovery",
           "manual and remote uninstall disable SCM automatic service restart");
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
  contains(uninstall_script, "function Remove-RuntimePathWithRetry",
           "runtime data removal retries transient file locks before deferring");
  contains(uninstall_script, "Runtime data remains for verified deferred directory cleanup:",
           "complete uninstall routes persistent runtime locks to final directory proof");
  contains(uninstall_script, "deferred_runtime_paths = @($script:DeferredRuntimePaths)",
           "uninstall diagnostics identify files delegated to deferred cleanup");
  contains(uninstall_script, "deletion_last_error = `$deleteLastError",
           "deferred cleanup records the final directory deletion error");
  contains(uninstall_script, "remaining_entries = @(`$remainingEntries)",
           "deferred cleanup records paths that survive bounded deletion");
  contains(uninstall_script, "attestation_error = `$attestationError",
           "deferred cleanup records the final callback transport error");
  contains(uninstall_script, "[Net.WebRequest]::DefaultWebProxy = `$null",
           "loopback lifecycle attestation bypasses machine proxy settings under LocalSystem");
  contains(uninstall_script, "attestation_errors = @(`$attestationErrors)",
           "deferred cleanup retains every bounded callback failure");
  contains(uninstall_script, "attestation_proxy_mode = `$attestationProxyMode",
           "cleanup receipt identifies whether loopback direct transport was selected");
  contains(uninstall_script, "`$requestHeaders['X-EDR-Uninstall-Token']",
           "loopback callback sends a dedicated token header in addition to Authorization");
  contains(uninstall_script, "attestation_last_http_status = `$attestationLastHttpStatus",
           "cleanup receipt retains the terminal callback HTTP status");
  contains(uninstall_script, "`$attestationLastHttpStatus -in @(400, 401, 403)",
           "non-retryable callback authentication failures stop immediately");
  contains(uninstall_script, "failure_reasons = @(`$failureReasons)",
           "deferred cleanup emits machine-readable failure reasons");
  contains(uninstall_script, "status = if (`$overallSucceeded) { 'succeeded' } else { 'failed' }",
           "cleanup receipt status covers both local teardown and required attestation");
  contains(uninstall_script, "local_status = if (`$localSucceeded) { 'succeeded' } else { 'failed' }",
           "cleanup receipt distinguishes local teardown from overall completion");
  contains(uninstall_script, "Management.Automation.Language.Parser]::ParseInput($cleanup",
           "generated deferred cleanup code is parsed before detached launch");
  contains(uninstall_script, "uninstall-cleanup-last.stderr.log",
           "deferred PowerShell failures are persisted outside program files");
  contains(uninstall_script, "uninstall-cleanup-last.json",
           "deferred cleanup persists a result outside the removed program directory");
  contains(uninstall_script, "edr.endpoint.uninstall.attestation.v1",
           "deferred cleanup reports positive service, process and directory teardown proof");
  contains(uninstall_script, "`$bodyFields.token_proof_hmac_sha256 = `$tokenProof",
           "loopback cleanup proves one-time token possession in the attestation body");
  contains(uninstall_script, "Security.Cryptography.HMACSHA256",
           "deferred cleanup uses HMAC-SHA256 for the header-independent token proof");
  contains(uninstall_script, "tcp_loopback_http11",
           "loopback attestation uses a byte-exact HTTP transport under LocalSystem");
  contains(uninstall_script, "New-Object Net.Sockets.TcpClient",
           "loopback attestation bypasses WebRequest header and body rewriting");
  contains(uninstall_script, "Content-Length: `$(`$bodyBytes.Length)",
           "loopback attestation sends an explicit UTF-8 body length");
  contains(uninstall_script, "attestation_request_body_bytes = `$attestationRequestBodyBytes",
           "cleanup receipt records the outgoing attestation body size");
  contains(uninstall_script, "Invoke-RestMethod -Uri `$attestationURL",
           "deferred cleanup posts its one-time completion attestation");
  contains(uninstall_script, "Skipped unrelated $name process PID",
           "uninstall never kills an unrelated same-name process by image name alone");
  contains(uninstall_script, "uninstall-script-last.json",
           "uninstall persists a stage-specific synchronous failure receipt outside program files");
  contains(uninstall_script, "uninstall-script-$safeLifecycleTaskID.json",
           "uninstall preserves a task-specific synchronous receipt across later reinstall attempts");
  contains(uninstall_script, "uninstall-cleanup-$safeLifecycleTaskID.json",
           "deferred cleanup preserves a task-specific receipt across later reinstall attempts");
  contains(uninstall_script, "function Set-UninstallStage",
           "uninstall checkpoints every synchronous stage before executing it");
  contains(uninstall_script, "ETW cleanup exceeded 15 seconds and was terminated; continuing uninstall",
           "best-effort ETW cleanup cannot block verified service and directory removal");
  contains(uninstall_script, "Write-UninstallScriptReceipt -Status \"running\"",
           "uninstall persists a receipt before entering teardown stages");
  contains(uninstall_script, "exit 0",
           "handled native helper warnings cannot leak a stale process exit code");
  free(uninstall_script);

  snprintf(path, sizeof(path), "%s/src/installer_worker/installer_worker_win.c", root);
  char *installer_worker = read_file(path);
  require_true(installer_worker != NULL, "read Windows installer worker");
  contains(installer_worker, "WaitForSingleObject(process.hProcess, 300000)",
           "remote uninstall observes native uninstaller completion");
  contains(installer_worker, "lifecycle_uninstall_launched pid=%lu",
           "remote uninstall logs the launched native uninstaller PID");
  contains(installer_worker, "CREATE_BREAKAWAY_FROM_JOB",
           "native uninstaller must survive Agent service Job Object teardown");
  contains(installer_worker, "lifecycle_uninstall_service_recovery_disabled",
           "remote uninstall must disable SCM recovery before stopping the Agent service");
  contains(installer_worker, "lifecycle_uninstall_service_recovery_restored",
           "failed remote uninstall must restore SCM recovery before recovering the Agent service");
  contains(installer_worker, "lifecycle_uninstall_failure_service_restarted",
           "failed remote uninstall must recover endpoint availability after recording failure");
  contains(installer_worker, "TerminateProcess(process.hProcess, ERROR_TIMEOUT)",
           "timed-out native uninstall must stop before endpoint service recovery begins");
  contains(installer_worker, "lifecycle_uninstall_completed",
           "remote uninstall journals verified native completion");
  contains(installer_worker, "--service-name %ls",
           "lifecycle worker binds uninstall to the installed service name");
  contains(installer_worker, "--attestation-token %ls",
           "lifecycle worker passes the one-time attestation secret to the native uninstaller");
  free(installer_worker);

  snprintf(path, sizeof(path), "%s/src/command/agent_lifecycle_command.c", root);
  char *lifecycle_command = read_file(path);
  require_true(lifecycle_command != NULL, "read endpoint lifecycle command implementation");
  contains(lifecycle_command, "--install-dir \\\"%s\\\"",
           "remote lifecycle handoff pins the worker to its installed runtime directory");
  contains(lifecycle_command, "agent-lifecycle-%s.worker.log",
           "remote lifecycle diagnostics are task-bound and survive removal of the installation directory");
  contains(lifecycle_command, "CREATE_BREAKAWAY_FROM_JOB",
           "lifecycle worker must escape the Agent service Job Object before stopping it");
  contains(lifecycle_command, "safe_https_url",
           "remote uninstall accepts only HTTPS attestation destinations");
  contains(lifecycle_command, "--attestation-token \\\"",
           "remote lifecycle handoff passes the signed task attestation secret");
  free(lifecycle_command);

  snprintf(path, sizeof(path), "%s/src/core/agent.c", root);
  char *agent_core = read_file(path);
  require_true(agent_core != NULL, "read Agent capability manifest implementation");
  contains(agent_core, "endpoint_uninstall_attestation_v1",
           "fixed Agent advertises the two-phase uninstall attestation protocol separately from legacy lifecycle support");
  free(agent_core);

  puts("ok (pure source contract; Windows execution intentionally not simulated)");
  return 0;
}
