"""Keep Headless asset scope separate from the unchanged real lifecycle checks.

The package byte/ZIP contract is exercised by the checkpoint owner's tests. These
checks guard its workflow call sites and reject widening the network asset set.
"""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/windows-install-upgrade-rollback.yml'
RELEASE_WORKFLOW = ROOT / '.github/workflows/edr-agent-client-release.yml'
EARLY_PREFLIGHT_STEP = 'Verify lifecycle preflight before native build'
DOWNLOAD_STEP = 'Download immutable runtime and Setup EXE release packages'
SETUP_STEP = 'Execute real Setup EXE install, upgrade, rollback, and uninstall'


def step(text, name):
    match = re.search(r'^      - name: ' + re.escape(name) + r'\n(.*?)(?=^      - |\Z)',
                      text, re.M | re.S)
    if not match:
        raise AssertionError(f'missing workflow step: {name}')
    return match[1]


def download_branches(text):
    body = step(text, DOWNLOAD_STEP)
    common, branches = body.split("          if ($env:LIFECYCLE_PACKAGE_SCOPE -ceq 'full') {\n", 1)
    full, remainder = branches.split("          } elseif ($env:LIFECYCLE_PACKAGE_SCOPE -ceq 'headless') {\n", 1)
    headless, denied = remainder.rsplit('          } else {\n', 1)
    if "throw 'package_scope must be full or headless'" not in denied:
        raise AssertionError('unknown package scope must fail closed')
    return common, full, headless


class WindowsLifecycleWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding='utf-8')

    def assert_early_preflight(self, text):
        build = text.split('  windows-build:\n', 1)[1].split('\n  windows-', 1)[0]
        body = step(build, EARLY_PREFLIGHT_STEP)
        self.assertNotIn('if:', body)
        self.assertIn('timeout-minutes: 3', body)
        self.assertIn('shell: pwsh\n', body)
        self.assertEqual(re.findall(r'^          & (.+)$', body, re.M), [
            r'.\tests\test_windows_lifecycle_first_hop.ps1',
            r'.\tests\test_windows_immutable_download.ps1',
        ])
        # Run on the actual harness host before dependency/build work, including
        # same-run checkpoint resumes; standalone lifecycle keeps its own gates.
        self.assertLess(build.index('actions/checkout@'), build.index('- name: '+EARLY_PREFLIGHT_STEP))
        self.assertLess(build.index('- name: '+EARLY_PREFLIGHT_STEP),
                        build.index('- name: Restore pinned ARM64-host Python tool cache'))

    def test_release_checks_lifecycle_preflight_before_native_build(self):
        self.assert_early_preflight(RELEASE_WORKFLOW.read_text(encoding='utf-8'))

    def test_early_preflight_host_skip_and_late_execution_are_detected(self):
        text = RELEASE_WORKFLOW.read_text(encoding='utf-8')
        body = step(text, EARLY_PREFLIGHT_STEP)
        original = '      - name: '+EARLY_PREFLIGHT_STEP+'\n'+body
        mutations = [
            text.replace(original, original.replace('shell: pwsh', 'shell: powershell'), 1),
            text.replace(original, original.replace('        shell:', "        if: steps.resume.outputs.restored != 'true'\n        shell:"), 1),
            text.replace(original, original.replace('          & .\\tests\\test_windows_lifecycle_first_hop.ps1\n', ''), 1),
            text.replace(original, original.replace('          & .\\tests\\test_windows_immutable_download.ps1\n', ''), 1),
            text.replace(original, '', 1).replace('      - name: Verify hosted release workflow contract\n',
                                                original+'      - name: Verify hosted release workflow contract\n', 1),
        ]
        for mutated in mutations:
            with self.subTest(mutation=mutations.index(mutated)):
                self.assertNotEqual(mutated, text)
                with self.assertRaises(AssertionError):
                    self.assert_early_preflight(mutated)

    def assert_asset_scope(self, text):
        common, full, headless = download_branches(text)
        common_calls = re.findall(r'^          Download-ImmutableAsset (.+)$', common, re.M)
        self.assertEqual(common_calls, [
            '$env:TARGET_TAG $targetRuntime downloads\\target',
            '$env:BASELINE_TAG $baselineRuntime downloads\\baseline',
        ])
        self.assertIn('$targetRuntime = "edr-agent-$env:TARGET_TAG-windows-${{ matrix.arch }}-exe.zip"', common)
        self.assertIn('$baselineRuntime = "edr-agent-$env:BASELINE_TAG-windows-${{ matrix.arch }}-exe.zip"', common)
        self.assertEqual(len(re.findall(r'^            Download-ImmutableAsset ', full, re.M)), 3)
        self.assertIn('Download-ImmutableAsset $env:TARGET_TAG $targetSetup downloads\\target', full)
        self.assertIn('Download-ImmutableAsset $env:BASELINE_TAG $baselineSetup downloads\\baseline', full)
        self.assertIn('Download-ImmutableAsset $env:TARGET_TAG "edr-agent-$env:TARGET_TAG-windows-${{ matrix.arch }}-artifact-manifest.json" downloads\\target', full)
        self.assertEqual(re.findall(r'^            Download-ImmutableAsset (.+)$', headless, re.M), [
            '$env:TARGET_TAG "edr-agent-$env:TARGET_TAG-windows-${{ matrix.arch }}-artifact-manifest.json" downloads\\target',
            '$env:BASELINE_TAG "edr-agent-$env:BASELINE_TAG-windows-${{ matrix.arch }}-artifact-manifest.json" downloads\\baseline',
        ])
        for forbidden in ('-setup.exe', 'SetupUI', 'setup-ui', 'Expand-Archive',
                          'Invoke-WebRequest', 'gh api', 'SkipSetupRollback'):
            self.assertNotIn(forbidden, headless)
        self.assertNotIn('Expand-Archive', common)
        self.assertEqual(full.count('Expand-Archive'), 2)

    def test_scope_defaults_and_early_rejection(self):
        call, dispatch = self.text.split('  workflow_dispatch:\n', 1)
        self.assertIn('      package_scope:\n', call)
        self.assertIn('        default: full\n        type: string', call)
        scope = dispatch.split('      package_scope:\n', 1)[1].split('      architecture:\n', 1)[0]
        self.assertIn('default: full', scope)
        self.assertEqual(re.findall(r'^          - (\w+)$', scope, re.M), ['full', 'headless'])
        validation = step(self.text, 'Validate lifecycle inputs')
        self.assertIn("$env:LIFECYCLE_PACKAGE_SCOPE -cnotin @('full', 'headless')", validation)
        for later in ('Verify lifecycle package scope contract', 'Resolve release tags', DOWNLOAD_STEP):
            self.assertLess(self.text.index('- name: Validate lifecycle inputs'),
                            self.text.index('- name: ' + later))
        self.assertLess(self.text.index('- name: Verify lifecycle package scope contract'),
                        self.text.index('- name: Resolve release tags'))
        self.assertIn('run: python tests/test_windows_lifecycle_workflow.py', self.text)

    def test_headless_downloads_only_the_two_required_assets_per_release(self):
        self.assert_asset_scope(self.text)

    def test_widening_asset_scope_is_detected(self):
        mutations = [
            ("if ($env:LIFECYCLE_PACKAGE_SCOPE -ceq 'full')", "if ($env:LIFECYCLE_PACKAGE_SCOPE -ceq 'headless')"),
            ('            Download-ImmutableAsset $env:TARGET_TAG $targetSetup downloads\\target\n',
             '            Download-ImmutableAsset $env:TARGET_TAG $targetSetup downloads\\target\n'
             '            Download-ImmutableAsset $env:TARGET_TAG "SetupUI.exe" downloads\\target\n'),
            ('            # Only ZIP + artifact manifest',
             '            Download-ImmutableAsset $env:TARGET_TAG $targetSetup downloads\\target\n'
             '            # Only ZIP + artifact manifest'),
            ('            # Only ZIP + artifact manifest',
             '            Expand-Archive unchecked.zip packages\\target\n'
             '            # Only ZIP + artifact manifest'),
        ]
        for old, new in mutations:
            with self.subTest(mutation=new):
                self.assertIn(old, self.text)
                with self.assertRaises((AssertionError, ValueError)):
                    self.assert_asset_scope(self.text.replace(old, new, 1))

    def test_baseline_uses_the_shared_scope_and_requires_actual_rollback(self):
        resolution = step(self.text, 'Resolve release tags')
        self.assertIn("@('select-baseline', '--target-tag', $target, '--package-scope', $env:LIFECYCLE_PACKAGE_SCOPE)", resolution)
        self.assertIn("@('--baseline-tag', $requestedBaseline)", resolution)
        self.assertIn("if ($env:LIFECYCLE_PACKAGE_SCOPE -ceq 'headless' -and -not $baselineSetupRollbackSupported)", resolution)
        self.assertIn("throw 'Headless lifecycle requires a published baseline with real installer rollback support'", resolution)
        self.assertNotIn('${{ inputs.target_tag }}', resolution.split('run: |', 1)[1])
        self.assertNotIn('${{ inputs.baseline_tag }}', resolution.split('run: |', 1)[1])

    def test_target_and_baseline_stage_use_their_own_verified_provenance(self):
        _, _, body = download_branches(self.text)
        self.assertEqual(body.count('windows_release_checkpoint.py stage-headless'), 2)
        target, baseline = body.split('$targetStageJson = ', 1)[1].split('$baselineStageJson = ', 1)
        for required in ("--tag $env:TARGET_TAG --arch '${{ matrix.arch }}'",
                         '--directory downloads\\target --destination packages\\target',
                         '--release-metadata release-metadata\\target.json --tag-commit $targetCommit',
                         '--expected-source-commit $env:GITHUB_SHA --expected-run-id $env:GITHUB_RUN_ID'):
            self.assertIn(required, target)
        self.assertNotIn('--published-baseline', target)
        for required in ("--tag $env:BASELINE_TAG --arch '${{ matrix.arch }}'",
                         '--directory downloads\\baseline --destination packages\\baseline',
                         '--release-metadata release-metadata\\baseline.json --tag-commit $baselineCommit',
                         '--published-baseline --target-tag $env:TARGET_TAG'):
            self.assertIn(required, baseline)
        self.assertNotIn('--expected-source-commit', baseline)
        self.assertEqual(body.count("if ($LASTEXITCODE -ne 0) { throw '"), 2)
        for name in ('target', 'baseline'):
            self.assertIn(f"'release-metadata/{name}.json'", body)
            self.assertIn(f'"{name.upper()}_SETUP_EXE=$(${name}Stage.setup_exe)"', body)
        self.assertNotIn('Set-Content -LiteralPath downloads', body)

    def test_tag_resolution_never_treats_network_failure_as_absence(self):
        _, _, body = download_branches(self.text)
        self.assertIn('git -c http.lowSpeedLimit=1 -c http.lowSpeedTime=30 ls-remote --exit-code origin "refs/tags/$Tag" "refs/tags/$Tag^{}"', body)
        self.assertIn('$status -eq 2 -and $Release.draft -eq $true', body)
        self.assertIn('"$($Release.target_commitish)" -cmatch \'^[0-9a-f]{40}$\'', body)
        self.assertIn('if ($status -ne 0) { throw', body)
        self.assertIn('$direct.Count -ne 1 -or $peeled.Count -gt 1', body)
        self.assertIn('if ($peeled.Count -eq 1) { return $peeled[0] }', body)

    def test_same_download_owner_keeps_integrity_and_failure_regressions(self):
        common, _, _ = download_branches(self.text)
        self.assertIn('$script:immutableReleases[$Tag] = $release', common)
        self.assertIn('$release = Get-ImmutableRelease $Tag', common)
        self.assertIn('$attempt -le 4', common)
        self.assertIn('-ConnectionTimeoutSeconds 30 -OperationTimeoutSeconds 60 -ErrorAction Stop', common)
        self.assertIn("$retryable = $statusCode -in @(408, 429, 500, 502, 503, 504)", common)
        self.assertLess(common.index("SHA-256 mismatch"), common.index('Move-Item -LiteralPath $partialPath'))
        self.assertLess(self.text.index('- name: Verify immutable asset download failure handling'),
                        self.text.index('- name: ' + DOWNLOAD_STEP))
        self.assertIn('run: ./tests/test_windows_immutable_download.ps1', self.text)

    def test_embedded_installers_feed_the_original_real_setup_lifecycle(self):
        setup = step(self.text, SETUP_STEP)
        headless = setup.split("if ($env:LIFECYCLE_PACKAGE_SCOPE -ceq 'headless') {", 1)[1].split('          } else {', 1)[0]
        self.assertIn('$targetSetupPath = $env:TARGET_SETUP_EXE', headless)
        self.assertIn('$baselineSetupPath = $env:BASELINE_SETUP_EXE', headless)
        self.assertIn('BaselineSetupExe = $baselineSetupPath', setup)
        self.assertIn('TargetSetupExe = $targetSetupPath', setup)
        self.assertIn('& .\\scripts\\windows_setup_exe_lifecycle_smoke.ps1 @lifecycleParams', setup)
        # This is the existing compatibility branch; Headless rejects it before downloads.
        self.assertIn("if ($env:BASELINE_SETUP_ROLLBACK_SUPPORTED -ne 'true')", setup)
        self.assertNotIn('continue', setup)
        self.assertNotIn('exit 0', setup)

    def test_original_native_update_rounds_and_evidence_remain_required(self):
        runtime = step(self.text, 'Execute native runtime update lifecycle')
        self.assertNotIn('if:', runtime)
        for required in ('$round -le $repeatCount', '.\\scripts\\windows_release_lifecycle_smoke.ps1',
                         '-BaselinePackageDir packages\\baseline', '-TargetPackageDir packages\\target',
                         '-BaselineVersion $env:BASELINE_VERSION', '-TargetVersion $env:TARGET_VERSION'):
            self.assertIn(required, runtime)
        upload = step(self.text, 'Upload Windows lifecycle evidence')
        self.assertIn('if: always()', upload)
        for required in ('setup-exe-evidence', 'runtime-evidence', 'release-metadata', 'retention-days: 7'):
            self.assertIn(required, upload)

    def test_old_updater_inputs_are_required_before_the_real_setup_lifecycle(self):
        name = 'Bind old updater transition to the target release manifest'
        binding = step(self.text, name)
        self.assertNotIn('if:', binding)
        for required in ('windows_release_checkpoint.py prepare-lifecycle-upgrade',
                         '--directory downloads\\target --baseline-directory downloads\\baseline',
                         '--tag $env:TARGET_TAG --baseline-tag $env:BASELINE_TAG',
                         '--destination release-metadata\\lifecycle-upgrade',
                         "if ($LASTEXITCODE -ne 0) { throw"):
            self.assertIn(required, binding)
        self.assertLess(self.text.index('- name: '+DOWNLOAD_STEP),self.text.index('- name: '+name))
        self.assertLess(self.text.index('- name: '+name),self.text.index('- name: '+SETUP_STEP))
        self.assertIn("UpgradeInput = 'release-metadata\\lifecycle-upgrade\\transition.json'",step(self.text,SETUP_STEP))
        regression = step(self.text,'Verify old updater lifecycle orchestration')
        self.assertNotIn('if:',regression)
        self.assertIn('run: ./tests/test_windows_lifecycle_first_hop.ps1',regression)
        self.assertLess(self.text.index('- name: Verify old updater lifecycle orchestration'),self.text.index('- name: '+DOWNLOAD_STEP))

    def test_old_agent_receives_offline_configuration_before_setup_starts_it(self):
        setup = step(self.text, SETUP_STEP)
        self.assertIn("BaselineConfigTemplate = 'packages\\baseline\\agent_windows_production.example.toml'", setup)
        owner = (ROOT / 'scripts/windows_setup_exe_lifecycle_smoke.ps1').read_text(encoding='utf-8')
        preparation = owner.index('  $offlineConfigHash = Initialize-LifecycleOfflineConfig $BaselineConfigTemplate')
        baseline = owner.index("  Invoke-Installer $BaselineSetupExe 'install-old-updater-baseline'")
        preservation = owner.index("    throw 'baseline Setup changed the prepared offline lifecycle configuration'")
        invocation = owner.index('  Invoke-BaselineUpdaterUpgrade $upgradeBinding')
        self.assertLess(owner.index('  Invoke-UninstallerAndAssertCleanup "uninstall-target-fresh"'), preparation)
        self.assertLess(preparation, baseline)
        self.assertLess(baseline, preservation)
        self.assertLess(preservation, invocation)
        self.assertIn('$clock.Elapsed.TotalSeconds -lt 60', owner)
        self.assertIn('Wait-LifecycleEmbeddedUpdater $BaselineVersion $InputBinding.baseline_updater_sha256', owner)

    def test_real_installer_fault_is_opt_in_and_uses_installed_candidate_after_first_hop(self):
        call, dispatch = self.text.split('  workflow_dispatch:\n', 1)
        for inputs in (call, dispatch):
            option = re.split(r'\n {6}\S', inputs.split('      installer_timeout_recovery:\n', 1)[1], 1)[0]
            self.assertIn('default: false', option)
            self.assertIn('type: boolean', option)
        invocation = step(self.text, SETUP_STEP)
        self.assertIn('LIFECYCLE_INSTALLER_TIMEOUT: ${{ inputs.installer_timeout_recovery }}', invocation)
        self.assertIn("ExerciseInstallerTimeout = $env:LIFECYCLE_INSTALLER_TIMEOUT -ceq 'true'", invocation)
        owner = (ROOT / 'scripts/windows_setup_exe_lifecycle_smoke.ps1').read_text(encoding='utf-8')
        self.assertLess(owner.index('  Invoke-BaselineUpdaterUpgrade $upgradeBinding'),
                        owner.index("  if ($ExerciseInstallerTimeout) {"))
        self.assertIn('Wait-LifecycleEmbeddedUpdater $TargetVersion $upgradeBinding.target_updater_sha256', owner)
        self.assertIn('Get-LifecycleTrustedPublisher $upgradeBinding', owner)
        self.assertLess(owner.index("tests\\Invoke-RealInstallerTimeoutRecovery.ps1"),
                        owner.index("Invoke-UninstallerAndAssertCleanup 'uninstall-old-updater-target'"))
        fixture = (ROOT / 'tests/Invoke-RealInstallerTimeoutRecovery.ps1').read_text(encoding='utf-8')
        for required in ("$env:GITHUB_ACTIONS -cne 'true'", "Operation='repair'", "DeadlineUnixMs=$issued+120000",
                         '$InputBinding.target_updater_sha256', '$InputBinding.installer_sha256',
                         'IsProcessInJob', 'GetProcessTimes', 'QueryFullProcessImageNameW', 'NtSuspendProcess',
                         '[LifecycleInstallerFault]::Exited($oldRuntime)', 'original_process_handle_signaled=$true',
                         '$actualChildren.Count -lt 1', '$stopped = $true', '$delegatedRunning = $true',
                         "$report.error_code -cne 'INSTALL_TIMEOUT'", "$report.status -cne 'failed_rolled_back'",
                         "$report.rollback -cne 'succeeded'", '$journal.installer_quiesced -ne $true',
                         'Assert-RecoveryFiles $files', '$beforeOwner -cne $afterOwner'):
            self.assertIn(required, fixture)
        for forbidden in ('Invoke-Expression', 'Set-Content -LiteralPath $Updater', 'Stop-Service',
                          'Invoke-Uninstaller', 'Invoke-FullInstallerRuntimeMirror'):
            self.assertNotIn(forbidden, fixture)

    def test_native_runner_identity_and_manifest_hashes_are_retained(self):
        identity = step(self.text, 'Record native runner identity')
        for required in ('RuntimeInformation]::OSArchitecture', '$native -cne $expected',
                         'source_commit=$env:GITHUB_SHA', 'run_id=$env:GITHUB_RUN_ID',
                         'harness_powershell=', 'updater_powershell=', "'^5\\.1\\.'"):
            self.assertIn(required, identity)
        self.assertIn('runner-evidence', step(self.text, 'Upload Windows lifecycle evidence'))


if __name__ == '__main__':
    unittest.main()
