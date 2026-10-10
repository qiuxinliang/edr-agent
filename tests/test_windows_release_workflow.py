"""Guard the restored job graph and retained release integrity boundaries."""
from pathlib import Path
import json
import re
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/edr-agent-client-release.yml'


class WindowsReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding='utf-8')
        self.jobs = dict(re.findall(r'^  ([\w-]+):\n(.*?)(?=^  [\w-]+:\n|\Z)',
                                   self.text.split('\njobs:\n', 1)[1], re.M | re.S))

    def test_single_usb_handoff_keeps_public_jobs_hosted(self):
        self.assertEqual(set(self.jobs), {'prepare-release', 'windows-build', 'usb-finalize', 'windows-lifecycle', 'publish-release'})
        for removed in ('usb-native', 'usb-installer', 'usb-manifest', 'self-hosted', 'build_purpose', 'unsigned-candidate-'):
            self.assertNotIn(removed, self.text)
        self.assertFalse(list((ROOT / '.github/workflows').glob('windows-usb-*.yml')))

    def test_usb_is_opt_in_and_unsigned_default_is_unchanged(self):
        modes = self.text.split('      release_mode:', 1)[1].split('      candidate:', 1)[0]
        self.assertEqual(re.findall(r'^          - (\w+)$', modes, re.M), ['unsigned', 'signed', 'usb'])
        self.assertIn('default: unsigned', modes)
        self.assertIn("vars.WINDOWS_RELEASE_MODE || 'unsigned'", self.text)
        self.assertIn('(UNSIGNED Windows AMD64 + ARM64)', self.jobs['publish-release'])

    def test_publication_still_requires_build_and_lifecycle_success(self):
        self.assertIn('needs: prepare-release', self.jobs['windows-build'])
        self.assertIn('needs: [prepare-release, usb-finalize]', self.jobs['windows-lifecycle'])
        publish = self.jobs['publish-release']
        needs = publish.split('    needs:\n', 1)[1].split('    runs-on:', 1)[0]
        self.assertEqual(re.findall(r'^      - ([\w-]+)$', needs, re.M), ['windows-build', 'windows-lifecycle', 'usb-finalize'])
        # No always() or job-level condition can bypass implicit successful needs.
        self.assertNotRegex(publish, r'(?m)^    if:')
        self.assertIn('windows-install-upgrade-rollback.yml', self.jobs['windows-lifecycle'])
        self.assertIn('windows_release_checkpoint.py prepare', self.jobs['prepare-release'])
        self.assertIn("needs.prepare-release.outputs.published != 'true'", self.jobs['windows-build'])

    def test_version_lock_and_checkpoint_gate(self):
        lock = self.text.split('\nconcurrency:\n', 1)[1].split('\nenv:', 1)[0]
        self.assertIn("format('win_{0}', inputs.version) || github.ref_name", lock)
        self.assertIn('cancel-in-progress: false', lock)
        build = self.jobs['windows-build']
        self.assertLess(build.index('name: Test\n'), build.index('name: Seal verified package checkpoint'))
        self.assertLess(build.index('name: Prepare release assets'), build.index('name: Seal verified package checkpoint'))
        self.assertLess(build.index('name: Retain verified package'), build.index('name: Upload ${{ matrix.arch }}'))
        for name in ('Build (Ninja)', 'Test', 'Package (setup exe + runtime zip)',
                     'Prepare release assets', 'Seal verified package checkpoint'):
            step = build.split(f'- name: {name}\n', 1)[1].split('\n      - ', 1)[0]
            self.assertIn("if: steps.resume.outputs.restored != 'true'", step)
        self.assertIn("'restore-input' } else { 'restore' }", build)
        self.assertIn('windows_release_checkpoint.py $command --arch', build)
        self.assertIn("if: env.WINDOWS_RELEASE_MODE != 'usb'", build)
        self.assertIn('windows_release_checkpoint.py upload --arch', build)
        self.assertNotIn('gh release upload', build)
        self.assertNotIn('--notes-file', self.jobs['publish-release'])

    def test_checkpoint_cleanup_follows_publication_with_scoped_permissions(self):
        publish = self.jobs['publish-release']
        cleanup = publish.index('windows_release_checkpoint.py cleanup-published')
        for step in ('Publish signed Windows release', 'Publish unsigned Windows release',
                     'Publish candidate without promoting latest'):
            self.assertLess(publish.index(step), cleanup)
        self.assertIn('      actions: write', publish)
        self.assertIn('  actions: read', self.text.split('\njobs:\n', 1)[0])
        checkpoint = self.jobs['windows-build'].split('- name: Retain verified package', 1)[1].split('\n      - ', 1)[0]
        self.assertIn('retention-days: 1', checkpoint)
        final = self.jobs['usb-finalize'].split('- name: Retain final signed bundle', 1)[1].split('\n      - ', 1)[0]
        self.assertIn('retention-days: 1', final)
        lifecycle = (ROOT / '.github/workflows/windows-install-upgrade-rollback.yml').read_text(encoding='utf-8')
        evidence = lifecycle.split('- name: Upload Windows lifecycle evidence', 1)[1]
        self.assertIn('retention-days: 7', evidence)

    def test_source_packaging_contract_runs_before_native_build(self):
        prepare = self.jobs['prepare-release']
        self.assertIn('python3 tests/test_windows_release_workflow.py', prepare)
        self.assertIn('cc -std=c11 -Wall -Wextra -Werror tests/test_agent_update_assets.c', prepare)
        self.assertIn('EDR_SOURCE_DIR="$GITHUB_WORKSPACE" "$RUNNER_TEMP/test_agent_update_assets"', prepare)
        self.assertLess(prepare.index('tests/test_agent_update_assets.c'),
                        prepare.index('windows_release_checkpoint.py prepare'))
        self.assertIn("--label-regex '^windows-release-gate$'", self.jobs['windows-build'])

    def assert_canonical_p0_test_inputs(self, build):
        def step(name):
            return build.split(f'- name: {name}\n', 1)[1].split('\n      - ', 1)[0]

        validation = step('Validate canonical P0 test input configuration')
        checkout = step('Checkout canonical P0 test inputs')
        binding = step('Bind canonical P0 test input directory')
        self.assertIn('P0_TEST_INPUTS_REF: ${{ vars.P0_TEST_INPUTS_REF }}', validation)
        self.assertIn("-cnotmatch '^[0-9a-f]{40}$'", validation)
        self.assertIn('IsNullOrWhiteSpace($env:P0_TEST_INPUTS_SSH_KEY)', validation)
        self.assertNotIn('Write-Host $env:P0_TEST_INPUTS_SSH_KEY', validation)
        self.assertIn('repository: qiuxinliang/EDRAI', checkout)
        self.assertIn('ref: ${{ vars.P0_TEST_INPUTS_REF }}', checkout)
        self.assertIn('ssh-key: ${{ secrets.P0_TEST_INPUTS_SSH_KEY }}', checkout)
        self.assertIn('persist-credentials: false', checkout)
        self.assertIn('path: canonical-p0-test-inputs', checkout)
        self.assertIn("Join-Path $env:GITHUB_WORKSPACE 'canonical-p0-test-inputs'", binding)
        self.assertIn('git -C $inputs rev-parse HEAD', binding)
        self.assertIn('$actualRef -cne $env:P0_TEST_INPUTS_REF', binding)
        for name in ('p0_rule_bundle_ir_v1.json', 'p0_rule_bundle_ir_v1.json.enc',
                     'sensor_interest_manifest.json'):
            self.assertIn(f"'{name}'", binding)
        self.assertIn('-PathType Leaf', binding)
        self.assertIn('"EDR_BACKEND_CONFIG_DIR=$inputs"', binding)
        self.assertIn('-FilePath $env:GITHUB_ENV -Append -Encoding utf8', binding)
        self.assertLess(build.index('name: Validate canonical P0'), build.index('name: Checkout canonical P0'))
        self.assertLess(build.index('name: Checkout canonical P0'), build.index('name: Bind canonical P0'))
        self.assertLess(build.index('name: Bind canonical P0'), build.index('name: Configure'))
        self.assertIn('"-DEDR_P0_TEST_CONFIG_DIR=$env:EDR_BACKEND_CONFIG_DIR"', build)
        # Private source inputs must never become a downloadable build artifact.
        for artifact in re.split(r'^      - ', build, flags=re.M):
            if 'uses: actions/upload-artifact@' not in artifact:
                continue
            paths = re.search(r'^          path:(.*?)(?=^          \S|\Z)',
                              artifact, re.M | re.S)[1]
            self.assertNotIn('canonical-p0-test-inputs', paths)
            self.assertNotRegex(paths, r'(?m)^\s*(?:\.|\$\{\{ github.workspace \}\})(?:/\*\*)?\s*$')

    def test_all_windows_build_owners_bind_private_immutable_test_inputs(self):
        for filename, job_name in (('edr-agent-ci.yml', 'build-windows'),
                                   ('edr-agent-client-build.yml', 'windows-build'),
                                   ('edr-agent-client-release.yml', 'windows-build')):
            with self.subTest(workflow=filename):
                text = (ROOT / '.github/workflows' / filename).read_text(encoding='utf-8')
                jobs = dict(re.findall(r'^  ([\w-]+):\n(.*?)(?=^  [\w-]+:\n|\Z)',
                                       text.split('\njobs:\n', 1)[1], re.M | re.S))
                self.assert_canonical_p0_test_inputs(jobs[job_name])
        for name in ('Validate canonical P0 test input configuration',
                     'Checkout canonical P0 test inputs', 'Bind canonical P0 test input directory'):
            step = self.jobs['windows-build'].split(f'- name: {name}\n', 1)[1].split('\n      - ', 1)[0]
            self.assertIn("if: steps.resume.outputs.restored != 'true'", step)

    def test_canonical_input_contract_rejects_mutable_refs_and_product_staging(self):
        build = self.jobs['windows-build']
        changes = {
            'mutable ref': ('ref: ${{ vars.P0_TEST_INPUTS_REF }}', 'ref: main'),
            'missing immutable check': ("-cnotmatch '^[0-9a-f]{40}$'", '-eq $null'),
            'persisted private credential': ('persist-credentials: false', 'persist-credentials: true'),
            'private inputs in product': ('path: canonical-p0-test-inputs', 'path: dist'),
            'private inputs artifact': ('path: dist/', 'path: canonical-p0-test-inputs/'),
            'unverified checkout': ('$actualRef -cne $env:P0_TEST_INPUTS_REF', '$false'),
        }
        for name, (before, after) in changes.items():
            with self.subTest(case=name), self.assertRaises(AssertionError):
                self.assert_canonical_p0_test_inputs(build.replace(before, after, 1))

    def test_windows_gates_use_pinned_openssl_before_any_ctest(self):
        manifest = json.loads((ROOT / 'vcpkg.json').read_text(encoding='utf-8'))
        openssl = [dependency for dependency in manifest['dependencies']
                   if isinstance(dependency, dict) and dependency['name'] == 'openssl']
        self.assertEqual(len(openssl), 1)
        self.assertIn('tools', openssl[0]['features'])
        for filename in ('edr-agent-ci.yml', 'edr-agent-client-build.yml', 'edr-agent-client-release.yml'):
            with self.subTest(workflow=filename):
                source = (ROOT / '.github/workflows' / filename).read_text(encoding='utf-8')
                test = source.split('- name: Test\n', 1)[1].split('\n      - ', 1)[0]
                if filename == 'edr-agent-client-release.yml':
                    self.assertIn("Join-Path $env:VCPKG_INSTALLED_ROOT 'tools\\openssl'", test)
                else:
                    self.assertIn("Join-Path $env:GITHUB_WORKSPACE 'vcpkg_installed\\x64-windows\\tools\\openssl'", test)
                self.assertIn("-LiteralPath (Join-Path $opensslTools 'openssl.exe') -PathType Leaf", test)
                self.assertIn('$env:PATH = "$opensslTools;$env:PATH"', test)
                self.assertLess(test.index("'openssl.exe'"), test.index('& ctest '))
                self.assertLess(test.index('$env:PATH ='), test.index('& ctest '))

    def assert_native_telemetry_release_gate(self, build):
        step = build.split('- name: Test\n', 1)[1].split('\n      - ', 1)[0]
        self.assertNotIn('continue-on-error:', step)
        self.assertIn("if: steps.resume.outputs.restored != 'true'", step)
        call = '& .\\tests\\run_telemetry_windows_native.ps1 @telemetryArgs'
        self.assertIn(call, step)
        self.assertLess(step.index("--label-regex '^windows-release-gate$'"), step.index(call))
        # PowerShell arrays splat positional values, including strings that
        # look like parameter names. A script's named parameters require a
        # hashtable; the old array bound Configuration='build' on native CI.
        self.assertIn("$telemetryArgs = @{ BuildDir = 'build'; Configuration = 'Release' }", step)
        self.assertNotRegex(step, r'\$telemetryArgs\s*(?:=|\+=)\s*@\(')
        self.assertIn("Join-Path $env:VCPKG_INSTALLED_ROOT 'tools\\openssl'", step)
        self.assertIn('$telemetryArgs.OpenSslBin = $opensslTools', step)
        self.assertRegex(step.split(call, 1)[1],
                         r'if\s*\(\$LASTEXITCODE -ne 0\)\s*\{\s*throw\b')
        self.assertLess(build.index(call), build.index('name: Package (setup exe + runtime zip)'))
        self.assertLess(build.index(call), build.index('name: Seal verified package checkpoint'))
        for name in ('Package (setup exe + runtime zip)', 'Seal verified package checkpoint'):
            later = build.split(f'- name: {name}\n', 1)[1].split('\n      - ', 1)[0]
            self.assertNotIn('continue-on-error:', later)
            self.assertNotIn('always()', later)
            self.assertNotIn('failure()', later)

    def test_native_telemetry_failures_block_packaging_and_publication(self):
        self.assert_native_telemetry_release_gate(self.jobs['windows-build'])
        runner = (ROOT / 'tests/run_telemetry_windows_native.ps1').read_text(encoding='utf-8')
        self.assertIn("$ErrorActionPreference = 'Stop'", runner)
        self.assertIn('--target telemetry_minimization_tests', runner)
        command = "-L '^telemetry-minimization$'"
        self.assertIn(command, runner)
        self.assertRegex(runner.split(command, 1)[1],
                         r'if\s*\(\$LASTEXITCODE -ne 0\)\s*\{\s*throw\b')
        self.assertNotRegex(self.jobs['windows-build'], r'(?m)^    continue-on-error:')
        self.assertNotRegex(self.jobs['publish-release'], r'(?m)^    if:')
        self.assertIn('      - windows-build\n', self.jobs['publish-release'])

    def test_native_telemetry_gate_rejects_missing_call_and_failure_bypass(self):
        build = self.jobs['windows-build']
        self.assert_native_telemetry_release_gate(build)
        call = '& .\\tests\\run_telemetry_windows_native.ps1 @telemetryArgs'
        cases = {
            'missing runner': build.replace(call, '# runner omitted', 1),
            'ignored failure': build.replace('- name: Test\n', '- name: Test\n        continue-on-error: true\n', 1),
            'unchecked runner failure': build.replace("if ($LASTEXITCODE -ne 0) { throw 'Native telemetry release gate failed' }",
                                                     '# runner exit was ignored', 1),
            'packaging after failure': build.replace('- name: Package (setup exe + runtime zip)\n',
                                                    '- name: Package (setup exe + runtime zip)\n        if: always()\n', 1),
            'positional script arguments': build.replace(
                "$telemetryArgs = @{ BuildDir = 'build'; Configuration = 'Release' }",
                "$telemetryArgs = @('-BuildDir', 'build', '-Configuration', 'Release')", 1),
            'positional OpenSSL option': build.replace(
                '$telemetryArgs.OpenSslBin = $opensslTools',
                "$telemetryArgs += @('-OpenSslBin', $opensslTools)", 1),
        }
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaises(AssertionError):
                self.assert_native_telemetry_release_gate(candidate)

    def test_baseline_is_selected_once_and_shared_with_classification_and_lifecycle(self):
        prepare, build, lifecycle = (self.jobs[name] for name in
                                     ('prepare-release', 'windows-build', 'windows-lifecycle'))
        selection = prepare.split('- name: Select published baseline for this run\n', 1)[1].split('\n      - ', 1)[0]
        self.assertIn('GH_TOKEN: ${{ github.token }}', selection)
        self.assertIn('set -euo pipefail', selection)
        self.assertIn('windows_release_checkpoint.py select-baseline --target-tag', selection)
        self.assertIn('baseline_tag: ${{ steps.baseline.outputs.baseline_tag }}', prepare)
        self.assertIn('EDR_PREVIOUS_RELEASE_TAG: ${{ needs.prepare-release.outputs.baseline_tag }}', build)
        classifier = build.split('- name: Classify supported upgrade path\n', 1)[1].split('\n      - ', 1)[0]
        self.assertIn('--previous-ref $previousTag --current-ref HEAD', classifier)
        self.assertIn("if (-not $previousTag) { throw", classifier)
        self.assertNotIn('git tag --list', classifier)
        self.assertNotIn('select-baseline', classifier)
        self.assertIn('needs: [prepare-release, usb-finalize]', lifecycle)
        self.assertIn('baseline_tag: ${{ needs.prepare-release.outputs.baseline_tag }}', lifecycle)
        standalone = (ROOT / '.github/workflows/windows-install-upgrade-rollback.yml').read_text(encoding='utf-8')
        self.assertIn('python-tool-${{ runner.os }}-${{ runner.arch }}-3.12.10-x64-v1', standalone)
        setup = standalone.split('- name: Set up pinned Python for baseline selection\n', 1)[1].split('\n      - ', 1)[0]
        self.assertIn('uses: actions/setup-python@v6', setup)
        self.assertIn("python-version: '3.12.10'", setup)
        self.assertIn('architecture: x64', setup)
        self.assertLess(standalone.index('- name: Set up pinned Python for baseline selection'),
                        standalone.index('- name: Resolve release tags'))
        resolution = standalone.split('- name: Resolve release tags\n', 1)[1].split('\n      - ', 1)[0]
        self.assertIn('windows_release_checkpoint.py @selectionArgs', resolution)
        self.assertIn("@('--baseline-tag', $requestedBaseline)", resolution)
        self.assertIn("if ($LASTEXITCODE -ne 0) { throw", resolution)
        self.assertIn('ConvertFrom-Json -ErrorAction Stop', resolution)
        self.assertNotIn('foreach ($release', resolution)

    def test_arm_python_cache_has_default_branch_producer(self):
        producer = (ROOT / '.github/workflows/edr-agent-prebuild-packages.yml').read_text(encoding='utf-8')
        for text in (self.text, producer):
            self.assertIn('python-tool-${{ runner.os }}-${{ runner.arch }}-3.12.10-x64-v1', text)
            self.assertIn('${{ runner.tool_cache }}/Python/3.12.10/x64.complete', text)
            self.assertIn("python-version: '3.12.10'", text)
        self.assertIn('branches:\n      - main', producer)

    def test_component_and_signed_manifest_checks_are_preserved(self):
        build = self.jobs['windows-build']
        for check in ('collector/forensic_collector_builtin.exe',
                      'packaged forensic builtin hash does not match native-package-integrity.json',
                      'CMS signer thumbprint does not match manifest trust binding',
                      'CMS signer subject does not match manifest trust binding'):
            self.assertIn(check, build)
        for producer in (build.split('- name: Package (setup exe + runtime zip)\n', 1)[1],
                         build.split('- name: Prepare release assets\n', 1)[1]):
            boundary = producer.split('\n      - ', 1)[0]
            for forbidden in ("'(^|/)p0_rule_[^/]*$'", "'(^|/)sensor_interest_manifest\\.json$'",
                              "'(^|/)agent_preprocess_rules_v1[^/]*$'"):
                self.assertIn(forbidden, boundary)
            self.assertRegex(boundary, r"agent_preprocess_rules_v1\[\^/\]\*\$'\)\s*\{\s*throw\b")
        self.assertIn('artifact-manifest.json.p7s', self.jobs['publish-release'])

    def test_usb_finalization_retains_both_retry_boundaries_and_signature_gate(self):
        build, finish = self.jobs['windows-build'], self.jobs['usb-finalize']
        self.assertIn('seal-input --arch', build)
        self.assertEqual(finish.count('private_signing_bridge.py dispatch'), 1)
        self.assertNotIn('--phase', finish)
        self.assertIn('restore-usb-final --directory finalized', finish)
        self.assertIn("steps.final-resume.outputs.restored != 'true'", finish)
        self.assertLess(finish.index('Verify-WindowsUsbSignatures.ps1'), finish.index('name: usb-verified-final'))
        self.assertLess(finish.index('name: usb-verified-final'), finish.index('windows_release_checkpoint.py upload'))
        self.assertIn("needs: [prepare-release, usb-finalize]", self.jobs['windows-lifecycle'])

    def test_candidate_never_promotes_latest(self):
        publish = self.jobs['publish-release']
        for name in ('Publish signed Windows release', 'Publish unsigned Windows release'):
            step = publish.split('- name: ' + name, 1)[1].split('\n      - ', 1)[0]
            self.assertIn("env.EDR_RELEASE_CANDIDATE != 'true'", step)
        candidate = publish.split('- name: Publish candidate without promoting latest', 1)[1]
        self.assertIn('--prerelease=true --latest=false', candidate)

    def test_syntax_validation_has_no_missing_or_retired_targets(self):
        validator = (ROOT / 'scripts/validate_windows_powershell_syntax.ps1').read_text(encoding='utf-8')
        targets = re.findall(r'^  "([^"\n]+\.ps1)"', validator, re.M)
        self.assertGreater(len(targets), 20)
        for target in targets:
            self.assertTrue((ROOT / target.replace('\\', '/')).is_file(), target)
        self.assertIn('tests\\test_windows_installer_acl.ps1', targets)


class WindowsReleaseWorkflowEncodingTests(unittest.TestCase):
    def test_contracts_under_windows_legacy_default_encoding(self):
        original_read_text = Path.read_text

        def legacy_read_text(path, encoding=None, errors=None):
            # Decode actual repository bytes; only simulate Windows's default
            # when a caller omits its encoding. Never replace/ignore bad bytes.
            return original_read_text(path, encoding=encoding or 'cp1252', errors=errors)

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(WindowsReleaseWorkflowTests)
        result = unittest.TestResult()
        with patch.object(Path, 'read_text', legacy_read_text):
            suite.run(result)
        self.assertGreater(result.testsRun, 0)
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)


if __name__ == '__main__':
    unittest.main()
