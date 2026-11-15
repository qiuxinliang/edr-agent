"""Guard the fixed diagnostic's scope independently of release acceptance.

Native PowerShell execution remains required on Windows. These tests cover the
workflow's declared boundaries, fixed source identities and failure ownership.
"""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/windows-install-upgrade-rollback.yml'
DRIVER = ROOT / 'tests/preflight_diagnostic/run_workflow.ps1'
SOURCE = '984b955a64f5513377c465426faf45f9a0e9bf72'
BASELINE = 'b51bc3d825e6d5666535463b34eb708201e6fda7'
RUN = '43672863753'


def job(text, name):
    match = re.search(r'^  ' + re.escape(name) + r':\n(.*?)(?=^  [\w-]+:\n|\Z)', text, re.M | re.S)
    if not match:
        raise AssertionError('missing job '+name)
    return match.group(1)


def check_scope(text, driver):
    diagnostic = job(text, 'preflight-diagnostic')
    if not re.search(r'preflight_diagnostic:\n.*?default: false\n\s+type: boolean', text, re.S):
        raise AssertionError('diagnostic must require an explicit opt-in')
    for name in ('native-lifecycle', 'recover-synthetic-owner',
                 'storage-compat-native-tools', 'signed-publisher-lifecycle'):
        condition = re.search(r'^    if: (.+)', job(text, name), re.M).group(1)
        if '!inputs.preflight_diagnostic' not in condition:
            raise AssertionError('diagnostic must exclude '+name)
    for value in ('runs-on: windows-2022', 'timeout-minutes: 20',
                  'github.event_name == \'workflow_dispatch\'', 'inputs.preflight_diagnostic',
                  "$v.target_tag -cne 'win_3.2.746'", "$v.baseline_tag -cne 'win_3.2.723'",
                  "$v.package_scope -cne 'headless'", "$v.architecture -cne 'amd64'",
                  '$v.native_repeat_count -ne 1', '-not $v.installer_timeout_recovery',
                  '$v.cache_recovery_subset -or $v.publisher_validation_request',
                  '--baseline-runtime packages/baseline', 'tests/preflight_diagnostic/verify.py'):
        if value not in diagnostic:
            raise AssertionError('missing fixed diagnostic boundary '+value)
    for value in (SOURCE, BASELINE, RUN, '/attempts/1', '--expected-source-commit $source',
                  '--expected-run-id $originalRun', '--published-baseline --target-tag win_3.2.746',
                  'prepare-lifecycle-upgrade', '$clock.ElapsedMilliseconds -ge 90000', '$job.StopAndDrain(5000)',
                  '-ExerciseInstallerTimeout', "Invoke-PreflightCollector 'before'",
                  "Invoke-PreflightCollector 'after' $lifecycleFailure.Exception.Message",
                  "status='not_reproduced'", "cause='unknown'", '  throw\n} finally'):
        if value not in driver:
            raise AssertionError('missing original-input/failure boundary '+value)
    if 'windows_release_lifecycle_smoke.ps1' in diagnostic or 'windows_release_lifecycle_smoke.ps1' in driver:
        raise AssertionError('diagnostic must stop before runtime repeat rounds')
    for condition in (r'\$large\.Count', r'\$clock\.ElapsedMilliseconds -ge 90000'):
        if not re.search(r'if \(' + condition + r'\) \{\s*\$job\.StopAndDrain\(5000\)', driver):
            raise AssertionError('each collector limit must terminate and drain its process tree')
    for forbidden in ('gh release', 'gh workflow', 'SkipCertificateCheck',
                      'AllowInsecureRedirect', 'WINDOWS_USB', 'WINDOWS_RELEASE_MODE'):
        if forbidden in diagnostic or forbidden in driver:
            raise AssertionError('unrelated release/signing authority '+forbidden)
    paths = diagnostic.split('          path: |\n', 1)[1]
    for forbidden in ('**', '*.db', '*.toml', 'packages/', 'baseline-source/', 'release-metadata/'):
        if forbidden in paths:
            raise AssertionError('artifact must exclude raw stores/configuration '+forbidden)


class WindowsPreflightDiagnosticWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding='utf-8')
        self.driver = DRIVER.read_text(encoding='utf-8')

    def test_fixed_scope_and_failure_owner(self):
        check_scope(self.text, self.driver)

    def test_original_release_source_run_checks_are_preserved(self):
        native = job(self.text, 'native-lifecycle')
        self.assertIn('--expected-source-commit $env:GITHUB_SHA --expected-run-id $env:GITHUB_RUN_ID', native)
        self.assertNotIn('--expected-run-id '+RUN, native)
        self.assertNotIn('--expected-source-commit '+SOURCE, native)

    def test_disabling_opt_in_or_exclusion_is_rejected(self):
        for original, replacement in (
            ('default: false\n        type: boolean\n\npermissions:', 'default: true\n        type: boolean\n\npermissions:'),
            ('!inputs.preflight_diagnostic && !inputs.cache_recovery_subset', '!inputs.cache_recovery_subset'),
            ("architecture -cne 'amd64'", "architecture -cne 'all'"),
            ('$v.native_repeat_count -ne 1', '$v.native_repeat_count -gt 5'),
            ('--baseline-runtime packages/baseline', '--baseline-runtime C:/Windows/System32'),
        ):
            mutated = self.text.replace(original, replacement, 1)
            self.assertNotEqual(mutated, self.text)
            with self.subTest(boundary=original), self.assertRaises(AssertionError):
                check_scope(mutated, self.driver)

    def test_losing_binding_timeout_or_first_failure_is_rejected(self):
        for original in ('--expected-run-id $originalRun', '--expected-source-commit $source',
                         '$clock.ElapsedMilliseconds -ge 90000', '$job.StopAndDrain(5000)',
                         '  throw\n} finally', '-ExerciseInstallerTimeout'):
            with self.subTest(boundary=original), self.assertRaises(AssertionError):
                check_scope(self.text, self.driver.replace(original, '', 1))

    def test_unrelated_operations_and_raw_artifacts_are_rejected(self):
        for mutation in ('gh release publish win_3.2.746', 'gh workflow run sign.yml',
                         'SkipCertificateCheck'):
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                check_scope(self.text, self.driver+'\n'+mutation)
        for pattern in ('**', '*.db', '*.toml', 'packages/'):
            mutated = self.text.replace('preflight-diagnostic-evidence/*.json', pattern, 1)
            with self.subTest(pattern=pattern), self.assertRaises(AssertionError):
                check_scope(mutated, self.driver)

    def test_temporary_harness_is_bound_and_original_installer_is_used(self):
        self.assertIn('cab5d85fa748c98ca4e06a759774b61c5ff505114332dd86c56b8a6edc158cb0', self.driver)
        self.assertIn('.Replace("`r`n", "`n")', self.driver)
        self.assertIn('$body.Replace($before,', self.driver)
        self.assertIn('$body.Replace($failed,', self.driver)
        self.assertIn('-BaselineSetupExe $baselineStage.setup_exe -TargetSetupExe $targetStage.setup_exe', self.driver)
        self.assertIn('[IO.File]::Delete($temporary)', self.driver)
        self.assertIn("('collector-'+$Stage+'.stderr')", self.driver)
        self.assertIn('$file.SetLength(262144)', self.driver)
        self.assertNotIn('*> `$null', self.driver)
        self.assertNotIn('MinFreeBytes=', self.driver)
        self.assertIn('--stable-copy-on-change', self.driver)
        self.assertIn("status='diagnostic_unavailable'; original_rollback_executed=$false", self.driver)
        self.assertIn("before_unavailable=(Test-Path (Join-Path $evidence 'before-error.json'))", self.driver)

    def test_private_tag_lookup_retains_original_checkout_authentication(self):
        diagnostic = job(self.text, 'preflight-diagnostic')
        first = diagnostic.split('      - uses: actions/checkout@v6\n', 1)[1]
        first = first.split('      - uses:', 1)[0]
        self.assertNotIn('persist-credentials: false', first)
        self.assertIn("Resolve-ReleaseTagCommit 'win_3.2.723' $baseline", self.driver)


if __name__ == '__main__':
    unittest.main()
