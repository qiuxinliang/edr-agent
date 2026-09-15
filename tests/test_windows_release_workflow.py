"""Guard the restored job graph and retained release integrity boundaries."""
from pathlib import Path
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

    def test_only_original_hosted_job_graph_remains(self):
        self.assertEqual(set(self.jobs), {'prepare-release', 'windows-build', 'windows-lifecycle', 'publish-release'})
        for removed in ('usb-native', 'USB_SIGNING_TOKEN', 'edr-agent-signing', 'self-hosted', 'build_purpose', 'unsigned-candidate-'):
            self.assertNotIn(removed, self.text)
        self.assertFalse(list((ROOT / '.github/workflows').glob('windows-usb-*.yml')))

    def test_original_modes_and_default_are_restored(self):
        modes = self.text.split('      release_mode:', 1)[1].split('      upgrade_class:', 1)[0]
        self.assertEqual(re.findall(r'^          - (\w+)$', modes, re.M), ['unsigned', 'signed'])
        self.assertIn('default: unsigned', modes)
        self.assertIn("vars.WINDOWS_RELEASE_MODE || 'unsigned'", self.text)
        self.assertIn('(UNSIGNED Windows AMD64 + ARM64)', self.jobs['publish-release'])

    def test_publication_still_requires_build_and_lifecycle_success(self):
        self.assertIn('needs: prepare-release', self.jobs['windows-build'])
        self.assertIn('needs: windows-build', self.jobs['windows-lifecycle'])
        publish = self.jobs['publish-release']
        needs = publish.split('    needs:\n', 1)[1].split('    runs-on:', 1)[0]
        self.assertEqual(re.findall(r'^      - ([\w-]+)$', needs, re.M), ['windows-build', 'windows-lifecycle'])
        # No always() or job-level condition can bypass implicit successful needs.
        self.assertNotRegex(publish, r'(?m)^    if:')
        self.assertIn('windows-install-upgrade-rollback.yml', self.jobs['windows-lifecycle'])
        self.assertIn('already published and is immutable', self.jobs['prepare-release'])

    def test_component_and_signed_manifest_checks_are_preserved(self):
        build = self.jobs['windows-build']
        for check in ('collector/forensic_collector_builtin.exe',
                      'packaged forensic builtin hash does not match native-package-integrity.json',
                      'CMS signer thumbprint does not match manifest trust binding',
                      'CMS signer subject does not match manifest trust binding',
                      'plaintext P0 rules must not be published'):
            self.assertIn(check, build)
        self.assertIn('artifact-manifest.json.p7s', self.jobs['publish-release'])

    def test_syntax_validation_has_no_missing_or_retired_targets(self):
        validator = (ROOT / 'scripts/validate_windows_powershell_syntax.ps1').read_text(encoding='utf-8')
        targets = re.findall(r'^  "([^"\n]+\.ps1)"', validator, re.M)
        self.assertGreater(len(targets), 20)
        for target in targets:
            self.assertTrue((ROOT / target.replace('\\', '/')).is_file(), target)
            self.assertNotIn('Usb', target)
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
