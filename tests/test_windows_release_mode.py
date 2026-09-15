import importlib.util
from pathlib import Path
import subprocess
import re
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/windows_release_mode.py"
spec = importlib.util.spec_from_file_location("release_mode", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseSigningModeTests(unittest.TestCase):
    def gate(self, job, mode, usb_result, build='success', lifecycle='success', purpose='release'):
        workflow = (SCRIPT.parent.parent / '.github/workflows/edr-agent-client-release.yml').read_text()
        block = re.split(r'\n  [\w-]+:\n', workflow.split(f'\n  {job}:\n', 1)[1], maxsplit=1)[0]
        expression = re.search(r'^    if: \$\{\{ (.+) \}\}$', block, re.MULTILINE).group(1)
        values = {
            'needs.prepare-release.outputs.signing-mode': mode,
            'needs.prepare-release.outputs.build-purpose': purpose,
            'needs.prepare-release.result': 'success',
            'needs.windows-build.result': build,
            'needs.windows-lifecycle.result': lifecycle,
            'needs.usb-publish-assets.result': usb_result,
        }
        for key, value in values.items():
            expression = expression.replace(key, repr(value))
        expression = expression.replace('always()', 'True').replace('&&', 'and').replace('||', 'or')
        # Evaluate the checked-in boolean gate, not a second implementation of it.
        return eval(expression, {'__builtins__': {}}, {})

    def test_checked_in_usb_gate_never_allows_skipped_or_failed_signing(self):
        for result in ('failure', 'cancelled', 'skipped', ''):
            for job in ('windows-lifecycle', 'publish-release'):
                with self.subTest(job=job, result=result):
                    self.assertFalse(self.gate(job, 'usb', result))
        self.assertTrue(self.gate('windows-lifecycle', 'usb', 'success'))
        self.assertTrue(self.gate('publish-release', 'usb', 'success'))
        self.assertFalse(self.gate('publish-release', 'usb', 'success', lifecycle='failure'))
        self.assertFalse(self.gate('windows-lifecycle', 'usb', 'success', build='failure'))

    def test_explicit_signed_mode_preserves_native_lifecycle(self):
        self.assertTrue(self.gate('windows-lifecycle', 'signed', 'skipped'))
        self.assertTrue(self.gate('publish-release', 'signed', 'skipped'))
        self.assertFalse(self.gate('publish-release', 'signed', 'skipped', lifecycle='failure'))

    def test_candidate_cannot_sign_promote_or_publish_even_if_other_jobs_succeed(self):
        for mode in ('signed', 'unsigned', 'usb'):
            for job in ('usb-native-sign', 'windows-lifecycle', 'publish-release'):
                with self.subTest(mode=mode, job=job):
                    self.assertFalse(self.gate(job, mode, 'success', purpose='candidate'))
        for job in ('windows-lifecycle', 'publish-release'):
            self.assertFalse(self.gate(job, 'unsigned', 'success', purpose='release'))

    def test_candidate_plan_needs_no_signing_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            for event in ('push', 'workflow_dispatch'):
                output = Path(directory) / event
                result = subprocess.run([sys.executable, str(SCRIPT), '--event', event,
                    '--purpose', 'candidate', '--configured', 'usb', '--output', str(output)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text(), 'mode=unsigned\npurpose=candidate\n')

    def test_release_plan_rejects_unsigned_and_emits_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            base = [sys.executable, str(SCRIPT), '--event', 'workflow_dispatch', '--purpose', 'release', '--output', str(output)]
            result = subprocess.run(base + ['--requested', 'unsigned'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            result = subprocess.run(base + ['--requested', 'usb'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(), 'mode=usb\npurpose=release\n')

    def test_workflow_candidate_defaults_and_artifact_only_boundary(self):
        workflow = (SCRIPT.parent.parent / '.github/workflows/edr-agent-client-release.yml').read_text()
        purpose_input = workflow.split('      build_purpose:', 1)[1].split('      release_mode:', 1)[0]
        self.assertIn('default: candidate', purpose_input)
        self.assertIn("BUILD_PURPOSE: ${{ inputs.build_purpose || 'candidate' }}", workflow)
        self.assertIn("if: steps.signing-mode.outputs.purpose == 'release'", workflow)
        upload = workflow.split('      - name: Upload ${{ matrix.arch }} release bundle', 1)[1].split('      - name:', 1)[0]
        self.assertIn("env.WINDOWS_BUILD_PURPOSE == 'release'", upload)
        self.assertIn('name: unsigned-candidate-', workflow)
        self.assertNotIn('Publish unsigned Windows release', workflow)

    def test_missing_configuration_requires_usb(self):
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event):
                self.assertEqual(module.resolve_mode(event), "usb")

    def test_supported_signed_modes(self):
        for mode in ("usb", "signed"):
            for event in ("push", "workflow_dispatch"):
                with self.subTest(event=event, mode=mode):
                    self.assertEqual(module.resolve_mode(event, configured=mode), mode)

    def test_manual_selection_has_precedence(self):
        self.assertEqual(module.resolve_mode("workflow_dispatch", "usb", "unsigned"), "usb")
        self.assertEqual(module.resolve_mode("workflow_dispatch", "signed", "usb"), "signed")

    def test_only_explicit_manual_unsigned_is_allowed(self):
        self.assertEqual(module.resolve_mode("workflow_dispatch", "unsigned", "usb"), "unsigned")
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event), self.assertRaises(ValueError):
                module.resolve_mode(event, configured="unsigned")
        with self.assertRaises(ValueError):
            module.resolve_mode("push", "unsigned", "unsigned")

    def test_unknown_mode_and_event_fail_closed(self):
        for mode in ("USB", " usb ", "disabled", "\nunsigned"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                module.resolve_mode("push", configured=mode)
        with self.assertRaises(ValueError):
            module.resolve_mode("pull_request", "usb")

    def test_output_contract_and_no_output_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            base = [sys.executable, str(SCRIPT), "--event", "push", "--output", str(output)]
            passed = subprocess.run(base, capture_output=True, text=True)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertEqual(output.read_text(), "mode=usb\n")
            failed = subprocess.run(base + ["--configured", "unsigned"], capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(output.read_text(), "mode=usb\n")


if __name__ == "__main__":
    unittest.main()
