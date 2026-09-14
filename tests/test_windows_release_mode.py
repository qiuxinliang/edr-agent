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
    def gate(self, job, mode, usb_result, build='success', lifecycle='success'):
        workflow = (SCRIPT.parent.parent / '.github/workflows/edr-agent-client-release.yml').read_text()
        block = re.split(r'\n  [\w-]+:\n', workflow.split(f'\n  {job}:\n', 1)[1], maxsplit=1)[0]
        expression = re.search(r'^    if: \$\{\{ (.+) \}\}$', block, re.MULTILINE).group(1)
        values = {
            'needs.prepare-release.outputs.signing-mode': mode,
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

    def test_explicit_other_modes_preserve_native_lifecycle(self):
        for mode in ('signed', 'unsigned'):
            self.assertTrue(self.gate('windows-lifecycle', mode, 'skipped'))
            self.assertTrue(self.gate('publish-release', mode, 'skipped'))
            self.assertFalse(self.gate('publish-release', mode, 'skipped', lifecycle='failure'))

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
