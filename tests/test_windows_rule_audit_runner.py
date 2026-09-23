"""Verify native evidence cannot be produced by a foreign host or emulated PE."""
import ctypes
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_rule_audit", ROOT / "scripts/verify_windows_rule_audit.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class WindowsRuleAuditRunnerTests(unittest.TestCase):
    def test_non_windows_host_cannot_claim_native_evidence(self):
        with patch.object(AUDIT.platform, "system", return_value="Darwin"):
            with self.assertRaisesRegex(RuntimeError, "requires a Windows host"):
                AUDIT.windows_native_architecture()

    def test_emulated_python_uses_the_kernel_native_architecture(self):
        def query(_process, process_machine, native_machine):
            ctypes.cast(process_machine, ctypes.POINTER(ctypes.c_ushort))[0] = 0x8664
            ctypes.cast(native_machine, ctypes.POINTER(ctypes.c_ushort))[0] = 0xAA64
            return 1
        kernel = Mock()
        kernel.IsWow64Process2.side_effect = query
        kernel.GetCurrentProcess.return_value = -1
        with patch.object(AUDIT.platform, "system", return_value="Windows"), \
                patch.object(ctypes, "WinDLL", return_value=kernel, create=True):
            self.assertEqual(AUDIT.windows_native_architecture(), "arm64")

    def test_native_check_reuses_pe_verifier_with_kernel_architecture(self):
        with patch.object(AUDIT, "windows_native_architecture", return_value="arm64"), \
                patch.dict(AUDIT.os.environ, {"PSMODULEPATH": "PowerShell7Modules", "KEEP_NATIVE_TEST": "present"}), \
                patch.object(AUDIT.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            self.assertEqual(AUDIT.verify_native_replay(ROOT, Path("replay.exe")), "arm64")
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("-Architecture") + 1], "arm64")
        self.assertEqual(command[command.index("-File") + 1],
                         str(ROOT / "scripts/Assert-WindowsPeArchitecture.ps1"))
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertNotIn("PSMODULEPATH", {key.upper() for key in run.call_args.kwargs["env"]})
        self.assertEqual(run.call_args.kwargs["env"]["KEEP_NATIVE_TEST"], "present")

    def test_foreign_pe_failure_cannot_proceed_to_replay(self):
        with patch.object(AUDIT, "windows_native_architecture", return_value="arm64"), \
                patch.object(AUDIT.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "PE architecture mismatch")):
            with self.assertRaisesRegex(RuntimeError, "PE architecture mismatch"):
                AUDIT.verify_native_replay(ROOT, Path("x64-replay.exe"))

    def test_unavailable_run_removes_stale_success_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            output.write_text('{"failed": 0}', encoding="utf-8")
            with patch.object(AUDIT.sys, "argv", ["audit", "--replay", "missing.exe",
                                                   "--output", str(output), "--native-windows"]), \
                    patch.object(AUDIT.platform, "system", return_value="Darwin"):
                with self.assertRaisesRegex(RuntimeError, "requires a Windows host"):
                    AUDIT.main()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
