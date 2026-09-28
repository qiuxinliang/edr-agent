"""Verify native evidence cannot be produced by a foreign host or emulated PE."""
import ctypes
import importlib.util
from pathlib import Path
import struct
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

    def test_native_replay_pe_header_and_machine_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            replay = Path(directory) / "replay.exe"
            for architecture, machine in (("amd64", 0x8664), ("arm64", 0xAA64)):
                valid = bytearray(256)
                valid[:2] = b"MZ"
                struct.pack_into("<I", valid, 0x3c, 128)
                struct.pack_into("<4sH", valid, 128, b"PE\0\0", machine)
                cases = [("valid", valid, None),
                         ("truncated", valid[:63], "DOS header"),
                         ("bad DOS", b"XX" + valid[2:], "DOS header")]
                for name, offset in (("offset before header", 0), ("offset outside file", 0xffffffff)):
                    bad = bytearray(valid)
                    struct.pack_into("<I", bad, 0x3c, offset)
                    cases.append((name, bad, "PE offset"))
                for name, signature, actual, error in (
                    ("foreign", b"PE\0\0", 0x8664 if machine == 0xAA64 else 0xAA64, "architecture mismatch"),
                    ("bad signature", b"PE12", machine, "PE signature")):
                    bad = bytearray(valid)
                    struct.pack_into("<4sH", bad, 128, signature, actual)
                    cases.append((name, bad, error))
                for name, raw, error in cases:
                    with self.subTest(architecture=architecture, case=name), \
                            patch.object(AUDIT, "windows_native_architecture", return_value=architecture), \
                            patch.object(AUDIT.subprocess, "run") as launch:
                        replay.write_bytes(raw)
                        if error:
                            with self.assertRaisesRegex(RuntimeError, error):
                                AUDIT.verify_native_replay(ROOT, replay)
                        else:
                            self.assertEqual(AUDIT.verify_native_replay(ROOT, replay), architecture)
                        launch.assert_not_called()

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
