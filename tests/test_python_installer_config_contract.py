#!/usr/bin/env python3

import argparse
import importlib.util
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest import mock


def _load_installer(source_root: Path):
    path = source_root / "scripts" / "edr_agent_install.py"
    spec = importlib.util.spec_from_file_location("edr_agent_install", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load installer module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _enroll_fixture():
    return {
        "endpoint_id": "endpoint-test-1",
        "tenant_id": "tenant-test-1",
        "server_addr": "platform.example:443",
        "rest_base_url": "https://platform.example/api/v1",
        "platform_bearer_token": "fixture-bearer",
        "request_signing_enabled": True,
        "request_signing_required": True,
        "request_signing_key_id": "request-key-1",
        "request_signing_secret": "Zml4dHVyZS1zZWNyZXQ=",
    }


class PythonInstallerConfigContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_root = Path(__file__).resolve().parents[1]
        cls.installer = _load_installer(cls.source_root)
        cls.agent = Path(TEST_AGENT).expanduser().resolve()
        if not cls.agent.is_file():
            raise RuntimeError(f"Agent executable does not exist: {cls.agent}")

    def setUp(self):
        self.previous_agent = os.environ.get("EDR_AGENT_EXECUTABLE")
        os.environ["EDR_AGENT_EXECUTABLE"] = str(self.agent)

    def tearDown(self):
        if self.previous_agent is None:
            os.environ.pop("EDR_AGENT_EXECUTABLE", None)
        else:
            os.environ["EDR_AGENT_EXECUTABLE"] = self.previous_agent

    def _render_fixture(self, install_dir: str) -> str:
        result = self.installer._normalize_enroll_result(
            _enroll_fixture(), "https://fallback.example/api/v1"
        )
        return self.installer._emit_toml(
            result["server_addr"],
            result["endpoint_id"],
            result["tenant_id"],
            result["rest_base"],
            result["rest_bearer_token"],
            "",
            "",
            "",
            "pem",
            "",
            "",
            "",
            "",
            "",
            result["request_signing_enabled"],
            result["request_signing_key_id"],
            result["request_signing_secret"],
            install_dir,
        )

    def test_generated_contract_is_accepted_by_real_agent_parser(self):
        with tempfile.TemporaryDirectory(prefix="edr-python-installer-") as temp_dir:
            target = Path(temp_dir) / "agent.toml"
            text = self._render_fixture(temp_dir)

            validated_by = self.installer._write_validated_config(str(target), text)

            self.assertEqual(self.agent, validated_by)
            self.assertEqual(text, target.read_text(encoding="utf-8"))
            self.assertIn("[platform.request_signing]", text)
            self.assertIn('key_id               = "request-key-1"', text)
            if os.name != "nt":
                self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))

    def test_valid_replacement_preserves_existing_posix_permissions(self):
        if os.name == "nt":
            self.skipTest("POSIX mode bits are not the Windows ACL contract")
        with tempfile.TemporaryDirectory(prefix="edr-python-installer-") as temp_dir:
            target = Path(temp_dir) / "agent.toml"
            target.write_text("# previous config\n", encoding="utf-8")
            target.chmod(0o640)

            observed_staged_modes = []
            validate = self.installer._validate_config_with_agent

            def inspect_then_validate(agent_path, config_path):
                observed_staged_modes.append(stat.S_IMODE(config_path.stat().st_mode))
                return validate(agent_path, config_path)

            with mock.patch.object(
                self.installer,
                "_validate_config_with_agent",
                side_effect=inspect_then_validate,
            ):
                self.installer._write_validated_config(
                    str(target), self._render_fixture(temp_dir)
                )

            self.assertEqual([0o600], observed_staged_modes)
            self.assertEqual(0o640, stat.S_IMODE(target.stat().st_mode))

    def test_windows_staged_config_uses_protected_sensitive_file_dacl(self):
        if os.name != "nt":
            self.skipTest("requires native Windows ACL APIs")
        import ctypes

        with tempfile.TemporaryDirectory(prefix="edr-python-installer-") as temp_dir:
            staged = Path(temp_dir) / "staged.toml"
            staged.write_text("secret", encoding="utf-8")
            self.installer._secure_staged_file_windows(staged)

            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            get_security = advapi32.GetNamedSecurityInfoW
            get_security.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
            ]
            get_security.restype = ctypes.c_uint32
            convert = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
            convert.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_void_p,
            ]
            convert.restype = ctypes.c_int
            kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            kernel32.LocalFree.restype = ctypes.c_void_p
            owner = ctypes.c_void_p()
            group = ctypes.c_void_p()
            dacl = ctypes.c_void_p()
            sacl = ctypes.c_void_p()
            descriptor = ctypes.c_void_p()
            result = get_security(
                str(staged),
                1,
                0x4,
                ctypes.byref(owner),
                ctypes.byref(group),
                ctypes.byref(dacl),
                ctypes.byref(sacl),
                ctypes.byref(descriptor),
            )
            self.assertEqual(0, result)
            text = ctypes.c_wchar_p()
            try:
                converted = convert(
                    descriptor, 1, 0x4, ctypes.byref(text), None
                )
                self.assertTrue(converted, ctypes.get_last_error())
                observed = text.value or ""
            finally:
                if text:
                    kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
                if descriptor:
                    kernel32.LocalFree(descriptor)

            self.assertIn("D:P", observed)
            self.assertIn(";;;SY)", observed)
            self.assertIn(";;;BA)", observed)
            self.assertIn(";;;OW)", observed)

    def test_real_parser_rejection_preserves_existing_config(self):
        with tempfile.TemporaryDirectory(prefix="edr-python-installer-") as temp_dir:
            target = Path(temp_dir) / "agent.toml"
            previous = "# existing known-good config\n"
            target.write_text(previous, encoding="utf-8")
            if os.name != "nt":
                target.chmod(0o640)

            with self.assertRaisesRegex(
                self.installer.ConfigValidationError,
                "Agent rejected generated config",
            ) as rejected:
                self.installer._write_validated_config(
                    str(target), '[server\nsecret = "must-not-appear-in-diagnostics"\n'
                )

            self.assertEqual(previous, target.read_text(encoding="utf-8"))
            self.assertNotIn("must-not-appear-in-diagnostics", str(rejected.exception))
            self.assertEqual([], list(target.parent.glob(".agent.toml.config-test-*.tmp")))
            if os.name != "nt":
                self.assertEqual(0o640, stat.S_IMODE(target.stat().st_mode))

    def test_enroll_contract_rejects_missing_identity_or_signing_material(self):
        missing_identity = _enroll_fixture()
        missing_identity["endpoint_id"] = ""
        with self.assertRaisesRegex(ValueError, "missing endpoint_id"):
            self.installer._normalize_enroll_result(
                missing_identity, "https://fallback.example/api/v1"
            )

        missing_signing_secret = _enroll_fixture()
        missing_signing_secret["request_signing_secret"] = ""
        with self.assertRaisesRegex(ValueError, "key_id or secret is missing"):
            self.installer._normalize_enroll_result(
                missing_signing_secret, "https://fallback.example/api/v1"
            )

        inconsistent_signing = _enroll_fixture()
        inconsistent_signing["request_signing_enabled"] = False
        with self.assertRaisesRegex(ValueError, "required while disabled"):
            self.installer._normalize_enroll_result(
                inconsistent_signing, "https://fallback.example/api/v1"
            )

    def test_missing_agent_fails_unless_generate_only_is_explicit(self):
        with tempfile.TemporaryDirectory(prefix="edr-python-installer-") as temp_dir:
            target = Path(temp_dir) / "agent.toml"
            previous = "# existing known-good config\n"
            target.write_text(previous, encoding="utf-8")
            text = self._render_fixture(temp_dir)
            with mock.patch.object(
                self.installer, "_resolve_agent_executable", return_value=None
            ):
                with self.assertRaisesRegex(
                    self.installer.ConfigValidationError,
                    "Agent executable not found",
                ):
                    self.installer._write_validated_config(str(target), text)
                self.assertEqual(previous, target.read_text(encoding="utf-8"))

                warnings = StringIO()
                with redirect_stderr(warnings):
                    validated_by = self.installer._write_validated_config(
                        str(target), text, allow_missing_agent=True
                    )
                self.assertIsNone(validated_by)
                self.assertEqual(text, target.read_text(encoding="utf-8"))
                self.assertIn("--generate-only", warnings.getvalue())

    def test_validation_timeout_is_bounded_and_reports_no_process_output(self):
        timeout = self.installer.subprocess.TimeoutExpired(
            cmd=[str(self.agent), "--config-test"], timeout=30, output="secret-output"
        )
        with mock.patch.object(
            self.installer.subprocess, "run", side_effect=timeout
        ) as run:
            with self.assertRaisesRegex(
                self.installer.ConfigValidationError,
                "could not run Agent config parser",
            ) as timed_out:
                self.installer._validate_config_with_agent(
                    self.agent, Path("not-written.toml")
                )
        self.assertEqual(30, run.call_args.kwargs["timeout"])
        self.assertIs(self.installer.subprocess.DEVNULL, run.call_args.kwargs["stdout"])
        self.assertIs(self.installer.subprocess.DEVNULL, run.call_args.kwargs["stderr"])
        self.assertNotIn("secret-output", str(timed_out.exception))

    def test_staging_failure_closes_descriptor_before_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="edr-python-installer-") as temp_dir:
            target = Path(temp_dir) / "agent.toml"
            real_mkstemp = tempfile.mkstemp
            real_unlink = Path.unlink
            opened = []

            def capture_descriptor(*args, **kwargs):
                fd, path = real_mkstemp(*args, **kwargs)
                opened.append((fd, Path(path)))
                return fd, path

            def require_closed_before_unlink(path, *args, **kwargs):
                if opened and path == opened[0][1]:
                    with self.assertRaises(OSError):
                        os.fstat(opened[0][0])
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(tempfile, "mkstemp", side_effect=capture_descriptor), \
                    mock.patch.object(self.installer.os, "fdopen", side_effect=OSError("injected staging failure")), \
                    mock.patch.object(Path, "unlink", new=require_closed_before_unlink):
                with self.assertRaisesRegex(OSError, "injected staging failure"):
                    self.installer._write_validated_config(str(target), "not-written")
            self.assertEqual(1, len(opened))
            self.assertFalse(opened[0][1].exists())
            self.assertFalse(target.exists())

    def test_parser_rejection_does_not_overwrite_active_certificates(self):
        with tempfile.TemporaryDirectory(prefix="edr-python-installer-") as temp_dir:
            root = Path(temp_dir)
            target = root / "agent.toml"
            ca_path = root / "certs" / "ca.pem"
            cert_path = root / "certs" / "client.pem"
            ca_path.parent.mkdir()
            target.write_text("# previous config\n", encoding="utf-8")
            ca_path.write_text("previous-ca", encoding="utf-8")
            cert_path.write_text("previous-client-cert", encoding="utf-8")

            with self.assertRaises(self.installer.ConfigValidationError):
                self.installer._install_enrollment_config(
                    str(target),
                    "[server\n",
                    str(ca_path),
                    "new-ca",
                    str(cert_path),
                    "new-client-cert",
                    "pem",
                )

            self.assertEqual("# previous config\n", target.read_text(encoding="utf-8"))
            self.assertEqual("previous-ca", ca_path.read_text(encoding="utf-8"))
            self.assertEqual("previous-client-cert", cert_path.read_text(encoding="utf-8"))

    def test_certificate_files_are_restored_if_config_commit_fails(self):
        with tempfile.TemporaryDirectory(prefix="edr-python-installer-") as temp_dir:
            root = Path(temp_dir)
            target = root / "agent.toml"
            ca_path = root / "certs" / "ca.pem"
            cert_path = root / "certs" / "client.pem"
            ca_path.parent.mkdir()
            target.write_text("# previous config\n", encoding="utf-8")
            ca_path.write_text("previous-ca", encoding="utf-8")
            cert_path.write_text("previous-client-cert", encoding="utf-8")

            with mock.patch.object(
                self.installer,
                "_replace_staged_config",
                side_effect=OSError("injected config commit failure"),
            ):
                with self.assertRaisesRegex(OSError, "injected config commit failure"):
                    self.installer._install_enrollment_config(
                        str(target),
                        self._render_fixture(temp_dir),
                        str(ca_path),
                        "new-ca",
                        str(cert_path),
                        "new-client-cert",
                        "pem",
                    )

            self.assertEqual("# previous config\n", target.read_text(encoding="utf-8"))
            self.assertEqual("previous-ca", ca_path.read_text(encoding="utf-8"))
            self.assertEqual("previous-client-cert", cert_path.read_text(encoding="utf-8"))

    def test_windows_partial_replace_failure_restores_original(self):
        with tempfile.TemporaryDirectory(prefix="edr-python-installer-") as temp_dir:
            root = Path(temp_dir)
            target = root / "agent.toml"
            staged = root / "staged.toml"
            target.write_text("previous-config", encoding="utf-8")
            staged.write_text("candidate-config", encoding="utf-8")
            observed_flags = []

            def fail_after_backup(target_name, staged_name, backup_name, flags, _, __):
                observed_flags.append(flags)
                os.replace(target_name, backup_name)
                return 0

            with self.assertRaisesRegex(
                self.installer.ConfigValidationError,
                "Windows error 1177; original config restored",
            ):
                self.installer._replace_file_windows(
                    target,
                    staged,
                    replace_file=fail_after_backup,
                    get_last_error=lambda: 1177,
                )

            self.assertEqual([0], observed_flags)
            self.assertEqual("previous-config", target.read_text(encoding="utf-8"))
            self.assertEqual("candidate-config", staged.read_text(encoding="utf-8"))
            self.assertEqual([], list(root.glob(".agent.toml.replace-*.bak")))

    def test_dry_run_redacts_bearer_and_request_signing_secret(self):
        text = self._render_fixture(str(self.source_root))
        redacted = self.installer._redact_generated_toml(text)
        self.assertNotIn("fixture-bearer", redacted)
        self.assertNotIn("Zml4dHVyZS1zZWNyZXQ=", redacted)
        self.assertEqual(2, redacted.count("<redacted>"))

    def test_dry_run_redacts_escaped_quotes_and_backslashes(self):
        value = self.installer._toml_escape('prefix"must-hide-this-tail\\end')
        text = f'rest_bearer_token = "{value}"\n[platform.request_signing]\nsecret = "{value}"\n'
        redacted = self.installer._redact_generated_toml(text)
        self.assertNotIn("must-hide-this-tail", redacted)
        self.assertNotIn("prefix", redacted)
        self.assertEqual(2, redacted.count("<redacted>"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True, help="path to the built Agent executable")
    options, unittest_args = parser.parse_known_args()
    TEST_AGENT = options.agent
    unittest.main(argv=[__file__] + unittest_args)
