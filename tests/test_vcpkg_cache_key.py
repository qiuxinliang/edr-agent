import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "scripts" / "vcpkg_cache_key.py"
SPEC = importlib.util.spec_from_file_location("vcpkg_cache_key", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


KEY_INPUTS = (
    "vcpkg.json",
    "dependencies.lock.json",
    "scripts/Initialize-VS2022Environment.ps1",
    "scripts/bootstrap_pinned_vcpkg.ps1",
    "scripts/vcpkg_cache_key.py",
    "scripts/vcpkg_release_cache.py",
)


class VcpkgCacheKeyTests(unittest.TestCase):
    def make_root(self, directory: str) -> Path:
        root = Path(directory)
        for index, relative in enumerate(KEY_INPUTS):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"input-{index}\n", encoding="utf-8")
        return root

    def test_cache_identity_is_deterministic_across_mapping_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            first = {
                "vc_tools": "14.44",
                "compilers": {"Hostx64/x64/cl.exe": "a", "Hostx64/arm64/cl.exe": "b"},
                "cmake": "cmake version 4.1.0",
            }
            second = {
                "cmake": "cmake version 4.1.0",
                "compilers": {"Hostx64/arm64/cl.exe": "b", "Hostx64/x64/cl.exe": "a"},
                "vc_tools": "14.44",
            }

            self.assertEqual(
                MODULE.cache_identity(root, "x64-windows", first),
                MODULE.cache_identity(root, "x64-windows", second),
            )

    def test_cache_identity_segregates_triplets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            x64_key, x64_prefix = MODULE.cache_identity(root, "x64-windows", {})
            arm64_key, arm64_prefix = MODULE.cache_identity(root, "arm64-windows", {})

        self.assertNotEqual(x64_key, arm64_key)
        self.assertEqual("edr-vcpkg-v3-x64-windows-", x64_prefix)
        self.assertEqual("edr-vcpkg-v3-arm64-windows-", arm64_prefix)
        self.assertTrue(x64_key.startswith(x64_prefix))
        self.assertTrue(arm64_key.startswith(arm64_prefix))

    def test_cache_identity_rotates_for_every_owned_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            baseline, _ = MODULE.cache_identity(
                root, "x64-windows", {"vc_tools": "14.44", "cmake": "cmake version 4.1.0"}
            )

            changed_toolchain, _ = MODULE.cache_identity(
                root, "x64-windows", {"vc_tools": "14.45", "cmake": "cmake version 4.1.0"}
            )
            self.assertNotEqual(baseline, changed_toolchain)

            for relative in KEY_INPUTS:
                with self.subTest(relative=relative):
                    path = root / relative
                    original = path.read_bytes()
                    path.write_bytes(original + b"changed\n")
                    changed, _ = MODULE.cache_identity(
                        root,
                        "x64-windows",
                        {"vc_tools": "14.44", "cmake": "cmake version 4.1.0"},
                    )
                    self.assertNotEqual(baseline, changed)
                    path.write_bytes(original)

    def test_main_writes_key_and_restore_prefix_to_github_output(self):
        toolchain = {"vc_tools": "14.44", "cmake": "cmake version 4.1.0"}
        root = SCRIPT.resolve().parents[1]
        expected_key, expected_prefix = MODULE.cache_identity(
            root, "x64-windows", toolchain
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github-output"
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}, clear=True), \
                    mock.patch.object(sys, "argv", [str(SCRIPT), "--triplet", "x64-windows"]), \
                    mock.patch.object(MODULE, "windows_toolchain", return_value=toolchain):
                MODULE.main()

            self.assertEqual(
                [f"key={expected_key}", f"restore-prefix={expected_prefix}"],
                output.read_text(encoding="utf-8").splitlines(),
            )

    def test_cache_identity_rejects_bad_triplet_and_missing_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            with self.assertRaisesRegex(ValueError, "Unsupported dependency triplet"):
                MODULE.cache_identity(root, "x86-windows", {})

            (root / "dependencies.lock.json").unlink()
            with self.assertRaises(FileNotFoundError):
                MODULE.cache_identity(root, "x64-windows", {})

    def test_windows_toolchain_requires_explicit_visual_studio_environment(self):
        complete = {
            "VCToolsVersion": "14.44",
            "WindowsSDKVersion": "10.0.26100.0",
            "VCToolsInstallDir": "C:/BuildTools/VC/Tools/MSVC/14.44",
        }
        for missing in complete:
            with self.subTest(missing=missing):
                environment = {name: value for name, value in complete.items() if name != missing}
                with mock.patch.dict(os.environ, environment, clear=True):
                    with self.assertRaisesRegex(ValueError, rf"missing: .*{missing}"):
                        MODULE.windows_toolchain()

    def test_windows_toolchain_hashes_selected_and_host_compiler_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            tools_root = root / "vs-tools"
            selected_compiler = root / "native" / "cl.exe"
            host_compiler = tools_root / "bin" / "Hostx64" / "x64" / "cl.exe"
            selected_compiler.parent.mkdir(parents=True)
            host_compiler.parent.mkdir(parents=True)
            selected_compiler.write_bytes(b"selected-v1")
            host_compiler.write_bytes(b"host-v1")
            environment = {
                "VCToolsVersion": "14.44.35207",
                "WindowsSDKVersion": "10.0.26100.0",
                "VCToolsInstallDir": str(tools_root),
                "ImageOS": "win11-arm64",
                "ImageVersion": "20260906.161.1",
            }
            cmake_result = subprocess.CompletedProcess(
                ["cmake", "--version"], 0, stdout="cmake version 4.1.0\n", stderr=""
            )

            powershell_result = subprocess.CompletedProcess(
                ["pwsh", "--version"], 0, stdout="PowerShell 7.6.4\n", stderr=""
            )
            def tool_version(command, **kwargs):
                return powershell_result if command[0] == "pwsh" else cmake_result

            with mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(MODULE.shutil, "which", return_value=str(selected_compiler)), \
                    mock.patch.object(MODULE.subprocess, "run", side_effect=tool_version) as run:
                initial_toolchain = MODULE.windows_toolchain()
                initial_key, _ = MODULE.cache_identity(root, "x64-windows", initial_toolchain)

                with mock.patch.dict(os.environ, {'GITHUB_REF': 'refs/tags/win_3.2.999', 'GITHUB_RUN_ID': '123'}):
                    self.assertEqual(initial_toolchain, MODULE.windows_toolchain())

                # Regression: the ARM64 image changed every package ABI while
                # cl.exe/CMake/SDK and the old shared Release key stayed equal.
                with mock.patch.dict(os.environ, {'ImageVersion': '20260914.169.1'}):
                    image_toolchain = MODULE.windows_toolchain()
                powershell_result.stdout = "PowerShell 7.6.6\n"
                powershell_toolchain = MODULE.windows_toolchain()
                powershell_result.stdout = "PowerShell 7.6.4\n"
                for triplet in ("x64-windows", "arm64-windows"):
                    original = MODULE.cache_identity(root, triplet, initial_toolchain)
                    for changed in (image_toolchain, powershell_toolchain):
                        with self.subTest(triplet=triplet, changed=changed):
                            self.assertNotEqual(original[0], MODULE.cache_identity(root, triplet, changed)[0])
                            self.assertEqual(original[1], MODULE.cache_identity(root, triplet, changed)[1])

                selected_compiler.write_bytes(b"selected-v2")
                selected_toolchain = MODULE.windows_toolchain()
                selected_key, _ = MODULE.cache_identity(root, "x64-windows", selected_toolchain)

                selected_compiler.write_bytes(b"selected-v1")
                host_compiler.write_bytes(b"host-v2")
                host_toolchain = MODULE.windows_toolchain()
                host_key, _ = MODULE.cache_identity(root, "x64-windows", host_toolchain)

            self.assertNotEqual(initial_toolchain["selected_compiler"],
                                selected_toolchain["selected_compiler"])
            self.assertNotEqual(initial_key, selected_key)
            self.assertNotEqual(initial_toolchain["compilers"], host_toolchain["compilers"])
            self.assertNotEqual(initial_key, host_key)
            self.assertEqual(12, run.call_count)
            run.assert_any_call(
                ["cmake", "--version"], check=True, capture_output=True,
                text=True, timeout=15,
            )
            run.assert_any_call(
                ["pwsh", "--version"], check=True, capture_output=True,
                text=True, timeout=15,
            )


if __name__ == "__main__":
    unittest.main()
