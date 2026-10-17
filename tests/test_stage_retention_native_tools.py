"""Offline PE/closure packaging regressions: no native process or network."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_tools", ROOT / "scripts/stage_retention_native_tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)


def pe(path, arch="arm64"):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = bytearray(512)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 60, 128)
    struct.pack_into("<4sH", raw, 128, b"PE\0\0", TOOLS.MACHINES[arch])
    struct.pack_into("<H", raw, 148, 240)
    struct.pack_into("<H", raw, 152, 0x20b)
    path.write_bytes(raw)
    return path


def dumpbin_output(*names):
    return "\n".join(["Dump of file fixture", "File Type: EXECUTABLE IMAGE", "",
                      "  Image has the following dependencies:", "", *names,
                      "", "  Summary", "        1000 .text", ""])


class NativeToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.build = self.repo / "contract-build"
        self.exe = pe(self.build / "tests" / TOOLS.TOOL)
        self.prefix = self.repo / "vcpkg_installed" / "arm64-windows"
        self.sqlite = pe(self.prefix / "bin" / "sqlite3.dll")
        self.redist = self.root / "MSVC" / "14.50.00000"
        self.crt = self.redist / "arm64" / "Microsoft.VC145.CRT"
        self.runtime = pe(self.crt / "vcruntime140.dll")
        self.compiler = self.root / "compiler" / "cl.exe"
        self.compiler.parent.mkdir()
        self.compiler.write_bytes(b"synthetic compiler identity")
        self.dumpbin = self.compiler.with_name("dumpbin.exe")
        self.dumpbin.write_bytes(b"synthetic dumpbin identity")
        (self.build / "CMakeCache.txt").write_text(
            f"CMAKE_C_COMPILER:FILEPATH={self.compiler}\nCMAKE_BUILD_TYPE:STRING=Release\n", encoding="utf-8")
        for path in (self.repo / "dependencies.lock.json", self.repo / "vcpkg.json",
                     self.prefix.parent / "vcpkg" / "status"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic locked identity", encoding="utf-8")
        self.args = argparse.Namespace(repo=self.repo, build_dir=self.build,
            dependency_prefix=self.prefix, msvc_redist_root=self.redist,
            compiler=self.compiler, dumpbin=self.dumpbin, output=self.root / "output",
            arch="arm64", source_sha="a" * 40, run_id="123", run_attempt="1")
        self.dependencies = {
            TOOLS.TOOL: ["sqlite3.dll", "vcruntime140.dll", "kernel32.dll"],
            "sqlite3.dll": ["vcruntime140.dll", "kernel32.dll"],
            "vcruntime140.dll": ["api-ms-win-crt-runtime-l1-1-0.dll", "kernel32.dll"]}

    def stage(self):
        # Only the external dumpbin boundary is replaced. Actual PE bytes,
        # closure selection, copying, hashes and manifest verification execute.
        def run(argv, **kwargs):
            self.assertEqual(argv[:3], [str(self.dumpbin), "/NOLOGO", "/DEPENDENTS"])
            output = dumpbin_output(*self.dependencies[Path(argv[3]).name])
            return argparse.Namespace(returncode=0, stdout=output.encode(), stderr=b"")
        with patch.object(TOOLS.subprocess, "run", side_effect=run):
            return TOOLS.stage(self.args)

    def test_exact_transitive_closure_and_provenance(self):
        manifest = self.stage()
        self.assertEqual({f["name"] for f in manifest["files"]},
                         {TOOLS.TOOL, "sqlite3.dll", "vcruntime140.dll"})
        self.assertEqual(manifest, json.loads((self.args.output / "manifest.json").read_text()))
        self.assertEqual(manifest["source_sha"], "a" * 40)
        self.assertEqual(manifest["run_id"], "123")
        self.assertEqual(manifest["equal_input_comparison_status"], "not_run_at_staging")
        self.assertEqual(manifest["purpose"], "private_isolated_storage_diagnostics")
        self.assertEqual(manifest["prior_contract_status"], "passed")
        self.assertIs(manifest["native_contracts_passed_before_staging"], True)
        self.assertNotIn("allowed_diagnostic_argv", manifest)
        self.assertFalse(manifest["product_payload"])
        self.assertEqual(manifest["provenance"]["compiler"]["sha256"], TOOLS.digest(self.compiler))
        self.assertEqual(manifest["provenance"]["vcpkg_status"]["sha256"], TOOLS.digest(self.prefix.parent / "vcpkg" / "status"))
        self.assertFalse((self.args.output / "kernel32.dll").exists())
        TOOLS.verify_stage(self.args.output, manifest)

    def test_failed_gate_artifact_is_explicitly_not_acceptance(self):
        self.args.prior_contract_status = "failed"
        manifest = self.stage()
        self.assertEqual(manifest["purpose"], "private_failed_gate_diagnostics")
        self.assertEqual(manifest["prior_contract_status"], "failed")
        self.assertIs(manifest["native_contracts_passed_before_staging"], False)
        self.assertEqual(manifest["native_contract_status_authority"],
                         "prior_failed_workflow_step_not_parsed_by_stager")
        self.assertIn("not_long_soak_or_release_acceptance", manifest["limitations"])
        self.assertEqual(manifest["equal_input_comparison_status"], "not_run_at_staging")
        self.assertFalse(manifest["product_payload"])
        self.assertEqual({f["name"] for f in manifest["files"]},
                         {TOOLS.TOOL, "sqlite3.dll", "vcruntime140.dll"})
        TOOLS.verify_stage(self.args.output, manifest)
        copied = self.args.output / "sqlite3.dll"
        original = copied.read_bytes()
        copied.write_bytes(original[:-1] + b"x")
        with self.assertRaisesRegex(ValueError, "hash/size mismatch"):
            TOOLS.verify_stage(self.args.output, manifest)

    def test_failed_gate_diagnostics_are_exactly_two_fixed_single_case_commands(self):
        self.args.prior_contract_status = "failed"
        manifest = self.stage()
        self.assertEqual(manifest["allowed_diagnostic_argv"],
                         [["--sliced-reclaim-contract"], ["--capacity-reclaim-contract"]])
        self.assertIn("isolated_sliced_and_capacity_reclaim_reproduction_only",
                      manifest["limitations"])
        self.assertNotIn(["--suite", "retention"], manifest["allowed_diagnostic_argv"])
        self.assertNotIn(["--alert-parent-soak", "7380"], manifest["allowed_diagnostic_argv"])
        self.assertIs(manifest["native_contracts_passed_before_staging"], False)

    def test_unknown_prior_gate_state_cannot_be_staged(self):
        for status in ("failure", "skipped", "cancelled", "", None):
            with self.subTest(status=status):
                self.args.prior_contract_status = status
                with self.assertRaisesRegex(ValueError, "status must be passed or failed"):
                    self.stage()
                self.assertFalse(self.args.output.exists())

    def test_cli_defaults_passed_and_accepts_explicit_failed(self):
        argv = ["stage_retention_native_tools.py"]
        for flag in ("repo", "build-dir", "dependency-prefix", "msvc-redist-root", "compiler", "dumpbin", "output",
                     "arch", "source-sha", "run-id", "run-attempt"):
            argv.extend(["--" + flag, str(getattr(self.args, flag.replace("-", "_")))])
        for status in (None, "failed"):
            expected = status or "passed"
            command = argv + (["--prior-contract-status", status] if status else [])
            # Only CLI parsing is under test here; the actual manifest/file
            # owner is exercised by the real stage() tests above.
            result = {"source_sha": self.args.source_sha, "arch": self.args.arch, "files": [],
                      "purpose": "fixture", "prior_contract_status": expected,
                      "native_contracts_passed_before_staging": expected == "passed"}
            with self.subTest(status=status), patch("sys.argv", command), \
                    patch.object(TOOLS, "stage", return_value=result) as stage, patch("builtins.print"):
                TOOLS.main()
                self.assertEqual(stage.call_args.args[0].prior_contract_status, expected)

    def test_missing_compiled_executable_has_no_fallback_in_either_status(self):
        self.exe.unlink()
        # A similarly named file in a different build location is not an owner.
        pe(self.build / "Release" / TOOLS.TOOL)
        for status in ("passed", "failed"):
            self.args.prior_contract_status = status
            with self.subTest(status=status), self.assertRaises(FileNotFoundError):
                self.stage()
            self.assertFalse(self.args.output.exists())

    def test_both_native_architectures(self):
        self.args.arch = "amd64"
        self.sqlite.parent.parent.rename(self.prefix.with_name("x64-windows"))
        self.args.dependency_prefix = self.prefix.with_name("x64-windows")
        self.crt.parent.rename(self.redist / "x64")
        for path in (self.exe, self.args.dependency_prefix / "bin" / "sqlite3.dll",
                     self.redist / "x64" / self.crt.name / "vcruntime140.dll"):
            pe(path, "amd64")
        self.assertEqual(self.stage()["arch"], "amd64")

    def test_wrong_architecture_exe_and_dependency(self):
        for status in ("passed", "failed"):
            self.args.prior_contract_status = status
            for path in (self.exe, self.sqlite, self.runtime):
                with self.subTest(status=status, file=path.name):
                    pe(path, "amd64")
                    with self.assertRaisesRegex(ValueError, "architecture mismatch"):
                        self.stage()
                    self.assertFalse(self.args.output.exists())
                    pe(path)

    def test_failed_gate_keeps_dependency_path_and_release_validation(self):
        self.args.prior_contract_status = "failed"
        self.dependencies[TOOLS.TOOL] = ["missing.dll", "kernel32.dll"]
        with self.assertRaisesRegex(ValueError, "Unresolved non-OS"):
            self.stage()
        self.dependencies[TOOLS.TOOL] = ["../outside.dll", "kernel32.dll"]
        with self.assertRaisesRegex(ValueError, "Invalid dependency name"):
            self.stage()
        self.dependencies[TOOLS.TOOL] = ["sqlite3.dll", "kernel32.dll"]
        (self.build / "CMakeCache.txt").write_text(
            f"CMAKE_C_COMPILER:FILEPATH={self.compiler}\nCMAKE_BUILD_TYPE:STRING=Debug\n")
        with self.assertRaisesRegex(ValueError, "Release contract"):
            self.stage()
        self.assertFalse(self.args.output.exists())

    def test_unknown_dependency_and_missing_sqlite_fail(self):
        for name in ("missing.dll", "api-ms-win-invented-l1-1-0.dll"):
            with self.subTest(dependency=name):
                self.dependencies[TOOLS.TOOL] = [name, "kernel32.dll"]
                with self.assertRaisesRegex(ValueError, "Unresolved non-OS"):
                    self.stage()
        self.dependencies[TOOLS.TOOL] = ["sqlite3.dll", "kernel32.dll"]
        self.sqlite.unlink()
        with self.assertRaisesRegex(ValueError, "Unresolved non-OS"):
            self.stage()

    def test_no_ambiguous_runtime_or_locked_root_collision(self):
        pe(self.prefix / "bin" / "vcruntime140.dll")
        with self.assertRaisesRegex(ValueError, "ambiguous across"):
            self.stage()
        (self.prefix / "bin" / "vcruntime140.dll").unlink()
        (self.crt.parent / "Microsoft.VC144.CRT").mkdir()
        with self.assertRaisesRegex(ValueError, "exactly one CRT"):
            self.stage()

    def test_dependency_paths_and_unrecognised_output_fail(self):
        for name in ("../evil.dll", "C:\\evil.dll", "evil.dll:stream", "no imports"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    TOOLS.parse_dependents(dumpbin_output(name))
        for output in ("", "File Type: DLL\nSummary", dumpbin_output("kernel32.dll") + "warning: fixture"):
            with self.assertRaises(ValueError):
                TOOLS.parse_dependents(output)

    def test_delay_load_dependencies_are_in_the_closure(self):
        output = dumpbin_output("kernel32.dll").replace("  Summary", "  Image has the following delay load dependencies:\n  sqlite3.dll\n\n  Summary")
        self.assertEqual(TOOLS.parse_dependents(output), ["kernel32.dll", "sqlite3.dll"])

    def test_symlink_or_parent_link_and_existing_output_fail(self):
        self.args.output.mkdir()
        with self.assertRaisesRegex(ValueError, "must be new"):
            self.stage()
        self.args.output.rmdir()
        alias = self.root / "alias"
        try:
            alias.symlink_to(self.prefix, target_is_directory=True)
        except OSError:
            self.skipTest("Host does not permit a symlink fixture")
        self.args.dependency_prefix = alias
        with self.assertRaisesRegex(ValueError, "Symlink/reparse"):
            self.stage()

    def test_changed_hash_extra_file_and_manifest_path_rejected(self):
        manifest = self.stage()
        copied = self.args.output / "sqlite3.dll"
        original = copied.read_bytes()
        copied.write_bytes(original[:-1] + b"x")
        with self.assertRaisesRegex(ValueError, "hash/size mismatch"):
            TOOLS.verify_stage(self.args.output, manifest)
        copied.write_bytes(original)
        extra = self.args.output / "unrequested.txt"
        extra.write_text("fixture")
        with self.assertRaisesRegex(ValueError, "extra files"):
            TOOLS.verify_stage(self.args.output, manifest)
        extra.unlink()
        manifest["files"][0]["name"] = "../escape.dll"
        with self.assertRaises(ValueError):
            TOOLS.verify_stage(self.args.output, manifest)

    def test_source_change_after_inspection_never_seals_a_manifest(self):
        original_digest = TOOLS.digest
        mutated = False

        def changing_digest(path):
            nonlocal mutated
            value = original_digest(path)
            if path == self.sqlite and not mutated:
                data = path.read_bytes()
                path.write_bytes(data[:-1] + b"x")
                mutated = True
            return value

        with patch.object(TOOLS, "digest", side_effect=changing_digest):
            with self.assertRaisesRegex(ValueError, "changed during staging"):
                self.stage()
        self.assertFalse((self.args.output / "manifest.json").exists())

    def test_compiler_and_release_build_owner_are_required(self):
        cache = self.build / "CMakeCache.txt"
        cache.write_text(f"CMAKE_C_COMPILER:FILEPATH={self.compiler}\nCMAKE_BUILD_TYPE:STRING=Debug\n")
        with self.assertRaisesRegex(ValueError, "Release contract"):
            self.stage()
        cache.write_text("CMAKE_C_COMPILER:FILEPATH=not-the-selected-compiler.exe\nCMAKE_BUILD_TYPE:STRING=Release\n")
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.stage()

    def test_workflow_upload_is_before_comparison_and_separate_from_release(self):
        workflow = (ROOT / ".github/workflows/evidence-retention-comparison.yml").read_text()
        contracts = workflow.index("- name: Build and execute actual native release")
        sliced = workflow.index("- name: Repeat the ARM64 bounded-reclaim contracts")
        stage = workflow.index("- name: Stage the compiled private native diagnostic tool")
        upload = workflow.index("- name: Preserve the private native diagnostic tool separately")
        comparison = workflow.index("- name: Equal-input native evidence")
        measurements = workflow.index("- name: Preserve measurements and failure logs only")
        self.assertLess(contracts, sliced)
        self.assertLess(sliced, stage)
        self.assertLess(stage, upload)
        self.assertLess(upload, comparison)
        contract_block = workflow[contracts:sliced]
        repeat_block = workflow[sliced:stage]
        stage_block = workflow[stage:upload]
        upload_block = workflow[upload:comparison]
        compare_block = workflow[comparison:measurements]
        self.assertIn("id: contracts", contract_block)
        self.assertIn("id: sliced", repeat_block)
        self.assertIn("if: ${{ matrix.arch == 'arm64' }}", repeat_block)
        self.assertIn("timeout-minutes: 5", repeat_block)
        self.assertIn("range(12)", repeat_block)
        self.assertIn("for label, argv in [('sliced', '--sliced-reclaim-contract'), ('capacity', '--capacity-reclaim-contract')]:", repeat_block)
        self.assertIn("case-{label}-{index:02d}.log", repeat_block)
        self.assertIn("timeout=180", repeat_block)
        self.assertIn("raise SystemExit(1)", repeat_block)
        self.assertIn("always() && (steps.contracts.outcome == 'success' || steps.contracts.outcome == 'failure')", stage_block)
        self.assertIn("'${{ steps.contracts.outcome }}' -eq 'success'", stage_block)
        self.assertIn("'${{ matrix.arch }}' -ne 'arm64' -or '${{ steps.sliced.outcome }}' -eq 'success'", stage_block)
        self.assertIn("{ 'passed' } else { 'failed' }", stage_block)
        self.assertIn("--prior-contract-status \"$prior\"", stage_block)
        self.assertIn("if ($prior -eq 'passed') { 'evidence-native-tools' } else { 'evidence-failed-gate-tools' }", stage_block)
        self.assertIn("artifact_prefix=$artifactPrefix", stage_block)
        self.assertIn("$env:GITHUB_OUTPUT", stage_block)
        self.assertIn("always() && steps.native-tools.outcome == 'success'", upload_block)
        self.assertIn("name: ${{ steps.native-tools.outputs.artifact_prefix }}-${{ matrix.arch }}-${{ github.sha }}", upload_block)
        self.assertIn("retention-days: 7", upload_block)
        self.assertIn("id: comparisons", compare_block)
        # No status override: Actions' normal success condition skips this
        # step after either native contract failure. Their failures stay fatal.
        self.assertNotIn("if:", compare_block)
        self.assertNotIn("continue-on-error:", workflow[contracts:measurements])
        self.assertIn("always() && (steps.comparisons.outcome == 'success' || steps.comparisons.outcome == 'failure')",
                      workflow[measurements:])


if __name__ == "__main__":
    unittest.main()
