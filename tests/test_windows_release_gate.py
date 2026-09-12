"""Exercise the real CMake gate dependency graph, not Windows OS behavior.

Tiny executables isolate the CI scheduling regression from product dependencies.
The actual response tests still run natively in the normal Windows CTest gate.
"""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "cmake" / "WindowsReleaseGate.cmake"
RUNTIME_GATE = ROOT / "cmake" / "AgentRuntimeGate.cmake"
LABEL = "^windows-release-gate$"
WINDOWS_EXPECTED = {
    "agent_update_command_contract", "agent_update_packaging_contract",
    "windows_headless_runtime_contract", "command_registry_and_payload_contract",
    "command_process_identity_and_receipts",
    "pmfe_pe_architectures", "windows_native_manifest_behavior",
    "windows_native_uninstall_behavior", "process_generation_same_handle_command_line",
    "kernel_file_io_identity",
    "response_file_security_behavior", "response_forensic_path_contract",
    "windows_isolation_mock_behavior", "windows_install_compatibility_behavior", "http_telemetry_budget",
}
RUNTIME_EXPECTED = {
    "command_inbox_persistence", "request_signing", "http_retry_contract", "command_result_json_contract",
    "event_bus_wait_and_mpmc", "event_batch_max_age", "response_capability_manifest_contract",
    "python_installer_config_contract",
    "detection_decision_combo", "detection_regression_scenarios",
    "detection_profile_and_trigger_modes", "detection_sensor_bridge",
    "webshell_semantic_rules", "pmfe_scan_detail_format", "command_signature_cross_language",
    "storage_queue_sqlite_contract", "p0_source_only_durable_contract", "p0_rule_ir_record_golden",
}
EXPECTED = WINDOWS_EXPECTED | RUNTIME_EXPECTED
PREVIOUSLY_UNBUILT = {
    "test_process_generation_windows", "test_response_file_security",
    "test_response_forensic_paths",
}


class WindowsReleaseGateTests(unittest.TestCase):
    def run_command(self, *args, success=True):
        result = subprocess.run(args, capture_output=True, text=True, timeout=90)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def fixture(self, directory, missing_target="", missing_test="", failing_test=""):
        pairs = re.findall(r'^edr_windows_release_gate\((\w+) (\w+|"")\)$',
                           GATE.read_text(encoding="utf-8"), re.MULTILINE)
        self.assertEqual({name for name, _ in pairs}, WINDOWS_EXPECTED)
        runtime_pairs = re.findall(r'^\s*edr_agent_runtime_gate\((\w+) (\w+)\)$',
                                   RUNTIME_GATE.read_text(encoding="utf-8"), re.MULTILINE)
        self.assertEqual({name for name, _ in runtime_pairs}, RUNTIME_EXPECTED)
        pairs += runtime_pairs
        source = Path(directory)
        (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        lines = ["cmake_minimum_required(VERSION 3.19)", "project(GateFixture C)", "enable_testing()",
                 "set(OpenSSL_FOUND TRUE)", "set(SQLite3_FOUND TRUE)", "set(EDR_PCRE2_AVAILABLE TRUE)"]
        for name, target in pairs:
            if target != '""' and target != missing_target:
                lines.append(f"add_executable({target} main.c)")
            if name != missing_test:
                command = target if target != '""' else '"${CMAKE_COMMAND}" -E true'
                if name == failing_test:
                    command = '"${CMAKE_COMMAND}" -E false'
                lines.append(f"add_test(NAME {name} COMMAND {command})")
        lines.append(f'include("{RUNTIME_GATE.as_posix()}")')
        lines.append(f'include("{GATE.as_posix()}")')
        (source / "CMakeLists.txt").write_text("\n".join(lines), encoding="utf-8")
        return source, source / "build", pairs

    def test_build_target_covers_every_selected_test_in_both_generators(self):
        for generator in ("Ninja", "Ninja Multi-Config"):
            with self.subTest(generator=generator), tempfile.TemporaryDirectory() as directory:
                source, build, pairs = self.fixture(directory)
                self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", generator,
                                 "-DCMAKE_BUILD_TYPE=Release")
                if generator == "Ninja":
                    old_targets = [target for _, target in pairs if target != '""' and target not in PREVIOUSLY_UNBUILT]
                    self.run_command("cmake", "--build", str(build), "--target", *old_targets)
                    failed = self.run_command("ctest", "--test-dir", str(build), "-C", "Release",
                                              "-L", LABEL, "--no-tests=error", success=False)
                    self.assertEqual(failed.stdout.count("***Not Run"), 3, failed.stdout + failed.stderr)
                self.run_command("cmake", "--build", str(build), "--config", "Release",
                                 "--target", "windows_release_gate_tests", "--parallel", "2")
                listed = self.run_command("ctest", "--test-dir", str(build), "-C", "Release",
                                          "-L", LABEL, "--show-only=json-v1")
                tests = json.loads(listed.stdout)["tests"]
                self.assertEqual({test["name"] for test in tests}, EXPECTED)
                for test in tests:
                    self.assertTrue(test.get("command") and Path(test["command"][0]).is_file(), test)
                passed = self.run_command("ctest", "--test-dir", str(build), "-C", "Release",
                                          "-L", LABEL, "--no-tests=error", "--output-on-failure")
                self.assertIn("100% tests passed", passed.stdout)

    def test_missing_target_fails_at_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            source, build, _ = self.fixture(directory, missing_target="test_response_file_security")
            result = self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja", success=False)
            self.assertIn("Windows release gate executable target is missing", result.stderr)

    def test_missing_registration_fails_at_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            source, build, _ = self.fixture(directory, missing_test="response_forensic_path_contract")
            result = self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja", success=False)
            self.assertIn("Windows release gate test is not registered", result.stderr)

    def test_missing_runtime_target_fails_at_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            source, build, _ = self.fixture(directory, missing_target="test_request_signing")
            result = self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja", success=False)
            self.assertIn("Agent runtime gate executable target is missing", result.stderr)

    def test_security_queue_and_detection_failures_block_both_gate_labels(self):
        # Inject failures in each newly required group, not just check labels in text.
        for name in ("request_signing", "storage_queue_sqlite_contract", "detection_sensor_bridge"):
            with self.subTest(test=name), tempfile.TemporaryDirectory() as directory:
                source, build, _ = self.fixture(directory, failing_test=name)
                self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
                self.run_command("cmake", "--build", str(build), "--target", "windows_release_gate_tests", "--parallel", "2")
                for label in (LABEL, "^agent-runtime-gate$"):
                    result = self.run_command("ctest", "--test-dir", str(build), "-L", label,
                                              "--no-tests=error", "--output-on-failure", success=False)
                    self.assertIn(name + " (Failed)", result.stdout + result.stderr)

    def test_empty_selection_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            source, build, _ = self.fixture(directory)
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            self.run_command("ctest", "--test-dir", str(build), "-L", "^no-such-gate$",
                             "--no-tests=error", success=False)

    def test_workflows_use_shared_build_and_run_gate(self):
        for workflow in ("edr-agent-client-build.yml", "edr-agent-client-release.yml"):
            source = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
            targets = re.search(r'\$(?:build|release)Targets = @\((.*?)\)', source, re.DOTALL)
            self.assertIsNotNone(targets)
            self.assertIn("'windows_release_gate_tests'", targets[1])
            self.assertIn("'forensic_collector'", targets[1])
            self.assertNotIn("'test_", targets[1])
            self.assertIn("cmake --build build --config Release --target", source)
            self.assertIn("ctest --test-dir build -C Release --output-on-failure --no-tests=error --label-regex '^windows-release-gate$'", source)

        source = (ROOT / ".github/workflows/edr-agent-ci.yml").read_text(encoding="utf-8")
        self.assertIn("'windows_release_gate_tests'", source)
        self.assertNotIn("'test_", source)
        self.assertIn("ctest --test-dir build -C Release --output-on-failure --no-tests=error --label-regex '^windows-release-gate$'", source)

    def test_monorepo_checks_out_pinned_agent_and_runs_nonempty_gates(self):
        workflow = ROOT.parent / ".github/workflows/edr-agent-ci.yml"
        if not (ROOT.parent / ".gitmodules").is_file():
            self.skipTest("standalone Agent checkout has no monorepo integration workflow")
        source = workflow.read_text(encoding="utf-8")
        checkouts = re.findall(r'uses: actions/checkout@[^\n]+\n(.*?)(?=\n      -|\Z)', source, re.DOTALL)
        self.assertTrue(checkouts)
        self.assertTrue(all("submodules: recursive" in block for block in checkouts))
        self.assertNotIn("EDR_BUILD_TESTS=OFF", source)
        self.assertNotIn("test_ave_behavior_gates", source)
        self.assertIn("git submodule status edr-agent", source)
        self.assertEqual(source.count("--no-tests=error"), 3)
        self.assertIn("--target agent_runtime_gate_tests", source)


if __name__ == "__main__":
    unittest.main()
