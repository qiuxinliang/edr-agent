"""Exercise the real CMake gate dependency graph, not Windows OS behavior.

Tiny executables isolate the CI scheduling regression from product dependencies.
The actual response tests still run natively in the normal Windows CTest gate.
"""
import json
import os
from pathlib import Path
import re
import shutil
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
    "behavior_record_alert_proto_contract",
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


def copy_sqlite_header_family(source: Path, destination: Path) -> set[str]:
    """Copy SQLite's public header and any vcpkg-generated companion headers."""
    headers = sorted(source.glob("sqlite3*.h"))
    names = {header.name for header in headers}
    if "sqlite3.h" not in names:
        raise AssertionError(f"SQLite include directory has no sqlite3.h: {source}")
    destination.mkdir(parents=True, exist_ok=True)
    for header in headers:
        shutil.copy2(header, destination / header.name)
    return names


class WindowsReleaseGateTests(unittest.TestCase):
    def run_command(self, *args, success=True, env=None):
        result = subprocess.run(args, capture_output=True, text=True, timeout=90, env=env)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_sqlite_header_relocation_includes_vcpkg_companion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            (source / "sqlite3.h").write_text(
                '#include "sqlite3-vcpkg-config.h"\n', encoding="utf-8")
            (source / "sqlite3-vcpkg-config.h").write_text(
                '#define SQLITE3_VCPKG_TEST 1\n', encoding="utf-8")
            self.assertEqual(
                {"sqlite3.h", "sqlite3-vcpkg-config.h"},
                copy_sqlite_header_family(source, destination))
            self.assertTrue((destination / "sqlite3-vcpkg-config.h").is_file())

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
        for name in ("request_signing", "storage_queue_sqlite_contract", "detection_sensor_bridge",
                     "behavior_record_alert_proto_contract", "command_signature_cross_language"):
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

    def test_keep_going_builds_independent_targets_but_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            lines = [
                "cmake_minimum_required(VERSION 3.19)", "project(KeepGoing C)",
                'add_custom_target(broken COMMAND "${CMAKE_COMMAND}" -E false)',
            ]
            targets = ("fd_installer_worker", "fd_headless_uninstaller")
            for target in targets:
                lines += [
                    f"add_executable({target} main.c)",
                    f'add_custom_command(TARGET {target} POST_BUILD COMMAND "${{CMAKE_COMMAND}}" '
                    f'-E touch "${{CMAKE_BINARY_DIR}}/{target}.built")',
                ]
            (source / "CMakeLists.txt").write_text("\n".join(lines), encoding="utf-8")
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            self.run_command("cmake", "--build", str(build), "--target", "broken", *targets,
                             "--parallel", "1", "--", "-k", "0", success=False)
            for target in targets:
                self.assertTrue((build / f"{target}.built").is_file(), target)

    def test_storage_queue_windows_branch_rejects_posix_calls(self):
        """Compile the actual test's Windows branch; not a Windows runtime test.

        Native Windows uses its real CRT/SDK. Other hosts supply declarations
        only and poison POSIX names their libc would otherwise silently accept.
        """
        cmake_source = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        begin = cmake_source.index("function(edr_apply_common_warnings")
        end = cmake_source.index('option(EDR_BUILD_TESTS', begin)
        tests_source = (ROOT / "tests/CMakeLists.txt").read_text(encoding="utf-8")
        definitions = re.search(r'target_compile_definitions\(test_storage_queue_sqlite PRIVATE[^)]*\)', tests_source)
        self.assertIsNotNone(definitions)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            (source / "windows.h").write_text(
                'void Sleep(unsigned long);\n', encoding="utf-8")
            (source / "process.h").write_text(
                'int _getpid(void);\nint _putenv_s(const char *, const char *);\n', encoding="utf-8")
            (source / "no_posix.h").write_text(
                '#include <stdlib.h>\n#pragma GCC poison setenv unsetenv getpid usleep\n',
                encoding="utf-8")
            lines = [
                'cmake_minimum_required(VERSION 3.20)', 'project(QueueWindowsBranch C)',
                'set(CMAKE_C_STANDARD 11)', 'set(CMAKE_EXPORT_COMPILE_COMMANDS ON)',
                # Compiler/Ninja discovery has already finished at project().
                'if(QUEUE_PREFIX_ONLY)',
                '  set(CMAKE_FIND_USE_CMAKE_SYSTEM_PATH FALSE)',
                '  set(CMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH FALSE)',
                '  set(CMAKE_FIND_USE_CMAKE_PATH FALSE)',
                '  set(CMAKE_FIND_USE_PACKAGE_ROOT_PATH FALSE)',
                'endif()',
                'find_package(SQLite3 REQUIRED)', cmake_source[begin:end],
                f'add_library(queue_probe OBJECT "{(ROOT / "tests/test_storage_queue_sqlite.c").as_posix()}")',
                definitions[0].replace("test_storage_queue_sqlite", "queue_probe"),
                f'target_include_directories(queue_probe PRIVATE "{(ROOT / "include").as_posix()}")',
                'if(TARGET SQLite3::SQLite3)',
                '  target_link_libraries(queue_probe PRIVATE SQLite3::SQLite3)',
                'else()', '  target_link_libraries(queue_probe PRIVATE SQLite::SQLite3)', 'endif()',
                'edr_apply_test_warnings(queue_probe)',
                'if(NOT WIN32)',
                '  target_compile_definitions(queue_probe PRIVATE _WIN32)',
                '  target_include_directories(queue_probe PRIVATE "${CMAKE_SOURCE_DIR}")',
                '  target_compile_options(queue_probe PRIVATE -Werror=implicit-function-declaration -include "${CMAKE_SOURCE_DIR}/no_posix.h")',
                'endif()',
                # Inspect the actual shared MSVC flags without passing them to
                # a non-MSVC compiler. This target is never built.
                'set(MSVC TRUE)', 'add_library(msvc_options OBJECT EXCLUDE_FROM_ALL "options.c")',
                'edr_apply_test_warnings(msvc_options)',
            ]
            (source / "options.c").write_text('int options(void) { return 0; }\n', encoding="utf-8")
            (source / "CMakeLists.txt").write_text("\n".join(lines), encoding="utf-8")
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            commands = json.loads((build / "compile_commands.json").read_text(encoding="utf-8"))
            flags = next(row["command"] for row in commands if row["file"].endswith("options.c"))
            self.assertIn("/we4013", flags)
            self.assertIn("/UNDEBUG", flags)
            self.run_command("cmake", "--build", str(build), "--target", "queue_probe")

            # Reproduce CI: a real SQLite package exists, but outside every
            # default search directory. Do not let a host SDK mask lost inputs.
            cache = dict(re.findall(r'^([A-Za-z0-9_]+):[^=\r\n]+=([^\r\n]*)$',
                                   (build / "CMakeCache.txt").read_text(encoding="utf-8"), re.MULTILINE))
            prefix = source / "relocated sqlite"
            (prefix / "lib").mkdir(parents=True)
            sqlite_include = Path(cache["SQLite3_INCLUDE_DIR"])
            copied_headers = copy_sqlite_header_family(sqlite_include, prefix / "include")
            source_companions = {
                header.name for header in sqlite_include.glob("sqlite3*.h")
                if header.name != "sqlite3.h"
            }
            self.assertTrue(source_companions.issubset(copied_headers))
            library = Path(cache["SQLite3_LIBRARY"])
            shutil.copy2(library, prefix / "lib" / library.name)
            isolated_env = os.environ.copy()
            isolated_env["CMAKE_PREFIX_PATH"] = str(source / "missing-prefix")
            isolated_env["CMAKE_INCLUDE_PATH"] = ""
            isolated_env["CMAKE_LIBRARY_PATH"] = ""
            missing = self.run_command(
                "cmake", "-S", str(source), "-B", str(source / "missing-build"), "-G", "Ninja",
                "-DQUEUE_PREFIX_ONLY=ON", env=isolated_env, success=False)
            self.assertIn("Could NOT find SQLite3", missing.stdout + missing.stderr)
            isolated_env["CMAKE_PREFIX_PATH"] = str(prefix)
            isolated_build = source / "isolated-build"
            self.run_command("cmake", "-S", str(source), "-B", str(isolated_build), "-G", "Ninja",
                             "-DQUEUE_PREFIX_ONLY=ON", env=isolated_env)
            self.run_command("cmake", "--build", str(isolated_build), "--target", "queue_probe",
                             env=isolated_env)
            isolated_cache = (isolated_build / "CMakeCache.txt").read_text(encoding="utf-8")
            self.assertIn(f"SQLite3_INCLUDE_DIR:PATH={prefix.as_posix()}/include", isolated_cache)

    def test_workflows_use_shared_build_and_run_gate(self):
        for workflow in ("edr-agent-client-build.yml", "edr-agent-client-release.yml"):
            source = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
            targets = re.search(r'\$(?:build|release)Targets = @\((.*?)\)', source, re.DOTALL)
            self.assertIsNotNone(targets)
            self.assertIn("'windows_release_gate_tests'", targets[1])
            self.assertIn("'forensic_collector'", targets[1])
            self.assertIn("'fd_installer_worker'", targets[1])
            self.assertIn("'fd_headless_uninstaller'", targets[1])
            self.assertNotIn("'test_", targets[1])
            self.assertRegex(source, r'cmake --build build --config Release --target \$(?:build|release)Targets[^\n]* -- -k 0\n\s+if \(\$LASTEXITCODE -ne 0\)')
            self.assertIn("python tests/test_pcre2_cmake_gate.py PCRE2CMakeGateTests.test_static_matcher_header_wins_over_shared_dependency_prefix -v", source)
            self.assertIn('throw "Windows PCRE2 header isolation regression failed"', source)
            probe_step = re.search(r'- name: Verify release gate build dependencies\n(.*?)(?=\n      - name:)',
                                   source, re.DOTALL)
            self.assertIsNotNone(probe_step)
            prefix_var = "VCPKG_INSTALLED_ROOT" if "release" in workflow else "VCPKG_INSTALLED_X64"
            self.assertIn('CMAKE_PREFIX_PATH: ${{ env.' + prefix_var + ' }}', probe_step[1])
            self.assertIn("ctest --test-dir build -C Release --output-on-failure --no-tests=error --label-regex '^windows-release-gate$'", source)

        source = (ROOT / ".github/workflows/edr-agent-ci.yml").read_text(encoding="utf-8")
        build_step = re.search(r'- name: Build\n(.*?)(?=\n      - name:)', source, re.DOTALL)
        self.assertIsNotNone(build_step)
        self.assertIn('CMAKE_PREFIX_PATH: ${{ github.workspace }}/vcpkg_installed/x64-windows', build_step[1])
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
