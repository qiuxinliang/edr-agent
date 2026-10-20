"""Exercise the real CMake gate dependency graph and platform branch contracts.

Tiny executables isolate the CI scheduling regression from product dependencies.
The host admission probe only adapts OS locks/clock; it is not Windows emulation.
The actual tests still run natively in the normal Windows CTest gate.
"""
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "cmake" / "WindowsReleaseGate.cmake"
RUNTIME_GATE = ROOT / "cmake" / "AgentRuntimeGate.cmake"
LABEL = "^windows-release-gate$"
WINDOWS_EXPECTED = {
    "agent_update_command_contract", "agent_update_packaging_contract",
    "windows_agent_update_invocation",
    "windows_headless_runtime_contract", "command_registry_and_payload_contract",
    "windows_headless_log_stream_initialization",
    "command_process_identity_and_receipts",
    "pmfe_pe_architectures", "windows_native_manifest_behavior",
    "windows_native_uninstall_behavior", "process_generation_same_handle_command_line",
    "cmd_actor_and_script_artifact",
    "kernel_file_io_identity", "collector_file_read_windows", "etw_network_decode_native",
    "etw_process_payload_identity_native", "tdh_property_alias_order_contract",
    "collector_health_disposition_json",
    "security_event_time_native", "security_event_time_failures", "wfas_provider_native",
    "rtq_long_command_windows", "rtq_collector_behavior",
    "response_file_security_behavior", "response_forensic_path_contract",
    "windows_isolation_mock_behavior", "windows_install_compatibility_behavior", "http_telemetry_budget",
    "windows_release_collector_pe_closure", "windows_inplace_collector_transaction",
    "windows_update_physical_guard", "windows_updater_health_clock", "windows_inno_evidence_space",
    "windows_storage_space_preflight",
    "windows_installer_log_redaction",
    "windows_installer_acl_behavior", "windows_installer_health_behavior",
    "openssl_tls_handshake", "windows_task_exit_behavior", "windows_task_trace_environment",
    "validation_trace_contract",
    "egress_command_delivery_mtls", "egress_receiver_resources",
    "windows_headless_log_stream_initialization",
}
RUNTIME_EXPECTED = {
    "storage_physical_guard", "storage_space_preflight", "shell_session_stream_completeness",
    "authorized_local_query_contract", "evidence_startup_index_manifest",
    "installer_runtime_health_classification", "report_events_ack_contract",
    "command_inbox_persistence", "command_upload_outbox_recovery", "request_signing", "http_retry_contract", "socket_connect_timeout_contract", "command_result_json_contract",
    "event_bus_wait_and_mpmc", "event_batch_max_age", "response_capability_manifest_contract",
    "transport_durable_owner", "transport_v2_status_capacity", "ave_sdk_smoke",
    "ave_parent_integrity",
    "process_evidence_pending", "telemetry_admission", "windows_event_policy", "health_upload", "pid_history_pmfe_generation",
    "behavior_record_alert_proto_contract",
    "behavior_record_alert_emit_contract", "p0_direct_emit_suppression", "p0_deferred_snapshot",
    "process_tree_cache", "local_evidence_cache_candidate", "local_evidence_cache_migration",
    "local_evidence_cache_retention", "local_evidence_cache_pressure_continuation", "command_fact_transport",
    "python_installer_config_contract",
    "detection_decision_combo", "detection_regression_scenarios",
    "detection_profile_and_trigger_modes", "detection_sensor_bridge",
    "security_event_xml_bounded_command_line", "process_create_coalescer_state_machine",
    "webshell_semantic_rules", "pmfe_scan_detail_format", "command_signature_cross_language",
    "storage_queue_sqlite_contract", "p0_source_only_durable_contract", "p0_source_only_capacity_recovery",
    "p0_runtime_delivery", "p0_rule_ir_record_golden",
    "p0_rule_ir_exclusions", "p0_validation_matrix", "windows_rule_semantic_audit", "process_command_admission",
    "pmfe_same_region_evidence", "pmfe_injection_generation",
    "periodic_schedule_boundaries", "attack_surface_sampled_groups", "attack_surface_command_admission",
    "log_rotation_retention_and_restart", "conditional_policy_authenticated_cache",
    "runtime_rule_cold_start_schedule",
}
NON_WINDOWS_RUNTIME_EXPECTED = {"ave_parent_integrity_mutex"}
EXPECTED = WINDOWS_EXPECTED | RUNTIME_EXPECTED | (
    NON_WINDOWS_RUNTIME_EXPECTED if os.name != "nt" else set())
PREVIOUSLY_UNBUILT = {
    "test_process_generation_windows", "test_response_file_security",
    "test_response_forensic_paths",
}
LOGGER_OWNERS = {
    "log_rotation_retention_and_restart": "test_log_rotation",
    "windows_headless_log_stream_initialization": "test_log_headless_windows",
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


def cmake_cache_path(cache_file: Path, key: str) -> Path:
    values = re.findall(rf'^{re.escape(key)}:[^=\r\n]+=([^\r\n]*)$',
                        cache_file.read_text(encoding="utf-8"), re.MULTILINE)
    if len(values) != 1 or not values[0] or values[0].endswith("-NOTFOUND"):
        raise AssertionError(f"CMake dependency path is missing: {key} in {cache_file}")
    return Path(values[0])


def verify_sqlite_package_location(cache_file: Path, include_dir: Path, library: Path) -> None:
    # CMake can expand a Windows 8.3 path and change drive/directory casing.
    # Compare filesystem identities, retaining the check against host fallback.
    for key, expected in (("SQLite3_INCLUDE_DIR", include_dir), ("SQLite3_LIBRARY", library)):
        actual = cmake_cache_path(cache_file, key)
        try:
            matches = actual.samefile(expected)
        except OSError as error:
            raise AssertionError(f"Cannot verify {key}: selected={actual}; expected={expected}") from error
        if not matches:
            raise AssertionError(f"Wrong SQLite dependency for {key}: selected={actual}; expected={expected}")


class WindowsReleaseGateTests(unittest.TestCase):
    def run_command(self, *args, success=True, env=None, timeout=90):
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_packaging_powershell_launchers_isolate_inherited_module_path(self):
        """Exercise the launcher; the native gate runs each packaging fixture."""
        names = ("windows_release_collector_pe_closure",
                 "windows_inplace_collector_transaction",
                 "windows_installer_log_redaction", "windows_update_physical_guard")
        definitions = (ROOT / "tests" / "CMakeLists.txt").read_text(encoding="utf-8")
        declarations = []
        for name in names:
            match = re.search(
                rf"  add_test\(NAME {re.escape(name)}\n.*?"
                r"(?=\n  (?:add_test|set_tests_properties)\()", definitions, re.DOTALL)
            self.assertIsNotNone(match, f"Missing CTest declaration for {name}")
            declarations.append(match.group(0).replace(
                "${CMAKE_CURRENT_SOURCE_DIR}", (ROOT / "tests").as_posix()).replace(
                "${CMAKE_SOURCE_DIR}", ROOT.as_posix()))

        # Carry the production deadline and polluted environment into the probe.
        properties = re.search(
            r"  set_tests_properties\(\s*windows_release_collector_pe_closure\s*"
            r"windows_inplace_collector_transaction\s*windows_installer_log_redaction\s*"
            r"windows_update_physical_guard\s*"
            r"PROPERTIES TIMEOUT \d+[^)]*\)", definitions)
        self.assertIsNotNone(properties)
        declarations.append(properties.group(0))

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            foreign_modules = build / "foreign-powershell-modules"
            foreign_modules.mkdir(parents=True)
            (source / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.20)\n"
                "project(packaging_launch_boundary NONE)\nenable_testing()\n"
                + "\n".join(declarations), encoding="utf-8")
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            listing = self.run_command("ctest", "--test-dir", str(build),
                                       "--show-only=json-v1")
            tests = json.loads(listing.stdout)["tests"]
            self.assertEqual({test["name"] for test in tests}, set(names))
            probe = [sys.executable, "-c",
                     "import os; assert 'PSModulePath' not in os.environ"]
            for test in tests:
                with self.subTest(test=test["name"]):
                    properties = {item["name"]: item["value"] for item in test["properties"]}
                    test_env = dict(value.split("=", 1) for value in properties["ENVIRONMENT"])
                    self.assertTrue(Path(test_env["PSModulePath"]).samefile(foreign_modules))
                    inherited = os.environ.copy()
                    inherited.update(test_env)
                    command = test["command"]
                    host_index = command.index("powershell.exe")
                    wrapper = command[:host_index]
                    self.assertIn("--unset=PSModulePath", wrapper)
                    # Removing isolation must expose the production CTest's
                    # polluted input; the unchanged wrapper must remove it.
                    self.run_command(*(arg for arg in wrapper if arg != "--unset=PSModulePath"),
                                     *probe, success=False, env=inherited)
                    self.run_command(*wrapper, *probe, env=inherited)
                    self.assertEqual(inherited["PSModulePath"], test_env["PSModulePath"])

    def test_updater_health_clock_uses_checkout_sha_and_isolated_powershell(self):
        production = (ROOT / "tests/CMakeLists.txt").read_text(encoding="utf-8")
        start = production.index("  # Pin the actual checkout bytes at configure time;")
        end = production.index("  add_test(NAME windows_installer_acl_behavior", start)
        fragment = production[start:end].replace(
            "${CMAKE_CURRENT_SOURCE_DIR}", (ROOT / "tests").as_posix()).replace(
            "${CMAKE_SOURCE_DIR}", ROOT.as_posix())
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            (source / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.20)\nproject(UpdaterClockPin NONE)\nenable_testing()\n"
                + fragment, encoding="utf-8")
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            listed = self.run_command("ctest", "--test-dir", str(build), "--show-only=json-v1")
            tests = json.loads(listed.stdout)["tests"]
            self.assertEqual([test["name"] for test in tests], ["windows_updater_health_clock"])
            command = tests[0]["command"]
            expected = hashlib.sha256((ROOT / "scripts/edr_agent_inplace_update.ps1").read_bytes()).hexdigest()
            self.assertIn("--unset=PSModulePath", command)
            self.assertIn("powershell.exe", command)
            self.assertIn("-NonInteractive", command)
            self.assertIn("-UpdaterSha256 '" + expected + "'", command[-1])
            self.assertIn("-UpdaterPath '" + (ROOT / "scripts/edr_agent_inplace_update.ps1").as_posix() + "'", command[-1])
            properties = {item["name"]: item["value"] for item in tests[0]["properties"]}
            self.assertEqual(properties["TIMEOUT"], 30)
            environment = properties["ENVIRONMENT"]
            self.assertEqual(len(environment), 1)
            self.assertTrue(environment[0].startswith("PSModulePath="))
            # CMake can canonicalize a Windows 8.3 temporary-directory alias.
            selected_modules = Path(environment[0][len("PSModulePath="):])
            self.assertTrue(selected_modules.is_absolute())
            self.assertEqual(selected_modules.resolve(), (build / "foreign-powershell-modules").resolve())

    def test_updater_health_clock_is_required_and_failure_blocks_windows_gate(self):
        name = "windows_updater_health_clock"
        with tempfile.TemporaryDirectory() as directory:
            source, build, _ = self.fixture(directory, missing_test=name)
            result = self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja", success=False)
            self.assertIn("Windows release gate test is not registered: " + name, result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            source, build, _ = self.fixture(directory, failing_test=name)
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            result = self.run_command("ctest", "--test-dir", str(build), "-L", LABEL,
                                      "-R", "^" + name + "$", "--no-tests=error", "--output-on-failure", success=False)
            self.assertIn("0% tests passed, 1 tests failed out of 1", result.stdout)
            self.assertNotIn("***Not Run", result.stdout)

    def test_update_invocation_uses_actual_contract_target_and_checkout_driver(self):
        production = (ROOT / "tests/CMakeLists.txt").read_text(encoding="utf-8")
        start = production.index("  # Run the actual C-generated caller")
        end = production.index("\nendif()", start)
        fragment = production[start:end].replace(
            "${CMAKE_CURRENT_SOURCE_DIR}", (ROOT / "tests").as_posix())
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            (source / "fixture.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (source / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.20)\nproject(UpdaterInvocationPin C)\nenable_testing()\n"
                "add_executable(test_agent_update_contract fixture.c)\n" + fragment,
                encoding="utf-8")
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            listed = self.run_command("ctest", "--test-dir", str(build), "--show-only=json-v1")
            tests = json.loads(listed.stdout)["tests"]
            self.assertEqual([test["name"] for test in tests], ["windows_agent_update_invocation"])
            command = tests[0]["command"]
            driver = ROOT / "tests/cache-recovery/windows_cache_recovery_ci.ps1"
            expected = hashlib.sha256(driver.read_bytes()).hexdigest()
            self.assertIn("--unset=PSModulePath", command)
            self.assertIn("powershell.exe", command)
            self.assertIn("-DriverSha256 '" + expected + "'", command[-1])
            self.assertIn("-DriverSource '" + driver.as_posix() + "'", command[-1])
            executable = re.search(r"-ContractExe '([^']+)'", command[-1])
            self.assertIsNotNone(executable)
            selected = Path(executable.group(1))
            self.assertEqual(selected.parent.resolve(), build.resolve())
            self.assertEqual(selected.name, "test_agent_update_contract" + (".exe" if os.name == "nt" else ""))
            properties = {item["name"]: item["value"] for item in tests[0]["properties"]}
            self.assertEqual(properties["TIMEOUT"], 90)
            self.assertEqual(len(properties["ENVIRONMENT"]), 1)
            self.assertTrue(properties["ENVIRONMENT"][0].startswith("PSModulePath="))

    def test_update_invocation_is_required_and_failure_blocks_windows_gate(self):
        name = "windows_agent_update_invocation"
        with tempfile.TemporaryDirectory() as directory:
            source, build, pairs = self.fixture(directory, missing_test=name)
            self.assertEqual(dict(pairs)[name], "test_agent_update_contract")
            result = self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja", success=False)
            self.assertIn("Windows release gate test is not registered: " + name, " ".join(result.stderr.split()))
        with tempfile.TemporaryDirectory() as directory:
            source, build, _ = self.fixture(directory, failing_test=name)
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            result = self.run_command("ctest", "--test-dir", str(build), "-L", LABEL,
                                      "-R", "^" + name + "$", "--no-tests=error", "--output-on-failure", success=False)
            self.assertIn("0% tests passed, 1 tests failed out of 1", result.stdout)
            self.assertNotIn("***Not Run", result.stdout)

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

    def test_sqlite_package_identity_accepts_aliases_and_rejects_other_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            include = root / "relocated sqlite/include"
            include.mkdir(parents=True)
            library = root / "relocated sqlite/lib/sqlite3.lib"
            library.parent.mkdir()
            library.touch()
            wrong_include = root / "other/include"
            wrong_include.mkdir(parents=True)
            wrong_library = root / "other/sqlite3.lib"
            wrong_library.touch()
            cache = root / "CMakeCache.txt"
            # Existing aliases exercise identity rather than cache text spelling
            # on all hosts; the real Windows probe also covers its TEMP 8.3 alias.
            include_alias = include / ".." / "include"
            library_alias = library.parent / ".." / "lib" / library.name
            for selected_include, selected_library, failure_key in (
                (include_alias, library_alias, None),
                (wrong_include, library_alias, "SQLite3_INCLUDE_DIR"),
                (include_alias, wrong_library, "SQLite3_LIBRARY"),
            ):
                with self.subTest(failure_key=failure_key):
                    cache.write_text(
                        f"SQLite3_INCLUDE_DIR:PATH={selected_include.as_posix()}\n"
                        f"SQLite3_LIBRARY:FILEPATH={selected_library.as_posix()}\n", encoding="utf-8")
                    if failure_key:
                        with self.assertRaisesRegex(AssertionError, f"Wrong SQLite dependency for {failure_key}"):
                            verify_sqlite_package_location(cache, include, library)
                    else:
                        verify_sqlite_package_location(cache, include, library)

    def fixture(self, directory, missing_target="", missing_test="", failing_test="", p0_inputs_available=True,
                failing_executable=""):
        pairs = re.findall(r'^edr_windows_release_gate\((\w+) (\w+|"")\)$',
                           GATE.read_text(encoding="utf-8"), re.MULTILINE)
        self.assertEqual({name for name, _ in pairs}, WINDOWS_EXPECTED)
        runtime_pairs = re.findall(r'^\s*edr_agent_runtime_gate\((\w+) (\w+)\)$',
                                   RUNTIME_GATE.read_text(encoding="utf-8"), re.MULTILINE)
        self.assertEqual({name for name, _ in runtime_pairs},
                         RUNTIME_EXPECTED | NON_WINDOWS_RUNTIME_EXPECTED)
        # The declarations include a real NOT WIN32 owner. Keep its mutex
        # coverage on host fixtures without selecting a nonexistent Windows
        # test/target in native release gates.
        if os.name == "nt":
            runtime_pairs = [(name, target) for name, target in runtime_pairs
                             if name not in NON_WINDOWS_RUNTIME_EXPECTED]
        pairs += runtime_pairs
        source = Path(directory)
        (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        if failing_executable:
            (source / "failure.c").write_text("int main(void) { return 23; }\n", encoding="utf-8")
        lines = ["cmake_minimum_required(VERSION 3.19)", "project(GateFixture C)", "enable_testing()",
                 # Each executable must still be a distinct build dependency.
                 # Its identical body need only be compiled once per fixture.
                 "add_library(gate_fixture_success OBJECT main.c)",
                 "set(OpenSSL_FOUND TRUE)", "set(SQLite3_FOUND TRUE)", "set(EDR_PCRE2_AVAILABLE TRUE)",
                 # This fixture tests scheduling with tiny executables; real
                 # canonical bytes are verified by the native product tests.
                 f"set(EDR_P0_TEST_CONFIG_AVAILABLE {'TRUE' if p0_inputs_available else 'FALSE'})"]
        if failing_executable:
            lines.append("add_library(gate_fixture_failure OBJECT failure.c)")
        # Preserve the logger declarations' order relative to the actual gate
        # include; a fixture must not hide an early production include.
        production = (ROOT / "tests/CMakeLists.txt").read_text(encoding="utf-8")
        gate_position = production.index("include(${CMAKE_SOURCE_DIR}/cmake/WindowsReleaseGate.cmake)")
        late_loggers = {name for name in LOGGER_OWNERS
                        if production.index(f"add_test(NAME {name} ") > gate_position}
        after_gate = []
        registered_targets = set()
        for name, target in pairs:
            declarations = after_gate if name in late_loggers else lines
            if target != '""' and target != missing_target and target not in registered_targets:
                executable_object = ("gate_fixture_failure" if target == failing_executable
                                     else "gate_fixture_success")
                declarations.append(f"add_executable({target} $<TARGET_OBJECTS:{executable_object}>)")
                registered_targets.add(target)
            if name != missing_test:
                command = target if target != '""' else '"${CMAKE_COMMAND}" -E true'
                if name == failing_test:
                    command = '"${CMAKE_COMMAND}" -E false'
                declarations.append(f"add_test(NAME {name} COMMAND {command})")
        lines.append(f'include("{RUNTIME_GATE.as_posix()}")')
        lines.append(f'include("{GATE.as_posix()}")')
        lines.extend(after_gate)
        (source / "CMakeLists.txt").write_text("\n".join(lines), encoding="utf-8")
        return source, source / "build", pairs

    def test_external_canonical_inputs_are_required_by_release_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            source, build, _ = self.fixture(directory, p0_inputs_available=False)
            result = self.run_command('cmake', '-S', str(source), '-B', str(build), success=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires external canonical P0 inputs', result.stdout + result.stderr)

    def test_gates_initialize_after_periodic_and_runtime_registration(self):
        source = (ROOT / 'tests/CMakeLists.txt').read_text(encoding='utf-8')
        for include in ('include(${CMAKE_SOURCE_DIR}/cmake/AgentRuntimeGate.cmake)',
                        'include(${CMAKE_SOURCE_DIR}/cmake/WindowsReleaseGate.cmake)'):
            self.assertEqual(source.count(include), 1)
            for name in ('periodic_schedule_boundaries', 'attack_surface_sampled_groups',
                         'log_rotation_retention_and_restart', 'conditional_policy_authenticated_cache',
                         'runtime_rule_cold_start_schedule', 'windows_headless_log_stream_initialization'):
                self.assertLess(source.index(f'add_test(NAME {name} '), source.index(include))

    def test_periodic_and_runtime_failures_block_native_release(self):
        for name in ('periodic_schedule_boundaries', 'attack_surface_sampled_groups',
                     'log_rotation_retention_and_restart', 'conditional_policy_authenticated_cache',
                     'runtime_rule_cold_start_schedule', 'windows_headless_log_stream_initialization'):
            with self.subTest(test=name), tempfile.TemporaryDirectory() as directory:
                source, build, _ = self.fixture(directory, failing_test=name)
                self.run_command('cmake', '-S', str(source), '-B', str(build), '-G', 'Ninja')
                # The complete build-dependency graph is verified for both
                # generators below. These failing commands are CMake -E false;
                # select exactly this labelled test to exclude incidental
                # missing executables from the failure evidence.
                result = self.run_command('ctest', '--test-dir', str(build), '--output-on-failure',
                                          '--no-tests=error', '--label-regex', LABEL,
                                          '--tests-regex', f'^{name}$', success=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stdout + result.stderr)
                self.assertIn('0% tests passed, 1 tests failed out of 1', result.stdout + result.stderr)

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
                                              "-L", LABEL, "--parallel", "4", "--no-tests=error", success=False)
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
                                          "-L", LABEL, "--parallel", "4", "--no-tests=error", "--output-on-failure")
                self.assertIn("100% tests passed", passed.stdout)

    def test_command_delivery_and_resource_failures_block_windows_gate(self):
        names = ("egress_command_delivery_mtls", "egress_receiver_resources")
        for name in names:
            with self.subTest(test=name), tempfile.TemporaryDirectory() as directory:
                source, build, pairs = self.fixture(directory, failing_test=name)
                self.assertEqual(dict(pairs)["egress_command_delivery_mtls"], "test_egress_tls_client")
                self.assertEqual(dict(pairs)["egress_receiver_resources"], '""')
                self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
                listing = self.run_command("ctest", "--test-dir", str(build), "-L", LABEL,
                                           "-R", "^(egress_command_delivery_mtls|egress_receiver_resources)$",
                                           "--show-only=json-v1")
                tests = json.loads(listing.stdout)["tests"]
                self.assertEqual({test["name"] for test in tests}, set(names))
                for test in tests:
                    properties = {item["name"]: item["value"] for item in test["properties"]}
                    self.assertIn("windows-release-gate", properties["LABELS"])
                result = self.run_command("ctest", "--test-dir", str(build), "-L", LABEL,
                                          "-R", f"^{name}$", "--no-tests=error",
                                          "--output-on-failure", success=False)
                self.assertIn(name + " (Failed)", result.stdout + result.stderr)
                self.assertIn("0% tests passed, 1 tests failed out of 1", result.stdout + result.stderr)

    def test_missing_target_fails_at_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            source, build, _ = self.fixture(directory, missing_target="test_response_file_security")
            result = self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja", success=False)
            self.assertIn("Windows release gate executable target is missing", result.stderr)

    def test_logger_executables_are_built_and_failures_block_windows_release(self):
        logger_pattern = "^(" + "|".join(map(re.escape, LOGGER_OWNERS)) + ")$"
        for name, target in LOGGER_OWNERS.items():
            with self.subTest(test=name), tempfile.TemporaryDirectory() as directory:
                source, build, _ = self.fixture(directory, failing_executable=target)
                self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja",
                                 "-DCMAKE_BUILD_TYPE=Release")
                # Both generators' complete dependency closure is checked above.
                # Isolate the logger regression here so unrelated executables
                # neither mask missing loggers nor repeat the full gate build.
                missing = self.run_command("ctest", "--test-dir", str(build), "-C", "Release",
                                           "-L", LABEL, "-R", logger_pattern,
                                           "--no-tests=error", success=False)
                self.assertEqual(missing.stdout.count("***Not Run"), 2,
                                 missing.stdout + missing.stderr)
                for owner in LOGGER_OWNERS:
                    self.assertIn(owner + " (Not Run)", missing.stdout + missing.stderr)

                self.run_command("cmake", "--build", str(build), "--config", "Release",
                                 "--target", *LOGGER_OWNERS.values(), "--parallel", "2")
                listing = self.run_command("ctest", "--test-dir", str(build), "-C", "Release",
                                           "-L", LABEL, "-R", logger_pattern, "--show-only=json-v1")
                selected = {test["name"]: test for test in json.loads(listing.stdout)["tests"]}
                self.assertEqual(set(selected), set(LOGGER_OWNERS))
                for owner, executable in LOGGER_OWNERS.items():
                    command = selected[owner]["command"]
                    self.assertTrue(Path(command[0]).is_file(), command)
                    self.assertEqual(Path(command[0]).stem, executable)
                result = self.run_command("ctest", "--test-dir", str(build), "-C", "Release",
                                          "-L", LABEL, "-R", logger_pattern,
                                          "--no-tests=error", "--output-on-failure",
                                          success=False)
                failed = re.findall(r"^\s*\d+ - (\w+) \(Failed\)(?:[ \t]+.*)?$",
                                    result.stdout, re.MULTILINE)
                self.assertEqual(failed, [name], result.stdout + result.stderr)
                self.assertIn("50% tests passed, 1 tests failed out of 2", result.stdout + result.stderr)
                self.assertNotIn("***Not Run", result.stdout + result.stderr)

    def test_missing_registration_fails_at_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            source, build, _ = self.fixture(directory, missing_test="response_forensic_path_contract")
            result = self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja", success=False)
            self.assertIn("Windows release gate test is not registered", result.stderr)

    def test_missing_canonical_inputs_fail_before_gate_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            source, build, _ = self.fixture(directory, p0_inputs_available=False)
            result = self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja", success=False)
            self.assertIn("Windows release gate requires external canonical P0 inputs", result.stderr)

    def test_missing_runtime_target_fails_at_configuration(self):
        for target in ("test_request_signing", "test_security_event_xml", "test_process_create_coalescer",
                       "test_process_command_admission",
                       "test_p0_candidate_replay", "test_p0_runtime_delivery", "test_ave_parent_integrity",
                       "test_p0_source_only_capacity_recovery"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                source, build, _ = self.fixture(directory, missing_target=target)
                result = self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja", success=False)
                self.assertIn("Agent runtime gate executable target is missing", result.stderr)
                self.assertIn(target, result.stderr)

    def test_security_queue_and_detection_failures_block_both_gate_labels(self):
        # Inject failures in each newly required group, not just check labels in text.
        names = ("request_signing", "storage_queue_sqlite_contract", "detection_sensor_bridge",
                     "behavior_record_alert_proto_contract", "command_signature_cross_language",
                     "security_event_xml_bounded_command_line", "process_create_coalescer_state_machine",
                     "process_command_admission",
                     "windows_rule_semantic_audit", "installer_runtime_health_classification",
                     "report_events_ack_contract", "p0_runtime_delivery", "ave_parent_integrity",
                     "p0_source_only_capacity_recovery")
        if os.name != "nt":
            names += ("ave_parent_integrity_mutex",)
        for name in names:
            with self.subTest(test=name), tempfile.TemporaryDirectory() as directory:
                source, build, _ = self.fixture(directory, failing_test=name)
                self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
                # Full executable dependency coverage is exercised above for
                # both generators. These commands are CMake -E false, so only
                # the selected test's label and failure propagation are in scope.
                for label in (LABEL, "^agent-runtime-gate$"):
                    result = self.run_command("ctest", "--test-dir", str(build), "-L", label,
                                              "-R", f"^{name}$", "--no-tests=error", "--output-on-failure", success=False)
                    self.assertIn(name + " (Failed)", result.stdout + result.stderr)
                    self.assertIn("0% tests passed, 1 tests failed out of 1", result.stdout + result.stderr)
                    self.assertNotIn("***Not Run", result.stdout + result.stderr)

    def test_installer_health_and_redaction_failures_block_windows_release(self):
        for name in ("windows_installer_health_behavior", "windows_installer_log_redaction",
                     "windows_task_trace_environment"):
            with self.subTest(test=name), tempfile.TemporaryDirectory() as directory:
                source, build, _ = self.fixture(directory, failing_test=name)
                self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
                result = self.run_command("ctest", "--test-dir", str(build), "-L", LABEL,
                                          "-R", f"^{name}$", "--no-tests=error", "--output-on-failure", success=False)
                self.assertIn(name + " (Failed)", result.stdout + result.stderr)
                self.assertIn("0% tests passed, 1 tests failed out of 1", result.stdout + result.stderr)
                self.assertNotIn("***Not Run", result.stdout + result.stderr)

    def test_release_and_remaining_telemetry_select_each_contract_once(self):
        """Exercise CTest's label exclusion with observable execution counts."""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            execution_log = source / "executed.txt"
            (source / "record.cmake").write_text(
                f'file(APPEND "{execution_log.as_posix()}" "${{NAME}}\\n")\n'
                'if("$ENV{EDR_GATE_FIXTURE_FAIL}" STREQUAL "${NAME}")\n'
                '  message(FATAL_ERROR "Injected ${NAME} failure")\n'
                'endif()\n', encoding="utf-8")
            lines = ["cmake_minimum_required(VERSION 3.19)",
                     "project(LabelSelection NONE)", "enable_testing()"]
            for name, labels in (
                ("release_only", "windows-release-gate"),
                ("shared", "windows-release-gate;telemetry-minimization"),
                ("telemetry_only", "telemetry-minimization"),
            ):
                lines += [
                    f'add_test(NAME {name} COMMAND "${{CMAKE_COMMAND}}" -DNAME={name} '
                    f'-P "{(source / "record.cmake").as_posix()}")',
                    f'set_tests_properties({name} PROPERTIES LABELS "{labels}")',
                ]
            (source / "CMakeLists.txt").write_text("\n".join(lines), encoding="utf-8")
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            release = ("ctest", "--test-dir", str(build), "-L", LABEL,
                       "--no-tests=error", "--output-on-failure")
            remaining = ("ctest", "--test-dir", str(build), "-L", "^telemetry-minimization$",
                         "-LE", LABEL, "--no-tests=error", "--output-on-failure")
            for failure in ("", "release_only", "shared", "telemetry_only"):
                with self.subTest(failure=failure):
                    execution_log.unlink(missing_ok=True)
                    env = os.environ.copy()
                    env["EDR_GATE_FIXTURE_FAIL"] = failure
                    self.run_command(*release, env=env,
                                     success=failure not in ("release_only", "shared"))
                    self.run_command(*remaining, env=env, success=failure != "telemetry_only")
                    self.assertCountEqual(execution_log.read_text(encoding="utf-8").splitlines(),
                                          ["release_only", "shared", "telemetry_only"])
            # A misspelled label must not turn an omitted phase into success.
            self.run_command("ctest", "--test-dir", str(build), "-L", "^missing-telemetry$",
                             "-LE", LABEL, "--no-tests=error", success=False)

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
                '/* Windows SDK rpcndr.h reserves small as a type macro. */\n'
                '#define small char\n#include <stddef.h>\n'
                '#define WINAPI\n#define WAIT_OBJECT_0 0\n'
                'typedef void *HANDLE; typedef unsigned long DWORD; typedef int BOOL;\n'
                'typedef struct { void *ptr; } SRWLOCK, CONDITION_VARIABLE;\n'
                '#define SRWLOCK_INIT {0}\n#define CONDITION_VARIABLE_INIT {0}\n'
                'void Sleep(DWORD);\n'
                'HANDLE CreateThread(void *, size_t, DWORD (WINAPI *)(void *), void *, DWORD, DWORD *);\n'
                'DWORD WaitForSingleObject(HANDLE, DWORD); BOOL CloseHandle(HANDLE);\n'
                'void AcquireSRWLockExclusive(SRWLOCK *); void ReleaseSRWLockExclusive(SRWLOCK *);\n'
                'void WakeAllConditionVariable(CONDITION_VARIABLE *);\n'
                'BOOL SleepConditionVariableSRW(CONDITION_VARIABLE *, SRWLOCK *, DWORD, unsigned long);\n',
                encoding="utf-8")
            (source / "process.h").write_text(
                'int _getpid(void);\nint _putenv_s(const char *, const char *);\n', encoding="utf-8")
            (source / "no_posix.h").write_text(
                '#include <stdlib.h>\n#pragma GCC poison setenv unsetenv getpid usleep\n'
                '/* DLL annotations only; preserve the real Windows API branch. */\n'
                '#define __declspec(x)\n#define __stdcall\n#define __cdecl\n',
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
                f'target_include_directories(queue_probe PRIVATE "{(ROOT / "include").as_posix()}" '
                f'"{(ROOT / "third_party/cjson").as_posix()}")',
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
            cache_file = build / "CMakeCache.txt"
            prefix = source / "relocated sqlite"
            (prefix / "lib").mkdir(parents=True)
            sqlite_include = cmake_cache_path(cache_file, "SQLite3_INCLUDE_DIR")
            copied_headers = copy_sqlite_header_family(sqlite_include, prefix / "include")
            source_companions = {
                header.name for header in sqlite_include.glob("sqlite3*.h")
                if header.name != "sqlite3.h"
            }
            self.assertTrue(source_companions.issubset(copied_headers))
            library = cmake_cache_path(cache_file, "SQLite3_LIBRARY")
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
            verify_sqlite_package_location(isolated_build / "CMakeCache.txt",
                                           prefix / "include", prefix / "lib" / library.name)

    def test_p0_direct_emit_windows_compiler_surface(self):
        """Compile the actual P0 test before installing external dependencies.

        On Windows this exercises cl.exe's C11 atomics, not a host compiler's
        approximation. Keep the later SQLite-enabled and runtime gates too.
        """
        self.compile_p0_windows_branches(with_sqlite=False)

    def test_p0_gate_windows_branches_compile_with_sqlite(self):
        """Compile real P0 gate tests with the production SQLite branches enabled.

        A host compiler accepting a POSIX API or ATOMIC_VAR_INIT is not evidence
        that MSVC accepts it. Native Windows uses its CRT/SDK; other hosts remove
        those conveniences while retaining the actual SQLite headers.
        """
        self.compile_p0_windows_branches(with_sqlite=True)

    def compile_p0_windows_branches(self, *, with_sqlite):
        cmake_source = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        begin = cmake_source.index("set(CMAKE_C_STANDARD 11)")
        end = cmake_source.index('option(EDR_BUILD_TESTS', begin)
        targets = ("test_p0_direct_emit_suppression",)
        if with_sqlite:
            targets += ("test_local_evidence_cache_candidate", "test_p0_deferred_snapshot",
                        "test_behavior_record_alert_emit", "test_process_tree_cache")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            (source / "windows.h").write_text(
                '#ifndef EDR_TEST_P0_WINDOWS_H\n#define EDR_TEST_P0_WINDOWS_H\n'
                '#include <stdint.h>\n#include <stddef.h>\n#define MAX_PATH 260\n'
                '/* Windows SDK rpcndr.h exposes this MIDL type macro. */\n'
                '#define small char\n'
                'typedef uint32_t DWORD;\n#define WINAPI\n'
                'typedef void *HANDLE;\ntypedef void *LPVOID;\ntypedef int BOOL;\n'
                '/* Compile-only SDK declarations; no synchronization implementation. */\n'
                'typedef uint32_t ULONG;\n'
                'typedef struct { void *Ptr; } SRWLOCK;\n'
                'typedef struct { void *Ptr; } CONDITION_VARIABLE;\n'
                '#define SRWLOCK_INIT {0}\n#define CONDITION_VARIABLE_INIT {0}\n'
                'void WINAPI AcquireSRWLockExclusive(SRWLOCK *);\n'
                'void WINAPI ReleaseSRWLockExclusive(SRWLOCK *);\n'
                'void WINAPI WakeAllConditionVariable(CONDITION_VARIABLE *);\n'
                'BOOL WINAPI SleepConditionVariableSRW(CONDITION_VARIABLE *, SRWLOCK *, DWORD, ULONG);\n'
                'HANDLE CreateThread(void *, size_t, DWORD (WINAPI *)(void *), void *, DWORD, DWORD *);\n'
                '#define FALSE 0\n#define TRUE 1\n#define CREATE_NO_WINDOW 0x08000000\n#define WAIT_OBJECT_0 0\n'
                'typedef struct { DWORD cb; } STARTUPINFOA;\n'
                'typedef struct { HANDLE hProcess, hThread; } PROCESS_INFORMATION;\n'
                'DWORD GetModuleFileNameA(HANDLE, char *, DWORD);\n'
                'BOOL CreateProcessA(const char *, char *, void *, void *, BOOL, DWORD, void *, const char *, STARTUPINFOA *, PROCESS_INFORMATION *);\n'
                'DWORD WaitForSingleObject(HANDLE, DWORD);\n'
                'DWORD WaitForMultipleObjects(DWORD, const HANDLE *, BOOL, DWORD);\nvoid Sleep(DWORD);\n'
                'BOOL TerminateProcess(HANDLE, unsigned);\n'
                'BOOL GetExitCodeProcess(HANDLE, DWORD *);\nBOOL CloseHandle(HANDLE);\n'
                'void ExitProcess(unsigned);\n'
                'typedef struct { DWORD dwLowDateTime, dwHighDateTime; } FILETIME;\n'
                'typedef uint16_t USHORT;\n'
                'typedef union { struct { DWORD LowPart; int32_t HighPart; }; int64_t QuadPart; } LARGE_INTEGER;\n'
                'typedef struct { uint64_t ReadOperationCount, WriteOperationCount, OtherOperationCount; '
                'uint64_t ReadTransferCount, WriteTransferCount, OtherTransferCount; } IO_COUNTERS;\n'
                'BOOL WINAPI QueryPerformanceCounter(LARGE_INTEGER *);\n'
                'BOOL WINAPI QueryPerformanceFrequency(LARGE_INTEGER *);\n'
                'HANDLE WINAPI GetCurrentProcess(void);\n'
                'BOOL WINAPI GetProcessTimes(HANDLE, FILETIME *, FILETIME *, FILETIME *, FILETIME *);\n'
                'BOOL WINAPI GetProcessIoCounters(HANDLE, IO_COUNTERS *);\n'
                'BOOL WINAPI IsWow64Process2(HANDLE, USHORT *, USHORT *);\n'
                'typedef struct { DWORD dwFileAttributes; FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime; '
                'DWORD nFileSizeHigh, nFileSizeLow; } WIN32_FILE_ATTRIBUTE_DATA;\n'
                'typedef enum { GetFileExInfoStandard, GetFileExMaxInfoLevel } GET_FILEEX_INFO_LEVELS;\n'
                '#define ERROR_FILE_NOT_FOUND 2\n#define FILE_ATTRIBUTE_REPARSE_POINT 0x00000400\n'
                'BOOL WINAPI GetFileAttributesExA(const char *, GET_FILEEX_INFO_LEVELS, void *);\n'
                'DWORD WINAPI GetLastError(void);\n'
                'typedef struct { DWORD nLength; void *lpSecurityDescriptor; BOOL bInheritHandle; } SECURITY_ATTRIBUTES;\n'
                'BOOL WINAPI CreateDirectoryA(const char *, SECURITY_ATTRIBUTES *);\n'
                'DWORD GetTempPathA(DWORD, char *);\n'
                'unsigned GetTempFileNameA(const char *, const char *, unsigned, char *);\n'
                'void GetSystemTimeAsFileTime(FILETIME *);\n'
                '/* Declarations only, matching the SDK surface used by the work-copy test.\n'
                ' * Native Windows continues to include the real SDK; these are not an emulator. */\n'
                'typedef uint32_t UINT;\n'
                'typedef uint64_t ULONGLONG;\n'
                'typedef union { struct { DWORD LowPart, HighPart; }; uint64_t QuadPart; } ULARGE_INTEGER;\n'
                'typedef struct { DWORD dwFileAttributes; FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;\n'
                '  DWORD dwVolumeSerialNumber, nFileSizeHigh, nFileSizeLow, nNumberOfLinks, nFileIndexHigh, nFileIndexLow;\n'
                '} BY_HANDLE_FILE_INFORMATION;\n'
                'typedef struct { LARGE_INTEGER CreationTime, LastAccessTime, LastWriteTime, ChangeTime;\n'
                '  DWORD FileAttributes; } FILE_BASIC_INFO;\n'
                'typedef enum { FileBasicInfo = 0 } FILE_INFO_BY_HANDLE_CLASS;\n'
                'typedef struct { DWORD dwFileAttributes; FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;\n'
                '  DWORD nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;\n'
                '  char cFileName[MAX_PATH], cAlternateFileName[14]; } WIN32_FIND_DATAA;\n'
                'typedef struct _OVERLAPPED OVERLAPPED;\n'
                '#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)\n'
                '#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)\n'
                '#define FILE_TYPE_DISK 0x0001\n'
                '#define FILE_ATTRIBUTE_DIRECTORY 0x00000010\n'
                '#define FILE_READ_ATTRIBUTES 0x00000080\n'
                '#define GENERIC_READ 0x80000000u\n'
                '#define GENERIC_WRITE 0x40000000u\n'
                '#define FILE_SHARE_READ 0x00000001\n'
                '#define FILE_SHARE_WRITE 0x00000002\n'
                '#define CREATE_NEW 1\n'
                '#define OPEN_EXISTING 3\n'
                '#define FILE_FLAG_OPEN_REPARSE_POINT 0x00200000\n'
                '#define FILE_FLAG_BACKUP_SEMANTICS 0x02000000\n'
                '#define FILE_NAME_NORMALIZED 0\n'
                '#define VOLUME_NAME_DOS 0\n'
                '#define FILE_BEGIN 0\n'
                '#define ERROR_SUCCESS 0\n'
                '#define ERROR_PATH_NOT_FOUND 3\n'
                '#define ERROR_NO_MORE_FILES 18\n'
                '#define CP_UTF8 65001\n'
                '#define MB_ERR_INVALID_CHARS 0x00000008\n'
                'DWORD WINAPI GetFileType(HANDLE);\n'
                'BOOL WINAPI GetFileInformationByHandle(HANDLE, BY_HANDLE_FILE_INFORMATION *);\n'
                'BOOL WINAPI GetFileInformationByHandleEx(HANDLE, FILE_INFO_BY_HANDLE_CLASS, void *, DWORD);\n'
                'DWORD WINAPI GetFinalPathNameByHandleA(HANDLE, char *, DWORD, DWORD);\n'
                'HANDLE WINAPI CreateFileA(const char *, DWORD, DWORD, SECURITY_ATTRIBUTES *, DWORD, DWORD, HANDLE);\n'
                'HANDLE WINAPI CreateFileW(const wchar_t *, DWORD, DWORD, SECURITY_ATTRIBUTES *, DWORD, DWORD, HANDLE);\n'
                'DWORD WINAPI GetFileAttributesA(const char *);\n'
                'void WINAPI SetLastError(DWORD);\n'
                'ULONGLONG WINAPI GetTickCount64(void);\n'
                'BOOL WINAPI SetFilePointerEx(HANDLE, LARGE_INTEGER, LARGE_INTEGER *, DWORD);\n'
                'BOOL WINAPI ReadFile(HANDLE, void *, DWORD, DWORD *, OVERLAPPED *);\n'
                'BOOL WINAPI WriteFile(HANDLE, const void *, DWORD, DWORD *, OVERLAPPED *);\n'
                'BOOL WINAPI FlushFileBuffers(HANDLE);\n'
                'HANDLE WINAPI FindFirstFileA(const char *, WIN32_FIND_DATAA *);\n'
                'BOOL WINAPI FindNextFileA(HANDLE, WIN32_FIND_DATAA *);\n'
                'BOOL WINAPI FindClose(HANDLE);\n'
                'DWORD WINAPI GetModuleFileNameW(HANDLE, wchar_t *, DWORD);\n'
                'int WINAPI MultiByteToWideChar(UINT, DWORD, const char *, int, wchar_t *, int);\n'
                'BOOL WINAPI GetDiskFreeSpaceExW(const wchar_t *, ULARGE_INTEGER *, ULARGE_INTEGER *, ULARGE_INTEGER *);\n'
                'int _stricmp(const char *, const char *);\n'
                'int _putenv_s(const char *, const char *);\n'
                '#endif /* EDR_TEST_P0_WINDOWS_H */\n', encoding="utf-8")
            (source / "msvc_surface.h").write_text(
                '#include <stdlib.h>\n#include <time.h>\n#include <stdatomic.h>\n'
                '/* Ignore DLL/calling-convention annotations in this compile-only host probe. */\n'
                '#define __declspec(x)\n#define __stdcall\n#define __cdecl\n'
                '#undef ATOMIC_VAR_INIT\n#undef CLOCK_REALTIME\n'
                '#pragma GCC poison ATOMIC_VAR_INIT clock_gettime CLOCK_REALTIME\n'
                '#pragma GCC poison setenv unsetenv getpid usleep pthread_create pthread_join\n'
                'int _putenv_s(const char *, const char *);\n', encoding="utf-8")
            # Fail explicitly if someone accidentally compiles only the empty
            # no-SQLite test branch again, even when the source still compiles.
            (source / "require_sqlite.h").write_text(
                '#if !defined(EDR_HAVE_SQLITE) || !EDR_HAVE_SQLITE\n'
                '#error P0 Windows probe requires SQLite behavior coverage\n'
                '#endif\n', encoding="utf-8")
            lines = [
                'cmake_minimum_required(VERSION 3.20)', 'project(P0WindowsBranches C)',
                'if(WIN32 AND NOT MSVC)',
                '  message(FATAL_ERROR "Windows compiler surface probe requires initialized MSVC")',
                'endif()',
                cmake_source[begin:end],
            ]
            if with_sqlite:
                lines.append('find_package(SQLite3 REQUIRED)')
            for target in targets:
                lines += [
                    f'add_library({target} OBJECT "{(ROOT / "tests" / (target + ".c")).as_posix()}")',
                    f'target_include_directories({target} PRIVATE "{(ROOT / "include").as_posix()}" '
                    f'"{(ROOT / "third_party/cjson").as_posix()}" '
                    f'"{(ROOT / "third_party/nanopb").as_posix()}" "{(ROOT / "src/proto").as_posix()}")',
                    f'edr_apply_test_warnings({target})',
                    'if(NOT WIN32)',
                    f'  target_compile_definitions({target} PRIVATE _WIN32)',
                    f'  target_include_directories({target} PRIVATE "${{CMAKE_SOURCE_DIR}}")',
                    f'  target_compile_options({target} PRIVATE -Werror=implicit-function-declaration '
                    '-include "${CMAKE_SOURCE_DIR}/msvc_surface.h")',
                    'endif()',
                ]
            lines.append('target_compile_definitions(test_p0_direct_emit_suppression PRIVATE EDR_P0_DIRECT_EMIT_TESTING=1)')
            if with_sqlite:
                lines += [
                    # Mirror the real target's private test-clock definition.
                    'target_compile_definitions(test_process_tree_cache PRIVATE EDR_PTC_TESTING=1)',
                    'target_compile_definitions(test_behavior_record_alert_emit PRIVATE EDR_HAVE_NANOPB=1 EDR_HAVE_SQLITE=1 EDR_OS_WINDOWS=1)',
                    'target_compile_definitions(test_local_evidence_cache_candidate PRIVATE EDR_HAVE_SQLITE=1 EDR_LOCAL_EVIDENCE_CACHE_TESTING=1)',
                    'if(TARGET SQLite3::SQLite3)',
                    '  target_link_libraries(test_local_evidence_cache_candidate PRIVATE SQLite3::SQLite3)',
                    'else()',
                    '  target_link_libraries(test_local_evidence_cache_candidate PRIVATE SQLite::SQLite3)',
                    'endif()',
                    'if(MSVC)',
                    '  target_compile_options(test_local_evidence_cache_candidate PRIVATE "/FI${CMAKE_SOURCE_DIR}/require_sqlite.h")',
                    'else()',
                    '  target_compile_options(test_local_evidence_cache_candidate PRIVATE "-include${CMAKE_SOURCE_DIR}/require_sqlite.h")',
                    'endif()',
                ]
            (source / "CMakeLists.txt").write_text("\n".join(lines), encoding="utf-8")
            options = []
            if os.name == "nt":
                # Do not infer the target from the possibly emulated Python/
                # CMake host. Reuse the architecture selected by VsDevCmd.
                arch = os.environ.get("VSCMD_ARG_TGT_ARCH", "").lower()
                self.assertIn(arch, ("x64", "arm64"), "Initialize Visual Studio before the compiler probe")
                options.append("-DEDR_WINDOWS_TARGET_ARCH=" + ("amd64" if arch == "x64" else "arm64"))
            # Early preflight needs no Chocolatey/Ninja installation; NMake is
            # supplied by the VS toolchain we have already initialized.
            generator = "NMake Makefiles" if os.name == "nt" and not with_sqlite else "Ninja"
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", generator,
                             "-DCMAKE_BUILD_TYPE=Release", *options)
            build_args = ("--parallel", "2", "--", "-k", "0") if generator == "Ninja" else ()
            self.run_command("cmake", "--build", str(build), *build_args)

    @unittest.skipIf(os.name == "nt", "the release gate executes the native Windows binary")
    def test_p0_windows_admission_behavior(self):
        """Execute the real Windows admission branches, not only compile the test.

        Only the emitter translation unit selects _WIN32. Its three OS calls
        are locks and a clock, supplied by a host adapter; all admission,
        matching, deduplication and queue assertions remain the real test.
        This supplements, but does not replace, native Windows execution.
        """
        cmake_source = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        settings = cmake_source[cmake_source.index("set(CMAKE_C_STANDARD 11)"):
                                cmake_source.index("option(EDR_BUILD_TESTS")]
        # Preserve the actual shared policy's public protobuf include/defines,
        # sources, and platform compiler options for this real codec consumer.
        policy_start = cmake_source.index("add_library(edr_egress_policy STATIC\n")
        policy_end = (cmake_source.index("edr_apply_common_warnings(edr_egress_policy)", policy_start)
                      + len("edr_apply_common_warnings(edr_egress_policy)"))
        policy = re.sub(
            r'(?<![\w/])(?:src|third_party|include)(?:/[\w.-]+)*',
            lambda match: f'"{(ROOT / match[0]).resolve().as_posix()}"',
            cmake_source[policy_start:policy_end],
        )
        trace_start = cmake_source.index("add_library(edr_validation_trace STATIC")
        trace_end = cmake_source.index("target_link_libraries(edr_agent PRIVATE edr_egress_policy", trace_start)
        trace = re.sub(
            r'(?<![\w/])(?:src|include)(?:/[\w.-]+)*',
            lambda match: f'"{(ROOT / match[0]).resolve().as_posix()}"',
            cmake_source[trace_start:trace_end],
        )
        tests_source = (ROOT / "tests/CMakeLists.txt").read_text(encoding="utf-8")
        target = tests_source[tests_source.index("add_executable(test_p0_direct_emit_suppression "):
                              tests_source.index("add_executable(test_p0_deferred_snapshot ")]
        target = target.replace("${CMAKE_CURRENT_SOURCE_DIR}", "${EDR_TEST_ROOT}/tests")
        target = target.replace("${CMAKE_SOURCE_DIR}", "${EDR_TEST_ROOT}")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            (source / "windows.h").write_text(
                '#pragma once\n#ifdef NDEBUG\n#error Admission probe requires assertions\n#endif\n'
                '#include <assert.h>\n#include <pthread.h>\n'
                '#include <stdint.h>\n#include <time.h>\n'
                '#define __declspec(x)\n#define __stdcall\n#define __cdecl\n'
                'typedef pthread_mutex_t SRWLOCK;\n#define SRWLOCK_INIT PTHREAD_MUTEX_INITIALIZER\n'
                'static void AcquireSRWLockExclusive(SRWLOCK *lock) { assert(pthread_mutex_lock(lock) == 0); }\n'
                'static void ReleaseSRWLockExclusive(SRWLOCK *lock) { assert(pthread_mutex_unlock(lock) == 0); }\n'
                'static uint64_t GetTickCount64(void) { struct timespec ts;\n'
                '  assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);\n'
                '  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u; }\n',
                encoding="utf-8")
            lines = [
                'cmake_minimum_required(VERSION 3.20)', 'project(P0WindowsAdmission C)',
                settings, 'find_package(Threads REQUIRED)', 'enable_testing()',
                f'set(EDR_TEST_ROOT "{ROOT.as_posix()}")', policy, trace, target,
                f'set_source_files_properties("{(ROOT / "src/preprocess/p0_rule_direct_emit.c").as_posix()}" '
                'PROPERTIES COMPILE_DEFINITIONS _WIN32 '
                'COMPILE_OPTIONS "-include;${CMAKE_SOURCE_DIR}/windows.h")',
                'target_include_directories(test_p0_direct_emit_suppression PRIVATE "${CMAKE_SOURCE_DIR}")',
                'target_compile_definitions(test_p0_direct_emit_suppression PRIVATE EDR_P0_WINDOWS_ADMISSION_TEST=1)',
            ]
            (source / "CMakeLists.txt").write_text("\n".join(lines), encoding="utf-8")
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja",
                             "-DCMAKE_BUILD_TYPE=Release")
            self.run_command("cmake", "--build", str(build), "--parallel", "2")
            completed = self.run_command(
                "ctest", "--test-dir", str(build), "--verbose", "--output-on-failure",
                "--no-tests=error", "-R", "^p0_direct_emit_suppression$")
            # The host probe must reach the same suite completion as native
            # Windows, not return after only the admission-specific cases.
            self.assertIn("test_p0_direct_emit_suppression: ok", completed.stdout)


    def test_shutdown_progress_real_boundaries_and_existing_callers(self):
        """Check the observer's concrete owners; no timer or delivery field is added."""
        header = (ROOT / "include/edr/shutdown_progress.h").read_text(encoding="utf-8")
        stages = re.findall(r"\b(EDR_SHUTDOWN_[A-Z0-9_]+)\s*=\s*(\d+)", header)
        self.assertEqual([int(value) for _, value in stages], list(range(1, 29)))
        owners = {name: [] for name, _ in stages[1:]}
        for rel in ("src/main.c", "src/core/agent.c", "src/collector/collector_win.c"):
            source = (ROOT / rel).read_text(encoding="utf-8")
            emitted = re.findall(r"edr_shutdown_progress\(shutdown_observer, (EDR_SHUTDOWN_[A-Z0-9_]+)\);", source)
            for name in emitted:
                owners[name].append(rel)
            self.assertEqual([int(dict(stages)[name]) for name in emitted],
                             sorted(int(dict(stages)[name]) for name in emitted))
        self.assertTrue(all(len(paths) == 1 for paths in owners.values()), owners)
        agent = (ROOT / "src/core/agent.c").read_text(encoding="utf-8")
        main = (ROOT / "src/main.c").read_text(encoding="utf-8")
        win = (ROOT / "src/collector/collector_win.c").read_text(encoding="utf-8")
        self.assertEqual(agent.count("edr_collector_stop(NULL)"), 2)
        self.assertEqual(agent.count("edr_collector_stop(shutdown_observer)"), 1)
        self.assertEqual(win.count("edr_collector_stop(NULL)"), 3)
        self.assertIn("e = edr_agent_run(agent, shutdown_observer);", main)
        self.assertIn("if (g_service_status_handle) {\n    shutdown_observer = &service_shutdown_observer;", main)
        self.assertIn("const EdrShutdownObserver *shutdown_observer = NULL;", main)
        # Compare the drain/control actions after removing diagnostics against
        # their established ownership order, not a fictitious successful stop.
        collector = win[win.index("int edr_collector_stop("):win.index("\nint edr_collector_get_health(")]
        actions = ("InterlockedExchange(&s_stopping, 1);", "ControlTraceW(",
                   "SetEvent(s_registry_watch_stop_event)", "EvtClose(s_security_sub)",
                   "WaitForSingleObject(s_consumer_thread, 30000)",
                   "WaitForSingleObject(s_registry_watch_thread, 30000)",
                   "edr_a44_split_path_stop()", "edr_network_trace_stop()",
                   "edr_collector_file_key_cache_reset()", "InterlockedExchange(&s_started, 0)")
        self.assertEqual([collector.index(action) for action in actions],
                         sorted(collector.index(action) for action in actions))
        tail = main[main.index("e = edr_agent_run(agent, shutdown_observer);"):main.index("\nstatic int edr_agent_config_test_main")]
        actions = ("edr_ingest_http_stop_command_poll_timeout(10000u)",
                   "edr_command_delivery_shutdown_timeout(10000u)",
                   "edr_command_executor_shutdown_timeout(30000u)", "edr_preprocess_stop()",
                   "edr_pmfe_shutdown()", "edr_shellcode_detector_shutdown()",
                   "edr_webshell_detector_shutdown()", "edr_net_fanout_shutdown()",
                   "edr_transport_shutdown()", "edr_validation_trace_stop()",
                   "edr_local_evidence_cache_close()", "edr_storage_queue_close()", "edr_agent_destroy(agent)")
        self.assertEqual([tail.index(action) for action in actions], sorted(tail.index(action) for action in actions))

    def test_service_outcome_reaches_scm_and_process_exit(self):
        """Execute the actual callback and dispatcher branch with SCM I/O adapted."""
        main = (ROOT / "src/main.c").read_text(encoding="utf-8")
        start = main.index("static void edr_service_set_status(DWORD state, DWORD win32_exit, DWORD wait_hint_ms) {")
        service = main[start:main.index("\n#endif\n\nint main(", start)]
        start = main.index("  if (run_as_service) {")
        dispatch = main[start:main.index("\n#else\n  (void)run_as_service", start)]
        outcome = re.search(r"^static volatile LONG g_service_exit_code = [^;]+;", main, re.MULTILINE)
        self.assertIsNotNone(outcome)
        probe = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "edr/agent.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef int BOOL;
typedef char *LPSTR;
typedef void *SERVICE_STATUS_HANDLE;
typedef pthread_mutex_t SRWLOCK;
#define SRWLOCK_INIT PTHREAD_MUTEX_INITIALIZER
#define WINAPI
#define NO_ERROR 0u
#define ERROR_SERVICE_SPECIFIC_ERROR 1066u
#define SERVICE_WIN32_OWN_PROCESS 16u
#define SERVICE_START_PENDING 2u
#define SERVICE_STOP_PENDING 3u
#define SERVICE_STOPPED 1u
#define SERVICE_RUNNING 4u
#define SERVICE_ACCEPT_STOP 1u
#define SERVICE_ACCEPT_SHUTDOWN 4u
#define SERVICE_CONTROL_STOP 1u
#define SERVICE_CONTROL_SHUTDOWN 5u
typedef struct { DWORD dwServiceType, dwCurrentState, dwControlsAccepted,
  dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint; } SERVICE_STATUS;
typedef struct { LPSTR lpServiceName; void (WINAPI *lpServiceProc)(DWORD, LPSTR *); } SERVICE_TABLE_ENTRYA;
static void AcquireSRWLockExclusive(SRWLOCK *p) { assert(pthread_mutex_lock(p) == 0); }
static void ReleaseSRWLockExclusive(SRWLOCK *p) { assert(pthread_mutex_unlock(p) == 0); }
static LONG InterlockedCompareExchange(volatile LONG *p, LONG desired, LONG expected) {
  __atomic_compare_exchange_n(p, &expected, desired, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  return expected;
}
static LONG InterlockedExchange(volatile LONG *p, LONG desired) {
  return __atomic_exchange_n(p, desired, __ATOMIC_SEQ_CST);
}
#endif
static EdrAgent *g_agent_for_ctrl;
static SERVICE_STATUS_HANDLE g_service_status_handle;
static SERVICE_STATUS g_service_status;
static SRWLOCK g_service_status_lock = SRWLOCK_INIT;
OUTCOME_DECLARATION
static const char *g_service_name = "synthetic-service";
static const char *g_service_config_path;
static int run_rc, run_calls, register_ok = 1, dispatcher_ok = 1, invoke_callback = 1;
static int status_calls, published, reject_status;
static SERVICE_STATUS attempted[8];
static int edr_agent_run_main(const char *config);
void edr_agent_shutdown(EdrAgent *agent) { (void)agent; }
static SERVICE_STATUS_HANDLE fake_RegisterServiceCtrlHandlerA(const char *name, void (WINAPI *handler)(DWORD)) {
  assert(strcmp(name, g_service_name) == 0 && handler);
  return register_ok ? (SERVICE_STATUS_HANDLE)(uintptr_t)1 : NULL;
}
static BOOL fake_SetServiceStatus(SERVICE_STATUS_HANDLE handle, SERVICE_STATUS *status) {
  assert(handle && status_calls < 8);
  attempted[status_calls++] = *status;
  if (reject_status) return 0;
  published++; return 1;
}
static BOOL fake_StartServiceCtrlDispatcherA(SERVICE_TABLE_ENTRYA *table) {
  assert(table[0].lpServiceName && table[0].lpServiceProc && !table[1].lpServiceName && !table[1].lpServiceProc);
  if (!dispatcher_ok) return 0;
  if (invoke_callback) table[0].lpServiceProc(0, NULL);
  return 1;
}
#define RegisterServiceCtrlHandlerA fake_RegisterServiceCtrlHandlerA
#define SetServiceStatus fake_SetServiceStatus
#define StartServiceCtrlDispatcherA fake_StartServiceCtrlDispatcherA
#define GetLastError() 5u
SERVICE_SOURCE
static int edr_agent_run_main(const char *config) {
  assert(config && strcmp(config, "synthetic-config") == 0);
  run_calls++;
  edr_service_set_status(SERVICE_RUNNING, NO_ERROR, 0);
  return run_rc;
}
static int run_dispatch(void) {
  const char *config = "synthetic-config";
  int run_as_service = 1;
DISPATCH_SOURCE
  return 99;
}
static void reset(void) {
  run_rc=run_calls=status_calls=published=reject_status=0;
  register_ok=dispatcher_ok=invoke_callback=1;
  g_service_status_handle=NULL;
  memset(&g_service_status, 0, sizeof(g_service_status));
  memset(attempted, 0, sizeof(attempted));
  /* The real dispatcher branch must overwrite an earlier successful outcome. */
  InterlockedExchange(&g_service_exit_code, 0);
}
static void verify_run(int rc) {
  reset(); run_rc=rc;
  assert(run_dispatch() == rc && run_calls == 1 && status_calls == 3 && published == 3);
  assert(attempted[0].dwCurrentState == SERVICE_START_PENDING && attempted[0].dwServiceSpecificExitCode == 0);
  assert(attempted[1].dwCurrentState == SERVICE_RUNNING && attempted[1].dwServiceSpecificExitCode == 0);
  assert(attempted[2].dwCurrentState == SERVICE_STOPPED);
  assert(attempted[2].dwWin32ExitCode == (rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR));
  assert(attempted[2].dwServiceSpecificExitCode == (DWORD)rc);
}
int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "--exit") == 0) {
    reset(); run_rc=atoi(argv[2]); return run_dispatch();
  }
  verify_run(0); verify_run(1); verify_run(7);
  reset(); register_ok=0;
  assert(run_dispatch() == 1 && run_calls == 0 && status_calls == 0);
  reset(); invoke_callback=0;
  assert(run_dispatch() == 1 && run_calls == 0 && status_calls == 0);
  reset(); dispatcher_ok=0;
  assert(run_dispatch() == 1 && run_calls == 0 && status_calls == 0);
  reset(); run_rc=1; reject_status=1;
  assert(run_dispatch() == 1 && run_calls == 1 && status_calls == 3 && published == 0);
  /* A later ordinary status must clear a prior service-specific error. */
  reject_status=0;
  edr_service_set_status(SERVICE_START_PENDING, NO_ERROR, 30000);
  assert(g_service_status.dwServiceSpecificExitCode == 0);
  edr_service_set_status(SERVICE_RUNNING, NO_ERROR, 0);
  assert(g_service_status.dwServiceSpecificExitCode == 0);
  edr_service_set_status(SERVICE_STOPPED, NO_ERROR, 0);
  assert(g_service_status.dwServiceSpecificExitCode == 0);
  reset(); reject_status=1;
  assert(run_dispatch() == 0 && run_calls == 1 && status_calls == 3 && published == 0);
  return 0;
}
'''
        probe = (probe.replace("OUTCOME_DECLARATION", outcome[0])
                 .replace("SERVICE_SOURCE", service).replace("DISPATCH_SOURCE", dispatch))
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            (source / "probe.c").write_text(probe, encoding="utf-8")
            (source / "CMakeLists.txt").write_text(
                'cmake_minimum_required(VERSION 3.20)\nproject(ServiceOutcome C)\n'
                'set(CMAKE_C_STANDARD 11)\nfind_package(Threads REQUIRED)\n'
                'add_executable(service_outcome probe.c)\n'
                f'include_directories("{(ROOT / "include").as_posix()}")\n'
                'target_link_libraries(service_outcome PRIVATE Threads::Threads)\n'
                'enable_testing()\nadd_test(NAME service_outcome COMMAND service_outcome)\n', encoding="utf-8")
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            self.run_command("cmake", "--build", str(build))
            self.run_command("ctest", "--test-dir", str(build), "--output-on-failure", "--no-tests=error")
            executable = build / ("service_outcome.exe" if os.name == "nt" else "service_outcome")
            for expected in (0, 1, 7):
                result = subprocess.run([str(executable), "--exit", str(expected)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_shutdown_progress_executes_service_and_collector_owners(self):
        """Execute actual C owners with simulated SCM/ETW I/O, not a service stop."""
        main = (ROOT / "src/main.c").read_text(encoding="utf-8")
        start = main.index("static void edr_service_set_status(DWORD state, DWORD win32_exit, DWORD wait_hint_ms) {")
        service = main[start:main.index("\nstatic void WINAPI edr_service_main", start)]
        win = (ROOT / "src/collector/collector_win.c").read_text(encoding="utf-8")
        start = win.index("int edr_collector_stop(")
        collector = win[start:win.index("\nint edr_collector_get_health", start)]
        probe = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "edr/agent.h"
#include "edr/collector.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef int BOOL;
typedef void *HANDLE;
typedef void *SERVICE_STATUS_HANDLE;
typedef pthread_mutex_t SRWLOCK;
#define SRWLOCK_INIT PTHREAD_MUTEX_INITIALIZER
#define WINAPI
#define NO_ERROR 0u
#define ERROR_SERVICE_SPECIFIC_ERROR 1066u
#define SERVICE_WIN32_OWN_PROCESS 16u
#define SERVICE_START_PENDING 2u
#define SERVICE_STOP_PENDING 3u
#define SERVICE_STOPPED 1u
#define SERVICE_RUNNING 4u
#define SERVICE_ACCEPT_STOP 1u
#define SERVICE_ACCEPT_SHUTDOWN 4u
#define SERVICE_CONTROL_STOP 1u
#define SERVICE_CONTROL_SHUTDOWN 5u
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 258u
typedef struct { DWORD dwServiceType, dwCurrentState, dwControlsAccepted,
  dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint; } SERVICE_STATUS;
static void AcquireSRWLockExclusive(SRWLOCK *p) { assert(pthread_mutex_lock(p) == 0); }
static void ReleaseSRWLockExclusive(SRWLOCK *p) { assert(pthread_mutex_unlock(p) == 0); }
static LONG InterlockedCompareExchange(volatile LONG *p, LONG desired, LONG expected) {
  __atomic_compare_exchange_n(p, &expected, desired, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  return expected;
}
#endif
static EdrAgent *g_agent_for_ctrl;
static SERVICE_STATUS_HANDLE g_service_status_handle;
static SERVICE_STATUS g_service_status;
static SRWLOCK g_service_status_lock = SRWLOCK_INIT;
static volatile LONG g_service_exit_code = 1;
static int held, attempts, failures, shutdowns;
static SERVICE_STATUS accepted[512];
static unsigned accepted_count;
static void locked(SRWLOCK *p) { AcquireSRWLockExclusive(p); assert(!held); held = 1; }
static void unlocked(SRWLOCK *p) { assert(held); held = 0; ReleaseSRWLockExclusive(p); }
#define AcquireSRWLockExclusive locked
#define ReleaseSRWLockExclusive unlocked
static BOOL fake_SetServiceStatus(SERVICE_STATUS_HANDLE h, SERVICE_STATUS *s) {
  assert(h && held);
  assert(s->dwServiceType == SERVICE_WIN32_OWN_PROCESS);
  assert(s->dwControlsAccepted == (s->dwCurrentState == SERVICE_RUNNING ?
      SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0));
  if (s->dwCurrentState == SERVICE_STOP_PENDING) assert(s->dwWaitHint == 30000);
  attempts++;
  if (failures) { failures--; return 0; }
  assert(accepted_count < 512); accepted[accepted_count++] = *s; return 1;
}
#define SetServiceStatus fake_SetServiceStatus
#define GetLastError() 5u
void edr_agent_shutdown(EdrAgent *agent) {
  assert(agent == g_agent_for_ctrl); locked(&g_service_status_lock); shutdowns++; unlocked(&g_service_status_lock);
}
SERVICE_SOURCE
static void publish_all(void) {
  for (int i = EDR_SHUTDOWN_MAIN_LOOP_EXITED; i <= EDR_SHUTDOWN_AGENT_DESTROY_RETURNED; i++) {
    edr_service_shutdown_progress(NULL, (EdrShutdownStage)i);
    edr_service_ctrl_handler(SERVICE_CONTROL_STOP);
  }
}
#ifdef _WIN32
static DWORD WINAPI concurrent(void *unused) { (void)unused; publish_all(); return 0; }
#else
static void *concurrent(void *unused) { (void)unused; publish_all(); return NULL; }
#endif
/* Collector calls are simulated; all lifecycle control flow below is actual. */
#define INVALID_PROCESSTRACE_HANDLE ((uintptr_t)-1)
#define EVENT_TRACE_CONTROL_STOP 1u
typedef struct { struct { DWORD BufferSize; } Wnode; } EVENT_TRACE_PROPERTIES;
static volatile int s_started, s_stopping, s_consumer_open_ok, s_consumer_running;
static uintptr_t s_session_handle;
static HANDLE s_registry_watch_stop_event, s_security_sub, s_consumer_thread,
  s_registry_watch_thread, s_consumer_ready_event;
static unsigned s_consumer_thread_id, s_registry_watch_thread_id;
static void *s_bus, *s_collector_cfg;
static const wchar_t *g_session_name = L"synthetic";
static unsigned waits, close_count, actions, reports;
static DWORD fail_wait;
static int a44_ok;
static EdrShutdownStage reported[32];
static int fake_collector_InterlockedCompareExchange(volatile int *p, int desired, int expected) {
  int old=*p; if (old == expected) *p=desired; return old;
}
static int fake_collector_InterlockedExchange(volatile int *p, int value) { int old=*p; *p=value; return old; }
static DWORD fake_collector_ControlTraceW(uintptr_t h, const wchar_t *name, EVENT_TRACE_PROPERTIES *p, unsigned mode) {
  assert(h == 1 && name && p->Wnode.BufferSize == sizeof(*p) && mode == EVENT_TRACE_CONTROL_STOP); actions++; return 5;
}
static BOOL fake_collector_SetEvent(HANDLE h) { assert(h); actions++; return 1; }
static BOOL fake_collector_EvtClose(HANDLE h) { assert(h); actions++; return 1; }
static DWORD fake_collector_WaitForSingleObject(HANDLE h, DWORD ms) { assert(h && ms == 30000); waits++; actions++; return waits == fail_wait ? WAIT_TIMEOUT : WAIT_OBJECT_0; }
static BOOL fake_collector_CloseHandle(HANDLE h) { assert(h); close_count++; actions++; return 1; }
static int edr_a44_split_path_stop(void) { actions++; return a44_ok; }
static void edr_network_trace_stop(void) { actions++; }
static void edr_collector_file_key_cache_reset(void) { actions++; }
static void edr_collector_file_read_metadata_gate_session_reset(void) { actions++; }

#undef InterlockedCompareExchange
#define InterlockedCompareExchange fake_collector_InterlockedCompareExchange
#undef InterlockedExchange
#define InterlockedExchange fake_collector_InterlockedExchange
#undef ControlTraceW
#define ControlTraceW fake_collector_ControlTraceW
#undef SetEvent
#define SetEvent fake_collector_SetEvent
#undef EvtClose
#define EvtClose fake_collector_EvtClose
#undef WaitForSingleObject
#define WaitForSingleObject fake_collector_WaitForSingleObject
#undef CloseHandle
#define CloseHandle fake_collector_CloseHandle
COLLECTOR_SOURCE
#undef InterlockedCompareExchange
#undef InterlockedExchange
#undef ControlTraceW
#undef SetEvent
#undef EvtClose
#undef WaitForSingleObject
#undef CloseHandle
static void collect_report(void *context, EdrShutdownStage stage) {
  assert(context == &reports && reports < 32); reported[reports++] = stage;
}
static void reset_collector(void) {
  s_started=1; s_stopping=0; s_consumer_running=1; s_consumer_open_ok=1;
  s_session_handle=1; s_consumer_thread=(HANDLE)(uintptr_t)2;
  s_registry_watch_thread=(HANDLE)(uintptr_t)3; s_registry_watch_stop_event=(HANDLE)(uintptr_t)4;
  s_consumer_ready_event=(HANDLE)(uintptr_t)5; s_security_sub=(HANDLE)(uintptr_t)6;
  s_bus=(void *)(uintptr_t)7; s_collector_cfg=(void *)(uintptr_t)8;
  waits=close_count=actions=reports=0; fail_wait=0; a44_ok=1;
}
int main(void) {
  EdrShutdownObserver observer={collect_report, &reports}, empty={0};
  edr_shutdown_progress(NULL, EDR_SHUTDOWN_MAIN_LOOP_EXITED);
  edr_shutdown_progress(&empty, EDR_SHUTDOWN_MAIN_LOOP_EXITED);
  edr_service_shutdown_progress(NULL, EDR_SHUTDOWN_MAIN_LOOP_EXITED); assert(attempts == 0);
  g_service_status_handle=(SERVICE_STATUS_HANDLE)(uintptr_t)1;
  g_agent_for_ctrl=(EdrAgent *)(uintptr_t)2;
  edr_service_set_status(SERVICE_START_PENDING, NO_ERROR, 30000);
  edr_service_set_status(SERVICE_START_PENDING, NO_ERROR, 30000);
  assert(g_service_status.dwCheckPoint == 2);
  edr_service_set_status(SERVICE_RUNNING, NO_ERROR, 0);
  edr_service_shutdown_progress(NULL, EDR_SHUTDOWN_MAIN_LOOP_EXITED); assert(attempts == 3);
  edr_service_ctrl_handler(SERVICE_CONTROL_STOP);
  assert(shutdowns == 1 && g_service_status.dwCheckPoint == 1);
  edr_service_ctrl_handler(SERVICE_CONTROL_STOP);
  assert(shutdowns == 2 && attempts == 4 && g_service_status.dwCheckPoint == 1);
  edr_service_shutdown_progress(NULL, (EdrShutdownStage)0);
  edr_service_shutdown_progress(NULL, (EdrShutdownStage)999); assert(attempts == 4);
  failures=1; edr_service_shutdown_progress(NULL, EDR_SHUTDOWN_MAIN_LOOP_EXITED);
  assert(attempts == 5 && accepted[accepted_count-1].dwCheckPoint == 1 && g_service_status.dwCheckPoint == 2);
  edr_service_shutdown_progress(NULL, EDR_SHUTDOWN_MAIN_LOOP_EXITED); assert(attempts == 5);
#ifdef _WIN32
  HANDLE threads[4];
  for (unsigned i=0;i<4;i++) { threads[i]=CreateThread(NULL,0,concurrent,NULL,0,NULL); assert(threads[i]); }
  for (unsigned i=0;i<4;i++) { assert(WaitForSingleObject(threads[i],10000) == WAIT_OBJECT_0); assert(CloseHandle(threads[i])); }
#else
  pthread_t threads[4];
  for (unsigned i=0;i<4;i++) assert(pthread_create(&threads[i], NULL, concurrent, NULL) == 0);
  for (unsigned i=0;i<4;i++) assert(pthread_join(threads[i], NULL) == 0);
#endif
  assert(g_service_status.dwCheckPoint == EDR_SHUTDOWN_AGENT_DESTROY_RETURNED);
  DWORD last=0;
  for (unsigned i=0;i<accepted_count;i++) if (accepted[i].dwCurrentState == SERVICE_STOP_PENDING) {
    assert(accepted[i].dwCheckPoint > last); last=accepted[i].dwCheckPoint;
  }
  edr_service_set_status(SERVICE_STOPPED, NO_ERROR, 0);
  int before=attempts;
  edr_service_shutdown_progress(NULL, EDR_SHUTDOWN_AGENT_DESTROY_RETURNED); assert(attempts == before);
  reset_collector(); assert(edr_collector_stop(NULL) == 1); unsigned plain_actions=actions;
  assert(reports == 0 && s_started == 0 && !s_bus && !s_consumer_thread);
  edr_service_set_status(SERVICE_RUNNING, NO_ERROR, 0);
  edr_service_ctrl_handler(SERVICE_CONTROL_STOP);
  unsigned accepted_before=accepted_count;
  failures=32;
  EdrShutdownObserver refused_scm={edr_service_shutdown_progress, NULL};
  reset_collector(); assert(edr_collector_stop(&refused_scm) == 1 && actions == plain_actions);
  assert(accepted_count == accepted_before && accepted[accepted_count-1].dwCheckPoint == 1);
  assert(g_service_status.dwCheckPoint == EDR_SHUTDOWN_COLLECTOR_CLEANUP_DONE);
  failures=0;
  edr_service_set_status(SERVICE_STOPPED, NO_ERROR, 0);
  reset_collector(); assert(edr_collector_stop(&observer) == 1 && actions == plain_actions);
  assert(reports == 9 && reported[0] == EDR_SHUTDOWN_COLLECTOR_ENTERED && reported[8] == EDR_SHUTDOWN_COLLECTOR_CLEANUP_DONE);
  reset_collector(); fail_wait=1; assert(edr_collector_stop(&observer) == 0);
  assert(reported[reports-1] == EDR_SHUTDOWN_SECURITY_CLOSE_RETURNED && s_started == 1 && s_bus && s_consumer_thread && close_count == 0);
  reset_collector(); fail_wait=2; assert(edr_collector_stop(&observer) == 0);
  assert(reported[reports-1] == EDR_SHUTDOWN_ETW_JOIN_PHASE_DONE && s_started == 1 && s_registry_watch_thread && close_count == 0);
  reset_collector(); a44_ok=0; assert(edr_collector_stop(&observer) == 0);
  assert(reported[reports-1] == EDR_SHUTDOWN_REGISTRY_JOIN_PHASE_DONE && s_started == 1 && s_bus && close_count == 0);
  reset_collector(); s_started=0; assert(edr_collector_stop(&observer) == 1 && reports == 0 && actions == 0);
  return 0;
}
'''
        probe = probe.replace("SERVICE_SOURCE", service).replace("COLLECTOR_SOURCE", collector)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            (source / "probe.c").write_text(probe, encoding="utf-8")
            (source / "abi.c").write_text(
                '#include "edr/agent.h"\n#include "edr/collector.h"\n'
                'extern EdrError edr_agent_run(EdrAgent *, const EdrShutdownObserver *);\n'
                'extern int edr_collector_stop(const EdrShutdownObserver *);\n', encoding="utf-8")
            (source / "CMakeLists.txt").write_text(
                'cmake_minimum_required(VERSION 3.20)\nproject(ShutdownProgress C)\n'
                'set(CMAKE_C_STANDARD 11)\nfind_package(Threads REQUIRED)\n'
                'add_library(abi OBJECT abi.c)\nadd_executable(progress probe.c)\n'
                f'include_directories("{(ROOT / "include").as_posix()}")\n'
                'target_link_libraries(progress PRIVATE Threads::Threads)\n'
                'enable_testing()\nadd_test(NAME shutdown_progress COMMAND progress)\n', encoding="utf-8")
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            self.run_command("cmake", "--build", str(build))
            self.run_command("ctest", "--test-dir", str(build), "--output-on-failure", "--no-tests=error")

    def test_file_read_consumer_lifecycle_gate_behavior(self):
        """Execute the production readiness predicate for every lifecycle combination.

        Only the atomic Windows read is adapted; this is not an ETW runtime
        test. The collector wiring contract separately checks its call sites.
        """
        collector = (ROOT / "src/collector/collector_win.c").read_text(encoding="utf-8")
        start = collector.index("static int edr_collector_file_read_consumer_ready(void) {")
        end = collector.index("static void edr_collector_file_read_metadata_gate_copy_health(", start)
        predicate = collector[start:end]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            (source / "probe.c").write_text(
                '#include <stdint.h>\n'
                'static volatile int32_t s_started, s_stopping, s_consumer_open_ok, s_consumer_running;\n'
                'static int32_t InterlockedCompareExchange(volatile int32_t *p, int32_t value, int32_t expected) {\n'
                '  int32_t before = *p; if (before == expected) *p = value; return before; }\n'
                + predicate + '\nint main(void) {\n'
                '  for (unsigned bits = 0; bits < 16; ++bits) {\n'
                '    s_started = (bits & 1) != 0; s_stopping = (bits & 2) != 0;\n'
                '    s_consumer_open_ok = (bits & 4) != 0; s_consumer_running = (bits & 8) != 0;\n'
                '    if (edr_collector_file_read_consumer_ready() != (bits == 13)) return (int)bits + 1;\n'
                '  }\n  return 0;\n}\n', encoding="utf-8")
            (source / "CMakeLists.txt").write_text(
                'cmake_minimum_required(VERSION 3.20)\nproject(FileReadLifecycle C)\n'
                'set(CMAKE_C_STANDARD 11)\nadd_executable(lifecycle_probe probe.c)\n'
                'enable_testing()\nadd_test(NAME lifecycle COMMAND lifecycle_probe)\n',
                encoding="utf-8")
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja")
            self.run_command("cmake", "--build", str(build), "--target", "lifecycle_probe")
            self.run_command("ctest", "--test-dir", str(build), "--output-on-failure", "--no-tests=error")

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
            if workflow == "edr-agent-client-release.yml":
                self.assertIn("& .\\tests\\run_telemetry_windows_native.ps1 @telemetryArgs", source)
                self.assertIn("$telemetryArgs.IncludeReleaseGate = $true", source)
            else:
                self.assertIn("ctest --test-dir build -C Release --output-on-failure --no-tests=error --label-regex '^windows-release-gate$'", source)

        source = (ROOT / ".github/workflows/edr-agent-ci.yml").read_text(encoding="utf-8")
        build_step = re.search(r'- name: Build\n(.*?)(?=\n      - name:)', source, re.DOTALL)
        self.assertIsNotNone(build_step)
        self.assertIn('CMAKE_PREFIX_PATH: ${{ github.workspace }}/vcpkg_installed/x64-windows', build_step[1])
        self.assertIn("python tests/test_pcre2_cmake_gate.py PCRE2CMakeGateTests.test_static_matcher_header_wins_over_shared_dependency_prefix -v", build_step[1])
        self.assertIn('throw "Windows PCRE2 header isolation regression failed"', build_step[1])
        self.assertIn("'windows_release_gate_tests'", source)
        # Reject a second CMake target whitelist, not quoted Python
        # discovery patterns such as 'test_vcpkg_*cache*.py'.
        self.assertNotRegex(source, r'''["']test_[A-Za-z0-9_]+["']''')
        self.assertIn("ctest --test-dir build -C Release --output-on-failure --no-tests=error --label-regex '^windows-release-gate$'", source)

    def test_dependency_cache_is_saved_before_product_failures(self):
        for workflow in ("edr-agent-ci.yml", "edr-agent-client-build.yml",
                         "edr-agent-client-release.yml", "edr-agent-prebuild-packages.yml"):
            with self.subTest(workflow=workflow):
                source = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
                steps = re.split(r'(?m)^      - ', source)[1:]
                def step_with(marker):
                    matches = [step for step in steps if marker in step]
                    self.assertEqual(len(matches), 1, marker)
                    return matches[0]
                initialize = step_with("name: Initialize pinned Visual Studio environment")
                if "prebuild" not in workflow:
                    preflight = step_with("name: Preflight native P0 test compiler before dependencies")
                    self.assertIn("WindowsReleaseGateTests.test_p0_direct_emit_windows_compiler_surface -v", preflight)
                    self.assertIn("if ($LASTEXITCODE -ne 0)", preflight)
                    self.assertLess(steps.index(initialize), steps.index(preflight))
                    self.assertLess(steps.index(preflight), steps.index(step_with("id: vcpkg-key\n")))
                identify = step_with("id: vcpkg-key\n")
                restore = step_with("id: vcpkg-cache\n")
                install = step_with("name: vcpkg install (")
                save = step_with("name: Save completed vcpkg dependencies")
                consumer = step_with("name: Publish shared vcpkg dependency cache" if "prebuild" in workflow
                                     else "name: Configure (")
                for before, after in zip((initialize, identify, restore, install, save),
                                         (identify, restore, install, save, consumer)):
                    self.assertLess(steps.index(before), steps.index(after))
                self.assertIn("vcpkg_cache_key.py --triplet", identify)
                self.assertIn("test_vcpkg_*cache*.py", identify)
                self.assertIn("if ($LASTEXITCODE -ne 0)", identify)
                self.assertIn("key: ${{ steps.vcpkg-key.outputs.key }}", restore)
                self.assertIn("${{ steps.vcpkg-key.outputs.restore-prefix }}", restore)
                self.assertIn("key: ${{ steps.vcpkg-cache.outputs.cache-primary-key }}", save)
                self.assertIn("steps.vcpkg-cache.outputs.cache-hit != 'true'", save)
                self.assertIn("hashFiles('.cache/vcpkg-bincache/**/*.zip') != ''", save)
                for cache_step in (restore, save):
                    paths = re.search(r'path: \|\n(.*?)(?=\n\s+key:)', cache_step, re.DOTALL)
                    self.assertIsNotNone(paths)
                    self.assertEqual(set(paths[1].split()),
                                     {".cache/vcpkg-downloads", ".cache/vcpkg-bincache"})
                self.assertIn('VCPKG_BINARY_SOURCES: "clear;files,', source)
                self.assertIn("Invoke-VcpkgInstallWithRetry.ps1", install)
                self.assertNotIn("actions/cache@", source)
                shared = step_with("name: Restore shared vcpkg dependency cache")
                self.assertLess(steps.index(restore), steps.index(shared))
                self.assertLess(steps.index(shared), steps.index(install))
                self.assertIn("vcpkg_release_cache.py restore --key '${{ steps.vcpkg-key.outputs.key }}'", shared)
                self.assertIn("--actions-cache-hit '${{ steps.vcpkg-cache.outputs.cache-hit }}'", shared)
                self.assertIn("GH_TOKEN: ${{ github.token }}", shared)
                self.assertNotIn("vcpkg-installed-", source)
                self.assertNotIn("gh release delete", source)
                if workflow in ("edr-agent-ci.yml", "edr-agent-client-build.yml"):
                    self.assertIn("permissions:\n  contents: read", source)
                    self.assertNotIn("vcpkg_release_cache.py publish", source)
                self.assertIn("test_vcpkg_install_retry.ps1", identify)
                self.assertIn("test_vs_host_architecture.ps1", identify)
                if workflow == "edr-agent-client-release.yml":
                    publish = step_with("name: Publish shared vcpkg dependency cache")
                    self.assertLess(steps.index(install), steps.index(publish))
                    self.assertLess(steps.index(publish), steps.index(consumer))
                    self.assertIn("steps.shared-vcpkg-publish.outcome == 'failure'", source)
                    # A shared archive can exist without matching current ABIs.
                    # Persist the completed local closure even after a successful
                    # (including already-published) shared publication step.
                    condition = re.search(r'(?m)^\s*if: (.*)$', save)
                    self.assertIsNotNone(condition)
                    self.assertEqual(condition[1], "(steps.vcpkg-cache.outputs.cache-hit != 'true' && hashFiles('.cache/vcpkg-bincache/**/*.zip') != '') && steps.resume.outputs.restored != 'true'")
                    self.assertLess(steps.index(publish), steps.index(save))
                for marker in re.findall(r'(?m)^\s*\$installed_marker = (.*)$', source):
                    self.assertEqual(marker, 'Join-Path $env:GITHUB_WORKSPACE "vcpkg_installed\\vcpkg\\status"')

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


def run_parallel_cases(cases, workers, stream):
    """Independent temp-dir fixtures; bounded concurrency, no test selection loss.

    Each case owns its TestResult and log, so failures cannot be swallowed or
    interleaved. Native product CTest remains a separate, mandatory release step.
    """
    if workers not in (1, 2):
        raise ValueError("Gate fixture parallelism must be 1 or 2")
    cases = list(cases)
    if not cases:
        raise ValueError("Empty gate fixture selection")

    def run_case(case):
        output = io.StringIO()
        started = time.monotonic()
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(case)
        return case.id(), result, output.getvalue(), time.monotonic() - started

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(run_case, cases))
    for name, result, output, elapsed in results:
        stream.write(output)
        stream.write(f"[gate-timing] {name}: {elapsed:.2f}s\n")
    total = sum(result.testsRun for _, result, _, _ in results)
    stream.write(f"Gate fixtures: {total}/{len(cases)} executed; workers={workers}\n")
    return total == len(cases) and all(result.wasSuccessful() for _, result, _, _ in results)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--parallel":
        names = unittest.defaultTestLoader.getTestCaseNames(WindowsReleaseGateTests)
        sys.exit(0 if run_parallel_cases((WindowsReleaseGateTests(name) for name in names),
                                        int(sys.argv[2]), sys.stderr) else 1)
    else:
        unittest.main()
