"""Exercise the real CMake gate dependency graph and platform branch contracts.

Tiny executables isolate the CI scheduling regression from product dependencies.
The host admission probe only adapts OS locks/clock; it is not Windows emulation.
The actual tests still run natively in the normal Windows CTest gate.
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
    "kernel_file_io_identity", "etw_network_decode_native",
    "security_event_time_native", "security_event_time_failures",
    "response_file_security_behavior", "response_forensic_path_contract",
    "windows_isolation_mock_behavior", "windows_install_compatibility_behavior", "http_telemetry_budget",
}
RUNTIME_EXPECTED = {
    "command_inbox_persistence", "request_signing", "http_retry_contract", "command_result_json_contract",
    "event_bus_wait_and_mpmc", "event_batch_max_age", "response_capability_manifest_contract",
    "behavior_record_alert_proto_contract",
    "behavior_record_alert_emit_contract", "p0_direct_emit_suppression", "p0_deferred_snapshot",
    "process_tree_cache", "local_evidence_cache_candidate",
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

    def test_p0_gate_windows_branches_compile_with_sqlite(self):
        """Compile real P0 gate tests with the production SQLite branches enabled.

        A host compiler accepting a POSIX API or ATOMIC_VAR_INIT is not evidence
        that MSVC accepts it. Native Windows uses its CRT/SDK; other hosts remove
        those conveniences while retaining the actual SQLite headers.
        """
        cmake_source = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        begin = cmake_source.index("set(CMAKE_C_STANDARD 11)")
        end = cmake_source.index('option(EDR_BUILD_TESTS', begin)
        targets = (
            "test_p0_direct_emit_suppression", "test_local_evidence_cache_candidate",
            "test_p0_deferred_snapshot", "test_behavior_record_alert_emit",
            "test_process_tree_cache",
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            build = source / "build"
            (source / "windows.h").write_text(
                '#include <stdint.h>\n#define MAX_PATH 260\n'
                'typedef uint32_t DWORD;\n'
                'typedef struct { DWORD dwLowDateTime, dwHighDateTime; } FILETIME;\n'
                'DWORD GetTempPathA(DWORD, char *);\n'
                'unsigned GetTempFileNameA(const char *, const char *, unsigned, char *);\n'
                'void GetSystemTimeAsFileTime(FILETIME *);\n'
                'int _putenv_s(const char *, const char *);\n', encoding="utf-8")
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
                cmake_source[begin:end], 'find_package(SQLite3 REQUIRED)',
            ]
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
            lines += [
                'target_compile_definitions(test_p0_direct_emit_suppression PRIVATE EDR_P0_DIRECT_EMIT_TESTING=1)',
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
            self.run_command("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja",
                             "-DCMAKE_BUILD_TYPE=Release")
            self.run_command("cmake", "--build", str(build), "--parallel", "2", "--", "-k", "0")

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
                f'set(EDR_TEST_ROOT "{ROOT.as_posix()}")', target,
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
            self.run_command("ctest", "--test-dir", str(build), "--output-on-failure",
                             "--no-tests=error", "-R", "^p0_direct_emit_suppression$")

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
                initialize = step_with("name: Initialize pinned Visual Studio 2022 environment")
                identify = step_with("id: vcpkg-key\n")
                restore = step_with("uses: actions/cache/restore@v5")
                install = step_with("name: vcpkg install (")
                save = step_with("uses: actions/cache/save@v5")
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
                self.assertIn("if: steps.vcpkg-cache.outputs.cache-hit != 'true'", save)
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
                self.assertIn("test_vs2022_host_architecture.ps1", identify)
                if workflow == "edr-agent-client-release.yml":
                    publish = step_with("name: Publish shared vcpkg dependency cache")
                    self.assertLess(steps.index(install), steps.index(publish))
                    self.assertLess(steps.index(publish), steps.index(consumer))
                    self.assertIn("steps.shared-vcpkg-publish.outcome == 'failure'", source)
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


if __name__ == "__main__":
    unittest.main()
