import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


AGENT_ROOT = Path(__file__).parents[1]
REPO_ROOT = AGENT_ROOT.parent
PRODUCER_PATH = AGENT_ROOT / "scripts" / "produce_pcre2_matcher_contract.py"
PRODUCER_SPEC = importlib.util.spec_from_file_location("pcre2_contract_producer", PRODUCER_PATH)
PRODUCER = importlib.util.module_from_spec(PRODUCER_SPEC)
assert PRODUCER_SPEC.loader is not None
PRODUCER_SPEC.loader.exec_module(PRODUCER)

FIXTURE_GATE_PATH = AGENT_ROOT / "scripts" / "verify_p0_durable_wire_fixtures.py"
FIXTURE_GATE_SPEC = importlib.util.spec_from_file_location("p0_durable_wire_fixture_gate", FIXTURE_GATE_PATH)
FIXTURE_GATE = importlib.util.module_from_spec(FIXTURE_GATE_SPEC)
assert FIXTURE_GATE_SPEC.loader is not None
FIXTURE_GATE_SPEC.loader.exec_module(FIXTURE_GATE)


def static_linux_amd64_archive() -> bytes:
    payload = bytearray(20)
    payload[:4] = b"\x7fELF"
    payload[18:20] = (62).to_bytes(2, "little")
    payload.extend(b"cmake-gate-static-pcre2")
    header = (
        f"{'pcre2.o/':<16}{0:<12}{0:<6}{0:<6}{0:<8}{len(payload):<10}".encode("ascii")
        + b"\x60\n"
    )
    return b"!<arch>\n" + header + bytes(payload) + (b"\n" if len(payload) % 2 else b"")


def write_pcre2_portfile(root: Path) -> Path:
    (root / "pcre2-test.patch").write_text("cmake gate patch\n", encoding="utf-8")
    portfile = root / "portfile.cmake"
    portfile.write_text(
        "vcpkg_from_github(\n"
        "  REPO PCRE2Project/pcre2\n"
        "  REF pcre2-test\n"
        f"  SHA512 {'a' * 128}\n"
        "  PATCHES\n"
        "    pcre2-test.patch\n"
        ")\n"
        "vcpkg_from_github(\n"
        "  REPO zherczeg/sljit\n"
        "  REF sljit-test\n"
        f"  SHA512 {'b' * 128}\n"
        ")\n",
        encoding="utf-8",
    )
    return portfile


def production_cmake_configure_blocks(source: str) -> list[str]:
    """Return every Agent configure block except the exact non-production stub.

    CMake defaults EDR_REQUIRE_PCRE2 to ON, so a missing build type or an
    explicit Debug build still selects the real matcher unless all three stub
    switches are present.  A multi-config generator can expose a release
    configuration even when its first build selects Debug, and is never an
    exemption.
    """
    lines = source.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        if not re.search(r"\bcmake(?:\.exe)?\b", line):
            continue
        if re.search(r"\bcmake(?:\.exe)?\b\s+--build\b", line):
            continue
        if not re.search(r"(?:\s-B(?:\s|$)|\s-S(?:\s|$)|\s--preset(?:\s|$))", line):
            continue
        command_lines = [line]
        cursor = index
        while command_lines[-1].rstrip().endswith(("\\", "`")) and cursor + 1 < len(lines):
            cursor += 1
            command_lines.append(lines[cursor])
        command = " ".join(part.strip().rstrip("\\`") for part in command_lines)
        explicit_stub_flags = all(token in command for token in (
            "EDR_BUILD_TESTS=ON",
            "EDR_REQUIRE_PCRE2=OFF",
            "EDR_P0_RULE_IR_ALLOW_TEST_STUB=ON",
        ))
        configuration_types = "CMAKE_CONFIGURATION_TYPES=" in command
        multi_config = bool(re.search(r"(?:Visual Studio|Xcode|Ninja Multi-Config)", command, re.IGNORECASE))
        build_type = re.search(r"CMAKE_BUILD_TYPE=([^\s\\`]+)", command, re.IGNORECASE)
        explicit_debug = bool(build_type and build_type.group(1).strip('"\'').lower() == "debug")
        if explicit_stub_flags and explicit_debug and not configuration_types and not multi_config:
            continue
        blocks.append(command)
    return blocks


class PCRE2CMakeGateTests(unittest.TestCase):
    def test_visual_studio_environment_preserves_caller_vcpkg_root(self):
        source = (AGENT_ROOT / "scripts" / "Initialize-VS2022Environment.ps1").read_text(encoding="utf-8")
        self.assertIn(
            '$callerVcpkgRoot = [Environment]::GetEnvironmentVariable("VCPKG_ROOT", "Process")',
            source,
        )
        self.assertIn(
            'if ($name -ieq "VCPKG_ROOT" -and -not [string]::IsNullOrWhiteSpace($callerVcpkgRoot))',
            source,
        )
        self.assertIn(
            'Add-Content -LiteralPath $GithubEnvPath -Value ("VCPKG_ROOT={0}" -f $callerVcpkgRoot)',
            source,
        )

    def configure(self, *, build_tests: bool, require_pcre2: bool,
                  allow_test_stub: bool, build_type: str = "",
                  extra_args: tuple[str, ...] = ()) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = [
                "cmake", "-S", str(AGENT_ROOT), "-B", str(root / "build"),
                f"-DEDR_BUILD_TESTS={'ON' if build_tests else 'OFF'}",
                f"-DEDR_REQUIRE_PCRE2={'ON' if require_pcre2 else 'OFF'}",
                f"-DEDR_P0_RULE_IR_ALLOW_TEST_STUB={'ON' if allow_test_stub else 'OFF'}",
                "-DCMAKE_DISABLE_FIND_PACKAGE_PCRE2=TRUE",
                f"-DEDR_PCRE2_INCLUDE_DIR={root / 'missing-include'}",
                f"-DEDR_PCRE2_LIBRARY={root / 'missing-library'}",
            ]
            if build_type:
                command.append(f"-DCMAKE_BUILD_TYPE={build_type}")
            command.extend(extra_args)
            return subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )

    def test_pcre2_verify_paths_normalize_windows_separators_and_reject_bad_paths(self):
        """Exercise the production CMake helper rather than duplicating path policy."""
        source = (AGENT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        helper_start = source.index("function(_edr_pcre2_require_below")
        helper_end = source.index("endfunction()", helper_start) + len("endfunction()")
        helper = source[helper_start:helper_end]
        self.assertIn('MATCHES "^\\\\.\\\\.($|[/\\\\\\\\])"', helper)
        verify_start = source.index('_edr_pcre2_json_member("${_edr_pcre2_verify_output}" "schema"')
        verify_end = source.index('add_library(edr_pcre2_static STATIC IMPORTED GLOBAL)', verify_start)
        verify_gate = source[verify_start:verify_end]
        self.assertIn(
            '_edr_pcre2_require_below("${_edr_pcre2_producer_root}" "${_edr_pcre2_verify_contract}"',
            verify_gate,
        )
        self.assertIn(
            '_edr_pcre2_require_below("${_edr_pcre2_producer_root}" "${_edr_pcre2_verify_prefix}"',
            verify_gate,
        )
        self.assertIn('"${_edr_pcre2_verify_contract_real}" STREQUAL "${_edr_pcre2_contract_real}"', verify_gate)
        self.assertIn('"${_edr_pcre2_verify_prefix_real}" STREQUAL "${_edr_pcre2_prefix_real}"', verify_gate)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "producer"
            contract = root / "p0_matcher_contract.json"
            prefix = root / "prefix"
            outside = Path(directory) / "outside.json"
            prefix.mkdir(parents=True)
            contract.write_text("{}", encoding="utf-8")
            outside.write_text("{}", encoding="utf-8")

            def invoke(candidate: str) -> subprocess.CompletedProcess[str]:
                script = Path(directory) / "require-below.cmake"
                script.write_text(
                    "cmake_minimum_required(VERSION 3.20)\n"
                    f"{helper}\n"
                    f"set(_root [==[{root.as_posix()}]==])\n"
                    f"_edr_pcre2_require_below(\"${{_root}}\" [==[{candidate}]==] \"test path\" _result)\n"
                    "message(STATUS \"RESULT=${_result}\")\n",
                    encoding="utf-8",
                )
                return subprocess.run(
                    ["cmake", "-P", str(script)], text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
                )

            windows_separator_contract = root.as_posix() + "\\\\p0_matcher_contract.json"
            normalized = invoke(windows_separator_contract)
            self.assertEqual(0, normalized.returncode, normalized.stdout)
            self.assertIn(f"RESULT={contract.resolve().as_posix()}", normalized.stdout)

            escaped = invoke(root.as_posix() + "\\\\..\\\\outside.json")
            self.assertNotEqual(0, escaped.returncode)
            self.assertIn("escapes the build-owned producer root", escaped.stdout)

            wrong = invoke(root.as_posix() + "\\\\missing.json")
            self.assertNotEqual(0, wrong.returncode)
            self.assertIn("does not exist", wrong.stdout)

    def test_default_product_configure_fails_when_pcre2_is_missing(self):
        completed = self.configure(build_tests=False, require_pcre2=True,
                                  allow_test_stub=False)
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("Production PCRE2 matcher builds require", completed.stdout)

    def test_explicit_stub_configure_is_marked_nonproduction(self):
        completed = self.configure(build_tests=True, require_pcre2=False,
                                  allow_test_stub=True, build_type="Debug")
        self.assertEqual(0, completed.returncode, completed.stdout)
        self.assertRegex(completed.stdout, r"explicit NON-PRODUCTION CTest stub\s+selected")
        self.assertIn("cannot publish or enforce P0 rules", completed.stdout)

    def test_published_ir_fixture_is_only_registered_with_verified_matcher(self):
        tests_cmake = (AGENT_ROOT / "tests" / "CMakeLists.txt").read_text(encoding="utf-8")
        fixture_start = tests_cmake.index("if(EDR_PCRE2_AVAILABLE)")
        fixture_gate = tests_cmake[fixture_start:tests_cmake.index("if(SQLite3_FOUND)", fixture_start)]
        self.assertIn("add_test(NAME p0_source_only_durable_contract", fixture_gate)
        self.assertIn("not registered because the non-production", fixture_gate)
        self.assertIn("PCRE2 stub cannot verify published IR authority", fixture_gate)
        self.assertNotIn("EDR_PCRE2_INCLUDE_DIR", fixture_gate)

        cmake_source = (AGENT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        production_gate = cmake_source[
            cmake_source.index("if(_edr_pcre2_explicit_test_stub)"):
            cmake_source.index("find_package(OpenSSL QUIET)")
        ]
        self.assertIn("set(EDR_PCRE2_AVAILABLE 1)", production_gate)

        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory) / "build"
            command = [
                "cmake", "-S", str(AGENT_ROOT), "-B", str(build), "-G", "Ninja",
                "-DCMAKE_BUILD_TYPE=Debug",
                "-DEDR_BUILD_TESTS=ON",
                "-DEDR_REQUIRE_PCRE2=OFF",
                "-DEDR_P0_RULE_IR_ALLOW_TEST_STUB=ON",
                "-DCMAKE_DISABLE_FIND_PACKAGE_PCRE2=TRUE",
            ]
            configured = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
            )
            self.assertEqual(0, configured.returncode, configured.stdout)
            self.assertIn("not registered because the non-production PCRE2 stub", configured.stdout)
            listed = subprocess.run(
                ["ctest", "--test-dir", str(build), "-N"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
            )
        self.assertEqual(0, listed.returncode, listed.stdout)
        self.assertNotIn("p0_source_only_durable_contract", listed.stdout)

    def test_release_rejects_explicit_stub(self):
        completed = self.configure(build_tests=True, require_pcre2=False,
                                  allow_test_stub=True, build_type="Release")
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("p0_rule_ir_stub.c is allowed only", completed.stdout)

    def test_all_release_class_configurations_reject_explicit_stub(self):
        for build_type in ("RelWithDebInfo", "MinSizeRel", "Production"):
            completed = self.configure(build_tests=True, require_pcre2=False,
                                      allow_test_stub=True, build_type=build_type)
            self.assertNotEqual(0, completed.returncode, build_type)
            self.assertIn("p0_rule_ir_stub.c is allowed only", completed.stdout)

        with tempfile.TemporaryDirectory() as directory:
            command = [
                "cmake", "-S", str(AGENT_ROOT), "-B", str(Path(directory) / "build"),
                "-G", "Ninja Multi-Config",
                "-DEDR_BUILD_TESTS=ON",
                "-DEDR_REQUIRE_PCRE2=OFF",
                "-DEDR_P0_RULE_IR_ALLOW_TEST_STUB=ON",
            ]
            completed = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
            )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("p0_rule_ir_stub.c is allowed only", completed.stdout)

    def test_production_configure_scanner_covers_defaults_debug_release_presets_multiconfig_and_variables(self):
        source = "\n".join((
            "cmake -S . -B default",
            "cmake -S . -B debug-default -DCMAKE_BUILD_TYPE=Debug",
            "cmake -S . -B rel -DCMAKE_BUILD_TYPE=Release -DEDR_REQUIRE_PCRE2=ON",
            "cmake -S . -B size -DCMAKE_BUILD_TYPE=MinSizeRel -DEDR_REQUIRE_PCRE2=ON",
            "cmake -S . -B prod -DCMAKE_BUILD_TYPE=Production -DEDR_REQUIRE_PCRE2=ON",
            "cmake -S . -B variable -DCMAKE_BUILD_TYPE=$BUILD_CONFIGURATION -DEDR_REQUIRE_PCRE2=ON",
            "cmake -S . -B multi -G \"Ninja Multi-Config\" -DEDR_REQUIRE_PCRE2=ON",
            "cmake --preset release-pinned",
            "cmake -S . -B debug -DCMAKE_BUILD_TYPE=Debug -DEDR_BUILD_TESTS=ON -DEDR_REQUIRE_PCRE2=OFF -DEDR_P0_RULE_IR_ALLOW_TEST_STUB=ON",
        ))
        discovered = production_cmake_configure_blocks(source)
        self.assertEqual(8, len(discovered), discovered)
        self.assertTrue(any("-B default" in command for command in discovered))
        self.assertTrue(any("-B debug-default" in command for command in discovered))
        self.assertFalse(any("-B debug -" in command for command in discovered))

    def test_production_configure_rejects_forged_contract_and_prefix_injection(self):
        """No caller-built archive can enter the Release linker path.

        This is the prior bypass shape: a synthetic target-correct ELF archive,
        matching header/pkg-config files, and a recomputed contract.  The
        external values are rejected *before* CMake consults their source-side
        self-report, which also makes a real clean locked checkout unable to
        bless an injected archive.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "installed" / "edr-x64-linux-static"
            header = prefix / "include" / "pcre2.h"
            archive = prefix / "lib" / "libpcre2-8.a"
            pkgconfig = prefix / "lib" / "pkgconfig" / "libpcre2-8.pc"
            header.parent.mkdir(parents=True)
            archive.parent.mkdir(parents=True)
            pkgconfig.parent.mkdir(parents=True)
            header.write_text("#define PCRE2_MAJOR 10\n#define PCRE2_MINOR 42\n", encoding="utf-8")
            archive.write_bytes(static_linux_amd64_archive())
            pkgconfig.write_text("Name: libpcre2-8\nVersion: 10.42\n", encoding="utf-8")
            portfile = write_pcre2_portfile(root)
            baseline, _ = PRODUCER.load_authority()
            contract = PRODUCER.contract_for(
                prefix,
                baseline=baseline,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-linux-static",
                portfile=portfile,
                target="linux/amd64",
            )
            contract_path = root / "p0_matcher_contract.json"
            PRODUCER.write_contract(contract_path, contract)
            completed = self.configure(
                build_tests=False,
                require_pcre2=True,
                allow_test_stub=False,
                build_type="Release",
                extra_args=(
                    f"-DEDR_PCRE2_MATCHER_CONTRACT_PATH={contract_path}",
                    f"-DEDR_PCRE2_STATIC_PREFIX={prefix}",
                    "-DEDR_PCRE2_PRODUCER_TARGET=linux/amd64",
                    f"-DEDR_PCRE2_VCPKG_ROOT={root}",
                ),
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn("reject caller-supplied", completed.stdout)

            for forbidden_arg in (
                f"-DEDR_PCRE2_MATCHER_CONTRACT_PATH={contract_path}",
                f"-DEDR_PCRE2_STATIC_PREFIX={prefix}",
            ):
                completed = self.configure(
                    build_tests=False,
                    require_pcre2=True,
                    allow_test_stub=False,
                    build_type="Release",
                    extra_args=(
                        forbidden_arg,
                        "-DEDR_PCRE2_PRODUCER_TARGET=linux/amd64",
                        f"-DEDR_PCRE2_VCPKG_ROOT={root}",
                    ),
                )
                self.assertNotEqual(0, completed.returncode)
                self.assertIn("reject caller-supplied", completed.stdout)

    def test_reconfigure_discards_owned_matcher_artifacts_and_reinvokes_producer(self):
        """A failed production configure cannot retain a forged prior archive.

        The deliberately invalid source root makes the real producer fail
        before downloading/building PCRE2.  Seeing its failure on both
        configures proves CMake invoked it again, while the sentinels prove
        that only the exact build-owned root was replaced.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            invalid_locked_root = root / "not-a-vcpkg-checkout"
            invalid_locked_root.mkdir()
            owned = build / "edr-pcre2-producer"
            owned.mkdir(parents=True)
            first_sentinel = owned / "forged-first-contract.json"
            first_sentinel.write_text("forged", encoding="utf-8")
            command = [
                "cmake", "-S", str(AGENT_ROOT), "-B", str(build), "-G", "Ninja",
                "-DCMAKE_BUILD_TYPE=Release",
                "-DEDR_BUILD_TESTS=OFF",
                "-DEDR_REQUIRE_PCRE2=ON",
                "-DEDR_P0_RULE_IR_ALLOW_TEST_STUB=OFF",
                "-DEDR_PCRE2_PRODUCER_TARGET=linux/amd64",
                f"-DEDR_PCRE2_VCPKG_ROOT={invalid_locked_root}",
            ]
            first = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
            )
            self.assertNotEqual(0, first.returncode)
            self.assertIn("PCRE2 matcher source build failed", first.stdout)
            self.assertIn("vcpkg root is not a checkout", first.stdout)
            self.assertFalse(first_sentinel.exists())

            second_sentinel = owned / "forged-second-archive.a"
            second_sentinel.write_bytes(static_linux_amd64_archive())
            second = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
            )
            self.assertNotEqual(0, second.returncode)
            self.assertIn("PCRE2 matcher source build failed", second.stdout)
            self.assertIn("vcpkg root is not a checkout", second.stdout)
            self.assertFalse(second_sentinel.exists())
            self.assertTrue(owned.is_dir())

    def test_stub_requires_an_explicit_test_build(self):
        completed = self.configure(build_tests=False, require_pcre2=False,
                                  allow_test_stub=True)
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("p0_rule_ir_stub.c is allowed only with EDR_BUILD_TESTS=ON", completed.stdout)

    def test_capability_manifest_marks_stub_as_nonproduction(self):
        source = (AGENT_ROOT / "src" / "core" / "agent.c").read_text(encoding="utf-8")
        self.assertIn('\\"production_ready\\":%s', source)
        self.assertIn('\\"release_class\\":\\"%s\\"', source)
        self.assertIn('pcre2_build ? "production" : "nonproduction_stub"', source)

    def test_nonproduction_stub_never_reports_a_healthy_artifact(self):
        stub = (AGENT_ROOT / "src" / "preprocess" / "p0_rule_ir_stub.c").read_text(encoding="utf-8")
        self.assertIn('"p0_rule_ir_unavailable_nonproduction_stub"', stub)
        healthy = stub[stub.index("int edr_p0_rule_ir_artifact_healthy"):stub.index(
            "void edr_p0_rule_ir_set_sensor_artifact_terminal_unhealthy"
        )]
        self.assertIn("return 0;", healthy)
        self.assertNotIn("return 1;", healthy)
        tests_cmake = (AGENT_ROOT / "tests" / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("test_p0_rule_ir_stub_health", tests_cmake)
        self.assertIn("p0_rule_ir_nonproduction_stub_health", tests_cmake)

    def test_product_default_and_release_ci_never_disable_pcre2(self):
        cmake_source = (AGENT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertRegex(
            cmake_source,
            r'option\(EDR_REQUIRE_PCRE2\s+"[^"]+"\s+ON\)',
        )
        self.assertRegex(
            cmake_source,
            r'option\(EDR_P0_RULE_IR_ALLOW_TEST_STUB\s+"[^"]+"\s+OFF\)',
        )

        release_ci_sources = [
            *sorted((AGENT_ROOT / ".github" / "workflows").glob("*.yml")),
            *sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")),
            *sorted((REPO_ROOT / "deploy" / "centos7-full-data").rglob("*.sh")),
        ]
        explicit_nonproduction_stubs = {
            AGENT_ROOT / ".github" / "workflows" / "edr-agent-ci.yml",
        }
        disabled = []
        pattern = re.compile(r"-DEDR_REQUIRE_PCRE2(?::[A-Za-z_]+)?=OFF\\b")
        for path in release_ci_sources:
            if pattern.search(path.read_text(encoding="utf-8")):
                source = path.read_text(encoding="utf-8")
                if path not in explicit_nonproduction_stubs or not all(
                    token in source for token in (
                        "if: false",
                        "CMAKE_BUILD_TYPE=Debug",
                        "EDR_BUILD_TESTS=ON",
                        "EDR_P0_RULE_IR_ALLOW_TEST_STUB=ON",
                    )
                ):
                    disabled.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual([], disabled, f"release/CI has an unqualified PCRE2 disable: {disabled}")

    def test_release_presets_forward_only_locked_source_and_target_inputs(self):
        presets = json.loads((AGENT_ROOT / "CMakePresets.json").read_text(encoding="utf-8"))
        base = next(item for item in presets["configurePresets"] if item["name"] == "base")
        expected = {
            "EDR_PCRE2_PRODUCER_TARGET": "$env{EDR_PCRE2_PRODUCER_TARGET}",
            "EDR_PCRE2_VCPKG_ROOT": "$env{EDR_PCRE2_VCPKG_ROOT}",
        }
        self.assertEqual(expected, base["cacheVariables"])
        self.assertNotIn("EDR_PCRE2_MATCHER_CONTRACT_PATH", base["cacheVariables"])
        self.assertNotIn("EDR_PCRE2_STATIC_PREFIX", base["cacheVariables"])
        by_name = {preset["name"]: preset for preset in presets["configurePresets"]}

        def inherits_base(preset: dict) -> bool:
            inherited = preset.get("inherits", [])
            names = [inherited] if isinstance(inherited, str) else inherited
            return any(name == "base" or inherits_base(by_name[name]) for name in names)

        for preset in presets["configurePresets"]:
            if preset.get("hidden"):
                continue
            self.assertTrue(inherits_base(preset), preset["name"])

    def test_every_production_configure_uses_cmake_owned_producer_inputs(self):
        """Keep every active production configure on the single CMake path.

        The inventory names owners, not a fragile per-file command count.
        Every discovered configure block is checked independently, so adding a
        second Release, MinSizeRel, preset, or multi-config invocation cannot
        inherit another block's PCRE2 authority by accident.
        """
        production_paths = {
            REPO_ROOT / ".github" / "workflows" / "edr-agent-ci.yml",
            REPO_ROOT / ".github" / "workflows" / "edr-agent-client-build.yml",
            REPO_ROOT / ".github" / "workflows" / "edr-agent-build-grpc-ort.yml",
            AGENT_ROOT / ".github" / "workflows" / "edr-agent-ci.yml",
            AGENT_ROOT / ".github" / "workflows" / "edr-agent-client-build.yml",
            AGENT_ROOT / ".github" / "workflows" / "edr-agent-client-release.yml",
            AGENT_ROOT / "scripts" / "ci_build.sh",
            AGENT_ROOT / "scripts" / "build_linux_native_docker.sh",
        }
        discovered: dict[Path, list[str]] = {}
        scan_roots = (
            REPO_ROOT / ".github" / "workflows",
            AGENT_ROOT / ".github" / "workflows",
            AGENT_ROOT / "scripts",
            REPO_ROOT / "deploy",
        )
        for scan_root in scan_roots:
            for path in scan_root.rglob("*"):
                if not path.is_file() or path.suffix not in {".sh", ".ps1", ".yml", ".yaml"}:
                    continue
                configure_blocks = production_cmake_configure_blocks(path.read_text(encoding="utf-8"))
                if configure_blocks:
                    discovered[path] = configure_blocks
        self.assertEqual(
            production_paths, set(discovered),
            "a production CMake configure was added without a single-path matcher owner",
        )
        for path, configure_blocks in discovered.items():
            for command in configure_blocks:
                self.assertNotIn("EDR_REQUIRE_PCRE2=OFF", command)
                self.assertNotIn("EDR_P0_RULE_IR_ALLOW_TEST_STUB=ON", command)
                self.assertNotIn("-DEDR_PCRE2_MATCHER_CONTRACT_PATH", command)
                self.assertNotIn("-DEDR_PCRE2_STATIC_PREFIX", command)
                for required_input in (
                    "-DEDR_PCRE2_PRODUCER_TARGET",
                    "-DEDR_PCRE2_VCPKG_ROOT",
                ):
                    self.assertIn(
                        required_input, command,
                        f"production configure lacks CMake-owned producer input {required_input}: "
                        f"{path.relative_to(REPO_ROOT)}\n{command}",
                    )

        cmake_source = (AGENT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("edr-pcre2-producer", cmake_source)
        self.assertIn("file(REMOVE_RECURSE \"${_edr_pcre2_producer_root}\")", cmake_source)
        self.assertIn("--producer-root \"${_edr_pcre2_producer_root}\"", cmake_source)
        self.assertIn("--verify-contract \"${_edr_pcre2_contract_real}\"", cmake_source)
        self.assertIn("edr.p0.matcher-producer-result.v1", cmake_source)

        root_ci = (REPO_ROOT / ".github" / "workflows" / "edr-agent-ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("libpcre2-dev", root_ci)
        self.assertGreaterEqual(root_ci.count("bootstrap_pinned_vcpkg.sh"), 2)
        self.assertIn("verify_p0_durable_wire_fixtures.py", root_ci)
        self.assertIn("test_p0_source_only_durable_contract", root_ci)
        for path in (
            REPO_ROOT / ".github" / "workflows" / "edr-agent-ci.yml",
            REPO_ROOT / ".github" / "workflows" / "edr-agent-client-build.yml",
            REPO_ROOT / ".github" / "workflows" / "edr-agent-build-grpc-ort.yml",
        ):
            self.assertIn("bootstrap_pinned_vcpkg.ps1", path.read_text(encoding="utf-8"))

    def test_linux_production_paths_require_real_openssl_and_never_ignore_ctest(self):
        linux_release_paths = (
            REPO_ROOT / ".github" / "workflows" / "edr-agent-ci.yml",
            AGENT_ROOT / "scripts" / "ci_build.sh",
            AGENT_ROOT / "scripts" / "build_linux_native_docker.sh",
        )
        for path in linux_release_paths:
            source = path.read_text(encoding="utf-8")
            self.assertIn("EDR_WITH_INGEST_HTTPS_OPENSSL=ON", source)
            self.assertIn("EDR_REQUIRE_HTTPS_REST=ON", source)

        docker_build = (AGENT_ROOT / "scripts" / "build_linux_native_docker.sh").read_text(encoding="utf-8")
        self.assertIn("libssl-dev", docker_build)
        self.assertNotRegex(docker_build, r"ctest[^\n]*\|\|\s*true")
        self.assertIn('if [[ "${EDR_RUN_CTEST:-0}" == "1" ]]; then\n  BUILD_TESTS=ON', docker_build)
        self.assertIn('"-DEDR_BUILD_TESTS=$BUILD_TESTS"', docker_build)
        self.assertIn('EDR_LINUX_BUILD_DIR must be empty for a fresh production build', docker_build)
        self.assertIn('-v "$ROOT:/work:ro"', docker_build)
        self.assertIn('-v "$BUILD_DIR:/build"', docker_build)
        for log_name in ("configure.log", "build.log", "ctest.log"):
            self.assertIn(f"/build/{log_name}", docker_build)
        self.assertIn('cmake --build /build -j"$(nproc 2>/dev/null || echo 4)"', docker_build)
        self.assertIn('cmake --build /build --target edr_agent', docker_build)

        signer_test = (AGENT_ROOT / "tests" / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("if(OpenSSL_FOUND)", signer_test)
        self.assertNotIn("if(OPENSSL_FOUND)", signer_test)

    def test_windows_runtime_stager_is_covered_by_the_powershell_51_parser_gate(self):
        parser_gate = (AGENT_ROOT / "scripts" / "validate_windows_powershell_syntax.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts\\stage_vcpkg_runtime_dlls_build_release.ps1", parser_gate)
        workflow_paths = (
            REPO_ROOT / ".github" / "workflows" / "edr-agent-client-build.yml",
            REPO_ROOT / ".github" / "workflows" / "edr-agent-build-grpc-ort.yml",
            AGENT_ROOT / ".github" / "workflows" / "edr-agent-client-build.yml",
            AGENT_ROOT / ".github" / "workflows" / "edr-agent-client-release.yml",
        )
        for path in workflow_paths:
            source = path.read_text(encoding="utf-8")
            self.assertIn("stage_vcpkg_runtime_dlls_build_release.ps1", source)
            self.assertIn("validate_windows_powershell_syntax.ps1", source)

    def test_configure_entrypoints_do_not_pass_removed_grpc_cache_variable(self):
        configure_sources = (
            REPO_ROOT / ".github" / "workflows" / "edr-agent-ci.yml",
            REPO_ROOT / ".github" / "workflows" / "edr-agent-client-build.yml",
            REPO_ROOT / ".github" / "workflows" / "edr-agent-build-grpc-ort.yml",
            AGENT_ROOT / "CMakePresets.json",
            AGENT_ROOT / ".github" / "workflows" / "edr-agent-ci.yml",
            AGENT_ROOT / ".github" / "workflows" / "edr-agent-client-build.yml",
            AGENT_ROOT / ".github" / "workflows" / "edr-agent-client-release.yml",
            AGENT_ROOT / "scripts" / "ci_build.sh",
            AGENT_ROOT / "scripts" / "build_linux_native_docker.sh",
            AGENT_ROOT / "scripts" / "build_windows_mingw.sh",
            AGENT_ROOT / "scripts" / "build_windows_mingw_docker.sh",
        )
        for path in configure_sources:
            self.assertNotIn("EDR_WITH_GRPC", path.read_text(encoding="utf-8"),
                             f"removed CMake variable leaked into {path.relative_to(REPO_ROOT)}")

    def test_release_packager_is_a_fresh_isolated_producer_boundary(self):
        source = (REPO_ROOT / "deploy" / "centos7-full-data" / "package-scripts" /
                  "build_pcre2_release_binaries.sh").read_text(encoding="utf-8")
        self.assertIn("--producer-root", source)
        self.assertIn("--verify-contract", source)
        self.assertIn("work_root_isolation", source)

    def test_windows_release_workflow_statically_binds_each_supported_matcher_target(self):
        source = (AGENT_ROOT / ".github" / "workflows" / "edr-agent-client-release.yml").read_text(encoding="utf-8")
        self.assertIn('"-DEDR_PCRE2_PRODUCER_TARGET=windows/$env:EDR_RELEASE_ARCH"', source)
        self.assertNotIn("--producer-root", source)
        self.assertNotIn("-DEDR_PCRE2_MATCHER_CONTRACT_PATH", source)
        self.assertNotIn("-DEDR_PCRE2_STATIC_PREFIX", source)
        self.assertIn("--verify-contract", source)
        for cmake_binding in (
            "EDR_PCRE2_MATCHER_CONTRACT_AUDIT_PATH",
            "EDR_PCRE2_STATIC_PREFIX_AUDIT_PATH",
            "EDR_PCRE2_PRODUCER_ROOT_AUDIT_PATH",
            "-DEDR_PCRE2_VCPKG_ROOT",
            "EDR_PCRE2_MATCHER_CONTRACT_SHA256",
        ):
            self.assertIn(cmake_binding, source)
        self.assertIn("CMake matcher producer audit root is not the build-owned root", source)
        self.assertIn("static PCRE2 release must not package a dynamic pcre2-8 DLL", source)

    def test_durable_wire_freshness_gate_is_owned_by_the_agent_emitter(self):
        source = (AGENT_ROOT / "scripts" / "verify_p0_durable_wire_fixtures.py").read_text(encoding="utf-8")
        self.assertIn("--emit-p0-source-only-durable-fixture", source)
        self.assertIn("--emit-terminal-authority-durable-fixture", source)
        self.assertIn("p0-enforcement-combined-", source)
        self.assertIn("edr-backend", source)
        self.assertIn("--regenerate", source)
        self.assertIn("generator_binary_sha256", source)
        self.assertIn("p0_ir_sha256", source)
        self.assertIn("require_deterministic_emission", source)
        self.assertIn("replace_staged_pair", source)
        self.assertIn("os.replace", source)

    def test_durable_wire_freshness_gate_rejects_stale_combined_fixture(self):
        gate = AGENT_ROOT / "scripts" / "verify_p0_durable_wire_fixtures.py"
        source_fixture = (REPO_ROOT / "edr-backend" / "platform" / "internal" / "handler" /
                          "testdata" / "p0_source_only_durable_wire_golden.json")
        terminal_fixture = (REPO_ROOT / "edr-backend" / "platform" / "internal" / "handler" /
                            "testdata" / "enforcement_terminal_authority_durable_wire_golden.json")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copied_source = root / "source.json"
            copied_terminal = root / "terminal.json"
            emitted_source = root / "emitted-source.json"
            emitted_terminal = root / "emitted-terminal.json"
            copied_source.write_bytes(source_fixture.read_bytes())
            copied_terminal.write_bytes(terminal_fixture.read_bytes())
            p0_ir = AGENT_ROOT / "config" / "p0_rule_bundle_ir_v1.json"
            p0_ir_value = json.loads(p0_ir.read_text(encoding="utf-8"))
            p0_ir_sha256 = hashlib.sha256(p0_ir.read_bytes()).hexdigest()
            synthetic_source = json.loads(source_fixture.read_text(encoding="utf-8"))
            for item in synthetic_source["fixtures"]:
                if item["stage"] == "direct":
                    item["rules_bundle_version"] = p0_ir_value["rules_bundle_version"]
                    item["rules_bundle_sha256"] = p0_ir_sha256
            synthetic_terminal = json.loads(terminal_fixture.read_text(encoding="utf-8"))
            synthetic_terminal["authority"]["rules_bundle_version"] = p0_ir_value["rules_bundle_version"]
            synthetic_terminal["authority"]["rules_bundle_sha256"] = p0_ir_sha256
            emitted_source.write_text(json.dumps(synthetic_source), encoding="utf-8")
            emitted_terminal.write_text(json.dumps(synthetic_terminal), encoding="utf-8")
            emitter = root / "emitter.py"
            emitter.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "key = 'SOURCE_FIXTURE' if sys.argv[1] == '--emit-p0-source-only-durable-fixture' else 'TERMINAL_FIXTURE'\n"
                "value = json.loads(Path(os.environ[key]).read_text(encoding='utf-8'))\n"
                "value.pop('fixture_generator', None)\n"
                "sys.stdout.write(json.dumps(value))\n",
                encoding="utf-8",
            )
            emitter.chmod(0o755)
            environment = dict(os.environ)
            environment["SOURCE_FIXTURE"] = str(emitted_source)
            environment["TERMINAL_FIXTURE"] = str(emitted_terminal)
            command = [
                sys.executable, str(gate), "--emitter", str(emitter),
                "--source-fixture", str(copied_source),
                "--terminal-fixture", str(copied_terminal),
                "--p0-ir", str(p0_ir),
            ]
            regenerate = subprocess.run(
                [*command, "--regenerate"], env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, regenerate.returncode, regenerate.stderr)
            first_source = copied_source.read_bytes()
            first_terminal = copied_terminal.read_bytes()
            repeated_regenerate = subprocess.run(
                [*command, "--regenerate"], env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, repeated_regenerate.returncode, repeated_regenerate.stderr)
            self.assertEqual(first_source, copied_source.read_bytes())
            self.assertEqual(first_terminal, copied_terminal.read_bytes())
            generated_source = json.loads(copied_source.read_text(encoding="utf-8"))
            generated_terminal = json.loads(copied_terminal.read_text(encoding="utf-8"))
            for generated in (generated_source, generated_terminal):
                provenance = generated["fixture_generator"]
                self.assertEqual(
                    "python3 edr-agent/scripts/verify_p0_durable_wire_fixtures.py "
                    "--emitter <compiled-test_p0_source_only_durable_contract> --regenerate",
                    provenance["command"],
                )
                self.assertEqual(provenance["command"], generated["reproduce_with"])
                self.assertRegex(provenance["generator_binary_sha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(provenance["p0_ir_sha256"], provenance["rules_bundle_sha256"])
                self.assertRegex(provenance["source_semantic_manifest_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(provenance["terminal_semantic_manifest_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(provenance["terminal_authority_identity_sha256"], r"^[0-9a-f]{64}$")
            generated_provenance = generated_source["fixture_generator"]
            self.assertEqual(
                FIXTURE_GATE.source_semantic_manifest_sha256(generated_source),
                generated_provenance["source_semantic_manifest_sha256"],
            )
            self.assertEqual(
                FIXTURE_GATE.terminal_semantic_manifest_sha256(generated_terminal),
                generated_provenance["terminal_semantic_manifest_sha256"],
            )
            self.assertEqual(
                FIXTURE_GATE.terminal_authority_identity_sha256(generated_terminal),
                generated_provenance["terminal_authority_identity_sha256"],
            )
            fresh = subprocess.run(command, env=environment, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, fresh.returncode, fresh.stderr)
            split_writer_source = json.loads(copied_source.read_text(encoding="utf-8"))
            split_writer_source["reproduce_with"] = "python3 hand_edit_fixture.py"
            with self.assertRaisesRegex(FIXTURE_GATE.FixtureError, "sole regeneration command"):
                FIXTURE_GATE.validate_source_fixture(
                    split_writer_source, label="split writer source fixture", require_generator=True)
            stale = json.loads(copied_terminal.read_text(encoding="utf-8"))
            stale["agent_builder"] = "stale-agent-emitter"
            copied_terminal.write_text(json.dumps(stale), encoding="utf-8")
            rejected = subprocess.run(command, env=environment, text=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("is stale", rejected.stderr)

    def test_durable_wire_gate_binds_terminal_idempotency_identity(self):
        source_fixture = json.loads((REPO_ROOT / "edr-backend" / "platform" / "internal" /
                                     "handler" / "testdata" /
                                     "p0_source_only_durable_wire_golden.json").read_text(encoding="utf-8"))
        terminal_fixture = json.loads((REPO_ROOT / "edr-backend" / "platform" / "internal" /
                                       "handler" / "testdata" /
                                       "enforcement_terminal_authority_durable_wire_golden.json").read_text(encoding="utf-8"))
        mutated = json.loads(json.dumps(terminal_fixture))
        mutated["authority"]["terminal_key"] = "p0-enforcement-drifted"
        with self.assertRaisesRegex(FIXTURE_GATE.FixtureError, "terminal fixture semantic IDs changed"):
            FIXTURE_GATE.require_same_semantic_ids(source_fixture, source_fixture, mutated, terminal_fixture)

    def test_durable_wire_gate_allows_only_reviewed_file_read_reason_split(self):
        source_fixture = json.loads((REPO_ROOT / "edr-backend" / "platform" / "internal" /
                                     "handler" / "testdata" /
                                     "p0_source_only_durable_wire_golden.json").read_text(encoding="utf-8"))
        terminal_fixture = json.loads((REPO_ROOT / "edr-backend" / "platform" / "internal" /
                                       "handler" / "testdata" /
                                       "enforcement_terminal_authority_durable_wire_golden.json").read_text(encoding="utf-8"))
        additions = set(FIXTURE_GATE.APPROVED_SOURCE_SEMANTIC_ADDITIONS)
        before = json.loads(json.dumps(source_fixture))
        before["fixtures"] = [
            item for item in before["fixtures"]
            if (
                item.get("stage"), item.get("event_type"), item.get("event_id"),
                item.get("reason"), item.get("rule_id", ""), item.get("gate_id", ""),
                item.get("loss_detected"),
            ) not in additions
        ]
        self.assertEqual(len(source_fixture["fixtures"]), len(before["fixtures"]) + 2)
        self.assertEqual(
            "split FileRead metadata backpressure causes",
            FIXTURE_GATE.require_same_semantic_ids(
                source_fixture, before, terminal_fixture, terminal_fixture,
                allow_approved_transition=True,
            ),
        )
        with self.assertRaisesRegex(FIXTURE_GATE.FixtureError, "source fixture semantic IDs changed"):
            FIXTURE_GATE.require_same_semantic_ids(
                source_fixture, before, terminal_fixture, terminal_fixture
            )
        unknown = json.loads(json.dumps(source_fixture))
        unknown["fixtures"][10]["reason"] = "file_read_unreviewed_reason"
        reordered = json.loads(json.dumps(source_fixture))
        reordered["fixtures"][0], reordered["fixtures"][1] = (
            reordered["fixtures"][1], reordered["fixtures"][0]
        )
        removed = json.loads(json.dumps(source_fixture))
        del removed["fixtures"][0]
        for drifted in (unknown, reordered, removed):
            with self.assertRaisesRegex(FIXTURE_GATE.FixtureError, "source fixture semantic IDs changed"):
                FIXTURE_GATE.require_same_semantic_ids(
                    drifted, before, terminal_fixture, terminal_fixture,
                    allow_approved_transition=True,
                )

    def test_durable_wire_gate_allows_only_the_committed_source_fields_truncated_transition(self):
        source_fixture = json.loads((REPO_ROOT / "edr-backend" / "platform" / "internal" /
                                     "handler" / "testdata" /
                                     "p0_source_only_durable_wire_golden.json").read_text(encoding="utf-8"))
        terminal_fixture = json.loads((REPO_ROOT / "edr-backend" / "platform" / "internal" /
                                       "handler" / "testdata" /
                                       "enforcement_terminal_authority_durable_wire_golden.json").read_text(encoding="utf-8"))
        before = json.loads(json.dumps(terminal_fixture))
        before_reasons = before["not_evaluable_reasons"]
        if "source_fields_truncated" in before_reasons:
            before_reasons.remove("source_fields_truncated")
        after = json.loads(json.dumps(before))
        after["not_evaluable_reasons"].append("source_fields_truncated")
        approval = FIXTURE_GATE.APPROVED_TERMINAL_SEMANTIC_TRANSITION
        self.assertEqual(approval["source_semantic_manifest_sha256"],
                         FIXTURE_GATE.source_semantic_manifest_sha256(source_fixture))
        self.assertEqual(approval["terminal_before_sha256"],
                         FIXTURE_GATE.terminal_semantic_manifest_sha256(before))
        self.assertEqual(approval["terminal_after_sha256"],
                         FIXTURE_GATE.terminal_semantic_manifest_sha256(after))
        self.assertEqual(approval["terminal_authority_identity_sha256"],
                         FIXTURE_GATE.terminal_authority_identity_sha256(before))
        self.assertEqual(approval["terminal_authority_identity_sha256"],
                         FIXTURE_GATE.terminal_authority_identity_sha256(after))
        self.assertEqual(
            "append source_fields_truncated",
            FIXTURE_GATE.require_same_semantic_ids(
                source_fixture, source_fixture, after, before, allow_approved_transition=True
            ),
        )
        with self.assertRaisesRegex(FIXTURE_GATE.FixtureError, "terminal fixture semantic IDs changed"):
            FIXTURE_GATE.require_same_semantic_ids(source_fixture, source_fixture, after, before)
        authority_drift = json.loads(json.dumps(after))
        authority_drift["authority"]["terminal_key"] = "p0-enforcement-drifted"
        reordered = json.loads(json.dumps(after))
        reordered["not_evaluable_reasons"][0], reordered["not_evaluable_reasons"][1] = (
            reordered["not_evaluable_reasons"][1], reordered["not_evaluable_reasons"][0]
        )
        deleted = json.loads(json.dumps(after))
        del deleted["not_evaluable_reasons"][0]
        unknown = json.loads(json.dumps(after))
        unknown["not_evaluable_reasons"][-1] = "unknown_reason"
        source_drift = json.loads(json.dumps(source_fixture))
        source_drift["fixtures"][0]["event_id"] = "source-semantic-drift"
        for emitted_source, emitted_terminal in (
            (source_fixture, authority_drift),
            (source_fixture, reordered),
            (source_fixture, deleted),
            (source_fixture, unknown),
            (source_drift, after),
        ):
            with self.assertRaisesRegex(FIXTURE_GATE.FixtureError, "semantic IDs changed"):
                FIXTURE_GATE.require_same_semantic_ids(
                    emitted_source, source_fixture, emitted_terminal, before,
                    allow_approved_transition=True,
                )

    def test_durable_wire_gate_restores_first_file_when_second_replace_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.json"
            terminal_path = root / "terminal.json"
            source_path.write_bytes(b"old source\n")
            terminal_path.write_bytes(b"old terminal\n")
            os.chmod(source_path, 0o640)
            os.chmod(terminal_path, 0o600)
            source_mode = stat.S_IMODE(source_path.stat().st_mode)
            terminal_mode = stat.S_IMODE(terminal_path.stat().st_mode)
            original_replace = FIXTURE_GATE.os.replace
            replace_calls = 0

            def fail_second_replace(source, destination):
                nonlocal replace_calls
                replace_calls += 1
                if replace_calls == 2:
                    raise OSError("injected second replacement failure")
                return original_replace(source, destination)

            with mock.patch.object(FIXTURE_GATE.os, "replace", side_effect=fail_second_replace):
                with self.assertRaisesRegex(FIXTURE_GATE.FixtureError,
                                            "staged pair replacement failed: injected second replacement failure; replaced paths restored"):
                    FIXTURE_GATE.replace_staged_pair(
                        source_path, {"fixture": "new source"},
                        terminal_path, {"fixture": "new terminal"},
                    )
            self.assertEqual(b"old source\n", source_path.read_bytes())
            self.assertEqual(b"old terminal\n", terminal_path.read_bytes())
            self.assertEqual(source_mode, stat.S_IMODE(source_path.stat().st_mode))
            self.assertEqual(terminal_mode, stat.S_IMODE(terminal_path.stat().st_mode))

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits are required for this assertion")
    def test_durable_wire_gate_preserves_fixture_permissions_on_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.json"
            terminal_path = root / "terminal.json"
            source_path.write_bytes(b"old source\n")
            terminal_path.write_bytes(b"old terminal\n")
            os.chmod(source_path, 0o640)
            os.chmod(terminal_path, 0o600)
            source_mode = stat.S_IMODE(source_path.stat().st_mode)
            terminal_mode = stat.S_IMODE(terminal_path.stat().st_mode)

            FIXTURE_GATE.replace_staged_pair(
                source_path, {"fixture": "new source"},
                terminal_path, {"fixture": "new terminal"},
            )

            self.assertEqual(source_mode, stat.S_IMODE(source_path.stat().st_mode))
            self.assertEqual(terminal_mode, stat.S_IMODE(terminal_path.stat().st_mode))

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits are required for this assertion")
    def test_durable_wire_gate_uses_0644_for_a_new_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "new-fixture.json"
            staged = FIXTURE_GATE.stage_fixture(target, b"new fixture\n")
            try:
                os.replace(staged, target)
            finally:
                staged.unlink(missing_ok=True)

            self.assertEqual(0o644, stat.S_IMODE(target.stat().st_mode))

    def test_production_gate_never_uses_system_find_library(self):
        source = (AGENT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        gate_start = source.index("if(_edr_pcre2_explicit_test_stub)")
        gate_end = source.index("find_package(OpenSSL QUIET)", gate_start)
        production_gate = source[gate_start:gate_end]
        self.assertIn("--verify-contract", production_gate)
        self.assertIn("--vcpkg-root", production_gate)
        self.assertIn("edr_pcre2_static STATIC IMPORTED", production_gate)
        self.assertNotIn("find_library", production_gate)
        self.assertNotIn("find_package(PCRE2", production_gate)

    def test_mingw_cross_builds_are_explicit_nonproduction_stubs(self):
        for relative in (
            Path("scripts") / "build_windows_mingw.sh",
            Path("scripts") / "build_windows_mingw_docker.sh",
        ):
            source = (AGENT_ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("CMAKE_BUILD_TYPE=Debug", source)
            self.assertIn("EDR_BUILD_TESTS=ON", source)
            self.assertIn("EDR_REQUIRE_PCRE2=OFF", source)
            self.assertIn("EDR_P0_RULE_IR_ALLOW_TEST_STUB=ON", source)
            self.assertIn("non-production", source)


if __name__ == "__main__":
    unittest.main()
