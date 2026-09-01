import importlib.util
import hashlib
import json
import os
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout


SCRIPT = Path(__file__).parents[1] / "scripts" / "produce_pcre2_matcher_contract.py"
SPEC = importlib.util.spec_from_file_location("produce_pcre2_matcher_contract", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


SOURCE_SHA512 = "a" * 128
SLJIT_SHA512 = "b" * 128
TEST_PATCH_SHA256 = hashlib.sha256(b"test pcre2 patch\n").hexdigest()


def static_archive_member(target: str, marker: bytes) -> bytes:
    if target == "linux/amd64":
        machine = 62
        payload = bytearray(20)
        payload[:4] = b"\x7fELF"
        payload[18:20] = machine.to_bytes(2, "little")
    elif target == "linux/arm64":
        machine = 183
        payload = bytearray(20)
        payload[:4] = b"\x7fELF"
        payload[18:20] = machine.to_bytes(2, "little")
    elif target == "windows/amd64":
        payload = bytearray(20)
        payload[:2] = (0x8664).to_bytes(2, "little")
    elif target == "windows/arm64":
        payload = bytearray(20)
        payload[:2] = (0xAA64).to_bytes(2, "little")
    else:
        raise ValueError(target)
    payload.extend(marker)
    header = (
        f"{'pcre2.o/':<16}{0:<12}{0:<6}{0:<6}{0:<8}{len(payload):<10}".encode("ascii")
        + b"\x60\n"
    )
    return header + bytes(payload) + (b"\n" if len(payload) % 2 else b"")


def static_archive_bytes(target: str, marker: bytes = b"immutable-static-pcre2",
                         extra_targets: tuple[str, ...] = ()) -> bytes:
    members = [static_archive_member(target, marker)]
    members.extend(static_archive_member(extra, b"extra-static-object") for extra in extra_targets)
    return b"!<arch>\n" + b"".join(members)


class PCRE2StaticProducerContractTests(unittest.TestCase):
    def write_portfile(self, root: Path) -> Path:
        (root / "pcre2-test.patch").write_text("test pcre2 patch\n", encoding="utf-8")
        portfile = root / "portfile.cmake"
        portfile.write_text(
            "vcpkg_from_github(\n"
            "  OUT_SOURCE_PATH SOURCE_PATH\n"
            "  REPO PCRE2Project/pcre2\n"
            "  REF \"pcre2-test\"\n"
            f"  SHA512 {SOURCE_SHA512}\n"
            "  PATCHES\n"
            "    pcre2-test.patch\n"
            ")\n"
            "vcpkg_from_github(\n"
            "  OUT_SOURCE_PATH SLJIT_SOURCE_PATH\n"
            "  REPO zherczeg/sljit\n"
            "  REF test-sljit-ref\n"
            f"  SHA512 {SLJIT_SHA512}\n"
            ")\n",
            encoding="utf-8",
        )
        return portfile

    def make_prefix(self, root: Path, *, target: str = "linux/amd64") -> tuple[Path, Path]:
        triplet = MODULE.TARGET_TRIPLETS[target]
        prefix = root / "installed" / triplet
        header = prefix / "include" / "pcre2.h"
        archive = prefix / "lib" / ("libpcre2-8.a" if target.startswith("linux/") else "pcre2-8.lib")
        pkgconfig = prefix / "lib" / "pkgconfig" / "libpcre2-8.pc"
        header.parent.mkdir(parents=True)
        archive.parent.mkdir(parents=True)
        header.write_text("#define PCRE2_MAJOR 10\n#define PCRE2_MINOR 42\n", encoding="utf-8")
        archive.write_bytes(static_archive_bytes(target))
        if target.startswith("linux/"):
            pkgconfig.parent.mkdir(parents=True)
            pkgconfig.write_text("Name: libpcre2-8\nVersion: 10.42\n", encoding="utf-8")
        return prefix, self.write_portfile(root)

    def make_locked_source_checkout(self, root: Path, portfile: Path) -> Path:
        """Provide the locked port contents while the Git check is mocked.

        Contract artifact tests do not need a network clone, but they must
        exercise the same checkout-derived portfile/source/patch comparison as
        a production configure.  ``verify_clean_pinned_vcpkg`` is the only
        mocked boundary; every source byte below ``ports/pcre2`` is real.
        """
        source_root = root / "vcpkg"
        source_port = source_root / "ports" / "pcre2"
        source_port.mkdir(parents=True)
        shutil.copy2(portfile, source_port / "portfile.cmake")
        shutil.copy2(portfile.parent / "pcre2-test.patch", source_port / "pcre2-test.patch")
        return source_root

    def verify_with_locked_source(self, contract_path: Path, prefix: Path,
                                  target: str, source_root: Path) -> Path:
        with mock.patch.object(
            MODULE,
            "verify_clean_pinned_vcpkg",
            return_value="https://github.com/microsoft/vcpkg.git",
        ):
            return MODULE.verify_contract(
                contract_path, prefix, target, vcpkg_root=source_root
            )

    def make_git_checkout(self, root: Path, portfile: Path, *, origin: str) -> tuple[Path, str]:
        """Create a real, clean Git checkout containing the authoritative port.

        This lets the verifier tests exercise the same HEAD/origin/status
        checks as production instead of treating a merely existing directory
        as a locked vcpkg checkout.
        """
        source_root = root / "vcpkg"
        source_port = source_root / "ports" / "pcre2"
        source_port.mkdir(parents=True)
        shutil.copy2(portfile, source_port / "portfile.cmake")
        shutil.copy2(portfile.parent / "pcre2-test.patch", source_port / "pcre2-test.patch")
        for command in (
            ("git", "init", "-q", str(source_root)),
            ("git", "-C", str(source_root), "config", "user.email", "pcre2-test@example.invalid"),
            ("git", "-C", str(source_root), "config", "user.name", "PCRE2 Contract Test"),
            ("git", "-C", str(source_root), "add", "ports/pcre2"),
            ("git", "-C", str(source_root), "commit", "-q", "-m", "locked pcre2 port"),
            ("git", "-C", str(source_root), "remote", "add", "origin", origin),
        ):
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        head = subprocess.run(
            ("git", "-C", str(source_root), "rev-parse", "HEAD"),
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()
        return source_root, head

    def verify_with_real_checkout(self, contract_path: Path, prefix: Path,
                                  target: str, source_root: Path, baseline: str) -> Path:
        with mock.patch.object(MODULE, "load_authority", return_value=(baseline, {})):
            return MODULE.verify_contract(
                contract_path, prefix, target, vcpkg_root=source_root
            )

    def commit_checkout_change(self, source_root: Path, path: Path, contents: str) -> str:
        path.write_text(contents, encoding="utf-8")
        relative = path.relative_to(source_root).as_posix()
        subprocess.run(
            ("git", "-C", str(source_root), "add", relative),
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        subprocess.run(
            ("git", "-C", str(source_root), "commit", "-q", "-m", "change locked source"),
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        return subprocess.run(
            ("git", "-C", str(source_root), "rev-parse", "HEAD"),
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()

    def test_contract_binds_concrete_static_artifacts_and_matcher_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix, portfile = self.make_prefix(Path(directory))
            contract = MODULE.contract_for(
                prefix,
                baseline="b" * 40,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-linux-static",
                portfile=portfile,
            )

        self.assertEqual(MODULE.CONTRACT_SCHEMA, contract["schema"])
        self.assertEqual(
            [
                {
                    "repo": "PCRE2Project/pcre2",
                    "ref": "pcre2-test",
                    "sha512": SOURCE_SHA512,
                    "patches_sha256": {
                        "pcre2-test.patch": TEST_PATCH_SHA256,
                    },
                },
                {
                    "repo": "zherczeg/sljit",
                    "ref": "test-sljit-ref",
                    "sha512": SLJIT_SHA512,
                    "patches_sha256": {},
                },
            ],
            contract["pcre2"]["source_inputs"],
        )
        self.assertEqual(8, contract["pcre2"]["code_unit_width"])
        self.assertEqual(["PCRE2_UTF"], contract["pcre2"]["compile_options"])
        self.assertEqual("fresh_pinned_vcpkg", contract["producer"]["source_build"])
        self.assertEqual("disabled", contract["producer"]["binary_package_cache"])
        self.assertEqual(
            "dedicated_empty_buildtrees_packages_installed_downloads",
            contract["producer"]["work_root_isolation"],
        )
        self.assertEqual("edr.dynamic-rules.source.v1", contract["agent_matcher"]["source_schema"])
        self.assertEqual("edr_p0_rule_bundle_ir_v1@2", contract["agent_matcher"]["rule_schema"])
        self.assertEqual(256, contract["agent_matcher"]["max_rules"])
        self.assertEqual("edr_p0_rule_bundle_ir_v1", contract["agent_matcher"]["bundle_kind"])
        self.assertEqual(2, contract["agent_matcher"]["ir_schema_version"])
        self.assertEqual("linux/amd64", contract["producer"]["target"])
        self.assertEqual("lib/libpcre2-8.a", contract["pcre2"]["static_library_relpath"])
        self.assertEqual("elf-x86_64", contract["pcre2"]["static_library_machine"])
        self.assertIn("src/preprocess/p0_rule_ir.c", contract["agent_matcher"]["sources_sha256"])
        self.assertIn("include/edr/p0_rule_ir.h", contract["agent_matcher"]["sources_sha256"])

    def test_rejects_shared_pcre2_output(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix, portfile = self.make_prefix(Path(directory))
            (prefix / "lib" / "libpcre2-8.so").write_bytes(b"forbidden")
            with self.assertRaisesRegex(MODULE.ContractError, "forbidden shared"):
                MODULE.contract_for(
                    prefix,
                    baseline="b" * 40,
                    origin="https://github.com/microsoft/vcpkg.git",
                    triplet="edr-x64-linux-static",
                    portfile=portfile,
                )

    def test_rejects_ambiguous_port_source_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            portfile = Path(directory) / "portfile.cmake"
            portfile.write_text(
                "vcpkg_from_github(\n"
                "  REPO PCRE2Project/pcre2\n"
                "  REF first\n"
                f"  SHA512 {SOURCE_SHA512}\n"
                ")\n"
                "vcpkg_from_github(\n"
                "  REPO PCRE2Project/pcre2\n"
                "  REF second\n"
                f"  SHA512 {SLJIT_SHA512}\n"
                ")\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.ContractError, "repeats source repository"):
                MODULE.port_source_authority(portfile)

    def test_build_environment_drops_caller_binary_cache_and_overlays(self):
        with mock.patch.dict(
            os.environ,
            {
                "VCPKG_BINARY_SOURCES": "clear;files,/attacker-cache,read",
                "VCPKG_OVERLAY_PORTS": "/attacker-ports",
                "VCPKG_OVERLAY_TRIPLETS": "/attacker-triplets",
                "VCPKG_DEFAULT_TRIPLET": "x64-windows",
                "VCPKG_DOWNLOADS": "/attacker-downloads",
            },
            clear=False,
        ):
            env = MODULE.static_build_environment("target-cc")

        self.assertEqual("clear", env["VCPKG_BINARY_SOURCES"])
        self.assertEqual("target-cc", env["CC"])
        self.assertNotIn("VCPKG_OVERLAY_PORTS", env)
        self.assertNotIn("VCPKG_OVERLAY_TRIPLETS", env)
        self.assertNotIn("VCPKG_DEFAULT_TRIPLET", env)
        self.assertNotIn("VCPKG_DOWNLOADS", env)

    def test_producer_forces_classic_single_port_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vcpkg_root = root / "vcpkg-checkout"
            vcpkg_root.mkdir()
            vcpkg = vcpkg_root / "vcpkg"
            vcpkg.write_text("#!/bin/sh\n", encoding="utf-8")
            vcpkg.chmod(0o755)
            producer_root = root / "producer"
            with mock.patch.object(MODULE, "run_checked") as run_checked:
                prefix = MODULE.build_static_pcre2(
                    vcpkg_root, producer_root, "edr-x64-linux-static", None
                )

        producer_root = producer_root.resolve()
        self.assertEqual(producer_root / "installed" / "edr-x64-linux-static", prefix)
        command = run_checked.call_args.args[0]
        self.assertEqual([str(vcpkg), "install", "pcre2"], command[:3])
        self.assertIn("--classic", command)
        self.assertEqual(
            str(producer_root / "buildtrees"),
            command[command.index("--x-buildtrees-root") + 1],
        )
        self.assertEqual(
            str(producer_root / "packages"),
            command[command.index("--x-packages-root") + 1],
        )
        self.assertEqual(
            str(producer_root / "installed"),
            command[command.index("--x-install-root") + 1],
        )
        self.assertEqual(
            str(producer_root / "downloads"),
            command[command.index("--downloads-root") + 1],
        )

    def test_rejects_prepopulated_producer_roots_instead_of_reusing_ignored_vcpkg_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vcpkg_root = root / "vcpkg-checkout"
            vcpkg_root.mkdir()
            vcpkg = vcpkg_root / "vcpkg"
            vcpkg.write_text("#!/bin/sh\n", encoding="utf-8")
            vcpkg.chmod(0o755)
            for root_name in ("buildtrees", "packages", "installed", "downloads"):
                producer_root = root / f"producer-{root_name}"
                stale = producer_root / root_name / "stale-pcre2-state"
                stale.parent.mkdir(parents=True)
                stale.write_text("must not be reused", encoding="utf-8")
                with self.assertRaisesRegex(MODULE.ContractError, "producer root must be empty"):
                    MODULE.build_static_pcre2(vcpkg_root, producer_root, "edr-x64-linux-static", None)

    def test_rejects_mixed_architecture_static_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, portfile = self.make_prefix(root)
            archive = prefix / "lib" / "libpcre2-8.a"
            archive.write_bytes(static_archive_bytes(
                "linux/amd64", extra_targets=("linux/arm64",)
            ))
            with self.assertRaisesRegex(MODULE.ContractError, "mixed target objects"):
                MODULE.contract_for(
                    prefix,
                    baseline="b" * 40,
                    origin="https://github.com/microsoft/vcpkg.git",
                    triplet="edr-x64-linux-static",
                    portfile=portfile,
                    target="linux/amd64",
                )

    def test_verify_rejects_archive_cross_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, portfile = self.make_prefix(root)
            baseline, _ = MODULE.load_authority()
            contract = MODULE.contract_for(
                prefix,
                baseline=baseline,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-linux-static",
                portfile=portfile,
                target="linux/amd64",
            )
            contract_path = root / "matcher-contract.json"
            MODULE.write_contract(contract_path, contract)
            source_root = self.make_locked_source_checkout(root, portfile)
            archive = prefix / "lib" / "libpcre2-8.a"
            archive.write_bytes(static_archive_bytes("linux/amd64", b"replaced-static-pcre2"))
            with self.assertRaisesRegex(MODULE.ContractError, "static archive hash mismatch"):
                self.verify_with_locked_source(contract_path, prefix, "linux/amd64", source_root)

    def test_verify_rejects_cross_architecture_archive_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, portfile = self.make_prefix(root)
            baseline, _ = MODULE.load_authority()
            contract = MODULE.contract_for(
                prefix,
                baseline=baseline,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-linux-static",
                portfile=portfile,
                target="linux/amd64",
            )
            contract_path = root / "matcher-contract.json"
            MODULE.write_contract(contract_path, contract)
            source_root = self.make_locked_source_checkout(root, portfile)
            (prefix / "lib" / "libpcre2-8.a").write_bytes(
                static_archive_bytes("linux/arm64", b"wrong-target")
            )
            with self.assertRaisesRegex(MODULE.ContractError, "expected elf-x86_64"):
                self.verify_with_locked_source(contract_path, prefix, "linux/amd64", source_root)

    def test_verify_rejects_contract_spoofed_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, portfile = self.make_prefix(root)
            baseline, _ = MODULE.load_authority()
            contract = MODULE.contract_for(
                prefix,
                baseline=baseline,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-linux-static",
                portfile=portfile,
                target="linux/amd64",
            )
            contract["producer"]["target"] = "linux/arm64"
            contract_path = root / "matcher-contract.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            source_root = self.make_locked_source_checkout(root, portfile)
            with self.assertRaisesRegex(MODULE.ContractError, "targets another build"):
                self.verify_with_locked_source(contract_path, prefix, "linux/amd64", source_root)

    def test_verify_rejects_self_reported_portfile_or_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, portfile = self.make_prefix(root)
            baseline, _ = MODULE.load_authority()
            contract = MODULE.contract_for(
                prefix,
                baseline=baseline,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-linux-static",
                portfile=portfile,
                target="linux/amd64",
            )
            source_root = self.make_locked_source_checkout(root, portfile)
            contract_path = root / "matcher-contract.json"

            contract["producer"]["vcpkg_portfile_sha256"] = "0" * 64
            MODULE.write_contract(contract_path, contract)
            with self.assertRaisesRegex(MODULE.ContractError, "portfile hash does not match"):
                self.verify_with_locked_source(contract_path, prefix, "linux/amd64", source_root)

            contract["producer"]["vcpkg_portfile_sha256"] = MODULE.sha256_file(portfile)
            contract["producer"]["vcpkg_checkout_origin"] = "https://example.invalid/vcpkg.git"
            MODULE.write_contract(contract_path, contract)
            with self.assertRaisesRegex(MODULE.ContractError, "checkout origin does not match"):
                self.verify_with_locked_source(contract_path, prefix, "linux/amd64", source_root)

            contract["producer"]["vcpkg_checkout_origin"] = "https://github.com/microsoft/vcpkg.git"
            contract["producer"]["script_sha256"] = "0" * 64
            MODULE.write_contract(contract_path, contract)
            with self.assertRaisesRegex(MODULE.ContractError, "not produced by this checked-in producer"):
                self.verify_with_locked_source(contract_path, prefix, "linux/amd64", source_root)

    def test_verify_rejects_real_checkout_wrong_head_and_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, portfile = self.make_prefix(root)
            source_root, _ = self.make_git_checkout(
                root, portfile, origin="https://github.com/microsoft/vcpkg.git"
            )
            contract = MODULE.contract_for(
                prefix,
                baseline="0" * 40,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-linux-static",
                portfile=source_root / "ports" / "pcre2" / "portfile.cmake",
                target="linux/amd64",
            )
            contract_path = root / "matcher-contract.json"
            MODULE.write_contract(contract_path, contract)
            with self.assertRaisesRegex(MODULE.ContractError, "does not match Agent locked baseline"):
                self.verify_with_real_checkout(
                    contract_path, prefix, "linux/amd64", source_root, "0" * 40
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, portfile = self.make_prefix(root)
            source_root, head = self.make_git_checkout(
                root, portfile, origin="https://example.invalid/vcpkg.git"
            )
            contract = MODULE.contract_for(
                prefix,
                baseline=head,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-linux-static",
                portfile=source_root / "ports" / "pcre2" / "portfile.cmake",
                target="linux/amd64",
            )
            contract_path = root / "matcher-contract.json"
            MODULE.write_contract(contract_path, contract)
            with self.assertRaisesRegex(MODULE.ContractError, "origin is not the official"):
                self.verify_with_real_checkout(contract_path, prefix, "linux/amd64", source_root, head)

    def test_verify_rejects_real_checkout_dirty_portfile_and_patch(self):
        for tampered_name, contents in (
            ("portfile.cmake", "# changed locked portfile\n"),
            ("pcre2-test.patch", "changed tracked patch\n"),
        ):
            with self.subTest(tampered=tampered_name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                prefix, portfile = self.make_prefix(root)
                source_root, head = self.make_git_checkout(
                    root, portfile, origin="https://github.com/microsoft/vcpkg.git"
                )
                source_portfile = source_root / "ports" / "pcre2" / "portfile.cmake"
                contract = MODULE.contract_for(
                    prefix,
                    baseline=head,
                    origin="https://github.com/microsoft/vcpkg.git",
                    triplet="edr-x64-linux-static",
                    portfile=source_portfile,
                    target="linux/amd64",
                )
                contract_path = root / "matcher-contract.json"
                MODULE.write_contract(contract_path, contract)
                (source_root / "ports" / "pcre2" / tampered_name).write_text(
                    contents, encoding="utf-8"
                )
                with self.assertRaisesRegex(MODULE.ContractError, "tracked or untracked modifications"):
                    self.verify_with_real_checkout(
                        contract_path, prefix, "linux/amd64", source_root, head
                    )

    def test_verify_recomputes_clean_checkout_port_sources_and_patches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, portfile = self.make_prefix(root)
            source_root, head = self.make_git_checkout(
                root, portfile, origin="https://github.com/microsoft/vcpkg.git"
            )
            source_portfile = source_root / "ports" / "pcre2" / "portfile.cmake"
            contract = MODULE.contract_for(
                prefix,
                baseline=head,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-linux-static",
                portfile=source_portfile,
                target="linux/amd64",
            )
            contract_path = root / "matcher-contract.json"
            MODULE.write_contract(contract_path, contract)

            changed_portfile = source_portfile.read_text(encoding="utf-8").replace(
                SOURCE_SHA512, "c" * 128
            )
            next_head = self.commit_checkout_change(source_root, source_portfile, changed_portfile)
            contract["producer"]["vcpkg_builtin_baseline"] = next_head
            MODULE.write_contract(contract_path, contract)
            with self.assertRaisesRegex(MODULE.ContractError, "portfile hash does not match"):
                self.verify_with_real_checkout(
                    contract_path, prefix, "linux/amd64", source_root, next_head
                )
            contract["producer"]["vcpkg_portfile_sha256"] = MODULE.sha256_file(source_portfile)
            MODULE.write_contract(contract_path, contract)
            with self.assertRaisesRegex(MODULE.ContractError, "sources or patches do not match"):
                self.verify_with_real_checkout(
                    contract_path, prefix, "linux/amd64", source_root, next_head
                )

            # Restore the original portfile in the contract only, then change a
            # tracked patch in a new clean commit.  The contract remains
            # syntactically self-consistent but must not be trusted over the
            # checkout's recomputed patch set.
            original_portfile = portfile.read_text(encoding="utf-8")
            next_head = self.commit_checkout_change(source_root, source_portfile, original_portfile)
            source_patch = source_root / "ports" / "pcre2" / "pcre2-test.patch"
            next_head = self.commit_checkout_change(source_root, source_patch, "changed committed patch\n")
            contract["producer"]["vcpkg_builtin_baseline"] = next_head
            contract["producer"]["vcpkg_portfile_sha256"] = MODULE.sha256_file(source_portfile)
            MODULE.write_contract(contract_path, contract)
            with self.assertRaisesRegex(MODULE.ContractError, "sources or patches do not match"):
                self.verify_with_real_checkout(
                    contract_path, prefix, "linux/amd64", source_root, next_head
                )

    def test_verify_command_requires_locked_source_checkout(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--verify-contract", "missing-contract.json",
                "--prefix", "missing-prefix",
                "--target", "linux/amd64",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("--verify-contract requires --prefix and --vcpkg-root", completed.stderr)

    def test_success_result_is_single_structured_json_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path = root / "p0_matcher_contract.json"
            prefix = root / "installed" / "edr-x64-linux-static"
            prefix.mkdir(parents=True)
            contract_path.write_text("{}\n", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                MODULE.emit_result(
                    mode="build",
                    contract_path=contract_path,
                    prefix=prefix,
                    target="linux/amd64",
                )
            lines = output.getvalue().splitlines()
            self.assertEqual(1, len(lines))
            result = json.loads(lines[0])
            self.assertEqual(MODULE.RESULT_SCHEMA, result["schema"])
            self.assertEqual("build", result["mode"])
            self.assertEqual("linux/amd64", result["target"])
            self.assertEqual(str(contract_path.resolve()), result["contract_path"])
            self.assertEqual(str(prefix.resolve()), result["prefix"])
            self.assertEqual(MODULE.sha256_file(contract_path), result["contract_sha256"])

        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("--print-library", source)
        self.assertNotIn("PCRE2 matcher contract produced:", source)
        self.assertNotIn("PCRE2 matcher contract verified:", source)

    def test_windows_contract_proves_static_coff_prefix_without_pkgconfig(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, portfile = self.make_prefix(root, target="windows/amd64")
            baseline, _ = MODULE.load_authority()
            contract = MODULE.contract_for(
                prefix,
                baseline=baseline,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-windows-static",
                portfile=portfile,
                target="windows/amd64",
            )
            self.assertIsNone(contract["pcre2"]["pkgconfig_relpath"])
            self.assertIsNone(contract["pcre2"]["pkgconfig_sha256"])
            self.assertEqual("coff-x64", contract["pcre2"]["static_library_machine"])
            contract_path = root / "matcher-contract.json"
            MODULE.write_contract(contract_path, contract)
            source_root = self.make_locked_source_checkout(root, portfile)
            archive = self.verify_with_locked_source(
                contract_path, prefix, "windows/amd64", source_root
            )
            self.assertEqual((prefix / "lib" / "pcre2-8.lib").resolve(), archive)

    def test_source_verification_rejects_auxiliary_source_contract_spoof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, portfile = self.make_prefix(root)
            baseline, _ = MODULE.load_authority()
            contract = MODULE.contract_for(
                prefix,
                baseline=baseline,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-linux-static",
                portfile=portfile,
                target="linux/amd64",
            )
            contract["pcre2"]["source_inputs"][1]["sha512"] = "c" * 128
            contract_path = root / "matcher-contract.json"
            MODULE.write_contract(contract_path, contract)
            source_root = root / "vcpkg"
            source_port = source_root / "ports" / "pcre2"
            source_port.mkdir(parents=True)
            shutil.copy2(portfile, source_port / "portfile.cmake")
            shutil.copy2(portfile.parent / "pcre2-test.patch", source_port / "pcre2-test.patch")
            with mock.patch.object(
                MODULE,
                "verify_clean_pinned_vcpkg",
                return_value="https://github.com/microsoft/vcpkg.git",
            ), self.assertRaisesRegex(MODULE.ContractError, "sources or patches do not match"):
                MODULE.verify_contract(
                    contract_path, prefix, "linux/amd64", vcpkg_root=source_root
                )

    def test_source_verification_rejects_applied_patch_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, portfile = self.make_prefix(root)
            baseline, _ = MODULE.load_authority()
            contract = MODULE.contract_for(
                prefix,
                baseline=baseline,
                origin="https://github.com/microsoft/vcpkg.git",
                triplet="edr-x64-linux-static",
                portfile=portfile,
                target="linux/amd64",
            )
            contract_path = root / "matcher-contract.json"
            MODULE.write_contract(contract_path, contract)
            source_root = root / "vcpkg"
            source_port = source_root / "ports" / "pcre2"
            source_port.mkdir(parents=True)
            shutil.copy2(portfile, source_port / "portfile.cmake")
            (source_port / "pcre2-test.patch").write_text("changed patch\n", encoding="utf-8")
            with mock.patch.object(
                MODULE,
                "verify_clean_pinned_vcpkg",
                return_value="https://github.com/microsoft/vcpkg.git",
            ), self.assertRaisesRegex(MODULE.ContractError, "sources or patches do not match"):
                MODULE.verify_contract(
                    contract_path, prefix, "linux/amd64", vcpkg_root=source_root
                )


if __name__ == "__main__":
    unittest.main()
