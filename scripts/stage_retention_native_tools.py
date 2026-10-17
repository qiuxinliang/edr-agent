#!/usr/bin/env python3
"""Stage a compiled native SQLite diagnostic tool; never build or download.

This is a private CI diagnostic artifact, not an Agent/installer/release payload.
The fixture uses real storage/query owners but has test-only rule matcher stubs.
The caller supplies the actual prior native-contract outcome. Failed-gate tools
are limited to isolated sliced-reclaim reproduction, never acceptance evidence.
Staging success is not a native-contract or later comparison result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import time


TOOL = "test_local_evidence_cache_candidate.exe"
MACHINES = {"amd64": 0x8664, "arm64": 0xaa64}
MAX_FILE = 64 * 1024**2
MAX_TOTAL = 256 * 1024**2
MAX_FILES = 32
# Same Windows OS boundary as stage_mingw_runtime_dlls.sh. API-set contracts
# below are finite, rather than accepting arbitrary DLL names/prefixes as OS.
OS_DLLS = frozenset((
    "advapi32 bcrypt cfgmgr32 comctl32 comdlg32 crypt32 dbghelp dnsapi dwmapi "
    "gdi32 imm32 iphlpapi kernel32 kernelbase msvcrt mswsock netapi32 ntdll "
    "ole32 oleaut32 powrprof psapi rpcrt4 secur32 setupapi shell32 shlwapi "
    "tdh ucrtbase user32 userenv version wevtapi winhttp winmm wintrust ws2_32 "
    "wtsapi32"
).split())
OS_DLLS = frozenset(name + ".dll" for name in OS_DLLS) | {"winspool.drv"} | frozenset(
    "api-ms-win-crt-" + family + "-l1-1-0.dll" for family in (
        "conio", "convert", "environment", "filesystem", "heap", "locale",
        "math", "multibyte", "private", "process", "runtime", "stdio",
        "string", "time", "utility"))
DLL_NAME = re.compile(r"[a-z0-9_][a-z0-9_.-]*\.(?:dll|drv)", re.ASCII)


def real_path(path, *, directory=False):
    """Reject symlinks/junctions in every existing component, including parents."""
    path = Path(os.path.abspath(path))
    for item in [path, *path.parents]:
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Symlink/reparse path is not permitted")
    if directory and not path.is_dir():
        raise ValueError("Required directory is missing")
    if not directory and not path.is_file():
        raise ValueError("Required regular file is missing")
    return path


def digest(path):
    size = path.stat().st_size
    if not 0 < size <= MAX_FILE:
        raise ValueError("File exceeds the bounded diagnostic artifact size")
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            sha.update(block)
    return sha.hexdigest()


def pe_machine(path):
    # Same bounded DOS/PE machine check as Assert-WindowsPeArchitecture.ps1;
    # signed Microsoft CRTs are allowed (the unsigned release gate is unrelated).
    with path.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError("Invalid PE DOS header")
        offset = int.from_bytes(dos[60:64], "little")
        if not 64 <= offset <= min(1024**2, path.stat().st_size - 24):
            raise ValueError("Invalid PE header offset")
        stream.seek(offset)
        pe = stream.read(24)
        if pe[:4] != b"PE\0\0":
            raise ValueError("Invalid PE signature")
        optional_size = int.from_bytes(pe[20:22], "little")
        optional = stream.read(optional_size)
        if not 112 <= optional_size <= 4096 or len(optional) != optional_size or optional[:2] != b"\x0b\x02":
            raise ValueError("Expected a complete PE32+ optional header")
        return struct.unpack_from("<H", pe, 4)[0]


def parse_dependents(output):
    """Fail closed if dumpbin's normal or delay import list is unrecognised."""
    if len(output) > 512 * 1024 or "File Type:" not in output or not re.search(r"(?m)^\s*Summary\s*$", output):
        raise ValueError("Unrecognised dumpbin dependency output")
    result, active = set(), False
    for line in output.splitlines():
        text = line.strip()
        if re.search(r"\b(?:error|warning)\b", text, re.I):
            raise ValueError("dumpbin reported a dependency diagnostic")
        if text in ("Image has the following dependencies:", "Image has the following delay load dependencies:"):
            active = True
        elif text == "Summary":
            active = False
        elif active and text:
            name = text.lower()
            if not DLL_NAME.fullmatch(name):
                raise ValueError("Invalid dependency name or unexpected dumpbin import section")
            result.add(name)
    # Every current native tool/runtime imports an OS DLL. An empty parse must
    # never silently stand in for a proven self-contained image.
    if not result:
        raise ValueError("dumpbin produced no recognised imports")
    return sorted(result)


def imports(path, dumpbin, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("Native tool staging deadline expired")
    output = subprocess.run([str(dumpbin), "/NOLOGO", "/DEPENDENTS", str(path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=min(15, remaining), check=False)
    if output.returncode or output.stderr:
        raise ValueError("dumpbin dependency inspection failed")
    return parse_dependents(output.stdout.decode("utf-8", errors="strict"))


def dll_index(directory):
    result = {}
    for path in directory.iterdir():
        if path.suffix.lower() != ".dll":
            continue
        name = path.name.lower()
        if not DLL_NAME.fullmatch(name) or name in result:
            raise ValueError("Invalid or ambiguous dependency filename")
        result[name] = real_path(path)
    return result


def verify_stage(directory, manifest):
    expected = {item["name"] for item in manifest["files"]} | {"manifest.json"}
    if {item.name for item in directory.iterdir()} != expected:
        raise ValueError("Staged artifact contains missing or extra files")
    for item in manifest["files"]:
        if item["name"] != Path(item["name"]).name or not (item["name"] == TOOL or DLL_NAME.fullmatch(item["name"])):
            raise ValueError("Invalid staged artifact path")
        path = real_path(directory / item["name"])
        if path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
            raise ValueError("Staged artifact hash/size mismatch")
        if pe_machine(path) != MACHINES[manifest["arch"]]:
            raise ValueError("Staged PE architecture mismatch")


def stage(args):
    deadline = time.monotonic() + 120
    prior_status = getattr(args, "prior_contract_status", "passed")
    if prior_status not in ("passed", "failed"):
        raise ValueError("Prior native-contract status must be passed or failed")
    prior_passed = prior_status == "passed"
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha) or not re.fullmatch(r"[1-9][0-9]*", args.run_id) or not re.fullmatch(r"[1-9][0-9]*", args.run_attempt):
        raise ValueError("Exact source/run identity is required")
    repo = real_path(args.repo, directory=True)
    build = real_path(args.build_dir, directory=True)
    executable = real_path(build / "tests" / TOOL)
    prefix = real_path(args.dependency_prefix, directory=True)
    compiler, dumpbin = real_path(args.compiler), real_path(args.dumpbin)
    cache = real_path(build / "CMakeCache.txt")
    cache_text = cache.read_text(encoding="utf-8")
    cached_compiler = re.findall(r"(?m)^CMAKE_C_COMPILER:(?:FILEPATH|STRING)=(.+)$", cache_text)
    if len(cached_compiler) != 1 or real_path(cached_compiler[0]) != compiler or compiler.parent != dumpbin.parent:
        raise ValueError("Compiler/dumpbin differ from the initialized CMake compiler owner")
    if not re.search(r"(?m)^CMAKE_BUILD_TYPE:STRING=Release$", cache_text):
        raise ValueError("Only the actual Release contract build may be staged")
    redist = real_path(args.msvc_redist_root, directory=True)
    redist_arch = real_path(redist / {"amd64": "x64", "arm64": "arm64"}[args.arch], directory=True)
    crt_dirs = sorted(p for p in redist_arch.glob("Microsoft.VC*.CRT") if p.is_dir())
    if len(crt_dirs) != 1:
        raise ValueError("The initialized MSVC redist must select exactly one CRT directory")
    crt = real_path(crt_dirs[0], directory=True)
    sources = {}
    for owner, directory in (("vcpkg/bin", real_path(prefix / "bin", directory=True)),
                             ("msvc/" + redist_arch.name + "/" + crt.name, crt)):
        for name, path in dll_index(directory).items():
            if name in sources:
                raise ValueError("Dependency name is ambiguous across locked roots")
            sources[name] = (path, owner + "/" + path.name)
    pending, files, total = [(executable, "contract-build/tests/" + TOOL)], {}, 0
    while pending:
        path, owner = pending.pop(0)
        name = TOOL if path == executable else path.name.lower()
        if name in files:
            continue
        if len(files) >= MAX_FILES or time.monotonic() > deadline:
            raise ValueError("Native tool dependency closure exceeded its bound")
        sha = digest(path)
        if pe_machine(path) != MACHINES[args.arch]:
            raise ValueError("Dependency PE architecture mismatch: " + name)
        dependencies = imports(path, dumpbin, deadline)
        total += path.stat().st_size
        if total > MAX_TOTAL:
            raise ValueError("Native tool dependency closure exceeds total bytes")
        files[name] = {"name": name, "bytes": path.stat().st_size, "sha256": sha,
                       "machine": MACHINES[args.arch], "imports": dependencies,
                       "origin": owner, "source": path}
        for dependency in dependencies:
            if dependency in OS_DLLS:
                continue
            if dependency not in sources:
                raise ValueError("Unresolved non-OS dependency: " + dependency)
            pending.append(sources[dependency])
    provenance = {}
    for label, path in (("compiler", compiler), ("dumpbin", dumpbin), ("cmake_cache", cache),
                        ("dependencies.lock.json", repo / "dependencies.lock.json"),
                        ("vcpkg.json", repo / "vcpkg.json"),
                        ("vcpkg_status", prefix.parent / "vcpkg" / "status"),
                        ("stager", Path(__file__))):
        path = real_path(path)
        provenance[label] = {"name": path.name, "bytes": path.stat().st_size, "sha256": digest(path)}
    manifest = {"schema": "edr.retention-native-tools.v1", "source_sha": args.source_sha,
                "arch": args.arch, "run_id": args.run_id, "run_attempt": args.run_attempt,
                "purpose": "private_isolated_storage_diagnostics" if prior_passed else "private_failed_gate_diagnostics",
                "product_payload": False, "prior_contract_status": prior_status,
                "native_contracts_passed_before_staging": prior_passed,
                "native_contract_status_authority": ("prior_successful_workflow_step_not_parsed_by_stager" if prior_passed
                                                     else "prior_failed_workflow_step_not_parsed_by_stager"),
                "equal_input_comparison_status": "not_run_at_staging",
                "limitations": ["test_only_rule_matcher_stubs", "not_live_endpoint_load_evidence",
                                "not_a_whole_workflow_or_release_gate_result"],
                "msvc_redist_version": redist.name, "provenance": provenance,
                "os_imports_not_packaged": sorted({d for f in files.values() for d in f["imports"] if d in OS_DLLS}),
                "files": [{k: v for k, v in f.items() if k != "source"} for _, f in sorted(files.items())]}
    if not prior_passed:
        # This restriction is consumed by the private supervisor, not by any
        # product/release owner. The workflow must preserve its gate failure.
        manifest["allowed_diagnostic_argv"] = [["--sliced-reclaim-contract"]]
        manifest["limitations"] += ["prior_native_contracts_failed",
                                    "isolated_sliced_reclaim_reproduction_only",
                                    "not_long_soak_or_release_acceptance"]
    output = Path(os.path.abspath(args.output))
    real_path(output.parent, directory=True)
    if output.exists() or output.is_symlink():
        raise ValueError("Native tool output must be new")
    output.mkdir()
    # Exclusive writes and a second source+destination hash check bind the
    # manifest to exactly the inspected bytes, not to pre-existing build DLLs.
    for name, item in sorted(files.items()):
        with item["source"].open("rb") as src, (output / name).open("xb") as dst:
            copied = 0
            while copied < item["bytes"]:
                if time.monotonic() > deadline:
                    raise ValueError("Native tool staging deadline expired")
                block = src.read(min(1024**2, item["bytes"] - copied))
                if not block:
                    raise ValueError("Dependency size changed during staging")
                dst.write(block)
                copied += len(block)
            if src.read(1):
                raise ValueError("Dependency size changed during staging")
        if digest(item["source"]) != item["sha256"]:
            raise ValueError("Dependency changed during staging")
    with (output / "manifest.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    verify_stage(output, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("repo", "build-dir", "dependency-prefix", "msvc-redist-root", "compiler", "dumpbin", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--arch", choices=sorted(MACHINES), required=True)
    parser.add_argument("--prior-contract-status", choices=("passed", "failed"), default="passed",
                        help="actual workflow step outcome; not independently verified by this stager")
    for flag in ("source-sha", "run-id", "run-attempt"):
        parser.add_argument("--" + flag, required=True)
    manifest = stage(parser.parse_args())
    print(json.dumps({"staged": True, "source_sha": manifest["source_sha"],
                      "arch": manifest["arch"], "files": len(manifest["files"]),
                      "purpose": manifest["purpose"], "prior_contract_status": manifest["prior_contract_status"],
                      "native_contracts_passed_before_staging": manifest["native_contracts_passed_before_staging"],
                      "whole_workflow_pass_claimed": False}))


if __name__ == "__main__":
    main()
