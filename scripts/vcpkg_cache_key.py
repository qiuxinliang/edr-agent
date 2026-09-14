"""Identify a Windows dependency-cache snapshot; vcpkg still validates every ABI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def digest_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def cache_identity(root, triplet, toolchain):
    if triplet not in ("x64-windows", "arm64-windows"):
        raise ValueError(f"Unsupported dependency triplet: {triplet}")
    # Share snapshots between PR, prebuild and release jobs with identical inputs.
    inputs = {name: digest_file(root / name) for name in (
        "vcpkg.json", "dependencies.lock.json", "scripts/Initialize-VS2022Environment.ps1",
        "scripts/bootstrap_pinned_vcpkg.ps1", "scripts/vcpkg_cache_key.py",
        "scripts/vcpkg_release_cache.py",
    )}
    encoded = json.dumps({"inputs": inputs, "toolchain": toolchain}, sort_keys=True).encode()
    prefix = f"edr-vcpkg-v3-{triplet}-"
    return prefix + hashlib.sha256(encoded).hexdigest(), prefix


def windows_toolchain():
    required = ("VCToolsVersion", "WindowsSDKVersion", "VCToolsInstallDir")
    missing = [name for name in required if not os.environ.get(name, "").strip()]
    if missing:
        raise ValueError("Initialize Visual Studio before cache restore; missing: " + ", ".join(missing))
    compiler = shutil.which("cl.exe")
    if not compiler:
        raise ValueError("Initialized Visual Studio compiler cl.exe was not found")
    cmake = subprocess.run(["cmake", "--version"], check=True, capture_output=True,
                           text=True, timeout=15).stdout.splitlines()[0]
    # vcpkg may use Hostarm64 even when the product environment uses Hostx64.
    tools_root = Path(os.environ["VCToolsInstallDir"])
    compilers = {path.relative_to(tools_root).as_posix(): digest_file(path)
                 for path in sorted((tools_root / "bin").glob("Host*/*/cl.exe"))}
    if not compilers:
        raise ValueError("Visual Studio toolchain contains no compiler binaries")
    return {
        "vc_tools": os.environ["VCToolsVersion"].strip(),
        "windows_sdk": os.environ["WindowsSDKVersion"].strip(),
        "selected_compiler": digest_file(compiler), "compilers": compilers,
        "cmake": cmake, "runner_arch": os.environ.get("RUNNER_ARCH", ""),
        "image": os.environ.get("ImageOS", ""),
        # A runner image republish alone is not a new ABI. Actual compiler
        # contents, SDK version, host and CMake remain part of the identity;
        # vcpkg independently verifies its complete per-package ABI inputs.
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--triplet", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    key, prefix = cache_identity(root, args.triplet, windows_toolchain())
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        raise ValueError("GITHUB_OUTPUT is required for the cache-key step")
    with open(output, "a", encoding="utf-8") as stream:
        stream.write(f"key={key}\nrestore-prefix={prefix}\n")
    print(f"[vcpkg] dependency cache key: {key}; package ABI checks remain enabled")


if __name__ == "__main__":
    main()
