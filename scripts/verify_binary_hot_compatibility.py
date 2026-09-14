#!/usr/bin/env python3
"""Prove that two Headless packages differ only in the raw Agent binary.

The platform's binary_hot path replaces only FDSensor.exe. A Release may claim
that class only when every app-local DLL/driver and lifecycle helper is byte
identical to the previous immutable Release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path, PurePosixPath


REQUIRED_NATIVE = (
    "FDSecurityInstallerWorker.exe",
    "uninstall.exe",
)
FORENSIC_BUILTIN = "collector/forensic_collector_builtin.exe"
RUNTIME_SUFFIXES = (".dll", ".sys")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _normalized_entry_name(value: str) -> str:
    normalized = PurePosixPath(value.replace("\\", "/")).as_posix().lstrip("/")
    if not normalized or normalized == "." or ".." in PurePosixPath(normalized).parts:
        raise ValueError(f"unsafe ZIP entry: {value}")
    return normalized


def _read_entries(package: Path) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    with zipfile.ZipFile(package) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = _normalized_entry_name(info.filename)
            key = name.lower()
            if key in entries:
                raise ValueError(f"duplicate ZIP entry: {name}")
            entries[key] = archive.read(info)
    return entries


def runtime_identity(package: Path) -> dict[str, str]:
    entries = _read_entries(package)
    raw_manifest = entries.get("native-package-integrity.json")
    if raw_manifest is None:
        raise ValueError("native-package-integrity.json is missing")
    try:
        manifest = json.loads(raw_manifest.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid native-package-integrity.json: {error}") from error
    if manifest.get("schema") != "edr.windows.native-package-integrity.v1":
        raise ValueError("unsupported native-package-integrity.json schema")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("native-package-integrity.json files must be an array")
    declared: dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict) or set(item) != {"name", "sha256"}:
            raise ValueError("native-package-integrity.json contains an invalid file entry")
        name = str(item["name"])
        normalized_name = _normalized_entry_name(name)
        if normalized_name != name or (PurePosixPath(name).name != name and name != FORENSIC_BUILTIN):
            raise ValueError(f"unsupported native component path: {name}")
        sha256 = str(item["sha256"]).strip().lower()
        if not SHA256_PATTERN.fullmatch(sha256):
            raise ValueError(f"native component SHA-256 is invalid: {name}")
        key = name.lower()
        if key in declared:
            raise ValueError(f"duplicate native component: {name}")
        declared[key] = sha256

    allowed = {name.lower() for name in REQUIRED_NATIVE} | {FORENSIC_BUILTIN.lower()}
    for name in declared:
        if name not in allowed and not name.endswith(".dll"):
            raise ValueError(f"unsupported native component: {name}")

    identity: dict[str, str] = {}
    for required in REQUIRED_NATIVE:
        key = required.lower()
        expected = declared.get(key)
        content = entries.get(key)
        if expected is None or not content:
            raise ValueError(f"required native component is missing: {required}")
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            raise ValueError(f"native component hash mismatch: {required}")
        identity[key] = actual

    forensic_key = FORENSIC_BUILTIN.lower()
    forensic_expected = declared.get(forensic_key)
    forensic_content = entries.get(forensic_key)
    if forensic_expected is not None or forensic_content is not None:
        if forensic_expected is None or not forensic_content:
            raise ValueError(f"forensic runtime component is missing or unbound: {FORENSIC_BUILTIN}")
        forensic_actual = hashlib.sha256(forensic_content).hexdigest()
        if forensic_actual != forensic_expected:
            raise ValueError(f"native component hash mismatch: {FORENSIC_BUILTIN}")
        identity[forensic_key] = forensic_actual

    for name, content in entries.items():
        if "/" not in name and name.endswith(RUNTIME_SUFFIXES):
            if not content:
                raise ValueError(f"runtime component is empty: {name}")
            actual = hashlib.sha256(content).hexdigest()
            if name.endswith(".dll"):
                expected = declared.get(name)
                if expected is None:
                    raise ValueError(f"runtime DLL is not bound by the integrity manifest: {name}")
                if actual != expected:
                    raise ValueError(f"runtime DLL hash mismatch: {name}")
            identity[name] = actual

    for name in declared:
        if name.endswith(".dll") and name not in identity:
            raise ValueError(f"declared runtime DLL is missing: {name}")
    return dict(sorted(identity.items()))


def verify_binary_hot_compatibility(previous: Path, current: Path) -> None:
    previous_identity = runtime_identity(previous)
    current_identity = runtime_identity(current)
    if previous_identity.keys() != current_identity.keys():
        removed = sorted(previous_identity.keys() - current_identity.keys())
        added = sorted(current_identity.keys() - previous_identity.keys())
        raise ValueError(f"runtime component set changed; removed={removed} added={added}")
    changed = [name for name in current_identity if current_identity[name] != previous_identity[name]]
    if changed:
        raise ValueError("runtime component hashes changed: " + ", ".join(changed))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    args = parser.parse_args()
    verify_binary_hot_compatibility(args.previous, args.current)
    print("binary_hot component identity proof passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
