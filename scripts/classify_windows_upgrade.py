#!/usr/bin/env python3
"""Classify a Windows Agent release into the safest supported upgrade path."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import PurePosixPath


VALID_CLASSES = {"binary_hot", "runtime_bundle", "installer_required"}
CLASS_RISK = {"binary_hot": 0, "runtime_bundle": 1, "installer_required": 2}

# These paths change installation layout, the updater itself, service/driver
# ownership, or assets that the current protocol cannot replace transactionally.
INSTALLER_REQUIRED_PREFIXES = (
    "config/",
    "install/windows-inno/",
    "install/windows-setup-ui/",
    "models/",
    "rules/",
    "third_party/windivert/",
)
INSTALLER_REQUIRED_FILES = {
    "cmakelists.txt",
    "resources/fdsensor.manifest",
    "scripts/edr_agent_inplace_update.ps1",
    "scripts/edr_agent_install.ps1",
    "scripts/edr_agent_postinstall_verify.ps1",
    "scripts/edr_agent_preflight.ps1",
    "scripts/edr_agent_zip_deploy.ps1",
    "scripts/edr_windows_autorun.ps1",
    "scripts/windows_service_install.ps1",
    "vcpkg-configuration.json",
    "vcpkg.json",
}

# Protocol v5 atomically replaces these lifecycle helpers, app-local DLLs, and
# their integrity manifest. They do not require the full Inno installer.
RUNTIME_BUNDLE_PREFIXES = ("src/installer_worker/",)
RUNTIME_BUNDLE_FILES: set[str] = set()

# Source-only changes are *not* automatically binary-hot. A release build also
# produces native lifecycle helpers and may pick up a different app-local
# runtime from the current Windows runner. The post-build Release gate may
# permit an explicit binary_hot override only after comparing those immutable
# runtime components with the previous published Release.
RUNTIME_SOURCE_PREFIXES = ("src/", "tests/")
RUNTIME_SOURCE_FILES = {"readme.md", "version"}


def normalize_path(value: str) -> str:
    return PurePosixPath(value.strip().replace("\\", "/")).as_posix().lstrip("./").lower()


def classify_paths(paths: list[str]) -> tuple[str, list[str]]:
    normalized = sorted({normalize_path(path) for path in paths if path.strip()})
    if not normalized:
        # A release without a trustworthy diff must never claim hot-update
        # eligibility. This covers shallow/manual builds and first releases.
        return "installer_required", ["release diff is empty or unavailable"]

    installer_reasons = [
        path
        for path in normalized
        if path in INSTALLER_REQUIRED_FILES
        or path.endswith("/cmakelists.txt")
        or any(path.startswith(prefix) for prefix in INSTALLER_REQUIRED_PREFIXES)
    ]
    if installer_reasons:
        return "installer_required", installer_reasons

    runtime_reasons = [
        path
        for path in normalized
        if path in RUNTIME_BUNDLE_FILES
        or any(path.startswith(prefix) for prefix in RUNTIME_BUNDLE_PREFIXES)
    ]
    if runtime_reasons:
        return "runtime_bundle", runtime_reasons
    if all(path in RUNTIME_SOURCE_FILES or any(path.startswith(prefix) for prefix in RUNTIME_SOURCE_PREFIXES) for path in normalized):
        return "runtime_bundle", normalized
    # Unknown build, packaging, resource, or repository layout changes must not
    # silently become a binary-only update. The operator can review and apply a
    # signed override, but automatic classification remains fail-closed.
    return "installer_required", normalized


def git_changed_paths(previous_ref: str, current_ref: str) -> list[str]:
    completed = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRT", previous_ref, current_ref, "--"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout.splitlines()


def resolve_upgrade_class(paths: list[str], override: str) -> tuple[str, list[str]]:
    automatic, reasons = classify_paths(paths)
    if override == "auto":
        return automatic, reasons
    if override not in VALID_CLASSES:
        raise ValueError("override must be auto, binary_hot, runtime_bundle, or installer_required")
    if override == "binary_hot":
        if automatic != "runtime_bundle":
            raise ValueError(
                f"binary_hot cannot override automatic {automatic}; installation-layout and unknown changes must fail closed"
            )
        return override, ["operator requested binary_hot; post-build component identity proof is required"]
    if CLASS_RISK[override] < CLASS_RISK[automatic]:
        raise ValueError(f"{override} cannot downgrade automatic {automatic}")
    return override, [f"operator promoted automatic {automatic} to {override}"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--previous-ref", default="")
    parser.add_argument("--current-ref", default="HEAD")
    parser.add_argument("--override", default="auto")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()

    paths = args.paths
    if not paths and args.previous_ref:
        paths = git_changed_paths(args.previous_ref, args.current_ref)
    override = args.override.strip().lower()
    try:
        upgrade_class, reasons = resolve_upgrade_class(paths, override)
    except ValueError as error:
        parser.error(str(error))
    print(upgrade_class)
    print("upgrade_class_reason=" + ",".join(reasons[:20]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
