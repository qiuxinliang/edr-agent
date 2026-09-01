#!/usr/bin/env python3
"""Build the Agent-owned static PCRE2 prefix and emit its matcher contract.

The P0 publisher must validate regexps with exactly the PCRE2 surface used by
the Agent.  A caller-supplied prefix or JSON declaration is not evidence of
that surface: it can name a different archive while retaining the same PCRE2
version.  This producer accepts only a clean vcpkg checkout at the Agent lock
baseline, disables binary-package caches, builds PCRE2 from that checkout, and
records hashes of the concrete header, pkg-config file, and static archive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
import shutil


AGENT_ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = AGENT_ROOT / "dependencies.lock.json"
MANIFEST_PATH = AGENT_ROOT / "vcpkg.json"
PORTFILE_RELATIVE = Path("ports") / "pcre2" / "portfile.cmake"
MATCHER_SOURCE_PATHS = (
    Path("src") / "preprocess" / "p0_rule_ir.c",
    Path("include") / "edr" / "p0_rule_ir.h",
)
TRIPLETS_DIR = AGENT_ROOT / "triplets"
TARGET_TRIPLETS = {
    "linux/amd64": "edr-x64-linux-static",
    "linux/arm64": "edr-arm64-linux-static",
    "windows/amd64": "edr-x64-windows-static",
    "windows/arm64": "edr-arm64-windows-static",
}
TARGET_ARCHIVE_MACHINES = {
    "linux/amd64": "elf-x86_64",
    "linux/arm64": "elf-aarch64",
    "windows/amd64": "coff-x64",
    "windows/arm64": "coff-arm64",
}
PCRE2_UPSTREAM_REPOSITORY = "PCRE2Project/pcre2"
# v3 binds each vcpkg source declaration and the patches applied to it.  v2
# carried only the first PCRE2 SHA512, which is insufficient for ports that
# fetch an auxiliary source such as SLJIT.
CONTRACT_SCHEMA = "edr.p0.matcher-contract.v3"
PRODUCER_KIND = "edr-agent-pcre2-static-producer-v1"
RESULT_SCHEMA = "edr.p0.matcher-producer-result.v1"


class ContractError(RuntimeError):
    """A release input cannot prove the Agent matcher contract."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_checked(args: list[str], *, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(args, check=False, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "command failed"
        raise ContractError(f"{' '.join(args[:3])}: {detail}")
    return completed.stdout.strip()


def load_authority() -> tuple[str, dict]:
    try:
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"read Agent dependency authority: {exc}") from exc
    baseline = lock.get("vcpkg", {}).get("builtin_baseline")
    if lock.get("schema") != "edr.native-dependencies.lock.v1" or not isinstance(baseline, str) or not re.fullmatch(r"[0-9a-f]{40}", baseline):
        raise ContractError("Agent dependency lock has no valid vcpkg builtin baseline")
    dependencies = manifest.get("dependencies")
    has_pcre2 = isinstance(dependencies, list) and any(
        item == "pcre2" or isinstance(item, dict) and item.get("name") == "pcre2"
        for item in dependencies
    )
    if manifest.get("builtin-baseline") != baseline or not has_pcre2:
        raise ContractError("Agent vcpkg manifest is not pinned to the lock baseline with pcre2")
    return baseline, manifest


def is_vcpkg_checkout(vcpkg_root: Path) -> bool:
    git = vcpkg_root / ".git"
    return git.is_dir() or git.is_file()


def verify_clean_pinned_vcpkg(vcpkg_root: Path, baseline: str) -> str:
    if not is_vcpkg_checkout(vcpkg_root):
        raise ContractError(f"vcpkg root is not a checkout: {vcpkg_root}")
    try:
        inside = run_checked(["git", "-C", str(vcpkg_root), "rev-parse", "--is-inside-work-tree"])
        head = run_checked(["git", "-C", str(vcpkg_root), "rev-parse", "HEAD"])
        status = run_checked(["git", "-C", str(vcpkg_root), "status", "--porcelain", "--untracked-files=all"])
        origin = run_checked(["git", "-C", str(vcpkg_root), "remote", "get-url", "origin"])
    except ContractError as exc:
        raise ContractError(f"inspect vcpkg checkout: {exc}") from exc
    if inside != "true" or head.lower() != baseline:
        raise ContractError(f"vcpkg checkout does not match Agent locked baseline {baseline}")
    if status:
        raise ContractError("vcpkg checkout has tracked or untracked modifications")
    normalized_origin = origin.rstrip("/").lower()
    allowed_origins = {
        "https://github.com/microsoft/vcpkg.git",
        "https://github.com/microsoft/vcpkg",
        "git@github.com:microsoft/vcpkg.git",
        "ssh://git@github.com/microsoft/vcpkg.git",
    }
    if normalized_origin not in allowed_origins:
        raise ContractError("vcpkg checkout origin is not the official microsoft/vcpkg repository")
    return origin


def bootstrap_pinned_vcpkg(vcpkg_root: Path, baseline: str) -> None:
    vcpkg_root.mkdir(parents=True, exist_ok=True)
    run_checked(["git", "-C", str(vcpkg_root), "init", "--quiet"])
    run_checked([
        "git", "-C", str(vcpkg_root), "remote", "add", "origin",
        "https://github.com/microsoft/vcpkg.git",
    ])
    run_checked(["git", "-C", str(vcpkg_root), "fetch", "--depth", "1", "origin", baseline])
    run_checked(["git", "-C", str(vcpkg_root), "checkout", "--detach", "--force", "FETCH_HEAD"])
    bootstrap = vcpkg_root / "bootstrap-vcpkg.bat" if os.name == "nt" else vcpkg_root / "bootstrap-vcpkg.sh"
    if not bootstrap.is_file():
        raise ContractError(f"bootstrap-vcpkg script missing in pinned vcpkg: {vcpkg_root}")
    command = ["cmd", "/c", str(bootstrap), "-disableMetrics"] if os.name == "nt" else [str(bootstrap), "-disableMetrics"]
    run_checked(command)


def resolve_source_vcpkg_root(vcpkg_root: Path, baseline: str) -> tuple[Path, Path | None]:
    source_mode = os.environ.get("VCPKG_SOURCE", "").strip().lower() == "source"
    vcpkg_root = vcpkg_root.resolve()
    if is_vcpkg_checkout(vcpkg_root):
        verify_clean_pinned_vcpkg(vcpkg_root, baseline)
        return vcpkg_root, None
    if not source_mode:
        verify_clean_pinned_vcpkg(vcpkg_root, baseline)
    temporary_root = Path(tempfile.mkdtemp(prefix="edr-pinned-vcpkg-"))
    try:
        bootstrap_pinned_vcpkg(temporary_root, baseline)
        verify_clean_pinned_vcpkg(temporary_root, baseline)
    except Exception:
        shutil.rmtree(temporary_root, ignore_errors=True)
        raise
    return temporary_root, temporary_root


def vcpkg_from_github_blocks(text: str) -> list[str]:
    """Return complete top-level vcpkg_from_github argument blocks.

    Do not take a first-SHA shortcut: a port can have several source fetches.
    This intentionally recognizes only balanced CMake function calls and
    fails closed for unterminated strings or calls.
    """
    blocks: list[str] = []
    expression = re.compile(r"\bvcpkg_from_github\s*\(")
    search_start = 0
    while match := expression.search(text, search_start):
        opening = text.find("(", match.start(), match.end())
        depth = 0
        quoted = False
        escaped = False
        for index in range(opening, len(text)):
            character = text[index]
            if quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    quoted = False
                continue
            if character == '"':
                quoted = True
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    blocks.append(text[opening + 1:index])
                    search_start = index + 1
                    break
                if depth < 0:
                    raise ContractError("PCRE2 portfile has an invalid vcpkg_from_github call")
        else:
            raise ContractError("PCRE2 portfile has an unterminated vcpkg_from_github call")
        if quoted:
            raise ContractError("PCRE2 portfile has an unterminated quoted source value")
    return blocks


def port_source_authority(portfile: Path) -> list[dict[str, object]]:
    """Bind every source and patch named by the locked PCRE2 port.

    Current vcpkg ports/pcre2 uses both the primary PCRE2 source and a vendored
    SLJIT source. Treating the first SHA512 in the file as the whole authority
    would silently omit the latter; this parser accepts only complete,
    structurally well-formed vcpkg_from_github declarations.
    """
    try:
        text = portfile.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContractError(f"read PCRE2 portfile: {exc}") from exc
    blocks = vcpkg_from_github_blocks(text)
    if not blocks:
        raise ContractError("PCRE2 portfile has no vcpkg_from_github source declarations")

    sources: list[dict[str, object]] = []
    all_patch_names: set[str] = set()
    for block in blocks:
        values: dict[str, str] = {}
        for key in ("REPO", "REF", "SHA512"):
            matches = re.findall(rf"(?m)^\s*{key}\s+([^\r\n]+?)\s*$", block)
            if len(matches) != 1:
                raise ContractError(f"PCRE2 portfile source declaration must have exactly one {key}")
            value = matches[0].strip()
            if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            if not value:
                raise ContractError(f"PCRE2 portfile source declaration has an empty {key}")
            values[key] = value
        if not re.fullmatch(r"[0-9a-fA-F]{128}", values["SHA512"]):
            raise ContractError("PCRE2 portfile source declaration has an invalid SHA512")
        repo = values["REPO"]
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", repo):
            raise ContractError("PCRE2 portfile source declaration has an unsafe repository name")
        if any(source["repo"] == repo for source in sources):
            raise ContractError(f"PCRE2 portfile repeats source repository {repo}")
        patches_sha256: dict[str, str] = {}
        lines = block.splitlines()
        try:
            patches_index = next(index for index, line in enumerate(lines) if line.strip() == "PATCHES")
        except StopIteration:
            patches_index = len(lines)
        for line in lines[patches_index + 1:]:
            patch_name = line.split("#", 1)[0].strip()
            if not patch_name:
                continue
            if not re.fullmatch(r"[A-Za-z0-9_.-]+\.patch", patch_name):
                raise ContractError("PCRE2 portfile has an unsafe or ambiguous patch declaration")
            if patch_name in all_patch_names:
                raise ContractError(f"PCRE2 portfile repeats patch declaration {patch_name}")
            patch_path = (portfile.parent / patch_name).resolve()
            try:
                patch_path.relative_to(portfile.parent.resolve())
            except ValueError as exc:
                raise ContractError("PCRE2 portfile patch escapes the port directory") from exc
            if not patch_path.is_file():
                raise ContractError(f"PCRE2 portfile patch is missing: {patch_name}")
            all_patch_names.add(patch_name)
            patches_sha256[patch_name] = sha256_file(patch_path)
        source = {
            "repo": repo,
            "ref": values["REF"],
            "sha512": values["SHA512"].lower(),
            "patches_sha256": patches_sha256,
        }
        sources.append(source)
    if sum(source["repo"] == PCRE2_UPSTREAM_REPOSITORY for source in sources) != 1:
        raise ContractError(
            f"PCRE2 portfile must declare exactly one {PCRE2_UPSTREAM_REPOSITORY} source"
        )
    return sources


def validate_contract_source_authority(source_inputs: object) -> None:
    if not isinstance(source_inputs, list) or not source_inputs:
        raise ContractError("matcher contract lacks complete PCRE2 source inputs")
    repositories: set[str] = set()
    patch_names: set[str] = set()
    primary_count = 0
    for source in source_inputs:
        if not isinstance(source, dict) or set(source) != {"repo", "ref", "sha512", "patches_sha256"}:
            raise ContractError("matcher contract PCRE2 source input is malformed")
        repo = source.get("repo")
        ref = source.get("ref")
        if (not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", repo) or
                not isinstance(ref, str) or not ref or "\n" in ref or "\r" in ref):
            raise ContractError("matcher contract PCRE2 source input has an unsafe repository or ref")
        if repo in repositories:
            raise ContractError("matcher contract repeats a PCRE2 source repository")
        repositories.add(repo)
        require_hash(source.get("sha512"), label=f"pcre2.source_inputs[{repo}].sha512", length=128)
        patches_sha256 = source.get("patches_sha256")
        if not isinstance(patches_sha256, dict):
            raise ContractError("matcher contract PCRE2 patch hash authority is malformed")
        for patch_name, patch_hash in patches_sha256.items():
            if (not isinstance(patch_name, str) or
                    not re.fullmatch(r"[A-Za-z0-9_.-]+\.patch", patch_name)):
                raise ContractError("matcher contract PCRE2 patch name is unsafe")
            if patch_name in patch_names:
                raise ContractError("matcher contract repeats a PCRE2 patch declaration")
            patch_names.add(patch_name)
            require_hash(patch_hash, label=f"pcre2.source_inputs[{repo}].patches_sha256[{patch_name}]")
        if repo == PCRE2_UPSTREAM_REPOSITORY:
            primary_count += 1
    if primary_count != 1:
        raise ContractError(f"matcher contract must bind exactly one {PCRE2_UPSTREAM_REPOSITORY} source")


def static_build_environment(cc: str | None) -> dict[str, str]:
    env = dict(os.environ)
    for name in (
        "VCPKG_BINARY_SOURCES", "VCPKG_OVERLAY_PORTS", "VCPKG_OVERLAY_TRIPLETS",
        "VCPKG_DEFAULT_TRIPLET", "VCPKG_DEFAULT_HOST_TRIPLET", "VCPKG_DOWNLOADS",
    ):
        env.pop(name, None)
    # A cached binary can be valid only if its provenance is authenticated by
    # a separate authority. This producer deliberately uses every source and
    # patch declared by the pinned port instead.
    env["VCPKG_BINARY_SOURCES"] = "clear"
    env["VCPKG_DISABLE_METRICS"] = "1"
    if cc:
        env["CC"] = cc
    return env


def create_isolated_work_roots(vcpkg_root: Path, producer_root: Path) -> dict[str, Path]:
    """Create the only vcpkg state directories that a producer invocation may use.

    vcpkg intentionally ignores buildtrees, packages, downloads, and installed
    output in its checkout.  A clean Git worktree therefore does not prove that
    an ordinary vcpkg invocation cannot reuse old artifacts from those paths.
    Keep every mutable directory below a caller-named, empty producer root and
    pass every one to vcpkg explicitly.
    """
    resolved_vcpkg = vcpkg_root.resolve()
    resolved_root = producer_root.resolve()
    if resolved_root == resolved_root.parent:
        raise ContractError("PCRE2 producer root must not be a filesystem root")
    try:
        resolved_root.relative_to(resolved_vcpkg)
    except ValueError:
        pass
    else:
        raise ContractError("PCRE2 producer root must be outside the vcpkg checkout")
    try:
        resolved_vcpkg.relative_to(resolved_root)
    except ValueError:
        pass
    else:
        raise ContractError("vcpkg checkout must be outside the PCRE2 producer root")
    if resolved_root.exists():
        if not resolved_root.is_dir():
            raise ContractError(f"PCRE2 producer root is not a directory: {resolved_root}")
        if any(resolved_root.iterdir()):
            raise ContractError(f"PCRE2 producer root must be empty: {resolved_root}")
    else:
        resolved_root.mkdir(parents=True, exist_ok=False)

    roots = {
        "buildtrees": resolved_root / "buildtrees",
        "packages": resolved_root / "packages",
        "installed": resolved_root / "installed",
        "downloads": resolved_root / "downloads",
    }
    for name, path in roots.items():
        path.mkdir(exist_ok=False)
        if any(path.iterdir()):
            raise ContractError(f"PCRE2 producer {name} root must be empty: {path}")
    return roots


def build_static_pcre2(vcpkg_root: Path, producer_root: Path, triplet: str, cc: str | None) -> Path:
    vcpkg_candidates = (vcpkg_root / "vcpkg", vcpkg_root / "vcpkg.exe")
    vcpkg = next((candidate for candidate in vcpkg_candidates if candidate.is_file()), None)
    if vcpkg is None or not os.access(vcpkg, os.X_OK):
        names = ", ".join(str(candidate) for candidate in vcpkg_candidates)
        raise ContractError(f"pinned vcpkg executable is missing or not executable: {names}")
    roots = create_isolated_work_roots(vcpkg_root, producer_root)
    command = [
        str(vcpkg), "install", "pcre2", "--classic", "--triplet", triplet,
        "--overlay-triplets", str(TRIPLETS_DIR),
        "--x-buildtrees-root", str(roots["buildtrees"]),
        "--x-packages-root", str(roots["packages"]),
        "--x-install-root", str(roots["installed"]),
        "--downloads-root", str(roots["downloads"]),
    ]
    run_checked(command, env=static_build_environment(cc))
    prefix = roots["installed"] / triplet
    try:
        prefix.resolve().relative_to(roots["installed"].resolve())
    except ValueError as exc:
        raise ContractError("vcpkg returned a prefix outside the producer install root") from exc
    return prefix


def pcre2_header_version(header: Path) -> str:
    text = header.read_text(encoding="utf-8", errors="strict")
    major = re.search(r"^\s*#\s*define\s+PCRE2_MAJOR\s+(\d+)\s*$", text, re.MULTILINE)
    minor = re.search(r"^\s*#\s*define\s+PCRE2_MINOR\s+(\d+)\s*$", text, re.MULTILINE)
    if not major or not minor:
        raise ContractError("generated PCRE2 header does not declare PCRE2_MAJOR and PCRE2_MINOR")
    return f"{major.group(1)}.{minor.group(1)}"


def pkgconfig_version(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="strict")
    match = re.search(r"^Version:\s*(\S+)\s*$", text, re.MULTILINE)
    if not match:
        raise ContractError("generated libpcre2-8.pc has no Version field")
    return match.group(1)


def target_for_triplet(triplet: str) -> str:
    matches = [target for target, candidate in TARGET_TRIPLETS.items() if candidate == triplet]
    if len(matches) != 1:
        raise ContractError(f"unrecognized Agent PCRE2 producer triplet: {triplet}")
    return matches[0]


def resolve_below(root: Path, relative: str, *, label: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ContractError(f"{label} must be a relative path below the producer prefix")
    resolved_root = root.resolve()
    resolved = (resolved_root / candidate).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ContractError(f"{label} escapes the producer prefix") from exc
    return resolved


def static_library_candidates(target: str) -> tuple[Path, ...]:
    if target.startswith("linux/"):
        return (Path("lib") / "libpcre2-8.a",)
    if target.startswith("windows/"):
        # vcpkg's native Windows static triplets use COFF archives.  Do not
        # accept a MinGW .a or a dynamic import library for a Windows release.
        return (Path("lib") / "pcre2-8.lib", Path("lib") / "libpcre2-8.lib")
    raise ContractError(f"unsupported PCRE2 producer target: {target}")


def has_static_archive_magic(path: Path) -> bool:
    with path.open("rb") as handle:
        return handle.read(8) == b"!<arch>\n"


def static_archive_machine(path: Path) -> str:
    """Prove every object in a static archive has one concrete architecture.

    Archive labels and a valid first object do not prove that later members are
    from the same build target.  Reject unknown or mixed object formats rather
    than linking a partially cross-swapped archive.
    """
    machines = {
        (b"\x7fELF", 62): "elf-x86_64",
        (b"\x7fELF", 183): "elf-aarch64",
        (b"COFF", 0x8664): "coff-x64",
        (b"COFF", 0xAA64): "coff-arm64",
    }
    with path.open("rb") as handle:
        if handle.read(8) != b"!<arch>\n":
            raise ContractError("generated PCRE2 library is not a static archive")
        object_machines: set[str] = set()
        while True:
            header = handle.read(60)
            if not header:
                break
            if len(header) != 60 or header[58:60] != b"\x60\n":
                raise ContractError("generated PCRE2 archive has an invalid member header")
            try:
                size = int(header[48:58].decode("ascii").strip())
            except ValueError as exc:
                raise ContractError("generated PCRE2 archive has an invalid member size") from exc
            if size < 0:
                raise ContractError("generated PCRE2 archive has a negative member size")
            member = handle.read(size)
            if len(member) != size:
                raise ContractError("generated PCRE2 archive is truncated")
            if size % 2:
                handle.read(1)
            name = header[:16].decode("ascii", errors="replace").strip()
            if name.startswith("#1/"):
                try:
                    name_size = int(name[3:])
                except ValueError as exc:
                    raise ContractError("generated PCRE2 archive has an invalid BSD member name") from exc
                if name_size > len(member):
                    raise ContractError("generated PCRE2 archive has a truncated BSD member name")
                member = member[name_size:]
            if name in {"/", "//"} or not member:
                continue
            if member.startswith(b"\x7fELF") and len(member) >= 20:
                machine = int.from_bytes(member[18:20], "little")
                result = machines.get((b"\x7fELF", machine))
            elif len(member) >= 2:
                machine = int.from_bytes(member[:2], "little")
                result = machines.get((b"COFF", machine))
            else:
                result = None
            if not result:
                raise ContractError("generated PCRE2 static archive has an unrecognized target object")
            object_machines.add(result)
        if not object_machines:
            raise ContractError("generated PCRE2 static archive has no recognized target object")
        if len(object_machines) != 1:
            found = ", ".join(sorted(object_machines))
            raise ContractError(f"generated PCRE2 static archive has mixed target objects: {found}")
        return next(iter(object_machines))


def require_target_archive_machine(path: Path, target: str) -> str:
    expected = TARGET_ARCHIVE_MACHINES.get(target)
    if not expected:
        raise ContractError(f"unsupported PCRE2 producer target: {target}")
    actual = static_archive_machine(path)
    if actual != expected:
        raise ContractError(
            f"generated PCRE2 static archive targets {actual}, expected {expected} for {target}"
        )
    return actual


def find_static_library(prefix: Path, target: str) -> tuple[Path, str]:
    found = [
        (resolve_below(prefix, relative.as_posix(), label="PCRE2 static library"), relative.as_posix())
        for relative in static_library_candidates(target)
        if resolve_below(prefix, relative.as_posix(), label="PCRE2 static library").is_file()
    ]
    if len(found) != 1:
        expected = ", ".join(path.as_posix() for path in static_library_candidates(target))
        raise ContractError(
            f"fresh static PCRE2 build must contain exactly one target static archive ({expected})"
        )
    archive, relative = found[0]
    # Both Unix ar archives and MSVC COFF libraries use this archive magic.
    if not has_static_archive_magic(archive):
        raise ContractError("generated PCRE2 library is not a static archive")
    require_target_archive_machine(archive, target)
    return archive, relative


def find_pkgconfig(prefix: Path, target: str) -> tuple[Path | None, str | None]:
    relative = Path("lib") / "pkgconfig" / "libpcre2-8.pc"
    path = resolve_below(prefix, relative.as_posix(), label="PCRE2 pkg-config metadata")
    if path.is_file():
        return path, relative.as_posix()
    if target.startswith("linux/"):
        raise ContractError("fresh Linux static PCRE2 build is missing lib/pkgconfig/libpcre2-8.pc")
    return None, None


def reject_shared_pcre2(prefix: Path) -> None:
    candidates = []
    for directory in (prefix / "lib", prefix / "bin"):
        if not directory.is_dir():
            continue
        candidates.extend(directory.glob("libpcre2-8.so*"))
        candidates.extend(directory.glob("libpcre2-8.dylib"))
        candidates.extend(directory.glob("pcre2-8.dll"))
        candidates.extend(directory.glob("libpcre2-8.dll"))
    if candidates:
        raise ContractError("fresh PCRE2 producer output contains forbidden shared libpcre2-8")


def matcher_contract_from_header(header: Path) -> dict:
    """Read the parser's public, immutable matcher input contract.

    The producer must not invent the source schema, IR schema, or capacity:
    the same checked-in header is compiled into the Agent and its hash is
    carried alongside these literal values below.
    """
    try:
        text = header.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContractError(f"read Agent matcher header: {exc}") from exc

    def string_macro(name: str) -> str:
        match = re.search(
            rf'^\s*#\s*define\s+{re.escape(name)}\s+"([^"\r\n]+)"\s*$',
            text,
            re.MULTILINE,
        )
        if not match:
            raise ContractError(f"Agent matcher header lacks string macro {name}")
        return match.group(1)

    def uint_macro(name: str) -> int:
        match = re.search(
            rf'^\s*#\s*define\s+{re.escape(name)}\s+(\d+)[uU]?\s*$',
            text,
            re.MULTILINE,
        )
        if not match:
            raise ContractError(f"Agent matcher header lacks unsigned integer macro {name}")
        value = int(match.group(1))
        if value <= 0:
            raise ContractError(f"Agent matcher header has non-positive {name}")
        return value

    bundle_kind = string_macro("EDR_P0_RULE_IR_BUNDLE_KIND")
    ir_schema_version = uint_macro("EDR_P0_RULE_IR_SCHEMA_VERSION")
    rule_schema = string_macro("EDR_P0_MATCHER_RULE_SCHEMA")
    if rule_schema != f"{bundle_kind}@{ir_schema_version}":
        raise ContractError("Agent matcher rule schema does not bind its kind and IR schema version")
    return {
        "source_schema": string_macro("EDR_P0_MATCHER_SOURCE_SCHEMA"),
        "rule_schema": rule_schema,
        "max_rules": uint_macro("EDR_P0_RULE_IR_MAX_RULES"),
        "bundle_kind": bundle_kind,
        "ir_schema_version": ir_schema_version,
    }


def contract_for(prefix: Path, *, baseline: str, origin: str, triplet: str,
                 portfile: Path, target: str | None = None) -> dict:
    target = target or target_for_triplet(triplet)
    if TARGET_TRIPLETS.get(target) != triplet:
        raise ContractError("PCRE2 target and vcpkg triplet do not agree")
    header = prefix / "include" / "pcre2.h"
    if not header.is_file():
        raise ContractError("fresh static PCRE2 build is missing include/pcre2.h")
    archive, archive_relative = find_static_library(prefix, target)
    pkgconfig, pkgconfig_relative = find_pkgconfig(prefix, target)
    reject_shared_pcre2(prefix)
    header_version = pcre2_header_version(header)
    pc_version = pkgconfig_version(pkgconfig) if pkgconfig else header_version
    if pkgconfig and pc_version != header_version:
        raise ContractError(f"PCRE2 header version {header_version} does not match pkg-config version {pc_version}")
    matcher_hashes: dict[str, str] = {}
    for relative in MATCHER_SOURCE_PATHS:
        source = AGENT_ROOT / relative
        if not source.is_file():
            raise ContractError(f"Agent matcher source missing: {relative}")
        matcher_hashes[str(relative)] = sha256_file(source)
    matcher_contract = matcher_contract_from_header(AGENT_ROOT / MATCHER_SOURCE_PATHS[1])
    source_inputs = port_source_authority(portfile)
    validate_contract_source_authority(source_inputs)
    return {
        "schema": CONTRACT_SCHEMA,
        "producer": {
            "kind": PRODUCER_KIND,
            "script_sha256": sha256_file(Path(__file__).resolve()),
            "vcpkg_builtin_baseline": baseline,
            "vcpkg_checkout_origin": origin,
            "vcpkg_triplet": triplet,
            "target": target,
            "vcpkg_portfile_sha256": sha256_file(portfile),
            "binary_package_cache": "disabled",
            "source_build": "fresh_pinned_vcpkg",
            "work_root_isolation": "dedicated_empty_buildtrees_packages_installed_downloads",
        },
        "pcre2": {
            "version": pc_version,
            "source_inputs": source_inputs,
            "code_unit_width": 8,
            "compile_options": ["PCRE2_UTF"],
            "header_sha256": sha256_file(header),
            "static_library_relpath": archive_relative,
            "static_library_sha256": sha256_file(archive),
            "static_library_machine": require_target_archive_machine(archive, target),
            "pkgconfig_relpath": pkgconfig_relative,
            "pkgconfig_sha256": sha256_file(pkgconfig) if pkgconfig else None,
        },
        "agent_matcher": {
            **matcher_contract,
            "sources_sha256": matcher_hashes,
        },
    }


def load_contract(path: Path) -> dict:
    try:
        contract = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"read matcher contract: {exc}") from exc
    if not isinstance(contract, dict):
        raise ContractError("matcher contract root must be an object")
    return contract


def require_hash(value: object, *, label: str, length: int = 64) -> str:
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise ContractError(f"matcher contract {label} must be a lowercase SHA-{length * 4} hash")
    return value


def verify_locked_source_authority(vcpkg_root: Path, baseline: str,
                                   producer: dict, pcre2: dict) -> None:
    """Recompute every source-side PCRE2 authority from the locked checkout.

    The contract is only a record of a source build.  It cannot authenticate
    its own baseline, remote, portfile, source archive hashes, or applied
    patches.  Requiring the clean checkout at configure time makes those
    values independently checkable instead of accepting self-reported JSON.
    """
    resolved_vcpkg_root = vcpkg_root.resolve()
    actual_origin = verify_clean_pinned_vcpkg(resolved_vcpkg_root, baseline)
    recorded_origin = producer.get("vcpkg_checkout_origin")
    if (not isinstance(recorded_origin, str) or
            actual_origin.rstrip("/").lower() != recorded_origin.rstrip("/").lower()):
        raise ContractError("matcher contract vcpkg checkout origin does not match source verification")
    portfile = resolved_vcpkg_root / PORTFILE_RELATIVE
    if not portfile.is_file():
        raise ContractError("locked vcpkg checkout is missing ports/pcre2/portfile.cmake")
    recorded_portfile_hash = require_hash(
        producer.get("vcpkg_portfile_sha256"), label="producer.vcpkg_portfile_sha256"
    )
    if recorded_portfile_hash != sha256_file(portfile):
        raise ContractError("matcher contract PCRE2 portfile hash does not match source verification")
    actual_source_inputs = port_source_authority(portfile)
    if pcre2.get("source_inputs") != actual_source_inputs:
        raise ContractError("matcher contract PCRE2 sources or patches do not match source verification")


def verify_contract(contract_path: Path, prefix: Path, target: str,
                    requested_library: Path | None = None, *,
                    vcpkg_root: Path) -> Path:
    """Validate a generated contract immediately before a production link.

    This intentionally re-reads every byte-bearing input which CMake consumes.
    A version string or caller supplied prefix alone is never accepted as
    provenance for a production matcher.
    """
    contract = load_contract(contract_path.resolve())
    if contract.get("schema") != CONTRACT_SCHEMA:
        raise ContractError(f"expected {CONTRACT_SCHEMA} matcher contract")
    baseline, _ = load_authority()
    producer = contract.get("producer")
    pcre2 = contract.get("pcre2")
    matcher = contract.get("agent_matcher")
    if not isinstance(producer, dict) or not isinstance(pcre2, dict) or not isinstance(matcher, dict):
        raise ContractError("matcher contract lacks producer, pcre2, or agent matcher authority")
    triplet = TARGET_TRIPLETS.get(target)
    if not triplet:
        raise ContractError(f"unsupported matcher contract target: {target}")
    if (producer.get("kind") != PRODUCER_KIND or
            producer.get("vcpkg_builtin_baseline") != baseline or
            producer.get("vcpkg_triplet") != triplet or
            producer.get("target") != target or
            producer.get("binary_package_cache") != "disabled" or
            producer.get("source_build") != "fresh_pinned_vcpkg" or
            producer.get("work_root_isolation") !=
            "dedicated_empty_buildtrees_packages_installed_downloads"):
        raise ContractError("matcher contract producer provenance is incomplete or targets another build")
    if require_hash(producer.get("script_sha256"), label="producer.script_sha256") != sha256_file(Path(__file__).resolve()):
        raise ContractError("matcher contract was not produced by this checked-in producer")
    require_hash(producer.get("vcpkg_portfile_sha256"), label="producer.vcpkg_portfile_sha256")
    validate_contract_source_authority(pcre2.get("source_inputs"))
    verify_locked_source_authority(vcpkg_root, baseline, producer, pcre2)
    if pcre2.get("code_unit_width") != 8 or pcre2.get("compile_options") != ["PCRE2_UTF"]:
        raise ContractError("matcher contract does not prove the 8-bit PCRE2_UTF ABI")

    resolved_prefix = prefix.resolve()
    if not resolved_prefix.is_dir():
        raise ContractError(f"PCRE2 producer prefix does not exist: {resolved_prefix}")
    header = resolve_below(resolved_prefix, "include/pcre2.h", label="PCRE2 header")
    if not header.is_file():
        raise ContractError("PCRE2 producer prefix is missing include/pcre2.h")
    archive_relative = pcre2.get("static_library_relpath")
    if not isinstance(archive_relative, str):
        raise ContractError("matcher contract lacks static_library_relpath")
    archive = resolve_below(resolved_prefix, archive_relative, label="PCRE2 static library")
    if not archive.is_file():
        raise ContractError("PCRE2 producer prefix is missing the contracted static archive")
    expected_candidates = {path.as_posix() for path in static_library_candidates(target)}
    if archive_relative not in expected_candidates:
        raise ContractError("matcher contract static library is not valid for its target")
    if requested_library is not None and requested_library.resolve() != archive:
        raise ContractError("CMake selected a PCRE2 library other than the contracted static archive")
    if not has_static_archive_magic(archive):
        raise ContractError("contracted PCRE2 library is not a static archive")
    if pcre2.get("static_library_machine") != require_target_archive_machine(archive, target):
        raise ContractError("contracted PCRE2 static archive target machine mismatch")
    reject_shared_pcre2(resolved_prefix)
    if require_hash(pcre2.get("header_sha256"), label="pcre2.header_sha256") != sha256_file(header):
        raise ContractError("contracted PCRE2 header hash mismatch")
    if require_hash(pcre2.get("static_library_sha256"), label="pcre2.static_library_sha256") != sha256_file(archive):
        raise ContractError("contracted PCRE2 static archive hash mismatch")
    header_version = pcre2_header_version(header)
    if pcre2.get("version") != header_version:
        raise ContractError("contracted PCRE2 version does not match its header")
    pkg_relative = pcre2.get("pkgconfig_relpath")
    pkg_hash = pcre2.get("pkgconfig_sha256")
    if target.startswith("linux/") and (not isinstance(pkg_relative, str) or not isinstance(pkg_hash, str)):
        raise ContractError("Linux matcher contract lacks static pkg-config provenance")
    if pkg_relative is None:
        if pkg_hash is not None:
            raise ContractError("matcher contract has a pkg-config hash without a pkg-config path")
    else:
        if not isinstance(pkg_relative, str) or not isinstance(pkg_hash, str):
            raise ContractError("matcher contract pkg-config provenance is malformed")
        pkgconfig = resolve_below(resolved_prefix, pkg_relative, label="PCRE2 pkg-config metadata")
        if not pkgconfig.is_file() or require_hash(pkg_hash, label="pcre2.pkgconfig_sha256") != sha256_file(pkgconfig):
            raise ContractError("contracted PCRE2 pkg-config hash mismatch")
        if pkgconfig_version(pkgconfig) != header_version:
            raise ContractError("contracted PCRE2 pkg-config version does not match its header")

    expected_matcher = matcher_contract_from_header(AGENT_ROOT / MATCHER_SOURCE_PATHS[1])
    for key, value in expected_matcher.items():
        if matcher.get(key) != value:
            raise ContractError(f"matcher contract {key} does not match the compiled Agent matcher")
    source_hashes = matcher.get("sources_sha256")
    if not isinstance(source_hashes, dict) or set(source_hashes) != {str(path) for path in MATCHER_SOURCE_PATHS}:
        raise ContractError("matcher contract source set is incomplete or ambiguous")
    for relative in MATCHER_SOURCE_PATHS:
        key = str(relative)
        if require_hash(source_hashes.get(key), label=f"agent_matcher.sources_sha256[{key}]") != sha256_file(AGENT_ROOT / relative):
            raise ContractError(f"matcher contract source hash mismatch for {key}")
    return archive


def write_contract(path: Path, contract: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(contract, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def emit_result(*, mode: str, contract_path: Path, prefix: Path,
                target: str, library: Path | None = None) -> None:
    """Emit the sole successful producer output consumed by CMake.

    The producer deliberately has no human-readable success line.  CMake
    consumes this typed result instead of treating an archive pathname printed
    on stdout as a trust assertion.  The paths remain audit metadata only:
    the production CMake gate independently constrains every one below its
    fresh build-owned producer root and immediately verifies the contract.
    """
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "mode": mode,
        "contract_path": str(contract_path.resolve()),
        "prefix": str(prefix.resolve()),
        "target": target,
        "contract_sha256": sha256_file(contract_path),
    }
    if library is not None:
        result["library"] = str(library.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vcpkg-root", type=Path,
                        help="clean locked vcpkg checkout required for a source build or contract verification")
    parser.add_argument("--producer-root", type=Path,
                        help="empty root for isolated buildtrees, packages, installed, and downloads")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--target", choices=sorted(TARGET_TRIPLETS), required=True)
    parser.add_argument("--cc", help="target C compiler used by vcpkg for this release target")
    parser.add_argument("--verify-contract", type=Path,
                        help="verify a previously generated contract against a producer prefix")
    parser.add_argument("--prefix", type=Path,
                        help="producer prefix used only with --verify-contract")
    parser.add_argument("--library", type=Path,
                        help="CMake-selected static archive to compare with the contract")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    resolved_vcpkg_root: Path | None = None
    temporary_root: Path | None = None
    try:
        if args.verify_contract:
            if not args.prefix or not args.vcpkg_root:
                raise ContractError("--verify-contract requires --prefix and --vcpkg-root")
            if args.producer_root or args.output or args.cc:
                raise ContractError("--verify-contract cannot be combined with producer build arguments")
            baseline, _ = load_authority()
            resolved_vcpkg_root, temporary_root = resolve_source_vcpkg_root(args.vcpkg_root, baseline)
            library = verify_contract(
                args.verify_contract, args.prefix, args.target, args.library,
                vcpkg_root=resolved_vcpkg_root,
            )
            emit_result(
                mode="verify",
                contract_path=args.verify_contract,
                prefix=args.prefix,
                target=args.target,
                library=library,
            )
            return 0
        if not args.vcpkg_root or not args.producer_root or not args.output:
            raise ContractError("producer build requires --vcpkg-root, --producer-root, and --output")
        baseline, _ = load_authority()
        resolved_vcpkg_root, temporary_root = resolve_source_vcpkg_root(args.vcpkg_root, baseline)
        origin = verify_clean_pinned_vcpkg(resolved_vcpkg_root, baseline)
        triplet = TARGET_TRIPLETS[args.target]
        portfile = resolved_vcpkg_root / PORTFILE_RELATIVE
        # Parse every source and patch before spending time in vcpkg.  The
        # same authority is parsed again after the build below, after the
        # checkout has been re-checked for modifications.
        port_source_authority(portfile)
        prefix = build_static_pcre2(resolved_vcpkg_root, args.producer_root.resolve(), triplet, args.cc)
        if verify_clean_pinned_vcpkg(resolved_vcpkg_root, baseline).rstrip("/").lower() != origin.rstrip("/").lower():
            raise ContractError("pinned vcpkg checkout changed while building PCRE2")
        contract = contract_for(prefix, baseline=baseline, origin=origin, triplet=triplet,
                                portfile=portfile, target=args.target)
        write_contract(args.output.resolve(), contract)
    except ContractError as exc:
        print(f"PCRE2 matcher contract producer: {exc}", file=sys.stderr)
        return 1
    finally:
        if temporary_root is not None:
            shutil.rmtree(temporary_root, ignore_errors=True)
    emit_result(
        mode="build",
        contract_path=args.output,
        prefix=prefix,
        target=args.target,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
