"""Cross-ref vcpkg cache transport through create-only dependency Releases.

Only ABI-keyed binary packages and original downloads are transported, never
installed state or extracted tools. vcpkg still validates package ABI and
download hashes. Actions caches remain a fast, ref-scoped first tier.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile


ARCHIVE = "vcpkg-cache.zip"
MANIFEST = "vcpkg-cache.json"
SCHEMA = "edr.vcpkg-release-cache.v1"
ROOTS = {"bincache": "vcpkg-bincache", "downloads": "vcpkg-downloads"}
MAX_BYTES = 2 * 1024 ** 3


def validate_key(key):
    if not re.fullmatch(r"edr-vcpkg-v3-(x64|arm64)-windows-[0-9a-f]{64}", key):
        raise ValueError("Invalid toolchain-bound dependency cache key")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def member_parts(name):
    parts = PurePosixPath(name).parts
    if not parts or '/'.join(parts) != name or parts[0] not in ROOTS:
        raise ValueError("Unsafe dependency cache member")
    if parts[0] == "bincache":
        if (len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{64}\.zip", parts[2]) or
                parts[1] != parts[2][:2]):
            raise ValueError("Binary cache member must use the vcpkg ABI shard/filename")
    elif (len(parts) != 2 or
          not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~@-]{0,239}", parts[1]) or
          PureWindowsPath(parts[1]).is_reserved() or parts[1].endswith(".")):
        raise ValueError("Unsafe dependency cache member")
    return parts[0], '/'.join(parts[1:])


def pack_cache(workspace, directory, key):
    validate_key(key)
    archive = directory / ARCHIVE
    count = 0
    total = 0
    if (workspace / ".cache").is_symlink():
        raise ValueError("Cache root must not be a symlink")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as package:
        for kind, folder in ROOTS.items():
            root = workspace / ".cache" / folder
            if root.is_symlink():
                raise ValueError("Cache directory must not be a symlink")
            for path in sorted(root.glob("*/*.zip" if kind == "bincache" else "*")):
                if not path.is_file() or path.is_symlink() or path.name.endswith((".part", ".tmp", ".lock")):
                    continue
                if path.parent.is_symlink():
                    raise ValueError("Cache shard must not be a symlink")
                name = f"{kind}/{path.relative_to(root).as_posix()}"
                member_parts(name)
                total += path.stat().st_size
                if total > MAX_BYTES - 1024 * 1024:
                    raise ValueError("Dependency cache exceeds the Release asset size budget")
                package.write(path, name)
                count += kind == "bincache"
    if not count:
        raise ValueError("No completed ABI-keyed binary packages to publish")
    manifest = {"schema": SCHEMA, "key": key, "sha256": sha256(archive),
                "size": archive.stat().st_size}
    (directory / MANIFEST).write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return count


def restore_cache(workspace, directory, key):
    validate_key(key)
    manifest_path = directory / MANIFEST
    if manifest_path.stat().st_size > 4096:
        raise ValueError("Oversized cache manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    archive = directory / ARCHIVE
    if (manifest.get("schema") != SCHEMA or manifest.get("key") != key or
            archive.stat().st_size > MAX_BYTES or
            manifest.get("size") != archive.stat().st_size or
            manifest.get("sha256") != sha256(archive)):
        raise ValueError("Dependency cache identity, size or SHA-256 mismatch")
    with zipfile.ZipFile(archive) as package:
        seen = set()
        count = 0
        total = 0
        members = package.infolist()
        if len(members) > 10000:
            raise ValueError("Too many dependency cache members")
        # Validate ALL paths and limits before writing even one member.
        for member in members:
            kind, name = member_parts(member.filename)
            normalized = member.filename.casefold()
            total += member.file_size
            if (normalized in seen or member.is_dir() or
                    stat.S_ISLNK(member.external_attr >> 16) or
                    member.flag_bits & 1 or total > MAX_BYTES):
                raise ValueError("Invalid or oversized dependency cache member")
            seen.add(normalized)
            count += kind == "bincache"
        if not count:
            raise ValueError("Dependency cache contains no binary packages")
        with tempfile.TemporaryDirectory(prefix="vcpkg-verified-", dir=directory) as staging:
            # CRC failures must also be discovered before touching the cache.
            package.extractall(staging)
            cache = workspace / ".cache"
            if cache.is_symlink():
                raise ValueError("Cache root must not be a symlink")
            for kind, folder in ROOTS.items():
                target = cache / folder
                if target.is_symlink():
                    raise ValueError("Cache directory must not be a symlink")
            for member in members:
                kind, name = member_parts(member.filename)
                target = cache / ROOTS[kind]
                destination = target / name
                if destination.parent.is_symlink():
                    raise ValueError("Cache shard must not be a symlink")
            for member in members:
                kind, name = member_parts(member.filename)
                destination = cache / ROOTS[kind] / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                # RUNNER_TEMP may be on C: while GITHUB_WORKSPACE is on D:.
                # Copy to a sibling then rename, so publication is volume-safe.
                with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
                    temporary = Path(output.name)
                try:
                    shutil.copyfile(Path(staging) / kind / name, temporary)
                    os.replace(temporary, destination)
                finally:
                    temporary.unlink(missing_ok=True)
    return count


def gh(*args):
    # Never print the process environment or authentication material.
    return subprocess.run(["gh", *args], capture_output=True, text=True, timeout=300)


def release_info(repository, key):
    result = gh("release", "view", key, "--repo", repository, "--json", "isDraft,assets")
    if result.returncode == 0:
        return json.loads(result.stdout)
    if re.search(r"release not found|HTTP 404|Not Found \(HTTP 404\)", result.stderr, re.I):
        return None
    raise RuntimeError(f"Dependency Release lookup failed (gh exit {result.returncode}); check repository access/network")


def require_complete(info):
    names = {asset["name"] for asset in info.get("assets", [])}
    if info.get("isDraft") or not {ARCHIVE, MANIFEST}.issubset(names):
        raise RuntimeError("Dependency Release is incomplete/draft; refusing to overwrite or consume it")


def transport(mode, repository, workspace, key, target, actions_hit=False):
    validate_key(key)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Explicit owner/repository is required")
    if mode == "restore" and actions_hit:
        return "actions-cache"
    info = release_info(repository, key)
    if info:
        require_complete(info)
        if mode == "publish":
            return "already-published"
    elif mode == "restore":
        print("[vcpkg] No matching shared dependency Release; using ABI-checked local cache/source build")
        return "source-or-local-abi-cache"
    with tempfile.TemporaryDirectory(prefix="vcpkg-release-") as temporary:
        directory = Path(temporary)
        if mode == "restore":
            result = gh("release", "download", key, "--repo", repository, "--dir", str(directory),
                        "--pattern", ARCHIVE, "--pattern", MANIFEST)
            if result.returncode:
                raise RuntimeError(f"Dependency cache download failed (gh exit {result.returncode}); no installed state restored")
            count = restore_cache(workspace, directory, key)
            print(f"[vcpkg] Shared cache restored: {count} binary packages; vcpkg ABI validation remains mandatory")
            return "shared-release:" + key
        if not re.fullmatch(r"[0-9a-f]{40}", target):
            raise ValueError("Dependency Release publication requires the exact producer commit")
        count = pack_cache(workspace, directory, key)
        # No delete/edit/upload --clobber path: concurrent producers may only
        # accept an already completed release with the same toolchain-bound key.
        result = gh("release", "create", key, str(directory / ARCHIVE), str(directory / MANIFEST),
                    "--repo", repository, "--target", target, "--prerelease", "--latest=false",
                    "--title", "vcpkg dependency cache " + key,
                    "--notes", "Toolchain-bound binary packages and source/tool downloads; no installed state. ABI validation required.")
        info = release_info(repository, key)
        if not info:
            raise RuntimeError(f"Dependency cache publication failed (gh exit {result.returncode})")
        require_complete(info)
        print(f"[vcpkg] Shared dependency Release ready: {key}; local packages={count}")
        return "published"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("restore", "publish"))
    parser.add_argument("--key", required=True)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--target", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--actions-cache-hit", choices=("true", "false", ""), default="false")
    args = parser.parse_args()
    result = transport(args.mode, args.repository, args.workspace, args.key, args.target,
                       args.actions_cache_hit == "true")
    if args.mode == "restore" and os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
            output.write("VCPKG_SOURCE=" + result + "\n")
    print(f"[vcpkg] shared_cache_{args.mode}={result}")


if __name__ == "__main__":
    main()
