"""Keep complete lifecycle diagnostics private when Actions storage is unavailable."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import zipfile

SOURCE = "qiuxinliang/edr-agent"
EVIDENCE_DIRS = ("setup-exe-evidence", "runtime-evidence")
MAX_BYTES = 1024 * 1024 * 1024
MAX_FILES = 20_000


def identity(run_id, attempt, commit, target_tag, architecture, repository=SOURCE):
    if repository != SOURCE:
        raise ValueError("Lifecycle evidence is restricted to the EDR source repository")
    if not all(re.fullmatch(r"[1-9][0-9]*", str(v)) for v in (run_id, attempt)):
        raise ValueError("Invalid lifecycle run identity")
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Invalid lifecycle source SHA")
    if not re.fullmatch(r"win_[0-9]+\.[0-9]+\.[0-9]+", target_tag):
        raise ValueError("Invalid lifecycle target tag")
    if architecture not in ("amd64", "arm64"):
        raise ValueError("Invalid lifecycle architecture")
    return dict(schema="edr.lifecycle-evidence.v1", repository=repository,
                run_id=str(run_id), attempt=str(attempt), commit=commit,
                target_tag=target_tag, architecture=architecture)


def regular_stat(path, directory=False):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise ValueError("Lifecycle evidence must not contain links or reparse points")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("Lifecycle evidence root is not a directory")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Lifecycle evidence must contain only regular, non-linked files")
    return info


def collect_files(workspace):
    workspace = Path(workspace).resolve(strict=True)
    files, missing, names, total = [], [], set(), 0
    for name in EVIDENCE_DIRS:
        root = workspace / name
        if not root.exists() and not root.is_symlink():
            missing.append(name)
            continue
        regular_stat(root, directory=True)
        directories = [root]
        while directories:
            directory = directories.pop()
            regular_stat(directory, directory=True)
            for path in sorted(directory.iterdir()):
                info = path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    regular_stat(path, directory=True)
                    directories.append(path)
                    continue
                info = regular_stat(path)
                if not path.resolve(strict=True).is_relative_to(workspace):
                    raise ValueError("Lifecycle evidence escaped the workspace")
                relative = path.relative_to(workspace).as_posix()
                if "\\" in relative or ":" in relative or relative.casefold() in names:
                    raise ValueError("Lifecycle evidence contains an unsafe or duplicate archive path")
                names.add(relative.casefold())
                total += info.st_size
                files.append((path, relative, info))
                if total > MAX_BYTES or len(files) > MAX_FILES:
                    raise ValueError("Lifecycle evidence exceeds the 1 GiB / 20000-file safety bound; no files were omitted")
    return sorted(files, key=lambda item: item[1]), missing


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def build_bundle(workspace, destination, owner, job_status):
    if job_status not in ("success", "failure", "cancelled"):
        raise ValueError("Invalid lifecycle job status")
    files, missing = collect_files(workspace)
    if job_status == "success" and (missing or not files):
        raise ValueError("Successful lifecycle job is missing required evidence directories")
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    name = f"windows-lifecycle-evidence-{owner['run_id']}-{owner['attempt']}-{owner['architecture']}"
    archive_path, receipt_path = destination / f"{name}.zip", destination / f"{name}.json"
    entries, actual_total = [], 0
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
        for path, relative, scanned in files:
            current = regular_stat(path)
            if (current.st_dev, current.st_ino) != (scanned.st_dev, scanned.st_ino):
                raise ValueError("Lifecycle evidence changed during collection")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            with os.fdopen(os.open(path, flags), "rb") as source:
                opened = os.fstat(source.fileno())
                if ((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                        != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)):
                    raise ValueError("Lifecycle evidence changed while opening")
                file_hash, size = hashlib.sha256(), 0
                with archive.open(relative, "w") as output:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        actual_total += len(chunk)
                        if actual_total > MAX_BYTES:
                            raise ValueError("Lifecycle evidence grew beyond its 1 GiB safety bound")
                        file_hash.update(chunk)
                        output.write(chunk)
                after = os.fstat(source.fileno())
                if (size != opened.st_size or after.st_mtime_ns != opened.st_mtime_ns
                        or after.st_size != opened.st_size):
                    raise ValueError("Lifecycle evidence changed while archiving")
                entries.append(dict(path=relative, size=size, sha256=file_hash.hexdigest()))
    receipt = dict(owner=owner, job_status=job_status, missing_directories=missing,
                   file_count=len(entries), uncompressed_bytes=actual_total, files=entries,
                   archive=dict(name=archive_path.name, size=archive_path.stat().st_size,
                                sha256=digest(archive_path)))
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return [archive_path, receipt_path], receipt


def publish_evidence(workspace, destination, owner, job_status, publisher):
    files, receipt = build_bundle(workspace, destination, owner, job_status)
    tag = f"edr-evidence-{owner['run_id']}-{owner['attempt']}-{owner['architecture']}"
    release = publisher(tag, owner, files, prerelease=False)
    print(f"Private lifecycle evidence retained: release_id={release['id']} "
          f"files={receipt['file_count']} sha256={receipt['archive']['sha256']}")
    return release, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-tag", required=True)
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--job-status", required=True, choices=("success", "failure", "cancelled"))
    parser.add_argument("--workspace", default=os.environ.get("GITHUB_WORKSPACE", "."))
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    if not os.environ.get("GH_TOKEN"):
        raise RuntimeError("Private lifecycle evidence needs USB_SIGNING_RELEASE_TOKEN with Contents write on the private signing repository")
    owner = identity(os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                     os.environ.get("GITHUB_SHA", ""), args.target_tag, args.arch,
                     os.environ.get("GITHUB_REPOSITORY", ""))
    from usb_release_transport import publish_files
    publish_evidence(args.workspace, args.output_dir, owner, args.job_status, publish_files)


if __name__ == "__main__":
    main()
