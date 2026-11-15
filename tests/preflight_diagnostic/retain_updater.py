"""Retain four fixed synthetic-CI updater diagnostics after the harness exits."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys

FILES = ("old-updater-report.json", "old-updater-journal.json",
         "old-updater.stdout.log", "old-updater.stderr.log")
FILE_LIMIT = 256 * 1024
MANIFEST_LIMIT = 8192
FLOOR = 2 * 1024**3
ALLOCATION_ALLOWANCE = 64 * 1024


def regular_metadata(path):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or getattr(value, "st_file_attributes", 0) & 1024:
        raise ValueError("source must be a regular file without reparse points")
    return value


def identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


def directories(path):
    result = []
    for parent in (path, *path.parents):
        value = parent.lstat()
        if not stat.S_ISDIR(value.st_mode) or getattr(value, "st_file_attributes", 0) & 1024:
            raise ValueError("diagnostic ancestor must be a directory without reparse points")
        result.append((value.st_dev, value.st_ino))
    return result


def source_bytes(path, original, offset):
    parents = directories(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if identity(os.fstat(stream.fileno())) != identity(original):
            raise ValueError("source identity changed before read")
        stream.seek(offset)
        raw = stream.read(FILE_LIMIT + 1)
        if len(raw) != original.st_size - offset or len(raw) > FILE_LIMIT:
            raise ValueError("source size changed during read")
        if identity(os.fstat(stream.fileno())) != identity(original):
            raise ValueError("source identity changed during read")
    if identity(regular_metadata(path)) != identity(original) or directories(path.parent) != parents:
        raise ValueError("source path changed during read")
    return raw


def save_bytes(target, raw):
    # An interrupted write stays visibly incomplete, never a truncated JSON file.
    partial = target.with_name(target.name + ".part")
    with partial.open("xb") as stream:
        if stream.write(raw) != len(raw):
            raise OSError("diagnostic write was incomplete")
        stream.flush()
        os.fsync(stream.fileno())
    if target.exists():
        raise FileExistsError("retained destination unexpectedly exists")
    partial.rename(target)


def failure(error, name, phase):
    # No exception text, configuration, environment dump or report body is emitted.
    return dict(file=name, phase=phase, type=type(error).__name__,
                errno=getattr(error, "errno", None), winerror=getattr(error, "winerror", None))


def retain(repo):
    os.umask(0o077)
    repo = Path(repo).absolute()
    source = repo / "setup-exe-evidence"
    parent = repo / "preflight-diagnostic-evidence"
    destination = parent / "updater"
    directories(repo)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("updater diagnostic destination already exists")
    if parent.exists():
        directories(parent)
    # Leave enough for an independent failure manifest even when copies cannot fit.
    if shutil.disk_usage(repo).free < FLOOR + MANIFEST_LIMIT + ALLOCATION_ALLOWANCE:
        raise OSError("original disk reserve cannot accommodate a retention manifest")
    parent.mkdir(mode=0o700, exist_ok=True)
    destination.mkdir(mode=0o700)
    report = dict(schema="edr.test.updater-retention.v1",
                  scope="retention only; identity/result not validated",
                  retention_status="collected", first_error=None, items=[])
    try:
        directories(destination)
        if shutil.disk_usage(destination).free < FLOOR + 4 * FILE_LIMIT + MANIFEST_LIMIT + ALLOCATION_ALLOWANCE:
            raise OSError("original disk reserve cannot accommodate the bounded retention peak")
        for name in FILES:
            item = dict(name=name, status="not_attempted")
            report["items"].append(item)
            phase = "source_metadata"
            try:
                try:
                    directories(source)
                    value = regular_metadata(source / name)
                except FileNotFoundError:
                    item["status"] = "missing"
                    continue
                item["source"] = dict(bytes=value.st_size, device=value.st_dev,
                                      file_id=value.st_ino, modified_ns=value.st_mtime_ns)
                item["original_sha256"] = None
                if name.endswith(".json") and value.st_size > FILE_LIMIT:
                    item["status"] = "omit_oversize"
                    continue
                offset = max(0, value.st_size - FILE_LIMIT)
                phase = "source_read"
                raw = source_bytes(source / name, value, offset)
                sha = hashlib.sha256(raw).hexdigest()
                if offset == 0:
                    item["original_sha256"] = sha
                phase = "destination_admission"
                if shutil.disk_usage(destination).free < FLOOR + len(raw) + MANIFEST_LIMIT + ALLOCATION_ALLOWANCE:
                    raise OSError("original disk reserve reached before retention")
                phase = "destination_write"
                save_bytes(destination / name, raw)
                item.update(status="retained_tail" if offset else "retained", truncated=bool(offset),
                            original_sha256=sha if offset == 0 else None,
                            retained=dict(bytes=len(raw), offset=offset, sha256=sha,
                                          hash_scope="retained tail" if offset else "entire original file"))
            except Exception as error:
                item["status"] = "error"
                item["error"] = failure(error, name, phase)
                if report["first_error"] is None:
                    report["first_error"] = item["error"]
                # Keep completed evidence and this first failure. No retries or later reads.
                break
    except Exception as error:
        report["first_error"] = failure(error, None, "retention_admission")
    completed = {item["name"] for item in report["items"]}
    report["items"].extend(dict(name=name, status="not_attempted") for name in FILES if name not in completed)
    if report["first_error"]:
        report["retention_status"] = "failed"
    elif any(item["status"] != "retained" for item in report["items"]):
        report["retention_status"] = "collected_with_gaps"
    encoded = (json.dumps(report, ensure_ascii=True, indent=2) + "\n").encode()
    if len(encoded) > MANIFEST_LIMIT:
        raise ValueError("retention manifest exceeds 8 KiB")
    if shutil.disk_usage(destination).free < FLOOR + len(encoded):
        raise OSError("original disk reserve reached before failure-manifest retention")
    save_bytes(destination / "manifest.json", encoded)
    return report


def main():
    if len(sys.argv) != 1:
        raise ValueError("retention CLI accepts no arbitrary path arguments")
    if sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true" or (
            os.environ.get("GITHUB_REPOSITORY") != "qiuxinliang/edr-agent"):
        raise ValueError("retention CLI requires the fixed Windows synthetic-CI repository")
    repo = Path(__file__).resolve().parents[2]
    report = retain(repo)
    print(json.dumps(dict(retention_status=report["retention_status"],
                         first_error=report["first_error"],
                         manifest="preflight-diagnostic-evidence/updater/manifest.json")))
    return int(report["first_error"] is not None)


if __name__ == "__main__":
    raise SystemExit(main())
