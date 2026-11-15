"""Retain four fixed synthetic-CI updater diagnostics after the harness exits."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

FILES = ("old-updater-report.json", "old-updater-journal.json",
         "old-updater.stdout.log", "old-updater.stderr.log")
FILE_LIMIT = 256 * 1024
SNAPSHOT_LIMIT = 4096
MANIFEST_LIMIT = 8192
FLOOR = 2 * 1024**3
ALLOCATION_ALLOWANCE = 64 * 1024
SNAPSHOT_ROOT = Path(r"C:\ProgramData\FDSecurity\logs")


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


def retained_json(path):
    value = regular_metadata(path)
    if value.st_size > FILE_LIMIT:
        raise ValueError("fixed JSON input exceeds its retention bound")
    def unique(pairs):
        if len({key for key, value in pairs}) != len(pairs):
            raise ValueError("duplicate JSON member")
        return dict(pairs)
    parsed = json.loads(source_bytes(path, value, 0).decode("utf-8-sig"), object_pairs_hook=unique)
    if not isinstance(parsed, dict):
        raise ValueError("fixed JSON input must be an object")
    return parsed


def retain_installer_snapshot(source, destination):
    unavailable = dict(status="installer_snapshot_unavailable", reason="binding_not_available")
    try:
        report = retained_json(destination / FILES[0])
        journal = retained_json(destination / FILES[1])
        summary = retained_json(source / "summary.json")
        events = [event for event in summary["events"] if event.get("stage") == "old-updater-upgrade"
                  and event.get("status") == "started"]
        cid = journal["command_id"]
        if not isinstance(cid, str) or not re.fullmatch(r"ci-old-updater-[0-9a-f]{32}", cid):
            return unavailable
        if journal["task_id"] != cid or len(events) != 1:
            return unavailable
        if not re.fullmatch(r"command_id=" + re.escape(cid) + r"(?:\s.*)?", events[0]["detail"]):
            return unavailable
        leaf = "agent-update-" + cid + "-" + cid + "-installer.log.redacted"
        expected = report["installer_log_sha256"]
        size = report["installer_log_size"]
        if (report.get("installer_log_status") != "ready" or
                ("installer_log_path" in report and report["installer_log_path"] != leaf) or
                journal["installer_log_file"] != leaf or type(size) is not int or not 0 <= size <= SNAPSHOT_LIMIT or
                journal["installer_log_size"] != size or type(journal["installer_log_size"]) is not int or
                not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or
                journal["installer_log_sha256"] != expected):
            return unavailable
        # No report-selected path is followed, and the unredacted log is never opened.
        path = SNAPSHOT_ROOT / leaf
        directories(SNAPSHOT_ROOT)
        metadata = regular_metadata(path)
        if metadata.st_size != size:
            return dict(status="installer_snapshot_unavailable", reason="snapshot_size_mismatch")
        raw = source_bytes(path, metadata, 0)
        if hashlib.sha256(raw).hexdigest() != expected:
            return dict(status="installer_snapshot_unavailable", reason="snapshot_digest_mismatch")
        if shutil.disk_usage(destination).free < FLOOR + size + MANIFEST_LIMIT + ALLOCATION_ALLOWANCE:
            raise OSError("original disk reserve reached before snapshot retention")
        save_bytes(destination / "installer.log.redacted", raw)
        return dict(status="retained", source_leaf=leaf, command_id=cid, bytes=size,
                    sha256=expected, source_file_id=metadata.st_ino,
                    report_leaf_present="installer_log_path" in report,
                    scope="hosted CI only; existing redacted snapshot bound to the unique started CI command")
    except FileNotFoundError:
        return dict(status="installer_snapshot_unavailable", reason="fixed_input_missing")
    except (ValueError, KeyError, TypeError, UnicodeError, AttributeError):
        return dict(status="installer_snapshot_unavailable", reason="binding_invalid")


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
        if shutil.disk_usage(destination).free < FLOOR + 4 * FILE_LIMIT + SNAPSHOT_LIMIT + MANIFEST_LIMIT + ALLOCATION_ALLOWANCE:
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
    report["installer_snapshot"] = dict(status="installer_snapshot_unavailable", reason="original_collection_incomplete")
    if report["first_error"] is None:
        try:
            report["installer_snapshot"] = retain_installer_snapshot(source, destination)
        except Exception as error:
            report["installer_snapshot"]["reason"] = "snapshot_collection_error"
            report["first_error"] = failure(error, "installer.log.redacted", "snapshot_retention")
    if report["first_error"]:
        report["retention_status"] = "failed"
    elif (any(item["status"] != "retained" for item in report["items"]) or
          report["installer_snapshot"]["status"] != "retained"):
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
