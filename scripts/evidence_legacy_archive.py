#!/usr/bin/env python3
"""On-demand inventory/archive of legacy local-source rows in a frozen queue copy.

No Agent caller, upload, schema change, policy upgrade, or cleanup. The input must
be an externally frozen, standalone copy (no SQLite sidecars), bound by SHA256.
That digest binds bytes, not endpoint identity or authority. Archives contain
sensitive original rows; only aggregates go to stdout. Failed outputs are kept
private and may be incomplete; file existence never establishes success. Use explicit ID ranges to split a large inventory. Inspect can finish when the
encoded archive would exceed its byte budget; archive_fits_byte_budget says so.
Verification/extraction require the external archive digest returned at creation.
An incomplete output is never a usable archive or permission to retire a source.
Source reads require Python 3.11+ SQLite length-limit support; older runtimes fail
before reading queue rows rather than allocate an unbounded row in Python.
"""
import argparse
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time

SCHEMA = "edr.legacy-local-archive.v1"
MAX_BYTES = 128 * 1024 * 1024  # Existing stopped-queue inventory budget.
MAX_ROW = 16 * 1024 * 1024
MAX_LINE = 24 * 1024 * 1024
MAX_ROWS = 100000
MAX_SOURCE = 512 * 1024 * 1024


class ArchiveError(Exception):
    pass


class Budget:
    def __init__(self, seconds=8, max_bytes=MAX_BYTES, max_rows=MAX_ROWS):
        self.until = time.monotonic() + seconds
        self.max_bytes, self.max_rows = max_bytes, max_rows

    def check(self):
        if time.monotonic() >= self.until:
            raise ArchiveError("deadline_exceeded")


def _identity(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def _windows_handle(path, directory=False, create_private=False):
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", wintypes.LPVOID), ("inherit", wintypes.BOOL)]
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                      ctypes.POINTER(SecurityAttributes), wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    attributes = None
    descriptor = wintypes.LPVOID()
    if create_private:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), wintypes.LPVOID]
        convert.restype = wintypes.BOOL
        if not convert("D:P(A;;FA;;;SY)(A;;FA;;;OW)", 1, ctypes.byref(descriptor), None):
            raise ArchiveError("private_output_acl_failed")
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
    try:
        # Parent handles deny DELETE sharing throughout all stages. Frozen
        # source handles additionally deny WRITE; output handles share nothing.
        handle = create(str(path), 0x80 if directory else (0x40000000 if create_private else 0x80000000),
                        3 if directory else (0 if create_private else 1),
                        ctypes.byref(attributes) if attributes else None,
                        1 if create_private else 3, 0x00200000 | (0x02000000 if directory else 0x80), None)
    finally:
        if descriptor:
            kernel.LocalFree.argtypes = [wintypes.LPVOID]
            kernel.LocalFree(descriptor)
    if handle == wintypes.HANDLE(-1).value:
        raise ArchiveError("path_handle_open_failed")
    return handle


def _windows_info(handle):
    import ctypes
    from ctypes import wintypes
    class FileInfo(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME),
                    ("access", wintypes.FILETIME), ("write", wintypes.FILETIME),
                    ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                    ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                    ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInfo)]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    result = FileInfo()
    if not kernel.GetFileInformationByHandle(handle, ctypes.byref(result)):
        raise ArchiveError("path_handle_identity_unavailable")
    if result.attributes & 0x400:
        raise ArchiveError("link_or_reparse_rejected")
    return result


def _windows_close(handle):
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle(handle)


class PinnedPath:
    """Keep the entire parent chain alive; never reopen a POSIX leaf by path."""
    def __init__(self, value):
        self.path = Path(os.path.abspath(value))
        self.parents = []
        try:
            if os.name == "nt":
                for parent in reversed(self.path.parents):
                    handle = _windows_handle(parent, directory=True)
                    self.parents.append(handle)
                    info = _windows_info(handle)
                    if not info.attributes & 0x10:
                        raise ArchiveError("parent_directory_required")
            else:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                fd = os.open(self.path.anchor, flags)
                self.parents.append((fd, None, self.path.anchor, _identity(os.fstat(fd))))
                for name in self.path.parts[1:-1]:
                    parent_fd = self.parents[-1][0]
                    fd = os.open(name, flags, dir_fd=parent_fd)
                    self.parents.append((fd, parent_fd, name, _identity(os.fstat(fd))))
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        if os.name == "nt":
            for handle in self.parents:
                if not _windows_info(handle).attributes & 0x10:
                    raise ArchiveError("parent_directory_changed")
        else:
            for fd, parent_fd, name, identity in self.parents:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if _identity(info) != identity or _identity(os.fstat(fd)) != identity:
                    raise ArchiveError("parent_directory_changed")

    def open(self, output=False):
        self.check()
        if os.name == "nt":
            import msvcrt
            handle = _windows_handle(self.path, create_private=output)
            try:
                if _windows_info(handle).attributes & 0x10:
                    raise ArchiveError("regular_file_required")
                fd = msvcrt.open_osfhandle(handle, (os.O_WRONLY if output else os.O_RDONLY) | os.O_BINARY)
            except BaseException:
                _windows_close(handle)
                raise
        else:
            parent_fd = self.parents[-1][0]
            parent = os.fstat(parent_fd)
            if output and (parent.st_uid != os.getuid() or parent.st_mode & 0o022):
                raise ArchiveError("output_parent_must_be_owned_and_not_group_or_world_writable")
            flags = os.O_NOFOLLOW | (os.O_WRONLY | os.O_CREAT | os.O_EXCL if output else os.O_RDONLY)
            fd = os.open(self.path.name, flags, 0o600, dir_fd=parent_fd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ArchiveError("regular_file_required")
        except BaseException:
            os.close(fd)
            raise
        bound = BoundFile(self, fd, output)
        try:
            bound.check()
            return bound
        except BaseException:
            bound.close()
            raise

    def free_bytes(self):
        self.check()
        if os.name != "nt":
            info = os.fstatvfs(self.parents[-1][0])
            return info.f_bavail * info.f_frsize
        return shutil.disk_usage(self.path.parent).free

    def sidecar_exists(self, suffix):
        self.check()
        try:
            if os.name == "nt":
                Path(str(self.path) + suffix).lstat()
            else:
                os.stat(self.path.name + suffix, dir_fd=self.parents[-1][0], follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def close(self):
        for item in reversed(self.parents):
            if os.name == "nt":
                _windows_close(item)
            else:
                os.close(item[0])
        self.parents = []


class BoundFile:
    def __init__(self, owner, fd, output):
        self.owner = owner
        self.identity = _identity(os.fstat(fd))
        self.stream = os.fdopen(fd, "wb" if output else "rb")

    @classmethod
    def open(cls, path, output=False, minimum_free=0):
        owner = PinnedPath(path)
        try:
            if minimum_free and owner.free_bytes() < minimum_free:
                raise ArchiveError("output_free_space_below_budget")
            return owner.open(output)
        except BaseException as exc:
            owner.close()
            if isinstance(exc, OSError) and exc.errno == errno.ELOOP:
                raise ArchiveError("link_or_reparse_rejected") from None
            raise

    def check(self):
        self.owner.check()
        if _identity(os.fstat(self.fileno())) != self.identity:
            raise ArchiveError("file_identity_changed")
        if os.name == "nt":
            import msvcrt
            _windows_info(msvcrt.get_osfhandle(self.fileno()))
            info = self.owner.path.stat()
        else:
            info = os.stat(self.owner.path.name, dir_fd=self.owner.parents[-1][0], follow_symlinks=False)
        if _identity(info) != self.identity:
            raise ArchiveError("file_identity_changed")

    def read(self, size):
        self.check()
        data = self.stream.read(size)
        self.check()
        return data

    def readline(self, size):
        self.check()
        data = self.stream.readline(size)
        self.check()
        return data

    def write(self, data):
        self.check()
        written = self.stream.write(data)
        self.check()
        return written

    def flush(self):
        self.check()
        self.stream.flush()
        self.check()

    def fileno(self):
        return self.stream.fileno()

    def close(self):
        try:
            self.stream.close()
        finally:
            self.owner.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def digest(source, budget, maximum):
    owned = not isinstance(source, BoundFile)
    source = BoundFile.open(source) if owned else source
    h, size = hashlib.sha256(), 0
    try:
        source.stream.seek(0)
        while True:
            budget.check()
            block = source.read(256 * 1024)
            if not block:
                break
            size += len(block)
            if size > maximum:
                raise ArchiveError("file_byte_budget_exceeded")
            h.update(block)
        source.stream.seek(0)
        return h.hexdigest()
    finally:
        if owned:
            source.close()


def check_digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ArchiveError("lowercase_sha256_required")


def private_output(value, minimum_free=0):
    return BoundFile.open(value, output=True, minimum_free=minimum_free)

def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"


def no_sidecars(source):
    if any(source.owner.sidecar_exists(suffix) for suffix in ("-wal", "-shm", "-journal")):
        raise ArchiveError("standalone_frozen_copy_required_sidecar_present")


def limit_sqlite_rows(connection):
    # Apply SQLite's own row/value limit before any source query. Checking a
    # fetched BLOB or extra metadata is too late: Python already owns its bytes.
    category = getattr(sqlite3, "SQLITE_LIMIT_LENGTH", None)
    if (category is None or not callable(getattr(connection, "setlimit", None)) or
            not callable(getattr(connection, "getlimit", None))):
        raise ArchiveError("sqlite_row_length_limit_unavailable_requires_python_3_11")
    connection.setlimit(category, MAX_LINE)
    if not 0 < connection.getlimit(category) <= MAX_LINE:
        raise ArchiveError("sqlite_row_length_limit_not_enforced")


def source_rows(source, expected, budget, after=0, through=9223372036854775807):
    check_digest(expected)
    with BoundFile.open(source) as bound:
        no_sidecars(bound)
        before = os.fstat(bound.fileno())
        if digest(bound, budget, MAX_SOURCE) != expected:
            raise ArchiveError("source_digest_mismatch")
        # macOS fdesc paths reopen this held descriptor directly. Some Unix
        # VFSes canonicalize /dev/fd to a mutable ordinary pathname: reject
        # those VFSes rather than silently losing the binding. Windows source
        # and parent handles deny replacement throughout sqlite's open/read.
        sqlite_path = bound.owner.path if os.name == "nt" else Path("/dev/fd") / str(bound.fileno())
        cn = sqlite3.connect(sqlite_path.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=0)
        try:
            limit_sqlite_rows(cn)
            if os.name != "nt":
                actual = cn.execute("PRAGMA database_list").fetchone()[2]
                if actual != str(sqlite_path):
                    raise ArchiveError("sqlite_descriptor_binding_unavailable")
                try:
                    alias_fd = os.open(sqlite_path, os.O_RDONLY | os.O_NOFOLLOW)
                except OSError:
                    raise ArchiveError("sqlite_descriptor_binding_unavailable") from None
                try:
                    alias_identity = _identity(os.fstat(alias_fd))
                finally:
                    os.close(alias_fd)
                if alias_identity != bound.identity:
                    raise ArchiveError("sqlite_descriptor_binding_unavailable")
            bound.check()
            cn.execute("PRAGMA query_only=ON")
            cn.set_progress_handler(lambda: int(time.monotonic() >= budget.until), 1000)
            columns = [row[1] for row in cn.execute("PRAGMA table_info(event_queue)")]
            if not {"id", "payload", "severity", "status", "terminal_reason"}.issubset(columns):
                raise ArchiveError("unsupported_queue_schema")
            policy = "retention_policy_version" if "retention_policy_version" in columns else "0"
            # LENGTH also bounds individual source values in SQLite. A SELECT
            # of an existing row can still return several individually small
            # values whose total exceeds that limit, so fail inside the same
            # SQLite step before its row is converted into Python objects.
            row_bytes = "+".join('COALESCE(length(CAST("' + name.replace('"', '""') + '" AS BLOB)),0)'
                                 for name in columns)
            query = "SELECT CASE WHEN " + row_bytes + ">? THEN zeroblob(?) ELSE NULL END,event_queue.* FROM event_queue WHERE id>? AND id<=? AND severity=2 AND status='local_evidence' AND terminal_reason='source_only_local_v3' AND " + policy + " IN(0,1) ORDER BY id LIMIT ?"
            yield {"kind": "header", "schema": SCHEMA, "source_db_sha256": expected,
                   "source_identity": "not_established", "policy_upgraded": False,
                   "scope": {"after_id": after, "through_id": through}, "columns": columns}
            for guarded in cn.execute(query, (MAX_LINE, MAX_LINE + 1, after, through, budget.max_rows + 1)):
                budget.check()
                bound.check()
                raw = guarded[1:]
                row = dict(zip(columns, raw))
                payload = row["payload"]
                if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_ROW:
                    raise ArchiveError("invalid_or_oversize_payload")
                values = {key: {"blob_base64": base64.b64encode(value).decode("ascii")}
                          if isinstance(value, bytes) else value for key, value in row.items()}
                record = {"kind": "row", "values": values, "payload_bytes": len(payload),
                          "payload_sha256": hashlib.sha256(payload).hexdigest()}
                if len(encoded(record)) > MAX_LINE:
                    raise ArchiveError("row_byte_budget_exceeded")
                yield record
            no_sidecars(bound)
            bound.check()
            after_stat = os.fstat(bound.fileno())
            if (before.st_size, before.st_mtime_ns) != (after_stat.st_size, after_stat.st_mtime_ns) or digest(bound, budget, MAX_SOURCE) != expected:
                raise ArchiveError("source_changed_during_read")
        except sqlite3.DataError as exc:
            if getattr(exc, "sqlite_errorcode", None) == getattr(sqlite3, "SQLITE_TOOBIG", 18):
                raise ArchiveError("source_sqlite_row_byte_budget_exceeded") from None
            raise
        finally:
            cn.close()


def archive(source, expected, output=None, budget=None, after=0, through=9223372036854775807):
    budget = budget or Budget()
    stream = None
    count = payload_bytes = written = 0
    first_id = last_id = None
    content_hash = hashlib.sha256()
    try:
        for record in source_rows(source, expected, budget, after, through):
            block = encoded(record)
            if record["kind"] == "header" and output is not None:
                stream = private_output(output, budget.max_bytes + 1024 * 1024)
            if record["kind"] == "row":
                count += 1
                payload_bytes += record["payload_bytes"]
                last_id = record["values"]["id"]
                if first_id is None:
                    first_id = last_id
            if count > budget.max_rows or payload_bytes > budget.max_bytes or (output is not None and written + len(block) + 1024 > budget.max_bytes):
                raise ArchiveError("archive_budget_exceeded_use_smaller_explicit_id_range")
            written += len(block)
            content_hash.update(block)
            if stream:
                stream.write(block)
        footer = {"kind": "complete", "rows": count, "payload_bytes": payload_bytes,
                  "content_sha256": content_hash.hexdigest()}
        block = encoded(footer)
        if stream:
            stream.write(block)
            stream.flush()
            os.fsync(stream.fileno())
        result = {"schema": SCHEMA, "complete": True, "rows": count, "payload_bytes": payload_bytes,
                  "archive_bytes": written + len(block), "archive_fits_byte_budget": written + len(block) <= budget.max_bytes,
                  "first_row_id": first_id, "last_row_id": last_id, "content_sha256": content_hash.hexdigest(),
                  "source_identity_established": False, "source_modified": False,
                  "retirement_authorized": False, "cleanup_performed": False}
        if stream:
            content_hash.update(block)
            result["archive_sha256"] = content_hash.hexdigest()
        return result
    finally:
        if stream:
            stream.close()


def verify(source, expected, budget=None, extract_id=None, output=None):
    budget = budget or Budget()
    check_digest(expected)
    with BoundFile.open(source) as bound:
        return _verify_bound(bound, expected, budget, extract_id, output)


def _verify_bound(bound, expected, budget, extract_id, output):
    if digest(bound, budget, budget.max_bytes) != expected:
        raise ArchiveError("archive_digest_mismatch")
    h, whole = hashlib.sha256(), hashlib.sha256()
    count = total = 0
    header = footer = None
    last_id = 0
    selected = None
    stream = bound
    while True:
        budget.check()
        block = stream.readline(MAX_LINE + 1)
        if not block:
            break
        if len(block) > MAX_LINE or not block.endswith(b"\n"):
            raise ArchiveError("invalid_or_oversize_archive_line")
        whole.update(block)
        record = json.loads(block)
        if header is None:
            if record.get("kind") != "header" or record.get("schema") != SCHEMA:
                raise ArchiveError("unsupported_archive_schema")
            header = record
        elif record.get("kind") == "row" and footer is None:
            values = record["values"]
            payload = base64.b64decode(values["payload"]["blob_base64"], validate=True)
            row_id = values["id"]
            if (type(row_id) is not int or row_id <= last_id or
                    not 0 < len(payload) <= MAX_ROW or record["payload_bytes"] != len(payload) or
                    record["payload_sha256"] != hashlib.sha256(payload).hexdigest() or
                    set(values) != set(header["columns"]) or values["severity"] != 2 or
                    values["status"] != "local_evidence" or values["terminal_reason"] != "source_only_local_v3" or
                    values.get("retention_policy_version", 0) not in (0, 1) or
                    not header["scope"]["after_id"] < row_id <= header["scope"]["through_id"]):
                raise ArchiveError("archive_row_integrity_failed")
            count += 1
            total += len(payload)
            last_id = row_id
            if count > budget.max_rows:
                raise ArchiveError("archive_row_budget_exceeded")
            if extract_id == row_id:
                selected = (payload, values.get("compressed"), record["payload_sha256"])
        elif record.get("kind") == "complete" and footer is None:
            footer = record
            if record != {"kind": "complete", "rows": count, "payload_bytes": total, "content_sha256": h.hexdigest()}:
                raise ArchiveError("archive_footer_integrity_failed")
            continue
        else:
            raise ArchiveError("archive_record_order_invalid")
        if footer is not None:
            raise ArchiveError("archive_has_trailing_records")
        h.update(block)
    if footer is None or whole.hexdigest() != expected:
        raise ArchiveError("archive_incomplete_or_changed")
    result = {"schema": SCHEMA, "complete": True, "rows": count, "payload_bytes": total,
              "archive_sha256": expected, "source_identity_established": False,
              "retirement_authorized": False, "cleanup_performed": False}
    if extract_id is not None:
        if selected is None:
            raise ArchiveError("row_not_in_archive")
        if output is None:
            raise ArchiveError("private_output_required")
        bound.check()
        with private_output(output, len(selected[0]) + 1024 * 1024) as target:
            target.write(selected[0]); target.flush(); os.fsync(target.fileno())
        result["extracted"] = {"row_id": extract_id, "payload_bytes": len(selected[0]),
                               "payload_sha256": selected[2], "compressed": selected[1],
                               "semantic_decoding": "not_performed"}
    return result


def perform(args):
    budget = Budget(args.timeout_seconds, args.max_bytes, args.max_rows)
    if args.operation in ("inspect", "archive"):
        return archive(args.source, args.sha256, args.output if args.operation == "archive" else None,
                       budget, args.after_id, args.through_id)
    return verify(args.source, args.sha256, budget, args.row_id if args.operation == "extract" else None, args.output)


def supervise(command, timeout_seconds):
    import tempfile
    # TemporaryFile is private and unnamed/delete-on-close. No child-created
    # evidence or diagnostic path is opened during timeout recovery.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(command, stdout=output, stderr=errors)
        try:
            process.wait(timeout=timeout_seconds + 1)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass  # A concurrent exit is resolved by the bounded wait.
            try:
                process.wait(timeout=1)
                reason = "hard_timeout_partial_output_may_remain"
            except subprocess.TimeoutExpired:
                reason = "writer_exit_unconfirmed_do_not_retry_or_reuse_output"
            print(json.dumps({"complete": False, "error": reason, "cleanup_performed": False}))
            return 1
        output.seek(0)
        result = output.read(65537)
        if len(result) > 65536 or (process.returncode and not result):
            print(json.dumps({"complete": False, "error": "worker_failed_partial_output_may_remain", "cleanup_performed": False}))
            return 1
        sys.stdout.buffer.write(result)
        return process.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inspect", "archive", "verify", "extract"))
    parser.add_argument("--source", required=True)
    parser.add_argument("--sha256", required=True, help="Trusted digest of frozen source copy or archive; does not establish event identity")
    parser.add_argument("--output", help="New private file; never stdout or an existing file")
    parser.add_argument("--after-id", type=int, default=0)
    parser.add_argument("--through-id", type=int, default=9223372036854775807)
    parser.add_argument("--row-id", type=int)
    parser.add_argument("--max-bytes", type=int, default=MAX_BYTES)
    parser.add_argument("--max-rows", type=int, default=MAX_ROWS)
    parser.add_argument("--timeout-seconds", type=float, default=8)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if (not 0 <= args.after_id < args.through_id <= 9223372036854775807 or
            not 0 < args.max_bytes <= MAX_BYTES or not 0 < args.max_rows <= MAX_ROWS or
            not 0 < args.timeout_seconds <= 60 or
            (args.operation in ("archive", "extract") and not args.output) or
            (args.operation == "extract" and (args.row_id is None or args.row_id <= 0)) or
            (args.operation in ("inspect", "verify") and args.output)):
        parser.error("invalid scope/budget or output; archive/extract require a new private file")
    if not args.worker:
        return supervise([sys.executable, __file__, *sys.argv[1:], "--worker"], args.timeout_seconds)
    try:
        print(json.dumps(perform(args), sort_keys=True))
        return 0
    except (ArchiveError, OSError, sqlite3.Error, ValueError, TypeError, KeyError) as exc:
        # Never expose row data, SQL, paths, or lower-level exception messages.
        reason = str(exc) if isinstance(exc, ArchiveError) else type(exc).__name__
        print(json.dumps({"complete": False, "error": reason, "partial_output_may_remain": True, "cleanup_performed": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
