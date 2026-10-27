#!/usr/bin/env python3
"""Explicit, bounded local inventory. Never opens evidence, follows links or cleans.

Pass every configured storage root, including distinct temp/output volumes. This
is an observation of those roots, not an atomic filesystem snapshot, runtime
quota or reservation. No Agent/heartbeat caller invokes this script.
"""
import argparse
import collections
import json
import os
import stat
import time


def allocated_bytes(path, info):
    if hasattr(info, "st_blocks"):
        return info.st_blocks * 512
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.GetCompressedFileSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        api.GetCompressedFileSizeW.restype = wintypes.DWORD
        high = wintypes.DWORD()
        ctypes.set_last_error(0)
        low = api.GetCompressedFileSizeW(path, ctypes.byref(high))
        if low == 0xFFFFFFFF and ctypes.get_last_error():
            return None
        return (high.value << 32) | low
    return None


def category(path, is_directory):
    name = os.path.basename(path).lower()
    if is_directory:
        return "directory_metadata"
    if name.endswith("-wal"):
        return "wal"
    if name.endswith("-shm"):
        return "shm"
    if name.endswith((".db", ".sqlite", ".sqlite3")):
        return "database"
    if ".tmp" in name or name.endswith((".req", ".staging")):
        return "temporary"
    if name.endswith((".pending", ".pending.done", ".pending.failed", ".policy-held")):
        return "outbox_metadata"
    if name.endswith((".tgz", ".tar.gz", ".zip", ".dmp")):
        return "artifact"
    return "other"  # Included, never assumed free or safe to delete.


def inventory(roots, max_entries=100000, timeout_s=10, include_files=False):
    started = time.monotonic()
    result = dict(schema="edr.storage.inventory.v1", scope="explicit_roots",
                  atomic_snapshot=False, runtime_quota=False, cleanup_performed=False,
                  roots=[os.path.abspath(p) for p in roots], complete=True,
                  apparent_bytes=0, allocated_bytes=0, allocated_available=True,
                  entries=0, stat_calls=0, duplicate_objects=0, errors=[], categories={})
    seen = set()
    counts = collections.defaultdict(lambda: dict(objects=0, apparent_bytes=0, allocated_bytes=0))
    if include_files:
        result["files"] = []

    def error(reason, path):
        result["complete"] = False
        if len(result["errors"]) < 64:
            result["errors"].append(dict(reason=reason, path=path))

    # Iterators rather than list(scandir): memory and I/O stop at the budget.
    stack = [iter(result["roots"])]
    while stack:
        if result["entries"] >= max_entries or time.monotonic() - started >= timeout_s:
            error("entry_or_time_budget", "")
            break
        try:
            entry = next(stack[-1])
        except StopIteration:
            iterator = stack.pop()
            if hasattr(iterator, "close"):
                iterator.close()
            continue
        except OSError as exc:
            error("directory_read_" + str(exc.errno), "")
            stack.pop().close()
            continue
        path = entry.path if isinstance(entry, os.DirEntry) else entry
        result["entries"] += 1
        result["stat_calls"] += 1
        try:
            info = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            error("stat_" + str(exc.errno), path)
            continue
        identity = (info.st_dev, info.st_ino)
        if not info.st_ino:
            error("file_identity_unavailable", path)
        elif identity in seen:
            result["duplicate_objects"] += 1
            continue
        else:
            seen.add(identity)
        is_dir = stat.S_ISDIR(info.st_mode)
        is_link = stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)
        if is_link:
            error("link_or_reparse_not_followed", path)
        if not (is_dir or is_link or stat.S_ISREG(info.st_mode)):
            error("special_file_not_opened", path)
        kind = category(path, is_dir)
        # Windows path-based allocation APIs must never follow a reparse point.
        allocated = None if is_link and os.name == "nt" else allocated_bytes(path, info)
        if allocated is None:
            result["allocated_available"] = False
            error("allocation_unavailable", path)
        amount = max(info.st_size, 0)
        result["apparent_bytes"] += amount
        result["allocated_bytes"] += allocated or 0
        counts[kind]["objects"] += 1
        counts[kind]["apparent_bytes"] += amount
        counts[kind]["allocated_bytes"] += allocated or 0
        if include_files:
            result["files"].append(dict(path=path, category=kind, apparent_bytes=amount,
                                        allocated_bytes=allocated))
        if is_dir and not is_link:
            if len(stack) >= 65:
                error("depth_budget", path)
            else:
                try:
                    stack.append(os.scandir(path))
                except OSError as exc:
                    error("directory_open_" + str(exc.errno), path)
    for iterator in stack:
        if hasattr(iterator, "close"):
            iterator.close()
    result["categories"] = dict(counts)
    result["totals_are_lower_bounds"] = not result["complete"]
    result["elapsed_ms"] = (time.monotonic() - started) * 1000
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", required=True, help="Configured root; repeat for every volume/output/temp root")
    parser.add_argument("--max-entries", type=int, default=100000)
    parser.add_argument("--timeout-seconds", type=float, default=10)
    parser.add_argument("--files", action="store_true", help="Include local paths for reconciliation; never evidence contents")
    parser.add_argument("--output", help="New local JSON report; existing files are never replaced")
    args = parser.parse_args()
    if not 1 <= args.max_entries <= 1000000 or not 0 < args.timeout_seconds <= 60:
        parser.error("require 1..1000000 entries and a timeout in (0,60] seconds")
    report = inventory(args.root, args.max_entries, args.timeout_seconds, args.files)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with open(args.output, "x", encoding="utf-8") as output:
            output.write(encoded)
    else:
        print(encoded, end="")
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
