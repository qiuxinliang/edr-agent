#!/usr/bin/env python3
"""Compare exact reference ranges with the current compact SQLite ledger.

This probe opens a closed copy read-only. It creates two isolated reference
ledgers and does not upgrade an evidence database.
"""

import argparse
from contextlib import closing
from itertools import groupby, zip_longest
import json
from pathlib import Path
import shutil
import sqlite3
from tempfile import TemporaryDirectory


REFERENCE_COLUMNS = (
    "id", "candidate_key", "fact_key", "source_identity", "artifact_override",
    "candidate_json_override", "created_ns", "upload_status", "minio_key",
)
REFS = ",".join(REFERENCE_COLUMNS)
REFERENCE_ROWS = f"SELECT {REFS} FROM compact_context_refs ORDER BY id"
RANGE_SIZE = 256

RANGE_SCHEMA = """
CREATE TABLE probe_owner_ranges (
    first_ref_id INTEGER PRIMARY KEY,
    first_candidate_key INTEGER NOT NULL,
    member_count INTEGER NOT NULL CHECK (member_count BETWEEN 2 AND 256),
    fact_key INTEGER NOT NULL,
    source_identity BLOB NOT NULL CHECK (length(source_identity)=32),
    created_ns INTEGER NOT NULL
);
CREATE INDEX probe_owner_ranges_owner
    ON probe_owner_ranges(first_candidate_key,first_candidate_key+member_count-1);
CREATE INDEX probe_owner_ranges_fact ON probe_owner_ranges(fact_key);
CREATE INDEX probe_owner_ranges_time ON probe_owner_ranges(created_ns);
"""


def run_key(row):
    ref, owner, fact, source, artifact, owner_json, stamp, status, object_key = row
    if (type(source) is bytes and len(source) == 32 and artifact is None
            and owner_json is None and type(stamp) is int
            and status == "local_manifest" and object_key == ""):
        # The difference alone is insufficient. Adjacent rows must also have
        # consecutive physical IDs, which proves every candidate in the run.
        return ref - owner, fact, source, stamp
    return None


def runs(rows):
    for key, group in groupby(rows, key=run_key):
        previous = None
        first = None
        count = 0
        for row in group:
            if key is None:
                yield row, 1
                continue
            if count and (row[0] != previous + 1 or count == RANGE_SIZE):
                yield first, count
                count = 0
            if not count:
                first = row
            previous = row[0]
            count += 1
        if count:
            yield first, count


def decoded(db):
    # Order both arms by their original first rowid, preserving the precise
    # position of singleton and exceptional rows.
    for (*row, count) in db.execute(
        f"SELECT {REFS},1 FROM compact_context_refs "
        "UNION ALL SELECT first_ref_id,first_candidate_key,fact_key,"
        "source_identity,NULL,NULL,created_ns,'local_manifest','',member_count "
        "FROM probe_owner_ranges ORDER BY 1"
    ):
        for offset in range(count):
            yield (row[0] + offset, row[1] + offset, *row[2:])


def check_decoded(source, baseline, candidate):
    count = 0
    for expected, control, actual in zip_longest(
        source.execute(REFERENCE_ROWS), baseline.execute(REFERENCE_ROWS), decoded(candidate)
    ):
        if expected is None or not all(
            row is not None and len(row) == len(expected)
            and all(type(a) is type(b) and a == b for a, b in zip(expected, row))
            for row in (control, actual)
        ):
            # Never emit the source digest or an object key.
            raise ValueError(f"reference mismatch at ordered position {count + 1}")
        count += 1
    return count


def file_identity(path):
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def closed_identity(path):
    if Path(f"{path}-journal").exists():
        raise ValueError("copy still has a rollback journal")
    wal = Path(f"{path}-wal")
    if wal.exists() and wal.stat().st_size:
        raise ValueError("copy still has a nonempty WAL")
    return file_identity(path)


def read_snapshot(path, mode="ro"):
    db = sqlite3.connect(path.as_uri() + f"?mode={mode}", uri=True)
    db.execute("PRAGMA query_only=ON")
    db.execute("BEGIN")
    return db


def checked_schema(source):
    columns = tuple(row[1] for row in source.execute("PRAGMA table_info(compact_context_refs)"))
    if columns != REFERENCE_COLUMNS:
        raise ValueError("unsupported compact reference columns")
    ddl = source.execute(
        "SELECT sql FROM sqlite_schema WHERE tbl_name='compact_context_refs' AND sql IS NOT NULL "
        "AND type IN ('index','table') ORDER BY type='table' DESC,name"
    ).fetchall()
    if not ddl:
        raise ValueError("missing compact reference schema")
    if source.execute(
        "SELECT 1 FROM compact_context_refs r "
        "LEFT JOIN context_candidates c ON c.id=r.candidate_key "
        "LEFT JOIN context_fact_keys f ON f.id=r.fact_key "
        "LEFT JOIN context_facts a ON a.fact_id=f.fact_id "
        "WHERE c.id IS NULL OR a.fact_id IS NULL LIMIT 1"
    ).fetchone():
        raise ValueError("unresolved compact candidate or fact key")
    return tuple(row[0] for row in ddl)


def write_ledger(source, path, ddl, candidate):
    insert = "INSERT INTO compact_context_refs VALUES (?,?,?,?,?,?,?,?,?)"
    with closing(sqlite3.connect(path)) as db:
        page_size, = source.execute("PRAGMA page_size").fetchone()
        db.execute(f"PRAGMA page_size={page_size}")
        db.execute(ddl[0])
        with db:
            if candidate:
                db.executescript(RANGE_SCHEMA)
                for row, count in runs(source.execute(REFERENCE_ROWS)):
                    if count == 1:
                        db.execute(insert, row)
                    else:
                        db.execute("INSERT INTO probe_owner_ranges VALUES (?,?,?,?,?,?)",
                                   (*row[:2], count, row[2], row[3], row[6]))
            else:
                db.executemany(insert, source.execute(REFERENCE_ROWS))
            for statement in ddl[1:]:
                db.execute(statement)
        # Both shapes get the same deterministic compact-and-close treatment.
        db.execute("VACUUM")


def measure(path):
    stat = path.stat()
    return {"file_bytes": stat.st_size,
            "allocated_bytes": stat.st_blocks * 512 if hasattr(stat, "st_blocks") else None}


def compare(path, output):
    path = path.resolve(strict=True)
    after_close = closed_identity(path)
    output.mkdir(mode=0o700)
    baseline = output / "baseline.sqlite"
    candidate = output / "ranges.sqlite"
    with TemporaryDirectory(dir=output) as directory:
        # SQLite may create lock side files even on a read-only open of a WAL
        # database. Only let it create them for a private copy of the input.
        snapshot = Path(directory) / "closed.sqlite"
        shutil.copyfile(path, snapshot)
        if after_close != closed_identity(path):
            raise ValueError("source copy identity changed")
        with closing(read_snapshot(snapshot, "rw")) as source:
            ddl = checked_schema(source)
            write_ledger(source, baseline, ddl, False)
            write_ledger(source, candidate, ddl, True)
            with closing(read_snapshot(candidate)) as ranges, closing(read_snapshot(baseline)) as original:
                for ledger in (ranges, original):
                    if ledger.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                        raise ValueError("probe ledger failed SQLite integrity check")
                count = check_decoded(source, original, ranges)
                range_count, = ranges.execute("SELECT count(*) FROM probe_owner_ranges").fetchone()
                singleton_count, = ranges.execute("SELECT count(*) FROM compact_context_refs").fetchone()
    if after_close != closed_identity(path):
        raise ValueError("source copy identity changed")
    return {"references": count, "ranges": range_count, "singletons": singleton_count,
            "existing_ledger": measure(baseline), "range_ledger": measure(candidate)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("closed_copy", type=Path)
    parser.add_argument("new_output_directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(compare(args.closed_copy, args.new_output_directory), indent=2))


if __name__ == "__main__":
    main()
