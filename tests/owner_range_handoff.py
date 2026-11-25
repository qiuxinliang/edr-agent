"""Open a packed synthetic window fixture and atomically restore its 751 layout.

The caller keeps a trusted receipt made from the standard synthetic source.
This experiment never derives the expected results from the packed image.
"""
from contextlib import closing, contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
from time import monotonic

from probe_evidence_owner_ranges import (
    PACKED_RANGE_USER_VERSION, RANGE_SCHEMA, RANGE_SIZE, REFERENCE_ROWS, decoded, runs,
)

STANDARD_FORMAT = 1
MAX_PAGES = 256
DB_BUDGET = 512 << 20
DISK_RESERVE = 2 << 30
# Includes WAL and SHM headers, sector padding and filesystem allocation rounding
# for the bounded synthetic database and all side files.
FILE_OVERHEAD = 256 << 10

SCHEMA_SQL = """SELECT type,name,tbl_name,sql FROM sqlite_schema
    WHERE sql IS NOT NULL AND substr(name,1,7)<>'sqlite_'
    ORDER BY type,name"""
PROJECTION_SQL = """SELECT artifact_id,candidate_id,fact_id,candidate_id_json,
    created_ns,upload_status,minio_key FROM context_reference_projection
    ORDER BY 1,2,3,4,5,6,7"""
INSERT = "INSERT INTO compact_context_refs VALUES(?,?,?,?,?,?,?,?,?)"


@dataclass(frozen=True)
class Manifest:
    standard_schema: str
    packed_schema: str
    protected_rows: str
    references: str
    projection: str
    count: int
    auto_vacuum: int
    encoding: str
    application_id: int


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def connect(path, mode):
    return sqlite3.connect(path.resolve().as_uri() + f"?mode={mode}", uri=True,
                           timeout=0, isolation_level=None)


def version(db):
    return db.execute("PRAGMA main.user_version").fetchone()[0]


def require_fixture(db, expected_version):
    # Marker belongs to the native witness, rather than a product database.
    if version(db) != expected_version:
        raise ValueError(f"expected evidence cache format {expected_version}")
    try:
        marker = db.execute("SELECT id FROM range_synthetic_marker").fetchall()
    except sqlite3.OperationalError as exc:
        raise ValueError("synthetic fixture marker missing") from exc
    if marker != [(751,)]:
        raise ValueError("invalid synthetic fixture marker")
    if db.execute("PRAGMA main.journal_mode").fetchone() != ("wal",):
        raise ValueError("the synthetic handoff requires WAL")
    if db.execute("SELECT 1 FROM context_retirement_progress LIMIT 1").fetchone():
        raise ValueError("pending retirement blocks evidence handoff")


def fingerprint(rows):
    digest = hashlib.sha256()
    count = 0
    for row in rows:
        # Encode the SQLite storage class as well as the value. A BLOB cannot
        # compare equal to the same bytes spelt as text.
        values = [(type(v).__name__, v.hex() if type(v) is bytes else v) for v in row]
        digest.update(json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode("ascii"))
        digest.update(b"\n")
        count += 1
    return digest.hexdigest(), count


def data_tables(objects):
    return [name for kind, name, _, _ in objects if kind == "table" and
            name not in ("compact_context_refs", "probe_owner_ranges")]


def protected_rows(db, tables):
    rows = [
        (name, *fingerprint(db.execute(f"SELECT rowid,* FROM {quote(name)} ORDER BY rowid")))
        for name in tables
    ]
    rows.append(("sqlite_sequence", *fingerprint(db.execute("SELECT * FROM sqlite_sequence ORDER BY name"))))
    return fingerprint(rows)[0]


def pack_fixture(standard: Path, packed: Path) -> Manifest:
    """Prepare one independent synthetic trial and return its trusted receipt."""
    with closing(connect(standard, "ro")) as source:
        source.execute("BEGIN")
        require_fixture(source, STANDARD_FORMAT)
        if source.execute("PRAGMA main.page_count").fetchone()[0] > MAX_PAGES:
            raise ValueError("standard fixture exceeds the synthetic page budget")
        objects = source.execute(SCHEMA_SQL).fetchall()
        if any(table == "probe_owner_ranges" for _, _, table, _ in objects):
            raise ValueError("packed fixture must start from the standard schema")
        tables = data_tables(objects)
        expect_protected = protected_rows(source, tables)
        expect_refs, count = fingerprint(source.execute(REFERENCE_ROWS))
        expect_projection, _ = fingerprint(source.execute(PROJECTION_SQL))
        auto_vacuum, = source.execute("PRAGMA main.auto_vacuum").fetchone()
        encoding, = source.execute("PRAGMA main.encoding").fetchone()
        application_id, = source.execute("PRAGMA main.application_id").fetchone()
        if encoding not in ("UTF-8", "UTF-16le", "UTF-16be"):
            raise ValueError("unsupported standard fixture encoding")
        with packed.open("xb"):
            pass
        with closing(connect(packed, "rw")) as dest:
            page_size, = source.execute("PRAGMA main.page_size").fetchone()
            dest.execute(f"PRAGMA main.page_size={page_size}")
            dest.execute(f"PRAGMA main.auto_vacuum={auto_vacuum}")
            dest.execute(f"PRAGMA main.encoding='{encoding}'")
            if dest.execute("PRAGMA main.journal_mode=WAL").fetchone() != ("wal",):
                raise ValueError("could not prepare synthetic WAL fixture")
            dest.execute("BEGIN IMMEDIATE")
            for kind, _, _, ddl in objects:
                if kind == "table":
                    dest.execute(ddl)
            for name in tables:
                table = quote(name)
                width = len(source.execute(f"PRAGMA table_info({table})").fetchall()) + 1
                params = ",".join("?" for _ in range(width))
                dest.executemany(f"INSERT INTO {table}(rowid,{columns(source, table)}) VALUES({params})",
                                 source.execute(f"SELECT rowid,* FROM {table} ORDER BY rowid"))
            dest.execute("DELETE FROM sqlite_sequence")
            dest.executemany("INSERT INTO sqlite_sequence VALUES (?,?)",
                             source.execute("SELECT * FROM sqlite_sequence ORDER BY rowid"))
            for kind, _, _, ddl in objects:
                if kind != "table":
                    dest.execute(ddl)
            # executescript would close the active transaction. RANGE_SCHEMA
            # contains table/index DDL only, with a semicolon after each statement.
            for statement in RANGE_SCHEMA.split(";"):
                if statement.strip():
                    dest.execute(statement)
            for row, count_in_run in runs(source.execute(REFERENCE_ROWS)):
                if count_in_run == 1:
                    dest.execute(INSERT, row)
                else:
                    dest.execute("INSERT INTO probe_owner_ranges VALUES (?,?,?,?,?,?)",
                                 (*row[:2], count_in_run, row[2], row[3], row[6]))
            if fingerprint(decoded(dest)) != (expect_refs, count):
                raise ValueError("packed fixture differs from the standard evidence")
            dest.execute(f"PRAGMA main.application_id={application_id}")
            dest.execute(f"PRAGMA main.user_version={PACKED_RANGE_USER_VERSION}")
            if version(dest) != PACKED_RANGE_USER_VERSION:
                raise ValueError("could not commit packed fixture format")
            packed_schema, _ = fingerprint(dest.execute(SCHEMA_SQL))
            dest.commit()
    return Manifest(fingerprint(objects)[0], packed_schema, expect_protected,
                    expect_refs, expect_projection, count, auto_vacuum, encoding, application_id)


def columns(db, table):
    return ",".join(quote(row[1]) for row in db.execute(f"PRAGMA table_info({table})"))


def enforce_budget(db, path, page_budget, max_db_bytes, reserve_bytes):
    page_size, = db.execute("PRAGMA main.page_size").fetchone()
    def side_size(suffix):
        try:
            return Path(str(path) + suffix).stat().st_size
        except FileNotFoundError:
            return 0

    if side_size("-journal"):
        raise ValueError("unexpected rollback journal blocks evidence handoff")
    main_bytes = max(path.stat().st_size, page_size * page_budget)
    wal_bytes = side_size("-wal")
    shm_bytes = side_size("-shm")
    # With cache spill and auto checkpoint disabled, bound the complete
    # address space plus the WAL written by this one transaction. Existing WAL
    # may stay pinned by a reader and is included independently.
    peak = main_bytes + wal_bytes + shm_bytes + (page_size + 24) * page_budget + FILE_OVERHEAD
    if page_budget < db.execute("PRAGMA main.page_count").fetchone()[0]:
        raise ValueError("evidence handoff exceeds the page budget")
    if peak > max_db_bytes or shutil.disk_usage(path.parent).free < reserve_bytes + peak:
        raise ValueError("insufficient disk budget to restore all compact references")
    if db.execute(f"PRAGMA main.max_page_count={page_budget}").fetchone() != (page_budget,):
        raise ValueError("could not impose the evidence handoff page budget")


@contextmanager
def without_implicit_checkpoint(path):
    if hasattr(sqlite3.Connection, "setconfig") and hasattr(sqlite3, "SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE"):
        with closing(connect(path, "rw")) as db:
            db.setconfig(sqlite3.SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, True)
            yield db
        return
    # Older Python does not expose NO_CKPT_ON_CLOSE. Start a read-only WAL
    # snapshot before opening the writer, and close it last. This avoids
    # checkpointing existing data even when an input check fails.
    with closing(connect(path, "ro")) as pin:
        pin.execute("BEGIN")
        pin.execute("PRAGMA main.schema_version").fetchone()
        with closing(connect(path, "rw")) as db:
            yield db


def require_bounded_ranges(db, expected_count):
    if db.execute("""SELECT 1 FROM probe_owner_ranges
            WHERE typeof(member_count)!='integer' OR member_count NOT BETWEEN 2 AND ?
               OR typeof(first_candidate_key)!='integer' OR typeof(fact_key)!='integer'
               OR typeof(source_identity)!='blob' OR length(source_identity)!=32
               OR typeof(created_ns)!='integer'
            LIMIT 1""", (RANGE_SIZE,)).fetchone():
        raise ValueError("invalid packed range member encoding")
    count, = db.execute("""SELECT (SELECT count(*) FROM compact_context_refs) +
        coalesce((SELECT sum(member_count) FROM probe_owner_ranges),0)""").fetchone()
    if count != expected_count:
        raise ValueError("packed references do not match the trusted count")


def restore(packed: Path, manifest: Manifest, *, page_budget=MAX_PAGES, max_db_bytes=DB_BUDGET,
            reserve_bytes=DISK_RESERVE, timeout_s=5, _before_commit=None) -> int:
    """Restore a verified synthetic fixture in place. Errors leave format 6."""
    if (type(page_budget) is not int or not 1 <= page_budget <= MAX_PAGES or
            not 0 < max_db_bytes <= DB_BUDGET or reserve_bytes < DISK_RESERVE or
            not 0 < timeout_s <= 150):
        raise ValueError("evidence handoff budget exceeds the supported test bounds")
    packed = packed.resolve(strict=True)
    deadline = monotonic() + timeout_s
    with without_implicit_checkpoint(packed) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA cache_spill=OFF")
        db.execute("PRAGMA wal_autocheckpoint=0")
        db.execute("PRAGMA temp_store=MEMORY")
        db.set_progress_handler(lambda: monotonic() >= deadline, 200)
        db.execute("BEGIN IMMEDIATE")
        try:
            require_fixture(db, PACKED_RANGE_USER_VERSION)
            enforce_budget(db, packed, page_budget, max_db_bytes, reserve_bytes)
            objects = db.execute(SCHEMA_SQL).fetchall()
            if db.execute("PRAGMA main.auto_vacuum").fetchone() != (manifest.auto_vacuum,):
                raise ValueError("packed cache auto-vacuum mode differs from the trusted receipt")
            if (db.execute("PRAGMA main.encoding").fetchone() != (manifest.encoding,) or
                    db.execute("PRAGMA main.application_id").fetchone() != (manifest.application_id,)):
                raise ValueError("packed cache metadata differs from the trusted receipt")
            if fingerprint(objects)[0] != manifest.packed_schema:
                raise ValueError("packed cache schema differs from the trusted receipt")
            tables = data_tables(objects)
            if protected_rows(db, tables) != manifest.protected_rows:
                raise ValueError("facts, candidate ownership or protected evidence differ from the receipt")
            require_bounded_ranges(db, manifest.count)
            existing = db.execute(REFERENCE_ROWS).fetchall()
            expanded = []
            for row in decoded(db):
                if len(expanded) == manifest.count:
                    raise ValueError("packed references exceed the trusted count")
                expanded.append(row)
            if fingerprint(expanded) != (manifest.references, manifest.count):
                raise ValueError("packed references do not match the trusted receipt")
            # All literal rows are already in compact_context_refs. Expand
            # only verified members whose rowids are absent.
            literal_ids = {row[0] for row in existing}
            db.executemany(INSERT, (row for row in expanded if row[0] not in literal_ids))
            if db.execute("""SELECT 1 FROM compact_context_refs r
                    LEFT JOIN context_candidates c ON c.id=r.candidate_key
                    LEFT JOIN p0_candidates p ON p.candidate_id=c.candidate_id
                    LEFT JOIN context_fact_keys k ON k.id=r.fact_key
                    LEFT JOIN context_facts f ON f.fact_id=k.fact_id
                    WHERE p.candidate_id IS NULL OR f.fact_id IS NULL
                       OR p.local_retention_state IS NOT 'retained'
                       OR p.endpoint_id IS NULL OR p.tenant_id IS NULL OR p.endpoint_id='' OR p.tenant_id=''
                       OR p.endpoint_id IS NOT f.endpoint_id OR p.tenant_id IS NOT f.tenant_id
                    LIMIT 1""").fetchone():
                raise ValueError("a compact reference has an invalid owner, fact or scope")
            db.execute("DROP TABLE probe_owner_ranges")
            if (fingerprint(db.execute(SCHEMA_SQL))[0] != manifest.standard_schema or
                    protected_rows(db, tables) != manifest.protected_rows or
                    fingerprint(db.execute(REFERENCE_ROWS)) != (manifest.references, manifest.count) or
                    fingerprint(db.execute(PROJECTION_SQL))[0] != manifest.projection or
                    db.execute("PRAGMA foreign_key_check").fetchone() or
                    db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]):
                raise ValueError("restored cache failed the standard layout or evidence checks")
            if monotonic() >= deadline:
                raise TimeoutError("evidence handoff exceeded its deadline")
            db.execute(f"PRAGMA main.user_version={STANDARD_FORMAT}")
            if _before_commit is not None:
                _before_commit()
            db.commit()
        except BaseException:
            db.set_progress_handler(None, 0)
            db.rollback()
            raise
    return manifest.count
