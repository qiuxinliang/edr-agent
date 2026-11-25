from contextlib import closing
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from owner_range_handoff import (
    INSERT, PROJECTION_SQL, REFERENCE_ROWS, connect, pack_fixture, restore, version,
)


def create_standard(path):
    with closing(sqlite3.connect(path, isolation_level=None)) as db:
        db.executescript("""
            PRAGMA page_size=512;
            PRAGMA auto_vacuum=INCREMENTAL;
            PRAGMA journal_mode=WAL;
            PRAGMA application_id=751;
            PRAGMA user_version=1;
            CREATE TABLE p0_candidates (candidate_id TEXT PRIMARY KEY, endpoint_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL, local_retention_state TEXT NOT NULL, until_ms INTEGER NOT NULL);
            CREATE TABLE context_retirement_progress (candidate_id TEXT PRIMARY KEY);
            CREATE TABLE context_candidates (id INTEGER PRIMARY KEY,
                candidate_id TEXT NOT NULL UNIQUE, candidate_id_json TEXT NOT NULL);
            CREATE TABLE context_facts (fact_id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL, tenant_id TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE context_fact_keys (id INTEGER PRIMARY KEY,
                fact_id TEXT NOT NULL UNIQUE REFERENCES context_facts(fact_id));
            CREATE TABLE compact_context_refs (id INTEGER PRIMARY KEY,
                candidate_key INTEGER NOT NULL REFERENCES context_candidates(id),
                fact_key INTEGER NOT NULL REFERENCES context_fact_keys(id), source_identity BLOB,
                artifact_override TEXT UNIQUE, candidate_json_override TEXT,
                created_ns INTEGER, upload_status TEXT, minio_key TEXT,
                UNIQUE(candidate_key,source_identity),UNIQUE(candidate_key,fact_key));
            CREATE INDEX candidate_time ON compact_context_refs(candidate_key,created_ns);
            CREATE INDEX fact_refs ON compact_context_refs(fact_key);
            CREATE INDEX ref_time ON compact_context_refs(created_ns);
            CREATE VIEW context_reference_projection AS
                SELECT COALESCE(r.artifact_override,c.candidate_id||':post_context:'||lower(hex(r.source_identity))) AS artifact_id,
                    c.candidate_id, f.fact_id, COALESCE(r.candidate_json_override,c.candidate_id_json) AS candidate_id_json,
                    r.created_ns, r.upload_status, r.minio_key
                FROM compact_context_refs r
                JOIN context_candidates c ON c.id=r.candidate_key
                JOIN context_fact_keys f ON f.id=r.fact_key;
            CREATE TABLE artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL);
            INSERT INTO artifacts(body) VALUES('first'),('removed'),('last');
            DELETE FROM artifacts WHERE id=2;
            CREATE TABLE range_synthetic_marker (id INTEGER PRIMARY KEY);
            INSERT INTO range_synthetic_marker VALUES(751);
            INSERT INTO context_facts VALUES('shared','endpoint','tenant','shared body'),
                ('independent','endpoint','tenant','independent body');
            INSERT INTO context_fact_keys VALUES(1,'shared'),(2,'independent');
            CREATE TRIGGER guard BEFORE INSERT ON compact_context_refs
            WHEN EXISTS(SELECT 1 FROM context_retirement_progress q
                JOIN context_candidates c ON c.candidate_id=q.candidate_id WHERE c.id=NEW.candidate_key)
            BEGIN SELECT RAISE(ABORT,'candidate retirement in progress'); END;
            BEGIN IMMEDIATE;
        """)
        for owner in range(1, 129):
            candidate_id = f"owner-{owner}"
            db.execute("INSERT INTO p0_candidates VALUES(?, 'endpoint','tenant','retained',?)",
                       (candidate_id, 40000 + owner))
            db.execute("INSERT INTO context_candidates VALUES (?,?,?)",
                       (owner, candidate_id, json.dumps(candidate_id)))
            db.execute(INSERT, (owner, owner, 1, b"s"*32, None, None, 68, "local_manifest", ""))
        db.execute(INSERT, (500, 2, 2, None, "literal-id", '"owner-2"', 70, "pending", "key"))
        db.commit()


class OwnerRangeHandoffTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.standard = self.root / "standard.sqlite"
        self.packed = self.root / "packed.sqlite"
        create_standard(self.standard)

    def pack(self):
        return pack_fixture(self.standard, self.packed)

    def snapshot(self, path):
        with closing(connect(path, "rw")) as db:
            return (version(db),
                    db.execute(REFERENCE_ROWS).fetchall(),
                    db.execute(PROJECTION_SQL).fetchall(),
                    db.execute("SELECT rowid,* FROM p0_candidates ORDER BY rowid").fetchall(),
                    db.execute("SELECT rowid,* FROM artifacts ORDER BY rowid").fetchall(),
                    db.execute("SELECT * FROM sqlite_sequence ORDER BY rowid").fetchall())

    def test_restore_uses_packed_members_only(self):
        manifest = self.pack()
        pre = self.snapshot(self.standard)
        packed = self.snapshot(self.packed)
        self.assertEqual(packed[0], 6)
        self.assertEqual(len(packed[1]), 1)
        self.standard.unlink()
        self.assertEqual(restore(self.packed, manifest), 129)
        self.assertEqual(self.snapshot(self.packed), pre)
        with closing(connect(self.packed, "rw")) as db:
            self.assertEqual(db.execute("PRAGMA auto_vacuum").fetchone(), (2,))
            self.assertEqual(db.execute("PRAGMA application_id").fetchone(), (751,))
            self.assertEqual(db.execute("PRAGMA quick_check").fetchall(), [("ok",)])
            self.assertIsNone(db.execute(
                "SELECT 1 FROM sqlite_schema WHERE tbl_name='probe_owner_ranges'").fetchone())

    def test_exception_after_new_marker_and_process_exit_recover(self):
        manifest = self.pack()
        before = self.snapshot(self.packed)

        def interrupt():
            raise RuntimeError("interrupt before commit")

        with self.assertRaisesRegex(RuntimeError, "interrupt before commit"):
            restore(self.packed, manifest, _before_commit=interrupt)
        self.assertEqual(self.snapshot(self.packed), before)
        code = """
import json, os, sys
from pathlib import Path
from owner_range_handoff import Manifest, restore
restore(Path(sys.argv[1]), Manifest(**json.loads(sys.argv[2])), _before_commit=lambda: os._exit(71))
"""
        proc = subprocess.run([sys.executable, "-B", "-c", code, str(self.packed),
                               json.dumps(asdict(manifest))], cwd=Path(__file__).resolve().parent,
                              timeout=15, check=False)
        self.assertEqual(proc.returncode, 71)
        self.assertEqual(self.snapshot(self.packed), before)
        self.assertEqual(restore(self.packed, manifest), 129)

    def test_full_does_not_expose_a_partially_restored_store(self):
        manifest = self.pack()
        before = self.snapshot(self.packed)
        with closing(connect(self.packed, "rw")) as db:
            pages, = db.execute("PRAGMA page_count").fetchone()
        with self.assertRaisesRegex(ValueError, "insufficient disk budget"):
            restore(self.packed, manifest, max_db_bytes=1024)
        with self.assertRaises(sqlite3.OperationalError) as result:
            restore(self.packed, manifest, page_budget=pages)
        self.assertEqual(str(result.exception), "database or disk is full")
        self.assertEqual(self.snapshot(self.packed), before)
        self.assertEqual(restore(self.packed, manifest), 129)

    def test_committed_wal_is_used_and_unexpected_protected_rows_are_rejected(self):
        manifest = self.pack()
        with closing(connect(self.packed, "rw")) as writer:
            writer.execute("PRAGMA user_version=1")
            self.assertEqual(writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(), (0, 0, 0))
            with self.packed.open("rb") as main:
                main.seek(60)
                self.assertEqual(int.from_bytes(main.read(4), "big"), 1)
            writer.execute("PRAGMA user_version=6")
            writer.execute("UPDATE p0_candidates SET until_ms=99 WHERE candidate_id='owner-2'")
            with self.assertRaisesRegex(ValueError, "protected evidence differ"):
                restore(self.packed, manifest)
            self.assertEqual(version(writer), 6)
            self.assertEqual(writer.execute("SELECT until_ms FROM p0_candidates WHERE candidate_id='owner-2'")
                             .fetchone(), (99,))
            writer.execute("UPDATE p0_candidates SET until_ms=40002 WHERE candidate_id='owner-2'")
            self.assertGreater(Path(str(self.packed) + "-wal").stat().st_size, 0)
            self.assertEqual(restore(self.packed, manifest), 129)
            self.assertEqual(version(writer), 1)
            self.assertEqual(writer.execute("SELECT count(*) FROM compact_context_refs").fetchone(), (129,))

    def test_pending_retirement_or_other_versions_fail_closed(self):
        with closing(connect(self.standard, "rw")) as source:
            for unsupported in (0, 2, 3, 4, 5, 6):
                source.execute(f"PRAGMA user_version={unsupported}")
                with self.assertRaisesRegex(ValueError, "expected evidence cache format 1"):
                    self.pack()
                self.assertFalse(self.packed.exists())
            source.execute("PRAGMA user_version=1")
        manifest = self.pack()
        with closing(connect(self.packed, "rw")) as db:
            db.execute("INSERT INTO context_retirement_progress VALUES('owner-2')")
            with self.assertRaisesRegex(ValueError, "pending retirement"):
                restore(self.packed, manifest)
            self.assertEqual(version(db), 6)

    def test_rejects_range_mismatch_and_cross_tenant_ownership(self):
        with closing(connect(self.standard, "rw")) as source:
            source.execute("UPDATE context_facts SET tenant_id='different' WHERE fact_id='shared'")
        manifest = self.pack()
        packed = self.snapshot(self.packed)
        with self.assertRaisesRegex(ValueError, "invalid owner, fact or scope"):
            restore(self.packed, manifest)
        self.assertEqual(self.snapshot(self.packed), packed)
        with closing(connect(self.packed, "rw")) as db:
            db.execute("UPDATE probe_owner_ranges SET member_count=127")
        with self.assertRaisesRegex(ValueError, "packed references do not match"):
            restore(self.packed, manifest)
        self.assertEqual(self.snapshot(self.packed), packed)
        with closing(connect(self.packed, "rw")) as db:
            db.execute("PRAGMA ignore_check_constraints=ON")
            db.execute("UPDATE probe_owner_ranges SET member_count=1000000000")
        with self.assertRaisesRegex(ValueError, "invalid packed range member encoding"):
            restore(self.packed, manifest)

    def test_reject_preserves_committed_wal_with_last_writer_closed(self):
        manifest = self.pack()
        writer = connect(self.packed, "rw")
        with closing(connect(self.packed, "ro")) as reader:
            reader.execute("BEGIN")
            reader.execute("PRAGMA schema_version").fetchone()
            writer.execute("UPDATE p0_candidates SET until_ms=99 WHERE candidate_id='owner-2'")
            writer.close()
        wal = Path(str(self.packed) + "-wal")
        original = (self.packed.read_bytes(), wal.read_bytes())
        self.assertTrue(original[1])
        with self.assertRaisesRegex(ValueError, "protected evidence differ"):
            restore(self.packed, manifest)
        self.assertEqual((self.packed.read_bytes(), wal.read_bytes()), original)
        with closing(connect(self.packed, "ro")) as db:
            self.assertEqual(version(db), 6)
            self.assertEqual(db.execute("SELECT until_ms FROM p0_candidates WHERE candidate_id='owner-2'")
                             .fetchone(), (99,))


if __name__ == "__main__":
    unittest.main()
