import sqlite3
import tempfile
import unittest
from pathlib import Path

from probe_evidence_owner_ranges import compare


class ReferenceRangeProbeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.closed = self.root / "closed.sqlite"

    def fixture(self, rows):
        with sqlite3.connect(self.closed) as db:
            db.executescript("""
                CREATE TABLE context_candidates(id INTEGER PRIMARY KEY);
                CREATE TABLE context_facts(fact_id TEXT PRIMARY KEY);
                CREATE TABLE context_fact_keys(id INTEGER PRIMARY KEY,fact_id TEXT);
                CREATE TABLE compact_context_refs (
                    id INTEGER PRIMARY KEY,candidate_key INTEGER,fact_key INTEGER,
                    source_identity BLOB,artifact_override TEXT,
                    candidate_json_override TEXT,created_ns INTEGER,
                    upload_status TEXT,minio_key TEXT
                );
                CREATE UNIQUE INDEX compact_context_ref_source
                    ON compact_context_refs(candidate_key,source_identity);
            """)
            db.executemany("INSERT INTO context_candidates VALUES (?)",
                           ((key,) for key in {row[1] for row in rows}))
            db.execute("INSERT INTO context_facts VALUES ('test-fact')")
            db.execute("INSERT INTO context_fact_keys VALUES (1,'test-fact')")
            db.executemany("INSERT INTO compact_context_refs VALUES (?,?,?,?,?,?,?,?,?)", rows)

    @staticmethod
    def row(ref, owner, *, stamp=3, status="local_manifest", object_key="",
            source=b"s" * 32, artifact=None, owner_json=None):
        return ref, owner, 1, source, artifact, owner_json, stamp, status, object_key

    def test_gaps_and_exceptions_are_never_inferred(self):
        self.fixture([
            self.row(1, 100), self.row(2, 101),
            self.row(4, 103), self.row(5, 104, stamp=4), self.row(6, 105, stamp=4),
            self.row(7, 106, status="queued", object_key="test-object"),
            self.row(8, 107, object_key=None),
            self.row(9, 108, source=None, artifact="legacy-test", owner_json='""'),
            self.row(10, 109), self.row(11, 111),
        ])
        before = self.closed.read_bytes()
        result = compare(self.closed, self.root / "output")
        self.assertEqual((result["references"], result["ranges"], result["singletons"]),
                         (10, 2, 6))
        self.assertEqual(self.closed.read_bytes(), before)

    def test_range_length_is_bounded(self):
        self.fixture([self.row(i, i) for i in range(1, 259)])
        result = compare(self.closed, self.root / "output")
        self.assertEqual((result["references"], result["ranges"], result["singletons"]),
                         (258, 2, 0))

    def test_unresolved_owner_stops_projection(self):
        self.fixture([self.row(1, 1)])
        with sqlite3.connect(self.closed) as db:
            db.execute("DELETE FROM context_candidates")
        with self.assertRaisesRegex(ValueError, "unresolved compact candidate"):
            compare(self.closed, self.root / "output")
        self.assertFalse((self.root / "output" / "ranges.sqlite").exists())

    def test_nonempty_wal_cannot_be_ignored(self):
        self.fixture([self.row(1, 1)])
        Path(f"{self.closed}-wal").write_bytes(b"test side file")
        with self.assertRaisesRegex(ValueError, "nonempty WAL"):
            compare(self.closed, self.root / "output")
        self.assertFalse((self.root / "output" / "ranges.sqlite").exists())


if __name__ == "__main__":
    unittest.main()
