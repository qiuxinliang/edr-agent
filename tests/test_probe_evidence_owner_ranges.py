from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from probe_evidence_owner_ranges import check_decoded, checked_schema, compare, read_snapshot, write_ledger


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
                    candidate_json_override TEXT,created_ns,
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

    def test_range_ledger_has_its_own_format_even_when_all_rows_are_literal(self):
        self.fixture([self.row(1, 1)])
        output = self.root / "output"
        compare(self.closed, output)
        for name, expected in (("baseline.sqlite", 0), ("ranges.sqlite", 6)):
            with closing(read_snapshot(output / name)) as db:
                self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (expected,))

    def test_failed_write_rolls_back_layout_marker_and_first_range_together(self):
        self.fixture([self.row(1, 1), self.row(2, 2)])
        output = self.root / "range-failure.sqlite"
        outside = []

        def interrupt_after_first_range(rows):
            first = next(iter(rows))
            yield first, 2
            with closing(sqlite3.connect(output, timeout=0)) as observer:
                outside.append(observer.execute("PRAGMA user_version").fetchone())
                outside.append(observer.execute("SELECT name FROM sqlite_schema").fetchall())
            raise RuntimeError("injected interruption after first range")

        with closing(read_snapshot(self.closed)) as source:
            ddl = checked_schema(source)
            with patch("probe_evidence_owner_ranges.runs", side_effect=interrupt_after_first_range):
                with self.assertRaisesRegex(RuntimeError, "injected interruption"):
                    write_ledger(source, output, ddl, True)

        self.assertEqual(outside, [(0,), []])
        with closing(read_snapshot(output)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (0,))
            self.assertEqual(db.execute("SELECT name FROM sqlite_schema").fetchall(), [])

    def test_compare_rejects_packaged_or_untagged_range_input(self):
        self.fixture([self.row(1, 1)])
        with closing(sqlite3.connect(self.closed)) as db, db:
            db.execute("PRAGMA user_version=6")
        with self.assertRaisesRegex(ValueError, "unsupported source evidence cache format 6"):
            compare(self.closed, self.root / "versioned")
        with closing(sqlite3.connect(self.closed)) as db, db:
            db.execute("PRAGMA user_version=1")
            db.execute("CREATE TABLE probe_owner_ranges(first_ref_id INTEGER PRIMARY KEY)")
        with self.assertRaisesRegex(ValueError, "source contains an experimental owner-range layout"):
            compare(self.closed, self.root / "untagged")

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

    def test_storage_class_difference_is_a_mismatch(self):
        self.fixture([self.row(1, 1)])
        output = self.root / "output"
        compare(self.closed, output)
        with closing(sqlite3.connect(output / "ranges.sqlite")) as candidate, closing(
            sqlite3.connect(output / "baseline.sqlite")
        ) as baseline:
            candidate.execute("UPDATE compact_context_refs SET created_ns=cast(3 AS REAL)")
            self.assertEqual(candidate.execute(
                "SELECT typeof(created_ns) FROM compact_context_refs").fetchone(), ("real",))
            with self.assertRaisesRegex(ValueError, "reference mismatch"):
                check_decoded(baseline, baseline, candidate)

    def test_external_wal_commit_is_rejected_even_when_main_file_stays_identical(self):
        self.fixture([self.row(1, 1)])
        with closing(sqlite3.connect(self.closed)) as writer:
            self.assertEqual(writer.execute("PRAGMA journal_mode=wal").fetchone(), ("wal",))
            writer.execute("SELECT count(*) FROM compact_context_refs").fetchone()
            before = self.closed.read_bytes()

            def inject_commit(source, path, ddl, candidate):
                if candidate:
                    writer.execute("UPDATE compact_context_refs SET created_ns=4")
                    writer.commit()
                    self.assertEqual(self.closed.read_bytes(), before)
                write_ledger(source, path, ddl, candidate)

            with patch("probe_evidence_owner_ranges.write_ledger", side_effect=inject_commit):
                with self.assertRaisesRegex(ValueError, "nonempty WAL"):
                    compare(self.closed, self.root / "output")


if __name__ == "__main__":
    unittest.main()
