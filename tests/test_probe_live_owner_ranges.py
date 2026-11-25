"""Exercise the shadow writer exclusively in synthetic temporary databases."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from probe_evidence_owner_ranges import REFERENCE_ROWS
from probe_live_owner_ranges import assert_matches_writer, install, logical_rows

BASE_SCHEMA = """CREATE TABLE compact_context_refs (
 id INTEGER PRIMARY KEY, candidate_key INTEGER NOT NULL, fact_key INTEGER NOT NULL,
 source_identity BLOB, artifact_override TEXT UNIQUE, candidate_json_override TEXT,
 created_ns INTEGER, upload_status TEXT,minio_key TEXT,
 UNIQUE(candidate_key,fact_key), UNIQUE(candidate_key,source_identity))"""
INSERT = "INSERT INTO compact_context_refs VALUES(?,?,?,?,?,?,?,?,?)"


def standard(ref_id, owner, fact):
    return (ref_id, owner, fact, fact.to_bytes(32,"big"), None, None, 41, "local_manifest","")


class LiveRangeTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "synthetic.sqlite"
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(BASE_SCHEMA)
        install(self.db)

    def test_commit_boundaries_and_snapshot(self):
        reader = sqlite3.connect(self.path, isolation_level=None)
        self.addCleanup(reader.close)
        for arrival in range(1, 33):
            self.db.execute("BEGIN")
            for owner in range(1, arrival):
                self.db.execute(INSERT, standard((arrival-1)*(arrival-2)//2 + owner, owner, arrival))
            if arrival==20:
                reader.execute("BEGIN")
                original = list(logical_rows(reader))
            self.db.commit()
            assert_matches_writer(self.db)
        self.assertEqual(len(original), 171)
        self.assertEqual(list(logical_rows(reader)), original)
        reader.commit()
        assert_matches_writer(reader)
        self.assertEqual(len(list(logical_rows(reader))), 496)
        self.assertEqual(reader.execute("SELECT count(*) FROM probe_owner_ranges").fetchone(), (30,))
        self.assertEqual(reader.execute("SELECT count(*) FROM probe_literals").fetchone(), (1,))

    def test_independent_middle_rewrite_and_retire_with_rollback(self):
        self.db.executemany(INSERT,[standard(i,i,7) for i in range(1,8)])
        before=list(self.db.execute(REFERENCE_ROWS))
        self.db.execute("""CREATE TRIGGER fail_split BEFORE INSERT ON probe_owner_ranges
            WHEN NEW.first_ref_id=5 BEGIN SELECT RAISE(ABORT,'injected split failure'); END""")
        self.db.execute("BEGIN")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected split failure"):
            self.db.execute("UPDATE compact_context_refs SET fact_key=42 WHERE id=4")
        self.db.rollback()
        self.assertEqual(list(logical_rows(self.db)),before)
        self.db.execute("DROP TRIGGER fail_split")
        self.db.execute("UPDATE compact_context_refs SET fact_key=42,upload_status='queued',minio_key='test' WHERE id=4")
        assert_matches_writer(self.db)
        self.assertEqual(list(logical_rows(self.db))[3][2],42)
        self.db.execute("DELETE FROM compact_context_refs WHERE id=4")
        self.assertEqual(list(logical_rows(self.db)),before[:3]+before[4:])
        self.db.execute(INSERT,standard(4,72,9))
        assert_matches_writer(self.db)
        with sqlite3.connect(self.path) as reopened:
            self.assertEqual(list(logical_rows(reopened))[3][1],72)

    def test_exact_replay_does_not_split_or_rewrite(self):
        self.db.executemany(INSERT, [standard(i, i, 2) for i in range(1, 257)])
        self.db.execute("UPDATE compact_context_refs SET fact_key=fact_key WHERE id%3=0")
        self.assertEqual(self.db.execute("SELECT member_count FROM probe_owner_ranges").fetchall(), [(256,)])
        self.assertEqual(self.db.execute("SELECT count(*) FROM probe_literals").fetchone(), (0,))
        assert_matches_writer(self.db)

    def test_edges_holes_and_nonstandard_states(self):
        self.db.executemany(INSERT,[standard(i,i,2) for i in range(1,261)])
        self.assertEqual(self.db.execute("SELECT max(member_count) FROM probe_owner_ranges").fetchone(),(256,))
        for i in (1,2,256,258,260,5):
            self.db.execute("DELETE FROM compact_context_refs WHERE id=?",(i,))
            assert_matches_writer(self.db)
        for i in (1,2,5,256,258,260):
            self.db.execute(INSERT,(i,1000+i,3,None,f"literal-{i}",None,None,None,None))
        assert_matches_writer(self.db)


if __name__ == "__main__":
    unittest.main()
