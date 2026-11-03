"""Exercise the actual embedded SQLite snapshot owner; no Agent is involved."""
import hashlib
from contextlib import closing
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
OWNER = ROOT / 'tests/Invoke-LifecycleStorageCompatibility.ps1'


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='edr-storage-snapshot-')
        self.root = Path(self.temp.name)
        self.install = self.root / 'installed'
        self.install.mkdir()
        self.config = self.install / 'agent.toml'
        self.cache = self.install / 'cache.db'
        self.queue = self.install / 'queue.db'
        self.output = self.root / 'snapshot.db'
        self.source = re.search(r"function Get-LifecycleStoragePython \{\s+return @'\n(.*?)\n'@", OWNER.read_text(), re.S).group(1)
        self.body = ('[agent]\ntenant_id="ci-fixture"\nendpoint_id="ci-fixture-endpoint"\n'
                     '[offline]\nqueue_db_path='+json.dumps(str(self.queue))+'\n'
                     'evidence_cache_path='+json.dumps(str(self.cache))+'\nmax_queue_size_mb=512\n'
                     'retention_hours=72\nevidence_cache_max_size_mb=512\n'
                     'evidence_cache_retention_hours=72\nevidence_cache_selected_retention_hours=0\n')
        self.config.write_text(self.body)
        self.writer = sqlite3.connect(self.cache)
        self.writer.execute('PRAGMA journal_mode=WAL')
        self.writer.execute('PRAGMA wal_autocheckpoint=0')
        self.writer.execute('CREATE TABLE fixture(value TEXT)')
        self.writer.execute('INSERT INTO fixture VALUES (?)', ('committed WAL: 兼容',))
        self.writer.commit()
        with closing(sqlite3.connect(self.queue)) as queue:
            queue.execute('CREATE TABLE fixture(value TEXT)')
            queue.commit()

    def tearDown(self):
        self.writer.close()
        self.temp.cleanup()

    def run_owner(self, mode='backup', expected=None):
        args = [mode, str(self.config), str(self.install)]
        if mode == 'backup':
            args += [expected or hashlib.sha256(self.config.read_bytes()).hexdigest(), 'cache', str(self.output)]
        return subprocess.run([sys.executable, '-I', '-B', '-c', self.source, *args], capture_output=True, text=True, timeout=20)

    def test_committed_wal_snapshot_excludes_uncommitted_rows_and_preserves_source(self):
        self.writer.execute('INSERT INTO fixture VALUES (?)', ('uncommitted',))
        paths = (self.cache, Path(str(self.cache)+'-wal'))
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        result = self.run_owner()
        self.assertEqual(result.returncode, 0, result.stderr)
        proof = json.loads(result.stdout)
        self.assertTrue(proof['sqlite_backup'] and proof['source_readonly'])
        self.assertEqual(proof['sha256'], hashlib.sha256(self.output.read_bytes()).hexdigest())
        with closing(sqlite3.connect(self.output)) as copy:
            self.assertEqual(copy.execute('SELECT value FROM fixture').fetchall(), [('committed WAL: 兼容',)])
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
        self.writer.commit()
        with closing(sqlite3.connect(self.output)) as copy:
            self.assertEqual(copy.execute('SELECT count(*) FROM fixture').fetchone()[0], 1)

    def test_existing_destination_is_never_overwritten(self):
        self.output.write_bytes(b'preserve')
        self.assertNotEqual(self.run_owner().returncode, 0)
        self.assertEqual(self.output.read_bytes(), b'preserve')

    def test_config_hash_change_rejected_before_destination_creation(self):
        self.assertNotEqual(self.run_owner(expected='0'*64).returncode, 0)
        self.assertFalse(self.output.exists())

    def test_config_identity_and_original_policy_are_returned(self):
        result = self.run_owner('config')
        self.assertEqual(result.returncode, 0, result.stderr)
        binding = json.loads(result.stdout)
        self.assertEqual(binding['tenant_id'], 'ci-fixture')
        self.assertEqual(Path(binding['cache']['path']), self.cache.resolve())
        self.assertEqual(binding['cache']['selected_retention_hours'], 72)
        self.assertEqual(binding['queue']['max_mb'], 512)

    def test_database_outside_install_root_rejected(self):
        outside = self.root/'outside.db'
        outside.write_bytes(b'public outside path fixture')
        self.config.write_text(self.body.replace(json.dumps(str(self.cache)), json.dumps(str(outside))))
        self.assertNotEqual(self.run_owner('config').returncode, 0)
        self.assertFalse(self.output.exists())

    def test_invalid_policy_and_path_alias_are_rejected(self):
        for body in (self.body.replace('selected_retention_hours=0', 'selected_retention_hours=-1'),
                     self.body.replace('max_queue_size_mb=512', 'max_queue_size_mb="512"'),
                     self.body.replace(json.dumps(str(self.queue)), json.dumps(str(self.cache)))):
            self.config.write_text(body)
            self.assertNotEqual(self.run_owner('config').returncode, 0)

    def test_symlink_database_rejected(self):
        link = self.install/'linked.db'
        link.symlink_to(self.cache)
        self.config.write_text(self.body.replace(json.dumps(str(self.cache)), json.dumps(str(link))))
        # Configuration admission must retain lexical path validation, rather
        # than silently following an alias to a different storage owner.
        self.assertNotEqual(self.run_owner().returncode, 0)


if __name__ == '__main__':
    unittest.main()
