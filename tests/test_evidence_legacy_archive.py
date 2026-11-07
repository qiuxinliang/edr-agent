"""Frozen synthetic queue copies only; no production evidence or service access."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / 'scripts/evidence_legacy_archive.py'
spec = importlib.util.spec_from_file_location('legacy_archive', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SqliteLimitCapabilityTest(unittest.TestCase):
    def test_unavailable_sqlite_row_limit_fails_closed(self):
        with self.assertRaisesRegex(m.ArchiveError, 'sqlite_row_length_limit_unavailable_requires_python_3_11'):
            m.limit_sqlite_rows(object())
        if not hasattr(sqlite3.Connection, 'setlimit'):
            cn = sqlite3.connect(':memory:')
            try:
                with self.assertRaisesRegex(m.ArchiveError, 'sqlite_row_length_limit_unavailable_requires_python_3_11'):
                    m.limit_sqlite_rows(cn)
            finally:
                cn.close()


@unittest.skipUnless(hasattr(sqlite3.Connection, 'setlimit'),
                     'archive source reads require Python 3.11+ SQLite length-limit support')
class LegacyArchiveTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='edr-legacy-archive-', dir='/private/tmp' if sys.platform == 'darwin' else None)
        self.root = Path(self.temp.name)
        self.db = self.root / 'frozen.db'
        cn = sqlite3.connect(self.db)
        cn.execute('CREATE TABLE event_queue(id INTEGER PRIMARY KEY,batch_id TEXT,payload BLOB,created_at INTEGER,compressed INTEGER,severity INTEGER,status TEXT,terminal_reason TEXT,retention_policy_version INTEGER,extra_metadata TEXT)')
        # Only old local-only rows are archived, never pending or typed owners.
        for row_id, policy, status, reason in [(1, 0, 'local_evidence', 'source_only_local_v3'), (2, 1, 'local_evidence', 'source_only_local_v3'), (3, 2, 'local_evidence', 'source_only_local_v3'), (4, 0, 'pending', ''), (5, 0, 'policy_held', 'missing_proof')]:
            cn.execute('INSERT INTO event_queue VALUES(?,?,?,?,?,?,?,?,?,?)', (row_id, 'secret-id-'+str(row_id), bytes([row_id])+b'\x00private-evidence\xff', 12345, row_id % 2, 2, status, reason, policy, 'private-extra'))
        cn.commit(); cn.close()
        self.before = self.db.read_bytes()
        self.bound = sha(self.db)

    def tearDown(self):
        self.assertEqual(self.db.read_bytes(), self.before)
        self.temp.cleanup()

    def make_archive(self, name='archive.jsonl', **kwargs):
        path = self.root / name
        report = m.archive(str(self.db), self.bound, str(path), **kwargs)
        return path, report

    def test_lossless_archive_verify_extract_and_no_authority_inference(self):
        path, report = self.make_archive()
        self.assertEqual(report['rows'], 2)
        self.assertFalse(report['retirement_authorized'])
        self.assertFalse(report['source_identity_established'])
        self.assertEqual(report['archive_sha256'], sha(path))
        verified = m.verify(str(path), report['archive_sha256'])
        self.assertEqual(verified['rows'], 2)
        rows = [json.loads(x) for x in path.read_bytes().splitlines()]
        self.assertEqual(rows[1]['values']['extra_metadata'], 'private-extra')
        self.assertEqual(rows[1]['values']['retention_policy_version'], 0)
        raw = self.root / 'row.bin'
        extracted = m.verify(str(path), sha(path), extract_id=1, output=str(raw))
        self.assertEqual(raw.read_bytes(), b'\x01\x00private-evidence\xff')
        self.assertEqual(extracted['extracted']['compressed'], 1)
        self.assertEqual(extracted['extracted']['semantic_decoding'], 'not_performed')
        if os.name != 'nt':
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(raw.stat().st_mode & 0o777, 0o600)
        self.assertEqual(set(self.root.iterdir()), {self.db, path, raw})

    def test_inventory_no_output_and_explicit_range(self):
        report = m.archive(str(self.db), self.bound, after=1, through=2)
        self.assertEqual(report['rows'], 1)
        self.assertNotIn('archive_sha256', report)
        self.assertEqual(set(self.root.iterdir()), {self.db})
        path, report = self.make_archive(after=1, through=2)
        self.assertEqual(m.verify(str(path), sha(path))['rows'], 1)
        with self.assertRaisesRegex(m.ArchiveError, 'row_not_in_archive'):
            m.verify(str(path), sha(path), extract_id=1, output=str(self.root/'never.bin'))
        self.assertFalse((self.root/'never.bin').exists())

    def test_inspect_distinguishes_payload_budget_from_archive_encoding_budget(self):
        report = m.archive(str(self.db), self.bound, budget=m.Budget(max_bytes=1100))
        self.assertTrue(report['complete'])
        self.assertFalse(report['archive_fits_byte_budget'])
        self.assertEqual((report['first_row_id'], report['last_row_id']), (1, 2))
        self.assertEqual(set(self.root.iterdir()), {self.db})

    def test_old_schema_without_retention_metadata_stays_unchanged(self):
        old = self.root/'old.db'
        cn = sqlite3.connect(old)
        cn.execute('CREATE TABLE event_queue(id INTEGER PRIMARY KEY,payload BLOB,severity INTEGER,status TEXT,terminal_reason TEXT)')
        cn.execute("INSERT INTO event_queue VALUES(1,?,2,'local_evidence','source_only_local_v3')", (b'old',))
        cn.commit(); cn.close()
        before = old.read_bytes()
        path = self.root/'old.jsonl'
        report = m.archive(str(old), sha(old), str(path))
        self.assertEqual(report['rows'], 1)
        self.assertNotIn('retention_policy_version', json.loads(path.read_bytes().splitlines()[1])['values'])
        self.assertEqual(m.verify(str(path), sha(path))['rows'], 1)
        self.assertEqual(old.read_bytes(), before)

    def test_digest_sidecars_and_existing_output_fail_before_use(self):
        with self.assertRaisesRegex(m.ArchiveError, 'source_digest_mismatch'):
            m.archive(str(self.db), '0'*64, str(self.root/'no.jsonl'))
        self.assertFalse((self.root/'no.jsonl').exists())
        for suffix in ['-wal', '-shm', '-journal']:
            side = Path(str(self.db)+suffix);side.write_bytes(b'')
            with self.assertRaisesRegex(m.ArchiveError, 'sidecar_present'):
                m.archive(str(self.db), self.bound)
            side.unlink()
        path = self.root/'exists.jsonl';path.write_bytes(b'preserve')
        with self.assertRaises((FileExistsError, m.ArchiveError)):
            m.archive(str(self.db), self.bound, str(path))
        self.assertEqual(path.read_bytes(), b'preserve')

    def test_links_and_untrusted_output_parent_rejected(self):
        if os.name == 'nt':
            self.skipTest('symlink creation requires an independent Windows privilege fixture')
        link = self.root/'linked.db';link.symlink_to(self.db)
        with self.assertRaisesRegex(m.ArchiveError, 'link_or_reparse'):
            m.archive(str(link), self.bound)
        target = self.root/'target';target.write_bytes(b'preserve')
        output = self.root/'out.jsonl';output.symlink_to(target)
        with self.assertRaises((FileExistsError, m.ArchiveError)):
            m.archive(str(self.db), self.bound, str(output))
        self.assertEqual(target.read_bytes(), b'preserve')
        shared = self.root/'shared';shared.mkdir();shared.chmod(0o777)
        with self.assertRaisesRegex(m.ArchiveError, 'not_group_or_world_writable'):
            m.archive(str(self.db), self.bound, str(shared/'out'))

    def test_limit_failure_never_creates_complete_archive(self):
        output = self.root/'partial.jsonl'
        with self.assertRaisesRegex(m.ArchiveError, 'archive_budget_exceeded'):
            m.archive(str(self.db), self.bound, str(output), budget=m.Budget(max_rows=1))
        self.assertNotIn(b'"kind":"complete"', output.read_bytes())
        with self.assertRaisesRegex(m.ArchiveError, 'incomplete'):
            m.verify(str(output), sha(output))
        output2 = self.root/'byte-limit.jsonl'
        with self.assertRaisesRegex(m.ArchiveError, 'archive_budget_exceeded'):
            m.archive(str(self.db), self.bound, str(output2), budget=m.Budget(max_bytes=1100))
        self.assertNotIn(b'"kind":"complete"', output2.read_bytes())

    def test_sqlite_rejects_oversize_payload_metadata_and_total_row_before_materializing(self):
        actual_connect = sqlite3.connect
        materialized = []
        class ObservedConnection(sqlite3.Connection):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.row_factory = self.observe_row

            @staticmethod
            def observe_row(cursor, row):
                if any(column[0] == 'payload' for column in cursor.description):
                    materialized.append(True)
                return row

        def observed_connect(*args, **kwargs):
            return actual_connect(*args, factory=ObservedConnection, **kwargs)

        for label, payload_bytes, metadata_bytes in [
                ('payload', m.MAX_LINE + 1, 1),
                ('metadata', 1, m.MAX_LINE + 1),
                ('total-row', m.MAX_ROW, m.MAX_LINE // 2)]:
            with self.subTest(label=label):
                source = self.root / (label + '.db')
                cn = actual_connect(source)
                cn.execute('CREATE TABLE event_queue(id INTEGER PRIMARY KEY,payload BLOB,severity INTEGER,status TEXT,terminal_reason TEXT,extra_metadata TEXT)')
                cn.execute("INSERT INTO event_queue VALUES(1,zeroblob(?),2,'local_evidence','source_only_local_v3',CAST(zeroblob(?) AS TEXT))",
                           (payload_bytes, metadata_bytes))
                cn.commit(); cn.close()
                before = sha(source)
                output = self.root / (label + '.jsonl')
                with patch.object(m.sqlite3, 'connect', side_effect=observed_connect), \
                        patch.object(m.base64, 'b64encode', side_effect=AssertionError('oversize row reached Python encoding')):
                    with self.assertRaisesRegex(m.ArchiveError, 'source_sqlite_row_byte_budget_exceeded'):
                        m.archive(str(source), before, str(output))
                self.assertEqual(materialized, [])
                self.assertNotIn(b'"kind":"complete"', output.read_bytes())
                self.assertEqual(sha(source), before)

    def test_sqlite_length_limit_must_be_read_back_within_budget(self):
        cn = sqlite3.connect(':memory:')
        try:
            m.limit_sqlite_rows(cn)
            self.assertEqual(cn.getlimit(sqlite3.SQLITE_LIMIT_LENGTH), m.MAX_LINE)
        finally:
            cn.close()
        from unittest.mock import Mock
        ignored_limit = Mock()
        ignored_limit.getlimit.return_value = m.MAX_LINE + 1
        with self.assertRaisesRegex(m.ArchiveError, 'sqlite_row_length_limit_not_enforced'):
            m.limit_sqlite_rows(ignored_limit)

    def test_tamper_truncation_and_wrong_payload_digest_fail(self):
        path, report = self.make_archive()
        path.write_bytes(path.read_bytes().replace(b'private-extra', b'changed-extra'))
        with self.assertRaisesRegex(m.ArchiveError, 'digest_mismatch'):
            m.verify(str(path), report['archive_sha256'])
        with self.assertRaisesRegex(m.ArchiveError, 'footer_integrity'):
            m.verify(str(path), sha(path))
        path2, report2 = self.make_archive('payload.jsonl')
        records = [json.loads(x) for x in path2.read_bytes().splitlines()]
        records[1]['payload_sha256'] = '0'*64
        path2.write_bytes(b''.join(m.encoded(x) for x in records))
        with self.assertRaisesRegex(m.ArchiveError, 'row_integrity'):
            m.verify(str(path2), sha(path2))
        path3, _ = self.make_archive('truncated.jsonl')
        path3.write_bytes(b'\n'.join(path3.read_bytes().splitlines()[:-1])+b'\n')
        with self.assertRaisesRegex(m.ArchiveError, 'incomplete'):
            m.verify(str(path3), sha(path3))

    def test_space_deadline_and_source_change_preserve_failure(self):
        usage = type('Usage', (), {'free': 0})()
        with patch.object(m.PinnedPath, 'free_bytes', return_value=0):
            with self.assertRaisesRegex(m.ArchiveError, 'free_space'):
                self.make_archive()
        self.assertFalse((self.root/'archive.jsonl').exists())
        with self.assertRaisesRegex(m.ArchiveError, 'deadline'):
            m.archive(str(self.db), self.bound, budget=m.Budget(seconds=-1))
        real_digest = m.digest
        calls = 0
        def changing_digest(*args):
            nonlocal calls
            calls += 1
            return real_digest(*args) if calls == 1 else '0'*64
        with patch.object(m, 'digest', side_effect=changing_digest):
            with self.assertRaisesRegex(m.ArchiveError, 'source_changed'):
                self.make_archive('changed.jsonl')
        self.assertNotIn(b'"kind":"complete"', (self.root/'changed.jsonl').read_bytes())

    def test_output_parent_swap_before_create_never_redirects_writes(self):
        if os.name == 'nt':
            self.skipTest('Windows deny-delete handles prevent the rename; native fixture required')
        parent = self.root/'output';parent.mkdir()
        moved = self.root/'moved';replacement = self.root/'replacement';replacement.mkdir()
        actual_open = m.os.open
        swapped = False
        def swap_before_leaf(path, flags, *args, **kwargs):
            nonlocal swapped
            if not swapped and flags & os.O_CREAT and kwargs.get('dir_fd') is not None:
                swapped = True
                parent.rename(moved)
                parent.symlink_to(replacement, target_is_directory=True)
            return actual_open(path, flags, *args, **kwargs)
        with patch.object(m.os, 'open', side_effect=swap_before_leaf):
            with self.assertRaisesRegex(m.ArchiveError, 'parent_directory_changed'):
                self.make_archive('output/archive.jsonl')
        self.assertTrue(swapped)
        self.assertFalse((replacement/'archive.jsonl').exists())
        self.assertEqual((moved/'archive.jsonl').read_bytes(), b'')

    def test_output_parent_swap_between_rows_stops_without_completion(self):
        if os.name == 'nt':
            self.skipTest('Windows native deny-delete sharing fixture required')
        parent = self.root/'output';parent.mkdir();moved = self.root/'moved'
        actual_write = m.BoundFile.write
        swapped = False
        def swapping_write(target, data):
            nonlocal swapped
            result = actual_write(target, data)
            if not swapped:
                swapped = True
                parent.rename(moved);parent.mkdir()
            return result
        with patch.object(m.BoundFile, 'write', new=swapping_write):
            with self.assertRaisesRegex(m.ArchiveError, 'parent_directory_changed'):
                self.make_archive('output/archive.jsonl')
        self.assertFalse((parent/'archive.jsonl').exists())
        self.assertNotIn(b'"kind":"complete"', (moved/'archive.jsonl').read_bytes())

    def test_extract_parent_swap_before_create_never_redirects_payload(self):
        if os.name == 'nt':
            self.skipTest('Windows native deny-delete sharing fixture required')
        archive, _ = self.make_archive()
        parent = self.root/'extract';parent.mkdir();moved = self.root/'moved'
        actual_open = m.os.open
        swapped = False
        def swap_before_leaf(path, flags, *args, **kwargs):
            nonlocal swapped
            if not swapped and flags & os.O_CREAT and kwargs.get('dir_fd') is not None:
                swapped = True
                parent.rename(moved);parent.mkdir()
            return actual_open(path, flags, *args, **kwargs)
        with patch.object(m.os, 'open', side_effect=swap_before_leaf):
            with self.assertRaisesRegex(m.ArchiveError, 'parent_directory_changed'):
                m.verify(str(archive), sha(archive), extract_id=1, output=str(parent/'row.bin'))
        self.assertFalse((parent/'row.bin').exists())
        self.assertEqual((moved/'row.bin').read_bytes(), b'')

    def test_source_replace_at_sqlite_open_is_bound_to_original_descriptor(self):
        if os.name == 'nt':
            self.skipTest('Windows denies source replacement while handle is open')
        moved = self.root/'original.db'
        replacement = self.root/'replacement.db'
        cn = sqlite3.connect(replacement);cn.execute('CREATE TABLE other(x)');cn.close()
        actual_connect = m.sqlite3.connect
        observed = []
        def replacing_connect(filename, *args, **kwargs):
            self.db.rename(moved);replacement.rename(self.db)
            cn = actual_connect(filename, *args, **kwargs)
            # sqlite actually opened the descriptor, not the substituted path.
            observed.append(cn.execute('SELECT COUNT(*) FROM event_queue').fetchone()[0])
            return cn
        try:
            with patch.object(m.sqlite3, 'connect', side_effect=replacing_connect):
                with self.assertRaisesRegex(m.ArchiveError, 'file_identity_changed'):
                    self.make_archive()
            self.assertEqual(observed, [5])
            self.assertFalse((self.root/'archive.jsonl').exists())
        finally:
            if moved.exists():
                self.db.unlink();moved.rename(self.db)

    def test_supervisor_timeout_has_bounded_exit_confirmation_and_no_communicate(self):
        import contextlib
        import io
        from unittest.mock import Mock
        process = Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired('worker', 9), subprocess.TimeoutExpired('worker', 1)]
        console = io.StringIO()
        with patch.object(m.subprocess, 'Popen', return_value=process), contextlib.redirect_stdout(console):
            self.assertEqual(m.supervise(['unused'], 8), 1)
        self.assertEqual(process.wait.call_args_list[0].kwargs, {'timeout': 9})
        self.assertEqual(process.wait.call_args_list[1].kwargs, {'timeout': 1})
        process.kill.assert_called_once()
        process.communicate.assert_not_called()
        self.assertEqual(json.loads(console.getvalue())['error'], 'writer_exit_unconfirmed_do_not_retry_or_reuse_output')

    def test_supervisor_terminates_actual_stalled_worker(self):
        import contextlib
        import io
        import time
        console = io.StringIO()
        start = time.monotonic()
        with contextlib.redirect_stdout(console):
            self.assertEqual(m.supervise([sys.executable, '-c', 'import time; time.sleep(30)'], .01), 1)
        self.assertLess(time.monotonic()-start, 3)
        self.assertEqual(json.loads(console.getvalue())['error'], 'hard_timeout_partial_output_may_remain')

    def test_cli_returns_only_summary_and_never_evidence_on_failure(self):
        command = [sys.executable, str(SCRIPT), 'archive', '--source', str(self.db), '--sha256', self.bound, '--output', str(self.root/'cli.jsonl')]
        done = subprocess.run(command, capture_output=True, timeout=12)
        self.assertEqual(done.returncode, 0, done.stdout)
        report = json.loads(done.stdout)
        self.assertEqual(report['rows'], 2)
        for private in [b'private-evidence', b'private-extra', b'secret-id-']:
            self.assertNotIn(private, done.stdout+done.stderr)
        bad = subprocess.run(command, capture_output=True, timeout=12)
        self.assertNotEqual(bad.returncode, 0)
        self.assertFalse(json.loads(bad.stdout)['complete'])
        self.assertEqual(bad.stderr, b'')


if __name__ == '__main__':
    unittest.main()
