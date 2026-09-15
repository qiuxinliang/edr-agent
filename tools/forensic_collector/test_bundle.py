"""Behavioral regression tests; all generated test artifacts are temporary."""
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

BIN = os.environ.get('BIN', '')


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='forensic bundle ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / 'shared output'
        self.out.mkdir()
        self.env = os.environ.copy()
        # Isolate external command output: this test never collects host data.
        self.commands = self.root / 'commands'
        self.commands.mkdir()
        for name in ('uname', 'hostname', 'uptime', 'ps', 'ss', 'netstat', 'lsof',
                     'crontab', 'ls', 'systemctl'):
            script = self.commands / name
            script.write_text('#!/bin/sh\nprintf "synthetic evidence\\n"\n')
            script.chmod(0o700)
        self.env['PATH'] = str(self.commands) + os.pathsep + self.env['PATH']

    def run_collector(self, bundle, scope='standard', request=None):
        cmd = [BIN, '--scope', scope, '--output-dir', str(self.out),
               '--out-file', str(bundle), '--timeout', '10']
        if request is not None:
            req = self.root / 'request.json'
            req.write_text(json.dumps(request))
            cmd += ['--request', str(req)]
        return subprocess.run(cmd, env=self.env, capture_output=True, timeout=20)

    def test_repeated_bundles_exclude_old_artifacts_and_themselves(self):
        old = self.out / 'old.tar.gz'
        old.write_bytes(b'old artifact' * 100000)
        (self.out / 'old.req').write_text('private request')
        (self.out / 'copied_99').write_text('stale target')
        sizes = []
        for index in range(8):
            bundle = self.out / ('bundle_%d.tar.gz' % index)
            result = self.run_collector(bundle)
            self.assertEqual(result.returncode, 0, result.stderr)
            with tarfile.open(bundle) as archive:
                names = {m.name.removeprefix('./') for m in archive.getmembers()}
                self.assertIn('manifest.json', names)
                self.assertFalse(any(n.endswith(('.tar.gz', '.req')) for n in names), names)
                self.assertNotIn('copied_99', names)
            sizes.append(bundle.stat().st_size)
        self.assertLess(max(sizes), 16384)
        self.assertLess(max(sizes), min(sizes) * 2)
        self.assertEqual(old.stat().st_size, 1200000)

    def test_large_target_fails_without_partial_bundle(self):
        target = self.root / 'large target'
        with target.open('wb') as f:
            f.truncate(65 * 1024 * 1024)
        bundle = self.out / 'large.tar.gz'
        result = self.run_collector(bundle, 'full', {'targets': [{'path': str(target)}]})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'64 MiB', result.stderr)
        self.assertFalse(bundle.exists())
        self.assertFalse((self.out / 'copied_00').exists())

    def test_target_budget_is_aggregate(self):
        target = self.root / 'target'
        with target.open('wb') as f:
            f.truncate(33 * 1024 * 1024)
        bundle = self.out / 'aggregate.tar.gz'
        result = self.run_collector(bundle, 'full', {'targets': [{'path': str(target)}] * 2})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(bundle.exists())
        self.assertLessEqual(sum(p.stat().st_size for p in self.out.iterdir()), 64 * 1024 * 1024)

    def test_failed_archive_does_not_report_stale_success(self):
        bundle = self.out / 'existing.tar.gz'
        bundle.write_bytes(b'keep old evidence')
        result = self.run_collector(bundle)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(bundle.read_bytes(), b'keep old evidence')

    def test_archive_failure_removes_partial_output(self):
        tar = self.commands / 'tar'
        tar.write_text('#!/bin/sh\nprintf partial > "$2"\nexit 1\n')
        tar.chmod(0o700)
        bundle = self.out / 'failed.tar.gz'
        result = self.run_collector(bundle)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(bundle.exists())

    def test_successful_targets_only_and_no_stale_scope_files(self):
        target = self.root / 'target'
        target.write_text('test evidence')
        bundle = self.out / 'target.tar.gz'
        result = self.run_collector(bundle, 'full', {'targets': [{'path': str(target)}]})
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(bundle) as archive:
            self.assertEqual(archive.extractfile('copied_00').read(), b'test evidence')
        result = self.run_collector(self.out / 'triage.tar.gz', 'triage')
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(self.out / 'triage.tar.gz') as archive:
            self.assertNotIn('copied_00', archive.getnames())
            self.assertNotIn('cron.txt', archive.getnames())


if __name__ == '__main__':
    if not BIN or not Path(BIN).is_file():
        raise SystemExit('Set BIN to the built forensic_collector_builtin executable')
    unittest.main()
