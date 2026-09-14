import importlib.util
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile


SPEC = importlib.util.spec_from_file_location(
    'release_cache', Path(__file__).parents[1] / 'scripts/vcpkg_release_cache.py')
CACHE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CACHE)
KEY = 'edr-vcpkg-v3-arm64-windows-' + 'a' * 64
ABI_PATH = 'ab/' + 'ab' * 32 + '.zip'
COMPLETE = {'isDraft': False, 'assets': [{'name': CACHE.ARCHIVE}, {'name': CACHE.MANIFEST}]}


class ReleaseCacheTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.producer = self.root / 'producer'
        self.consumer = self.root / 'consumer'
        self.assets = self.root / 'assets'
        self.assets.mkdir()
        self.put(self.producer / '.cache/vcpkg-bincache' / ABI_PATH, b'package')
        self.put(self.producer / '.cache/vcpkg-downloads/cmake-4.4.0-windows-x86_64.zip', b'tool archive')

    def put(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def rewrite_manifest(self):
        archive = self.assets / CACHE.ARCHIVE
        (self.assets / CACHE.MANIFEST).write_text(json.dumps({
            'schema': CACHE.SCHEMA, 'key': KEY, 'size': archive.stat().st_size,
            'sha256': CACHE.sha256(archive)}), encoding='utf-8')

    def test_roundtrip_preserves_abi_shards_and_original_tools_not_installed_state(self):
        self.put(self.producer / 'vcpkg_installed/vcpkg/status', b'must not travel')
        self.put(self.producer / '.cache/vcpkg-downloads/tools/cmake/cmake.exe', b'extracted')
        self.put(self.producer / '.cache/vcpkg-downloads/incomplete.part', b'incomplete')
        self.assertEqual(CACHE.pack_cache(self.producer, self.assets, KEY), 1)
        # Simulate Windows C: -> D: restriction: replace must only use siblings.
        replace = CACHE.os.replace
        def same_volume(source, destination):
            self.assertEqual(Path(source).parent, Path(destination).parent)
            replace(source, destination)
        with mock.patch.object(CACHE.os, 'replace', side_effect=same_volume):
            self.assertEqual(CACHE.restore_cache(self.consumer, self.assets, KEY), 1)
        self.assertEqual((self.consumer / '.cache/vcpkg-bincache' / ABI_PATH).read_bytes(), b'package')
        files = {p.relative_to(self.consumer).as_posix() for p in self.consumer.rglob('*') if p.is_file()}
        self.assertEqual(files, {'.cache/vcpkg-bincache/' + ABI_PATH,
                                '.cache/vcpkg-downloads/cmake-4.4.0-windows-x86_64.zip'})

    def test_hash_key_and_size_mismatch_do_not_touch_existing_cache(self):
        CACHE.pack_cache(self.producer, self.assets, KEY)
        path = self.assets / CACHE.MANIFEST
        original = json.loads(path.read_text())
        for name, value in [('sha256', '0'*64), ('key', KEY.replace('arm64', 'x64')), ('size', 1)]:
            with self.subTest(field=name):
                path.write_text(json.dumps(dict(original, **{name: value})))
                with self.assertRaisesRegex(ValueError, 'mismatch'):
                    CACHE.restore_cache(self.consumer, self.assets, KEY)
                self.assertFalse(self.consumer.exists())

    def test_unsafe_members_rejected_before_any_extraction(self):
        names = ['../outside', 'downloads/../escape', 'downloads/C:/escape',
                 'downloads/con', 'downloads/file.', 'downloads/file:stream',
                 'downloads/./file', 'downloads//file', 'downloads/back\\slash',
                 'bincache/' + ABI_PATH.replace('ab/', 'ff/'),
                 'vcpkg_installed/vcpkg/status']
        for name in names:
            with self.subTest(name=name):
                with zipfile.ZipFile(self.assets / CACHE.ARCHIVE, 'w') as package:
                    package.writestr('bincache/' + ABI_PATH, b'package')
                    package.writestr(name, b'bad')
                self.rewrite_manifest()
                with self.assertRaises(ValueError):
                    CACHE.restore_cache(self.consumer, self.assets, KEY)
                self.assertFalse(self.consumer.exists())

    def test_duplicate_windows_names_and_symlinks_rejected(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                with zipfile.ZipFile(self.assets / CACHE.ARCHIVE, 'w') as package:
                    package.writestr('bincache/' + ABI_PATH, b'package')
                    if symlink:
                        member = zipfile.ZipInfo('downloads/link')
                        member.create_system = 3
                        member.external_attr = (stat.S_IFLNK | 0o777) << 16
                        package.writestr(member, 'outside')
                    else:
                        package.writestr('downloads/Tool.zip', b'a')
                        package.writestr('downloads/tool.zip', b'b')
                self.rewrite_manifest()
                with self.assertRaises(ValueError):
                    CACHE.restore_cache(self.consumer, self.assets, KEY)
                self.assertFalse(self.consumer.exists())

    def test_corrupt_crc_detected_before_touching_cache(self):
        CACHE.pack_cache(self.producer, self.assets, KEY)
        archive = self.assets / CACHE.ARCHIVE
        archive.write_bytes(archive.read_bytes().replace(b'package', b'corrupt'))
        self.rewrite_manifest()  # Even a matching outer hash cannot hide bad ZIP CRC.
        with self.assertRaises(zipfile.BadZipFile):
            CACHE.restore_cache(self.consumer, self.assets, KEY)
        self.assertFalse(self.consumer.exists())

    def test_empty_binary_cache_and_size_budget_fail(self):
        with mock.patch.object(CACHE, 'MAX_BYTES', 1):
            with self.assertRaises(ValueError):
                CACHE.pack_cache(self.producer, self.assets, KEY)
        (self.producer / '.cache/vcpkg-bincache' / ABI_PATH).unlink()
        with self.assertRaisesRegex(ValueError, 'No completed'):
            CACHE.pack_cache(self.producer, self.assets, KEY)

    def test_exact_actions_hit_does_not_use_network(self):
        with mock.patch.object(CACHE, 'gh') as gh:
            result = CACHE.transport('restore', 'owner/repo', self.consumer, KEY, '', True)
        self.assertEqual(result, 'actions-cache')
        gh.assert_not_called()

    def test_only_release_absence_is_source_fallback_not_auth_or_network_failure(self):
        for status, error in [(1, 'release not found'), (1, 'HTTP 403'), (1, 'TLS failed')]:
            with self.subTest(error=error), mock.patch.object(CACHE, 'gh', return_value=
                    subprocess.CompletedProcess([], status, '', error)):
                if 'not found' in error:
                    self.assertEqual(CACHE.transport('restore', 'owner/repo', self.consumer, KEY, ''),
                                     'source-or-local-abi-cache')
                else:
                    with self.assertRaises(RuntimeError):
                        CACHE.transport('restore', 'owner/repo', self.consumer, KEY, '')

    def test_shared_restore_works_independent_of_producer_tag(self):
        CACHE.pack_cache(self.producer, self.assets, KEY)
        def download(*args):
            self.assertEqual(args[:3], ('release', 'download', KEY))
            destination = Path(args[args.index('--dir') + 1])
            for name in (CACHE.ARCHIVE, CACHE.MANIFEST):
                shutil.copyfile(self.assets / name, destination / name)
            return subprocess.CompletedProcess([], 0)
        with mock.patch.object(CACHE, 'release_info', return_value=COMPLETE), \
                mock.patch.object(CACHE, 'gh', side_effect=download), \
                mock.patch.dict(CACHE.os.environ, {'GITHUB_REF': 'refs/tags/win_3.2.999'}):
            result = CACHE.transport('restore', 'owner/repo', self.consumer, KEY, '')
        self.assertEqual(result, 'shared-release:' + KEY)
        self.assertTrue((self.consumer / '.cache/vcpkg-bincache' / ABI_PATH).is_file())

    def test_publish_is_create_only_idempotent_and_race_safe(self):
        for code in (0, 1):  # Another producer can win the same immutable release.
            with self.subTest(code=code), \
                    mock.patch.object(CACHE, 'release_info', side_effect=[None, COMPLETE]), \
                    mock.patch.object(CACHE, 'gh', return_value=subprocess.CompletedProcess([], code)) as gh:
                self.assertEqual(CACHE.transport('publish', 'owner/repo', self.producer, KEY, 'b'*40), 'published')
                args = gh.call_args.args
                self.assertEqual(args[:3], ('release', 'create', KEY))
                self.assertIn('--latest=false', args)
                self.assertIn('--prerelease', args)
                self.assertNotIn('--clobber', args)
                self.assertEqual(args[args.index('--target') + 1], 'b'*40)
        with mock.patch.object(CACHE, 'release_info', return_value=COMPLETE), \
                mock.patch.object(CACHE, 'gh') as gh:
            self.assertEqual(CACHE.transport('publish', 'owner/repo', self.producer, KEY, 'b'*40), 'already-published')
            gh.assert_not_called()

    def test_incomplete_release_is_not_consumed_or_overwritten(self):
        for mode in ('restore', 'publish'):
            with self.subTest(mode=mode), \
                    mock.patch.object(CACHE, 'release_info', return_value={'isDraft': False, 'assets': []}), \
                    mock.patch.object(CACHE, 'gh') as gh:
                with self.assertRaisesRegex(RuntimeError, 'incomplete'):
                    CACHE.transport(mode, 'owner/repo', self.consumer, KEY, 'b'*40)
                gh.assert_not_called()

    def test_gh_has_a_timeout_and_does_not_shell_interpolate(self):
        with mock.patch.object(CACHE.subprocess, 'run') as run:
            CACHE.gh('release', 'view', KEY)
            run.assert_called_once_with(['gh', 'release', 'view', KEY],
                                        capture_output=True, text=True, timeout=300)


if __name__ == '__main__':
    unittest.main()
