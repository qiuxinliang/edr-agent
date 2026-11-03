import copy
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

MODULE = Path(__file__).parent / 'storage_compat' / 'transfer.py'
spec = importlib.util.spec_from_file_location('storage_compat_transfer', MODULE)
transfer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transfer)


class StorageToolTransferTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = dict(GITHUB_REPOSITORY=transfer.PUBLIC, GITHUB_EVENT_NAME='workflow_dispatch',
            GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2', GITHUB_SHA='a' * 40)
        self.owner = transfer.identity('arm64', self.env)
        self.bundle = self.root / 'stage'
        self.bundle.mkdir()
        (self.bundle / 'manifest.json').write_text('{"fixture":"transport-only"}\n')
        (self.bundle / 'legacy').mkdir()
        (self.bundle / 'legacy' / 'storage_compat_queue.exe').write_bytes(b'not-a-native-test-tool')

    def packaged(self):
        with patch.object(transfer, 'verify_bundle') as verify:
            files = transfer.package(self.root, self.bundle, self.root / 'out', self.owner)
        self.assertEqual(verify.call_count, 2)
        verify.assert_called_with(self.root, self.bundle, self.owner)
        entries = {p.name: dict(id=i + 1, name=p.name, size=p.stat().st_size,
            state='uploaded', digest='sha256:' + hashlib.sha256(p.read_bytes()).hexdigest())
            for i, p in enumerate(files)}
        return files, entries, json.loads(files[1].read_text())

    def test_identity_rejects_wrong_repository_event_run_attempt_architecture_and_commit(self):
        for key, value in [('GITHUB_REPOSITORY', 'outside/repo'), ('GITHUB_EVENT_NAME', 'pull_request'),
                           ('GITHUB_RUN_ID', '0'), ('GITHUB_RUN_ATTEMPT', '../1'), ('GITHUB_SHA', 'main')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                transfer.identity('arm64', dict(self.env, **{key: value}))
        with self.assertRaises(ValueError):
            transfer.identity('x86', self.env)

    def test_package_binds_all_bytes_and_rechecks_native_closure(self):
        files, entries, receipt = self.packaged()
        transfer.validate_receipt(receipt, entries, self.owner)
        self.assertEqual(receipt['owner'], self.owner)
        with zipfile.ZipFile(files[0]) as archive:
            self.assertCountEqual(archive.namelist(), ['manifest.json', 'legacy/storage_compat_queue.exe'])
            self.assertEqual(archive.read('legacy/storage_compat_queue.exe'), b'not-a-native-test-tool')

    def test_failed_native_validation_cannot_create_a_package(self):
        with patch.object(transfer, 'verify_bundle', side_effect=ValueError('native closure invalid')):
            with self.assertRaisesRegex(ValueError, 'native closure invalid'):
                transfer.package(self.root, self.bundle, self.root / 'out', self.owner)
        self.assertFalse((self.root / 'out').exists())

    def test_manifest_change_after_packing_is_rejected(self):
        def validate(*args):
            if validation.call_count == 2:
                (self.bundle / 'manifest.json').write_text('{"changed":true}')
        with patch.object(transfer, 'verify_bundle', side_effect=validate) as validation:
            with self.assertRaisesRegex(ValueError, 'changed during packaging'):
                transfer.package(self.root, self.bundle, self.root / 'out', self.owner)

    def test_archive_identity_and_all_owner_dimensions_are_enforced(self):
        _, entries, receipt = self.packaged()
        for key, value in [('run_id', '124'), ('attempt', '3'), ('commit', 'b' * 40),
                           ('architecture', 'amd64'), ('repository', 'other/repo')]:
            changed = copy.deepcopy(receipt)
            changed['owner'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                transfer.validate_receipt(changed, entries, self.owner)
        for key, value in [('name', 'other.zip'), ('size', 0), ('sha256', 'b' * 64)]:
            changed = copy.deepcopy(receipt)
            changed['archive'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                transfer.validate_receipt(changed, entries, self.owner)
        with self.assertRaises(ValueError):
            transfer.validate_receipt(receipt, dict(entries, unexpected={}), self.owner)

    def test_private_evidence_is_not_published(self):
        files, _, _ = self.packaged()
        with patch.object(transfer, 'package', return_value=files), \
             patch.object(transfer.transport, 'publish_files', return_value={'id': 99}) as publish:
            transfer.upload(self.root, self.bundle, self.root / 'upload', self.owner)
        publish.assert_called_once_with('edr-evidence-storage-tools-123-2-arm64', self.owner, files, prerelease=False)

    def test_release_must_match_current_run_and_remain_draft(self):
        release = dict(id=99, tag_name=transfer.tag(self.owner), draft=True, prerelease=True,
            body=transfer.transport.PREFIX + json.dumps(self.owner, sort_keys=True))
        transfer.validate_release(release, self.owner)
        for key, value in [('draft', False), ('prerelease', False), ('tag_name', 'edr-evidence-other'), ('body', '{}')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                transfer.validate_release(dict(release, **{key: value}), self.owner)

    def test_missing_or_public_transport_never_creates_local_inputs(self):
        with patch.object(transfer.transport, 'api', return_value={'private': False}), \
             patch.object(transfer.transport, 'find_release') as find:
            with self.assertRaises(ValueError):
                transfer.download(self.root, self.root / 'download', self.owner)
            find.assert_not_called()
        with patch.object(transfer.transport, 'api', return_value={'private': True}), \
             patch.object(transfer.transport, 'find_release', return_value=None):
            with self.assertRaisesRegex(ValueError, 'no substitute'):
                transfer.download(self.root, self.root / 'download', self.owner)
        self.assertFalse((self.root / 'download').exists())

    def exercise_download(self, mutate=False):
        files, entries, _ = self.packaged()
        release = dict(id=99, tag_name=transfer.tag(self.owner), draft=True, prerelease=True,
            body=transfer.transport.PREFIX + json.dumps(self.owner, sort_keys=True))
        later = copy.deepcopy(entries)
        if mutate:
            later[files[0].name]['id'] += 100
        def fetch(asset, destination):
            shutil.copyfile(next(p for p in files if p.name == asset['name']), destination)
        with patch.object(transfer.transport, 'api', return_value={'private': True}), \
             patch.object(transfer.transport, 'find_release', return_value=release), \
             patch.object(transfer.transport, 'assets', side_effect=[entries, later]), \
             patch.object(transfer.transport, 'download_asset', side_effect=fetch), \
             patch.object(transfer, 'verify_bundle') as verify:
            bundle = transfer.download(self.root, self.root / 'download', self.owner)
        verify.assert_called_once_with(self.root, bundle, self.owner)
        return bundle

    def test_roundtrip_rechecks_native_bundle_and_retains_identical_bytes(self):
        bundle = self.exercise_download()
        for original in self.bundle.rglob('*'):
            if original.is_file():
                self.assertEqual(original.read_bytes(), (bundle / original.relative_to(self.bundle)).read_bytes())

    def test_asset_replacement_during_download_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'asset identity changed'):
            self.exercise_download(mutate=True)


if __name__ == '__main__':
    unittest.main()
