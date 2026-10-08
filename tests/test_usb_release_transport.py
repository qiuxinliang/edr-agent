import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('transport', Path(__file__).parents[1] / 'scripts/usb_release_transport.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


class ReleaseAPI:
    def __init__(self):
        self.release = None
        self.files = {}
        self.posts = 0
        self.private = True

    def call(self, path, data=None, method=None):
        if path == '':
            return dict(private=self.private)
        if path.startswith('releases?'):
            return [copy.deepcopy(self.release)] if self.release else []
        if path == 'releases' and data:
            self.posts += 1
            self.release = dict(data, id=12)
            return copy.deepcopy(self.release)
        if path == 'releases/12/assets?per_page=100':
            return list(self.files.values())
        if path == 'releases/12':
            if data:
                self.release.update(data)
            return copy.deepcopy(self.release)
        raise AssertionError(path)

    def upload(self, command, **kwargs):
        path = Path(command[4])
        self.files[path.name] = dict(name=path.name, size=path.stat().st_size,
                                    digest='sha256:' + t.digest(path), id=1, state='uploaded')
        return type('Result', (), dict(returncode=0))()


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.file = Path(self.directory.name) / 'evidence.zip'
        self.file.write_bytes(b'verified bytes')
        self.fake = ReleaseAPI()
        self.owner = dict(schema='edr.lifecycle-evidence.v1', run_id='123', commit='a'*40)
        self.tag = 'edr-evidence-123-1-arm64'

    def publish(self, **kwargs):
        with patch.object(t, 'api', self.fake.call), patch.object(t.subprocess, 'run', self.fake.upload):
            return t.publish_files(self.tag, self.owner, [self.file], **kwargs)

    def test_private_evidence_remains_draft(self):
        result = self.publish()
        self.assertTrue(result['draft'])
        self.assertEqual(self.fake.release['make_latest'], 'false')

    def test_results_seal_only_after_freshness_and_digest(self):
        calls = []
        result = self.publish(prerelease=True, before_seal=lambda: calls.append(len(self.fake.files)))
        self.assertEqual(calls, [1])
        self.assertFalse(result['draft'])
        self.assertTrue(result['prerelease'])

    def test_public_destination_refused(self):
        self.fake.private = False
        with self.assertRaisesRegex(ValueError, 'private'):
            self.publish()
        self.assertEqual(self.fake.posts, 0)

    def test_existing_owned_asset_is_not_uploaded_again(self):
        self.publish()
        with patch.object(t, 'api', self.fake.call), patch.object(t.subprocess, 'run') as upload:
            t.publish_files(self.tag, self.owner, [self.file])
        upload.assert_not_called()
        self.assertEqual(self.fake.posts, 1)

    def test_owner_collision_no_upload(self):
        self.publish()
        self.fake.release['body'] = 'unrelated release'
        with self.assertRaisesRegex(ValueError, 'ownership'):
            self.publish()

    def test_wrong_existing_bytes_not_overwritten(self):
        self.publish()
        self.file.write_bytes(b'changed input')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.publish()

    def test_extra_asset_rejected(self):
        self.publish()
        self.fake.files['unexpected'] = dict(name='unexpected')
        with self.assertRaisesRegex(ValueError, 'Unexpected assets'):
            self.publish()

    def test_expired_executor_cannot_seal(self):
        def expired():
            raise ValueError('executor cancelled')
        with self.assertRaisesRegex(ValueError, 'cancelled'):
            self.publish(prerelease=True, before_seal=expired)
        self.assertTrue(self.fake.release['draft'])
        self.assertTrue(self.file.exists())

    def test_ambiguous_post_reconciles_without_second_post(self):
        real = self.fake.call
        def ambiguous(path, data=None, method=None):
            result = real(path, data, method)
            if path == 'releases' and data:
                raise RuntimeError('response lost')
            return result
        with patch.object(t, 'api', ambiguous), patch.object(t.subprocess, 'run', self.fake.upload):
            t.publish_files(self.tag, self.owner, [self.file])
        self.assertEqual(self.fake.posts, 1)

    def test_upload_failure_retains_local_data(self):
        with patch.object(t, 'api', self.fake.call), patch.object(t.subprocess, 'run', side_effect=t.subprocess.TimeoutExpired('gh', 300)):
            with self.assertRaisesRegex(RuntimeError, 'retained'):
                t.publish_files(self.tag, self.owner, [self.file])
        self.assertTrue(self.file.exists())
        self.assertTrue(self.fake.release['draft'])

    def test_signature_scope_and_response_identity_are_bound(self):
        signer = t.signer_identity('123', '1', 'a'*40)
        context = dict(scope='headless', request_id='b'*32, source={'run_id':'12'}, executor={'run_id':'23'})
        owner = t.result_owner(context, signer)
        release = dict(tag_name=t.result_tag(signer), prerelease=True, body=t.PREFIX+json.dumps(owner, sort_keys=True))
        t.check_owner(release, t.result_tag(signer), owner)
        altered = copy.deepcopy(owner)
        altered['context']['executor']['run_id'] = '24'
        with self.assertRaises(ValueError):
            t.check_owner(release, t.result_tag(signer), altered)

    def test_asset_digest_is_mandatory_and_unsigned_ui_is_required(self):
        names = t.expected_names('3.2.621')
        self.assertEqual(len(names), 12)
        self.assertEqual(sum(name.endswith('setup-ui.zip') for name in names), 2)
        with self.assertRaises(ValueError):
            t.check_asset(dict(id=1, name='a', size=1, state='uploaded'), 'a', 1, '0'*64)

    def test_download_counter_does_not_invalidate_identity(self):
        first = dict(a=dict(id=1, name='a', size=1, state='uploaded', digest='sha256:'+'0'*64, download_count=0))
        second = copy.deepcopy(first)
        second['a']['download_count'] = 1
        self.assertEqual(t.asset_identity(first), t.asset_identity(second))
        second['a']['id'] = 2
        self.assertNotEqual(t.asset_identity(first), t.asset_identity(second))

    def test_download_bounds_before_starting_network(self):
        for size, sha in [(1024**3+1, 'sha256:'+'0'*64), (1, ''), (0, 'sha256:'+'0'*64)]:
            with patch.object(t.subprocess, 'run') as fetch:
                with self.assertRaises(ValueError):
                    t.download_asset(dict(id=1,name='blob',size=size,digest=sha,state='uploaded'), self.file.parent/'blob')
                fetch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
