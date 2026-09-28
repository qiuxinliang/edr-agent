"""Signing data boundary regressions; no network, certificate or release writes."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import windows_usb_bundle as bundle
import windows_release_checkpoint as cp
import private_signing_bridge as bridge

SOURCE = dict(tag='win_3.2.999', commit='a'*40, repository=bridge.SOURCE,
              run_id='1234', mode='usb', upgrade_class='auto')
PIN = 'A'*40


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, candidate=True):
        assets = self.root / ('candidate' if candidate else 'signed')
        assets.mkdir()
        prefix = 'edr-agent-win_3.2.999-windows-arm64-'
        runtime = {'FDSensor.exe': b'sensor', 'FDSecurityInstallerWorker.exe': b'worker',
                   'uninstall.exe': b'uninstall', 'collector/forensic_collector_builtin.exe': b'collector',
                   'edr_agent_setup.exe': b'setup', 'VERSION': b'3.2.999', 'data.bin': b'unchanged'}
        status = 'unsigned' if candidate else 'signed'
        caps = dict(signature_status=status)
        runtime['package-capabilities.json'] = json.dumps(caps).encode()
        native = dict(schema='edr.windows.native-package-integrity.v1', files=[
            dict(name=n, sha256=cp.hashlib.sha256(v).hexdigest()) for n, v in runtime.items() if n in bundle.NATIVE])
        runtime['native-package-integrity.json'] = json.dumps(native).encode()
        m = dict(version='3.2.999', target_arch='arm64', setup_target_arch='arm64', capabilities=caps,
                 ui_exe_sha256=cp.hashlib.sha256(b'ui').hexdigest(), setup_exe_sha256=cp.hashlib.sha256(b'setup').hexdigest(),
                 agent_binary_sha256=cp.hashlib.sha256(b'sensor').hexdigest(),
                 runtime_identity_sha256=cp.hashlib.sha256(runtime['native-package-integrity.json']).hexdigest(),
                 publisher_thumbprint='' if candidate else PIN, setup_exe_signed=not candidate,
                 ui_exe_signed=not candidate, generated_at_utc='fixture')
        runtime['full-installer-manifest.json'] = json.dumps(m).encode()
        ui = {'FDSecuritySetupUI.exe': b'ui', 'FDSecuritySetup.exe': b'setup',
              'setup-ui-manifest.json': json.dumps(m).encode()}
        if not candidate:
            runtime['full-installer-manifest.p7s'] = ui['setup-ui-manifest.p7s'] = b'cms'
        for suffix, files in [('exe.zip', runtime), ('setup-ui.zip', ui)]:
            with zipfile.ZipFile(assets / (prefix+suffix), 'w') as z:
                for name, value in files.items():
                    z.writestr(name, value)
        for suffix, value in [('FDSensor.exe', b'sensor'), ('setup.exe', b'setup')]:
            (assets / (prefix+suffix)).write_bytes(value)
        signature = dict(status='unsigned') if candidate else dict(status='signed', format='cms-detached-sha256', signer_thumbprint=PIN, signer_subject='publisher')
        entries = [dict(name=p.name, sha256=cp.digest(p), size=p.stat().st_size) for p in assets.iterdir()]
        manifest = dict(version='3.2.999', build_provenance=SOURCE, signature=signature, artifacts=entries)
        (assets / (prefix+'artifact-manifest.json')).write_text(json.dumps(manifest))
        if not candidate:
            (assets / (prefix+'artifact-manifest.json.p7s')).write_bytes(b'cms')
        cp.seal(assets, SOURCE, 'arm64', candidate=candidate)
        return assets

    def test_candidate_cannot_be_uploaded_as_signed_release(self):
        a = self.fixture()
        with self.assertRaises(ValueError):
            cp.verify_checkpoint(a, SOURCE, 'arm64')
        bundle.stage(a, self.root/'stage', SOURCE, 'arm64', True)

    def test_source_mismatch_and_corrupted_input_rejected(self):
        a = self.fixture()
        with self.assertRaises(ValueError):
            cp.verify_checkpoint(a, dict(SOURCE, commit='b'*40), 'arm64', candidate=True)
        next(a.glob('*FDSensor.exe')).write_bytes(b'changed')
        with self.assertRaises(ValueError):
            bundle.stage(a, self.root/'stage', SOURCE, 'arm64', True)

    def test_signature_only_data_changes_and_absent_optional_collector(self):
        for candidate, name in [(True, 'before'), (False, 'after')]:
            bundle.stage(self.fixture(candidate), self.root/name, SOURCE, 'arm64', candidate)
        bundle.compare(self.root/'before', self.root/'after', PIN, 'publisher')
        (self.root/'after/runtime/data.bin').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'immutable'):
            bundle.compare(self.root/'before', self.root/'after', PIN, 'publisher')

    def test_archive_rejects_traversal_ads_duplicate_case_and_links(self):
        for names in (['../escape'], ['/absolute'], ['C:/absolute'], ['ok', 'OK'], ['a:stream'], ['CON.txt'], ['dir/../escape']):
            with self.subTest(names=names):
                archive = self.root/'bad.zip'
                with zipfile.ZipFile(archive, 'w') as z:
                    for name in names:
                        z.writestr(name, b'bad')
                with self.assertRaises(ValueError):
                    bundle.unpack(archive, self.root/'expanded')
                self.assertFalse((self.root/'expanded').exists())
        with zipfile.ZipFile(self.root/'bad.zip', 'w') as z:
            info = zipfile.ZipInfo('link')
            info.external_attr = 0o120777 << 16
            z.writestr(info, 'target')
        with self.assertRaises(ValueError):
            bundle.unpack(self.root/'bad.zip', self.root/'expanded')

    def test_metadata_changes_outside_signing_rejected(self):
        for candidate, name in [(True, 'before'), (False, 'after')]:
            bundle.stage(self.fixture(candidate), self.root/name, SOURCE, 'arm64', candidate)
        path = self.root/'after/ui/setup-ui-manifest.json'
        m = bundle.read(path)
        m['preserves_existing_identity'] = False
        path.write_text(json.dumps(m))
        with self.assertRaisesRegex(ValueError, 'Installer contract'):
            bundle.compare(self.root/'before', self.root/'after', PIN, 'publisher')

    def test_usb_final_resume_checks_both_architectures(self):
        from unittest.mock import patch
        api = cp.GitHub(bridge.SOURCE)
        with patch.object(api, 'call', return_value=json.dumps([{'artifacts': []}])):
            self.assertFalse(cp.restore_usb_final(api, self.root/'final', SOURCE))
        for expired in (True, False):
            count = 1 if expired else 2
            with patch.object(api, 'call', return_value=json.dumps([{'artifacts': [dict(name='usb-verified-final', expired=expired)]*count}])):
                with self.assertRaises(ValueError):
                    cp.restore_usb_final(api, self.root/'final', SOURCE)


class AdmissionTests(unittest.TestCase):
    def source(self):
        return dict(repository=dict(full_name=bridge.SOURCE), head_repository=dict(full_name=bridge.SOURCE),
                    path=bridge.RELEASE_WORKFLOW, id=1234, run_attempt=2, head_sha='a'*40,
                    status='in_progress', event='push', head_branch='win_3.2.999')

    def test_release_origin_and_current_attempt(self):
        info = self.source()
        bridge.validate_source('1234', '2', 'a'*40, '3.2.999', info)
        for field, value in [('status','completed'), ('run_attempt',1), ('event','pull_request'),
                             ('head_branch','main'), ('head_sha','b'*40), ('path','arbitrary.yml'),
                             ('head_repository',dict(full_name='attacker/fork'))]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                bridge.validate_source('1234', '2', 'a'*40, '3.2.999', dict(info, **{field:value}))
        for branch in bridge.RELEASE_BRANCHES:
            bridge.validate_source('1234', '2', 'a'*40, '3.2.999', dict(info, event='workflow_dispatch', head_branch=branch))
        with self.assertRaises(ValueError):
            bridge.validate_source('1234', '2', 'a'*40, '3.2.999', dict(info, event='workflow_dispatch', head_branch='untrusted-feature'))

    def test_exact_two_immutable_artifacts(self):
        items = [dict(name='release-input-'+a, id=i, expired=False,
                      workflow_run=dict(id=1234, head_sha='a'*40)) for i,a in enumerate(('amd64','arm64'),1)]
        self.assertEqual(bridge.select_artifacts(items, '1234', 'a'*40), ['1','2'])
        for invalid in (items[:1], items+items[:1], [dict(items[0], expired=True),items[1]]):
            with self.assertRaises(ValueError):
                bridge.select_artifacts(invalid, '1234', 'a'*40)

    def test_dispatch_once_and_cancel_when_hardware_queue_exceeds_deadline(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        args = SimpleNamespace(run='1234', attempt='2', commit='a'*40, version='3.2.999')
        request = 'b'*32
        calls = []
        def api(path, data=None):
            calls.append((path, data))
            if path.endswith('/dispatches') or path.endswith('/cancel'):
                return None
            if path == f'repos/{bridge.SOURCE}/actions/runs/1234':
                return self.source()
            if '/workflows/sign.yml/runs?' in path:
                return {'workflow_runs':[dict(id=99, display_title=bridge.title('1234','2',request))]}
            if path.endswith('/jobs?per_page=100'):
                return {'jobs':[dict(name='finalize',status='queued',conclusion=None)]}
            return dict(status='in_progress')
        with patch.object(bridge, 'api', side_effect=api), patch.object(bridge.uuid, 'uuid4', return_value=SimpleNamespace(hex=request)), \
             patch.object(bridge.signal, 'signal'), patch.object(bridge.time, 'sleep'), \
             patch.object(bridge.time, 'monotonic', side_effect=[1,2,3,304,305]):
            with self.assertRaisesRegex(TimeoutError, 'queued for 5 minutes'):
                bridge.dispatch(args)
        self.assertEqual(sum(p.endswith('/dispatches') for p,_ in calls), 1)
        self.assertEqual(sum(p.endswith('/cancel') for p,_ in calls), 1)


if __name__ == '__main__':
    unittest.main()
