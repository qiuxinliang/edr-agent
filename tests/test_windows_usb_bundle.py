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
        if not candidate:
            for name in bundle.NATIVE & runtime.keys():
                runtime[name] += b'-signed'
            runtime['edr_agent_setup.exe'] = b'repacked-setup-signed'
        ui_setup = b'setup' if candidate else b'repacked-setup'
        status = 'unsigned' if candidate else 'signed'
        caps = dict(signature_status=status)
        runtime['package-capabilities.json'] = json.dumps(caps).encode()
        native = dict(schema='edr.windows.native-package-integrity.v1', files=[
            dict(name=n, sha256=cp.hashlib.sha256(v).hexdigest()) for n, v in runtime.items() if n in bundle.NATIVE])
        runtime['native-package-integrity.json'] = json.dumps(native).encode()
        m = dict(version='3.2.999', target_arch='arm64', setup_target_arch='arm64', capabilities=dict(signature_status='unsigned'),
                 ui_exe_sha256=cp.hashlib.sha256(b'ui').hexdigest(), setup_exe_sha256=cp.hashlib.sha256(ui_setup).hexdigest(),
                 agent_binary_sha256=cp.hashlib.sha256(runtime['FDSensor.exe']).hexdigest(),
                 runtime_identity_sha256=cp.hashlib.sha256(runtime['native-package-integrity.json']).hexdigest(),
                 publisher_thumbprint='' if candidate else PIN, setup_exe_signed=False,
                 ui_exe_signed=False, generated_at_utc='fixture', upgrade_protocol='edr.windows.full-installer-upgrade.v1',
                 preserves_existing_identity=True, preserves_offline_queue=True, preserves_evidence_cache=True)
        full = copy.deepcopy(m)
        if not candidate:
            full = {key: m[key] for key in ('version', 'target_arch', 'setup_target_arch', 'agent_binary_sha256',
                                           'runtime_identity_sha256', 'publisher_thumbprint', 'generated_at_utc',
                                           'upgrade_protocol', 'preserves_existing_identity', 'preserves_offline_queue',
                                           'preserves_evidence_cache')}
            full.update(name='FDSecurity Headless Installer', setup_exe='FDSecuritySetup.exe', setup_exe_signed=True,
                        setup_exe_sha256=cp.hashlib.sha256(runtime['edr_agent_setup.exe']).hexdigest(), capabilities=caps)
        runtime['full-installer-manifest.json'] = json.dumps(full).encode()
        ui = {'FDSecuritySetupUI.exe': b'ui', 'FDSecuritySetup.exe': ui_setup,
              'setup-ui-manifest.json': json.dumps(m).encode()}
        if not candidate:
            runtime['full-installer-manifest.p7s'] = b'headless-cms'
            ui['setup-ui-manifest.p7s'] = b'ui-cms'
        for suffix, files in [('exe.zip', runtime), ('setup-ui.zip', ui)]:
            with zipfile.ZipFile(assets / (prefix+suffix), 'w') as z:
                for name, value in files.items():
                    z.writestr(name, value)
        for suffix, value in [('FDSensor.exe', runtime['FDSensor.exe']), ('setup.exe', runtime['edr_agent_setup.exe'])]:
            (assets / (prefix+suffix)).write_bytes(value)
        signature = dict(status='unsigned') if candidate else dict(status='signed', authenticode_scope='headless', format='cms-detached-sha256', signer_thumbprint=PIN, signer_subject='publisher')
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

    def test_unsigned_ui_wrapper_is_immutable(self):
        for candidate, name in [(True, 'before'), (False, 'after')]:
            bundle.stage(self.fixture(candidate), self.root/name, SOURCE, 'arm64', candidate)
        path = self.root/'after/ui/FDSecuritySetupUI.exe'
        path.write_bytes(b'ui-signed-or-replaced')
        with self.assertRaisesRegex(ValueError, 'immutable'):
            bundle.compare(self.root/'before', self.root/'after', PIN, 'publisher')

    def test_ui_entry_point_signature_claim_cannot_change(self):
        for candidate, name in [(True, 'before'), (False, 'after')]:
            bundle.stage(self.fixture(candidate), self.root/name, SOURCE, 'arm64', candidate)
        path = self.root/'after/ui/setup-ui-manifest.json'
        manifest = bundle.read(path)
        for key in ('ui_exe_signed', 'setup_exe_signed'):
            invalid = dict(manifest, **{key: True})
            path.write_text(json.dumps(invalid))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'Installer contract'):
                bundle.compare(self.root/'before', self.root/'after', PIN, 'publisher')
        invalid = copy.deepcopy(manifest)
        invalid['capabilities']['signature_status'] = 'signed'
        path.write_text(json.dumps(invalid))
        with self.assertRaisesRegex(ValueError, 'Installer contract'):
            bundle.compare(self.root/'before', self.root/'after', PIN, 'publisher')

    def test_headless_manifest_independently_binds_signed_setup_and_preservation(self):
        for candidate, name in [(True, 'before'), (False, 'after')]:
            bundle.stage(self.fixture(candidate), self.root/name, SOURCE, 'arm64', candidate)
        path = self.root/'after/runtime/full-installer-manifest.json'
        manifest = bundle.read(path)
        self.assertNotIn('ui_exe_sha256', manifest)
        self.assertNotEqual(manifest['setup_exe_sha256'], bundle.read(self.root/'after/ui/setup-ui-manifest.json')['setup_exe_sha256'])
        for key, value in (('setup_exe_signed', False), ('preserves_offline_queue', False),
                           ('setup_exe_sha256', '0'*64), ('publisher_thumbprint', 'B'*40), ('ui_exe_signed', True)):
            path.write_text(json.dumps(dict(manifest, **{key: value})))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'Headless installer contract'):
                bundle.compare(self.root/'before', self.root/'after', PIN, 'publisher')

    def test_ui_manifest_hashes_are_bound_to_current_signed_runtime(self):
        assets = self.fixture(False)
        archive = next(assets.glob('*setup-ui.zip'))
        with zipfile.ZipFile(archive) as z:
            entries = {info.filename: z.read(info) for info in z.infolist()}
        manifest = json.loads(entries['setup-ui-manifest.json'])
        manifest['agent_binary_sha256'] = cp.hashlib.sha256(b'sensor').hexdigest()
        entries['setup-ui-manifest.json'] = json.dumps(manifest).encode()
        with zipfile.ZipFile(archive, 'w') as z:
            for name, value in entries.items():
                z.writestr(name, value)
        release_path = next(assets.glob('*artifact-manifest.json'))
        release = bundle.read(release_path)
        for entry in release['artifacts']:
            p = assets / entry['name']
            entry.update(sha256=cp.digest(p), size=p.stat().st_size)
        release_path.write_text(json.dumps(release))
        cp.seal(assets, SOURCE, 'arm64')
        with self.assertRaisesRegex(ValueError, 'agent_binary_sha256'):
            bundle.stage(assets, self.root/'after', SOURCE, 'arm64', False)

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

    def artifacts(self):
        return [dict(name='release-input-'+arch, id=artifact_id, expired=False,
                     size_in_bytes=1024, digest='sha256:'+str(artifact_id)*64,
                     workflow_run=dict(id=1234, head_sha='a'*40))
                for artifact_id, arch in enumerate(('amd64', 'arm64'), 1)]

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
        items = self.artifacts()
        self.assertEqual(bridge.select_artifacts(items, '1234', 'a'*40), ['1','2'])
        for invalid in (items[:1], items+items[:1], [dict(items[0], expired=True),items[1]]):
            with self.assertRaises(ValueError):
                bridge.select_artifacts(invalid, '1234', 'a'*40)
        for key, value in (('id', True), ('size_in_bytes', 0), ('size_in_bytes', '1024'),
                           ('digest', None), ('digest', 'sha256:invalid'),
                           ('workflow_run', dict(id=1235, head_sha='a'*40)),
                           ('workflow_run', dict(id=1234, head_sha='b'*40))):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                bridge.select_artifacts([dict(items[0], **{key: value}), items[1]], '1234', 'a'*40)

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
            if path == f'repos/{bridge.SOURCE}/actions/runs/1234/artifacts?per_page=100&page=1':
                return {'total_count': 2, 'artifacts': self.artifacts()}
            if '/workflows/sign.yml/runs?' in path:
                return {'workflow_runs':[dict(id=99, display_title=bridge.title('1234','2',request))]}
            if path.endswith('/jobs?per_page=100'):
                return {'jobs':[dict(name='finalize',status='queued',conclusion=None)]}
            if path == f'repos/{bridge.SIGNER}/actions/runs/99':
                return dict(repository=dict(full_name=bridge.SIGNER), head_repository=dict(full_name=bridge.SIGNER),
                            path='.github/workflows/sign.yml', event='workflow_dispatch', head_branch='main',
                            id=99, run_attempt=1, head_sha='c'*40, status='in_progress',
                            display_title=bridge.title('1234','2',request))
            raise AssertionError('Unexpected GitHub API request: ' + path)
        with patch.object(bridge, 'api', side_effect=api), patch.object(bridge.uuid, 'uuid4', return_value=SimpleNamespace(hex=request)), \
             patch.object(bridge.signal, 'signal'), patch.object(bridge.time, 'sleep'), \
             patch.dict(bridge.os.environ, dict(RECOVERY_MODE='false', EXECUTOR_RUN='', EXECUTOR_ATTEMPT='', EXECUTOR_COMMIT='')), \
             patch.object(bridge.time, 'monotonic', side_effect=[1,2,3,304,305]):
            with self.assertRaisesRegex(TimeoutError, 'queued for 5 minutes'):
                bridge.dispatch(args)
        self.assertEqual(sum(p.endswith('/dispatches') for p,_ in calls), 1)
        self.assertEqual(sum(p.endswith('/cancel') for p,_ in calls), 1)
        self.assertIn((f'repos/{bridge.SIGNER}/actions/runs/99/cancel', {}), calls)


if __name__ == '__main__':
    unittest.main()
