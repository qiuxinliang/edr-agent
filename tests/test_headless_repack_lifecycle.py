"""Behavioral coverage of the no-build Headless lifecycle trust boundary."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('headless_lifecycle', SCRIPTS / 'headless_repack_lifecycle.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def asset(name, data=b'payload', identity=1):
    return dict(id=identity, name=name, size=len(data), digest='sha256:' + hashlib.sha256(data).hexdigest(), state='uploaded')


def public_fixture():
    owner = dict(repository=m.PUBLIC, run_id='123', tag='win_3.2.659', commit='a' * 40,
                 mode='unsigned', upgrade_class='installer_required', p0_test_inputs={'sha256': 'b' * 64})
    release = dict(id=789, tag_name=owner['tag'], target_commitish=owner['commit'], draft=False,
                   body='<!-- edr-release-source:' + json.dumps(owner) + ' -->')
    run = dict(id=123, head_sha=owner['commit'], repository={'full_name': m.PUBLIC},
               head_repository={'full_name': m.PUBLIC}, path='.github/workflows/edr-agent-client-release.yml',
               status='completed', conclusion='success', run_attempt=1,
               event='workflow_dispatch', head_branch='codex/ic3-p0-deployment')
    jobs = [dict(name='Build Windows ' + arch + ' (native)', status='completed', conclusion='success', run_attempt=1) for arch in m.ARCHES]
    return owner, release, run, jobs


def transfer_fixture():
    owner, _, _, _ = public_fixture()
    source = dict(owner=owner, attempt='1')
    args = argparse.Namespace(source_tag=owner['tag'], private_run='456', private_attempt='1', private_commit='c' * 40, private_release_id='999')
    executor = dict(repository=m.PRIVATE, run_id='456', attempt='1', commit='c' * 40)
    provenance = dict(schema='edr.published-headless-repack.v1', source=dict(owner, attempt='1'), executor=executor,
                      previous_signature_test={'run_id': '111', 'attempt': '1', 'commit': 'd' * 40}, scope='headless', version='3.2.659')
    transfer = dict(provenance, schema='edr.published-headless-repack-transfer.v1', signer=executor)
    release = dict(id=999, tag_name='edr-usb-headless-repack-456-1', body=m.PREFIX + json.dumps(transfer, sort_keys=True),
                   draft=False, prerelease=True, target_commitish=args.private_commit)
    run = dict(id=456, run_attempt=1, head_sha=args.private_commit, repository={'full_name': m.PRIVATE},
               head_repository={'full_name': m.PRIVATE}, path='.github/workflows/published-headless-repack.yml',
               event='workflow_dispatch', head_branch='main', status='completed', conclusion='success')
    assets = {}
    files = []
    for arch in m.ARCHES:
        for suffix in m.SUFFIXES:
            name = f'edr-agent-win_3.2.659-windows-{arch}-{suffix}'
            item = asset(name, identity=len(assets) + 1)
            assets[name] = item
            files.append(dict(arch=arch, name=name, size=item['size'], sha256=item['digest'][7:]))
    assets['result.json'] = asset('result.json', identity=20)
    receipt = dict(schema='edr.published-headless-repack-result.v1', status='succeeded', installable=True,
                   version='3.2.659', scope='headless', publisher_thumbprint='A' * 40,
                   source=provenance['source'], executor=executor, previous_signature_test=provenance['previous_signature_test'],
                   repack_provenance=provenance, admission_sha256='e' * 64, files=files)
    return args, source, transfer, release, run, receipt, assets


def pe_bytes(arch='amd64', installer=False):
    data = bytearray(768)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<HH', data, 132, 0x14C if installer else m.ARCHES[arch], 1)
    struct.pack_into('<H', data, 148, 240)
    struct.pack_into('<H', data, 152, 0x10B if installer else 0x20B)
    struct.pack_into('<I', data, 212, 512)
    struct.pack_into('<I', data, 244 if installer else 260, 16)
    struct.pack_into('<II', data, 408, 256, 512)
    data[512:] = b'A' * 256
    return bytes(data)


def signed_bytes(data):
    result = bytearray(data)
    struct.pack_into('<I', result, 216, 12345)
    struct.pack_into('<II', result, 296, len(data), 16)
    result += struct.pack('<IHH', 16, 0x200, 2) + b'CERTDATA'
    return bytes(result)


class SourceAdmission(unittest.TestCase):
    def setUp(self):
        self.owner, self.release, self.run, self.jobs = public_fixture()

    def check(self):
        return m.validate_public(self.release, self.run, self.jobs, self.owner['tag'], self.owner['commit'], '123')

    def test_success_is_exact_source(self):
        self.assertEqual(self.check(), self.owner)

    def test_rejects_wrong_sha_status_fork_and_event(self):
        for key, value in [('head_sha', 'f' * 40), ('status', 'in_progress'), ('conclusion', 'failure'),
                           ('event', 'pull_request'), ('head_branch', 'arbitrary'),
                           ('head_repository', {'full_name': 'other/fork'})]:
            with self.subTest(key=key):
                original = self.run[key]
                self.run[key] = value
                with self.assertRaises(ValueError): self.check()
                self.run[key] = original

    def test_push_only_exact_release_tag(self):
        self.run.update(event='push', head_branch=self.owner['tag'])
        self.check()
        self.run['head_branch'] = 'main'
        with self.assertRaises(ValueError): self.check()

    def test_rejects_unsigned_owner_mismatch_and_duplicate_provenance(self):
        self.release['body'] *= 2
        with self.assertRaises(ValueError): self.check()
        self.release['body'] = '<!-- edr-release-source:' + json.dumps(dict(self.owner, mode='usb')) + ' -->'
        with self.assertRaises(ValueError): self.check()

    def test_requires_both_native_build_successes(self):
        self.jobs[1]['conclusion'] = 'skipped'
        with self.assertRaises(ValueError): self.check()
        self.jobs[1]['conclusion'] = 'success'
        self.jobs[1]['run_attempt'] = 2
        with self.assertRaises(ValueError): self.check()

    def test_rejects_moved_public_tag(self):
        responses = [self.release, self.run, {'jobs': self.jobs}, {'object': {'type': 'commit', 'sha': 'f' * 40}}]
        with mock.patch.object(m, 'api', side_effect=responses), self.assertRaisesRegex(ValueError, 'tag moved'):
            m.public_source(self.owner['tag'])


class TransferAdmission(unittest.TestCase):
    def setUp(self):
        self.args, self.source, self.owner, self.release, self.run, self.receipt, self.assets = transfer_fixture()

    def test_exact_transfer_and_result(self):
        self.assertEqual(m.validate_transfer(self.release, self.run, self.args, self.source), self.owner)
        m.validate_result(self.receipt, self.owner, self.assets, '3.2.659', 'A' * 40)

    def test_continuous_delivery_requires_exact_signing_job_and_pinned_baseline(self):
        self.args.baseline_tag='win_3.2.658'
        self.owner['baseline_tag']=self.args.baseline_tag
        self.release['body']=m.PREFIX+json.dumps(self.owner)
        self.run['run_attempt']=2
        job=dict(name='Sign and repackage Headless',status='completed',conclusion='success',run_attempt=1)
        self.assertEqual(m.validate_transfer(self.release,self.run,self.args,self.source,[job]),self.owner)
        for jobs in ([],[job,job],[dict(job,run_attempt=2)],[dict(job,conclusion='failure')],[dict(job,status='in_progress')]):
            with self.subTest(jobs=jobs),self.assertRaises(ValueError):
                m.validate_transfer(self.release,self.run,self.args,self.source,jobs)
        self.args.baseline_tag='win_3.2.657'
        with self.assertRaises(ValueError): m.validate_transfer(self.release,self.run,self.args,self.source,[job])

    def test_refuses_stale_partial_or_foreign_private_run(self):
        for key, value in [('run_attempt', 2), ('conclusion', 'failure'), ('status', 'in_progress'),
                           ('path', '.github/workflows/sign.yml'), ('head_sha', 'f' * 40)]:
            with self.subTest(key=key):
                run = dict(self.run, **{key: value})
                with self.assertRaises(ValueError): m.validate_transfer(self.release, run, self.args, self.source)
        with self.assertRaises(ValueError):
            m.validate_transfer(dict(self.release, draft=True), self.run, self.args, self.source)

    def test_source_unsigned_mode_is_preserved_not_rewritten(self):
        self.owner['source'].pop('mode')
        self.release['body'] = m.PREFIX + json.dumps(self.owner)
        with self.assertRaises(ValueError): m.validate_transfer(self.release, self.run, self.args, self.source)

    def test_test_only_failed_and_missing_inputs_never_installable(self):
        for key, value in [('schema', 'edr.published-headless-signing-test-result.v1'), ('installable', False),
                           ('status', 'failed'), ('scope', 'all'), ('publisher_thumbprint', 'B' * 40)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.validate_result(dict(self.receipt, **{key: value}), self.owner, self.assets, '3.2.659', 'A' * 40)

    def test_exact_ten_payload_inventory_and_official_digest(self):
        self.receipt['files'][0]['sha256'] = 'a' * 64
        with self.assertRaises(ValueError): m.validate_result(self.receipt, self.owner, self.assets, '3.2.659', 'A' * 40)
        self.receipt['files'][0]['sha256'] = self.assets[self.receipt['files'][0]['name']]['digest'][7:]
        self.assets['unexpected.exe'] = asset('unexpected.exe', identity=99)
        with self.assertRaises(ValueError): m.validate_result(self.receipt, self.owner, self.assets, '3.2.659', 'A' * 40)

    def test_official_assets_require_unique_size_digest_and_id(self):
        good = asset('one.zip')
        self.assertEqual(m.checked_assets([good]), {'one.zip': good})
        for key, value in [('digest', None), ('size', 0), ('id', 0), ('state', 'new')]:
            with self.subTest(key=key), self.assertRaises(ValueError): m.checked_assets([dict(good, **{key: value})])
        with self.assertRaises(ValueError): m.checked_assets([good, dict(good, name='ONE.zip', id=2)])

    def test_download_counters_do_not_change_immutable_asset_snapshot(self):
        good = asset('one.zip')
        before = m.checked_assets([dict(good, download_count=0, updated_at='before')])
        after = m.checked_assets([dict(good, download_count=7, updated_at='after')])
        self.assertEqual(before, after)
        for key, value in [('id', 2), ('digest', 'sha256:' + 'b' * 64)]:
            self.assertNotEqual(before, m.checked_assets([dict(good, **{key: value})]))


class LocalPackageChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def runtime_fixture(self):
        directory = self.root / 'runtime'
        directory.mkdir()
        for name in m.NATIVE:
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(pe_bytes())
        (directory / 'edr_agent_setup.exe').write_bytes(pe_bytes(installer=True))
        (directory / 'VERSION').write_text('3.2.659', encoding='utf-8')
        caps = dict(signature_status='unsigned', target_arch='amd64')
        (directory / 'package-capabilities.json').write_text(json.dumps(caps), encoding='utf-8')
        integrity = dict(schema='edr.windows.native-package-integrity.v1',
                         files=[dict(name=n, sha256=m.digest(directory / n)) for n in sorted(m.NATIVE - {'FDSensor.exe'})])
        (directory / 'native-package-integrity.json').write_text(json.dumps(integrity), encoding='utf-8')
        full = dict(version='3.2.659', target_arch='amd64', setup_target_arch='amd64', setup_exe_signed=False,
                    setup_exe_sha256=m.digest(directory / 'edr_agent_setup.exe'), agent_binary_sha256=m.digest(directory / 'FDSensor.exe'),
                    runtime_identity_sha256=m.digest(directory / 'native-package-integrity.json'), capabilities=caps)
        (directory / 'full-installer-manifest.json').write_text(json.dumps(full), encoding='utf-8')
        assets = {f'edr-agent-win_3.2.659-windows-amd64-{suffix}': asset(suffix, (directory / name).read_bytes(), index + 1)
                  for index, (name, suffix) in enumerate([('FDSensor.exe', 'FDSensor.exe'), ('edr_agent_setup.exe', 'setup.exe')])}
        return directory, assets

    def test_runtime_validates_arch_version_and_native_integrity(self):
        directory, assets = self.runtime_fixture()
        self.assertEqual(set(m.runtime_contract(directory, assets, 'win_3.2.659', 'amd64', False)), m.NATIVE)
        (directory / 'VERSION').write_text('3.2.658', encoding='utf-8')
        with self.assertRaises(ValueError): m.runtime_contract(directory, assets, 'win_3.2.659', 'amd64', False)
        (directory / 'VERSION').write_text('3.2.659', encoding='utf-8')
        (directory / 'ARCH').write_text('arm64', encoding='utf-8')
        with self.assertRaises(ValueError): m.runtime_contract(directory, assets, 'win_3.2.659', 'amd64', False)
        (directory / 'ARCH').write_text('amd64', encoding='utf-8')
        (directory / 'uninstall.exe').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'integrity failure'): m.runtime_contract(directory, assets, 'win_3.2.659', 'amd64', False)

    def test_runtime_standalone_identity_is_mandatory(self):
        directory, assets = self.runtime_fixture()
        assets['edr-agent-win_3.2.659-windows-amd64-FDSensor.exe']['digest'] = 'sha256:' + 'b' * 64
        with self.assertRaisesRegex(ValueError, 'standalone'): m.runtime_contract(directory, assets, 'win_3.2.659', 'amd64', False)

    def test_full_installer_hash_binding_is_mandatory(self):
        directory, assets = self.runtime_fixture()
        path = directory / 'full-installer-manifest.json'
        value = m.read(path)
        value['runtime_identity_sha256'] = '0' * 64
        path.write_text(json.dumps(value), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'manifest closure'): m.runtime_contract(directory, assets, 'win_3.2.659', 'amd64', False)

    def installed_fixture(self):
        runtime, _ = self.runtime_fixture()
        root = self.root / 'inputs'
        for label in ('target', 'baseline'):
            shutil.copytree(runtime, root / label / 'runtime')
        (root / 'baseline/runtime/VERSION').write_text('3.2.658', encoding='utf-8')
        source = dict(owner=public_fixture()[0])
        baseline = dict(owner=dict(source['owner'], tag='win_3.2.658'))
        (root / 'admission.json').write_text(json.dumps(dict(schema='edr.headless-lifecycle-input.v1', architecture='amd64', source=source, baseline=baseline)), encoding='utf-8')
        actual = self.root / 'installed'
        shutil.copytree(runtime, actual)
        return argparse.Namespace(root=str(root), install_dir=str(actual), evidence_dir=str(self.root / 'evidence'),
                                  stage='install-target-fresh', expected_version='3.2.659', arch='amd64')

    def test_actual_installed_native_hashes_are_retained_per_stage(self):
        args = self.installed_fixture()
        for stage, version in [('install-target-fresh', '3.2.659'), ('upgrade-target', '3.2.659'),
                               ('install-baseline', '3.2.658'), ('repair-baseline', '3.2.658'), ('rollback-baseline', '3.2.658')]:
            args.stage, args.expected_version = stage, version
            (Path(args.install_dir) / 'VERSION').write_text(version, encoding='utf-8')
            m.installed(args)
            receipt = m.read(Path(args.evidence_dir) / (stage + '.installed-native.json'))
            self.assertEqual(receipt['status'], 'succeeded')
            self.assertEqual(len(receipt['files']), 4)
            self.assertTrue(all(f['actual_sha256'] == f['expected_sha256'] for f in receipt['files']))

    def test_actual_installed_tampering_fails_and_keeps_failure_receipt(self):
        args = self.installed_fixture()
        (Path(args.install_dir) / 'FDSensor.exe').write_bytes(pe_bytes('arm64'))
        with self.assertRaisesRegex(ValueError, 'bytes differ'): m.installed(args)
        receipt = m.read(Path(args.evidence_dir) / 'install-target-fresh.installed-native.json')
        self.assertEqual(receipt['status'], 'failed')
        self.assertTrue(any(f['actual_sha256'] != f['expected_sha256'] for f in receipt['files']))

    def test_installed_checkpoint_cannot_claim_other_stage_or_version(self):
        args = self.installed_fixture()
        args.stage = 'unverified-custom-stage'
        with self.assertRaises(ValueError): m.installed(args)
        args.stage, args.expected_version = 'rollback-baseline', '3.2.659'
        with self.assertRaises(ValueError): m.installed(args)

    def test_ast_adapter_requires_unique_function_and_preserves_old_checks(self):
        executable = os.environ.get('EDR_TEST_POWERSHELL') or shutil.which('pwsh') or shutil.which('powershell')
        if not executable:
            self.skipTest('PowerShell unavailable; run native AST adapter regression on Windows')
        root = self.root / 'adapter'
        root.mkdir()
        (root / 'admission.json').write_text(json.dumps(dict(schema='edr.headless-lifecycle-input.v1', architecture='amd64', publisher_thumbprint='A' * 40, publisher_subject='publisher')), encoding='utf-8')
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        script = ". " + quote(SCRIPTS / 'Verify-HeadlessRepackLifecycle.ps1') + ' -Root ' + quote(root) + " -Architecture amd64 -Thumbprint '" + 'A' * 40 + "' -Subject publisher\n" + r'''
$ErrorActionPreference = 'Stop'
$text = 'function Assert-InstalledRuntime { param([bool]$Fail) if($Fail){throw "original-failure"}; $script:trace.Add("original") }'
$hook = '$script:trace.Add("new-hash-check")'
$script:trace = [Collections.Generic.List[string]]::new()
$augmented = Add-HeadlessInstalledCheck $text $hook
if ($augmented.Replace("`n$hook`n", '') -cne $text) { throw 'Adapter changed original source bytes beyond the additive hook' }
. ([ScriptBlock]::Create($augmented))
Assert-InstalledRuntime $false
if (($script:trace -join ',') -cne 'original,new-hash-check') { throw 'Original assertion did not run before hash check' }
$script:trace.Clear()
try { Assert-InstalledRuntime $true; throw 'Old failure was bypassed' } catch { if($_.Exception.Message -cne 'original-failure'){throw} }
if ($script:trace.Count -ne 0) { throw 'Hash check executed after original assertion failure' }
foreach ($invalid in @('function Other {}', ($text + "`n" + 'function assert-installedruntime {}'))) {
  $rejected = $false
  try { Add-HeadlessInstalledCheck $invalid $hook | Out-Null } catch { $rejected = $true }
  if (-not $rejected) { throw 'Zero or ambiguous assertion function was accepted' }
}
'''
        result = subprocess.run([executable, '-NoProfile', '-NonInteractive', '-Command', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_zip_rejects_unsafe_names_duplicates_and_links(self):
        for index, names in enumerate([['../bad'], ['CON.txt'], ['x:y'], ['a', 'A'], ['a', 'a/b'], ['a/b', 'a']]):
            archive = self.root / f'{index}.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                for name in names: z.writestr(name, b'data')
            with self.subTest(names=names), self.assertRaises(ValueError): m.extract(archive, self.root / f'out{index}')
        archive = self.root / 'link.zip'
        info = zipfile.ZipInfo('link')
        info.external_attr = 0o120777 << 16
        with zipfile.ZipFile(archive, 'w') as z: z.writestr(info, b'../other')
        with self.assertRaises(ValueError): m.extract(archive, self.root / 'linkout')

    def test_zip_raw_backslash_is_rejected_even_on_windows(self):
        archive = self.root / 'raw.zip'
        with zipfile.ZipFile(archive, 'w') as z: z.writestr('a/b', b'contents')
        # Equal-length local+central name replacement defeats ZipInfo's Windows normalization.
        archive.write_bytes(archive.read_bytes().replace(b'a/b', b'a\\b'))
        with self.assertRaises(ValueError): m.extract(archive, self.root / 'out')

    def test_zip_safe_contents_extract_and_cannot_overwrite(self):
        archive = self.root / 'ok.zip'
        with zipfile.ZipFile(archive, 'w') as z: z.writestr('a/b', b'contents')
        m.extract(archive, self.root / 'out')
        self.assertEqual((self.root / 'out/a/b').read_bytes(), b'contents')
        with self.assertRaises(ValueError): m.extract(archive, self.root / 'out')

    def test_native_signed_payload_exact_except_documented_fields(self):
        for arch in m.ARCHES:
            original, signed = self.root / ('original-' + arch), self.root / ('signed-' + arch)
            data = pe_bytes(arch)
            original.write_bytes(data)
            signed.write_bytes(signed_bytes(data))
            m.same_payload(original, signed, arch)
            altered = bytearray(signed.read_bytes()); altered[520] ^= 1; signed.write_bytes(altered)
            with self.assertRaisesRegex(ValueError, 'payload changed'): m.same_payload(original, signed, arch)

    def test_rejects_wrong_arch_and_bad_certificate_bounds(self):
        original, signed = self.root / 'original', self.root / 'signed'
        original.write_bytes(pe_bytes())
        signed.write_bytes(signed_bytes(pe_bytes()))
        with self.assertRaises(ValueError): m.same_payload(original, signed, 'arm64')
        changed = bytearray(signed.read_bytes()); struct.pack_into('<I', changed, 768, 1000); signed.write_bytes(changed)
        with self.assertRaises(ValueError): m.same_payload(original, signed, 'amd64')

    def test_manifest_requires_original_source_and_exact_headless_assets(self):
        args, source, _, _, _, receipt, assets = transfer_fixture()
        prefix = 'edr-agent-win_3.2.659-windows-amd64-'
        value = dict(version='3.2.659', build_provenance=source['owner'], repack_provenance=receipt['repack_provenance'],
                     signature=dict(format='cms-detached-sha256', status='signed', authenticode_scope='headless', signer_thumbprint='A' * 40, signer_subject='publisher'),
                     artifacts=[dict(name=prefix + suffix, size=assets[prefix + suffix]['size'], sha256=assets[prefix + suffix]['digest'][7:]) for suffix in ('exe.zip','setup.exe','FDSensor.exe')])
        path = self.root / 'manifest.json'
        path.write_text(json.dumps(value), encoding='utf-8')
        m.manifest_contract(path, assets, source, '3.2.659', 'amd64', receipt, 'A' * 40, 'publisher')
        value['artifacts'][0]['sha256'] = 'e' * 64
        path.write_text(json.dumps(value), encoding='utf-8')
        with self.assertRaises(ValueError): m.manifest_contract(path, assets, source, '3.2.659', 'amd64', receipt, 'A' * 40, 'publisher')

    def test_repack_cannot_change_unrelated_update_policy(self):
        _, source, _, _, _, receipt, assets = transfer_fixture()
        prefix = 'edr-agent-win_3.2.659-windows-amd64-'
        original = dict(version='3.2.659', build_provenance=source['owner'], signature={'status': 'unsigned'},
                        runtime_capabilities={'some_existing_capability': True}, artifacts=[])
        for suffix in ('exe.zip', 'setup.exe', 'FDSensor.exe', 'setup-ui.zip'):
            entry = dict(name=prefix + suffix, size=123, sha256='f' * 64)
            if suffix == 'FDSensor.exe': entry['update'] = dict(upgrade_class='installer_required', runtime_identity_sha256='e' * 64, min_current_version='0.0.0')
            original['artifacts'].append(entry)
        (self.root / 'native-package-integrity.json').write_text('{}', encoding='utf-8')
        target = copy.deepcopy(original)
        target['signature'] = dict(format='cms-detached-sha256', status='signed', authenticode_scope='headless', signer_thumbprint='A' * 40, signer_subject='publisher')
        target['repack_provenance'] = receipt['repack_provenance']
        target['artifacts'] = target['artifacts'][:3]
        for entry in target['artifacts']:
            item = assets[entry['name']]
            entry.update(size=item['size'], sha256=item['digest'][7:])
            if entry['name'].endswith('-FDSensor.exe'): entry['update']['runtime_identity_sha256'] = m.digest(self.root / 'native-package-integrity.json')
        before, after = self.root / 'before.json', self.root / 'after.json'
        before.write_text(json.dumps(original), encoding='utf-8'); after.write_text(json.dumps(target), encoding='utf-8')
        m.compare_artifact_manifest(before, after, self.root, receipt, assets, '3.2.659', 'amd64', 'A' * 40, 'publisher')
        target['artifacts'][2]['update']['min_current_version'] = '3.2.659'
        after.write_text(json.dumps(target), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'unrelated artifact/update'):
            m.compare_artifact_manifest(before, after, self.root, receipt, assets, '3.2.659', 'amd64', 'A' * 40, 'publisher')

    def test_failed_public_download_never_accepts_partial(self):
        destination = self.root / 'download.zip'
        item = asset('download.zip')
        def incomplete(command, **kwargs):
            kwargs['stdout'].write(b'wrong')
            return argparse.Namespace(returncode=0)
        with mock.patch.object(m.subprocess, 'run', side_effect=incomplete), self.assertRaisesRegex(ValueError, 'size/digest'):
            m.fetch(m.PUBLIC, item, destination)
        self.assertFalse(destination.exists())
        self.assertFalse(destination.with_name(destination.name + '.partial').exists())

    def test_private_token_is_restored_after_download_failure(self):
        import os
        with mock.patch.dict(os.environ, {'GH_TOKEN': 'actions-sentinel', 'USB_SIGNING_RELEASE_TOKEN': 'contents-sentinel'}):
            def fail(*args):
                self.assertEqual(os.environ['GH_TOKEN'], 'contents-sentinel')
                raise RuntimeError('transport failure')
            with mock.patch.object(m, 'download_asset', side_effect=fail), self.assertRaises(RuntimeError):
                m.fetch(m.PRIVATE, asset('x.zip'), self.root / 'x.zip')
            self.assertEqual(os.environ['GH_TOKEN'], 'actions-sentinel')


if __name__ == '__main__':
    unittest.main()
