"""Fixed media/identity/routing boundaries; no setup, network or signing."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
import exact_installed_742_747 as exact


def request():
    value={'schema':exact.SCHEMA}
    for label,version in [('source','3.2.742'),('target','3.2.747')]:
        prefix='edr-agent-win_'+version+'-windows-arm64-';items={a['name']:a for a in exact.ASSETS[label]}
        value[label+'_publisher_proof']=dict(schema='edr.windows.publisher-verification.v1',arch='arm64',version=version,
            verifier_source_commit=exact.checkpoint.PUBLISHER_VERIFIER_COMMIT,thumbprint=exact.THUMBPRINT,
            subject_der_sha256=exact.DER_SHA,subject='CN=fixture metadata; no cryptographic proof fabricated',
            manifest_sha256=items[prefix+'artifact-manifest.json']['digest'][7:],
            signature_sha256=items[prefix+'artifact-manifest.json.p7s']['digest'][7:],
            artifact_sha256=items[prefix+'FDSensor.exe']['digest'][7:])
    return value


class BoundaryTests(unittest.TestCase):
    def test_fixed_request_and_rejections(self):
        exact.validate_request(request())
        for label in ('source','target'):
            for field,bad in [('arch','amd64'),('version','3.2.738'),('verifier_source_commit','f'*40),
                ('thumbprint','A'*40),('subject_der_sha256','0'*64),('artifact_sha256','0'*64),
                ('signature_sha256','0'*64),('manifest_sha256','0'*64)]:
                value=request();value[label+'_publisher_proof'][field]=bad
                with self.subTest(label=label,field=field),self.assertRaises(ValueError):exact.validate_request(value)
        value=request();value['legacy_tag']='win_3.2.723'
        with self.assertRaises(ValueError):exact.validate_request(value)

    def test_route_is_explicit_and_mutually_exclusive(self):
        env=dict(GITHUB_EVENT_NAME='workflow_dispatch',LIFECYCLE_PACKAGE_SCOPE='full',
            LIFECYCLE_ARCHITECTURE='arm64',LIFECYCLE_TARGET_TAG='win_3.2.747',LIFECYCLE_BASELINE_TAG='win_3.2.742')
        raw=json.dumps(request());exact.validate_routing(raw,env)
        self.assertIsNone(exact.validate_routing('',{}))
        for field,bad in [('GITHUB_EVENT_NAME','workflow_call'),('LIFECYCLE_ARCHITECTURE','all'),
            ('LIFECYCLE_PACKAGE_SCOPE','headless'),('LIFECYCLE_TARGET_TAG','win_3.2.748'),
            ('LIFECYCLE_BASELINE_TAG','win_3.2.687'),('CACHE_RECOVERY_SUBSET','true'),
            ('PUBLISHER_VALIDATION_REQUEST','legacy'),('PUBLISHER_VERIFICATION_JSON','{}')]:
            with self.subTest(field=field),self.assertRaises(ValueError):exact.validate_routing(raw,{**env,field:bad})
        with self.assertRaisesRegex(ValueError,'Duplicate'):exact.validate_routing('{"schema":"duplicate",'+raw[1:],env)

    def test_late_health_flag_cannot_be_ignored_or_mix_other_modes(self):
        env=dict(GITHUB_EVENT_NAME='workflow_dispatch',LIFECYCLE_PACKAGE_SCOPE='full',LIFECYCLE_ARCHITECTURE='arm64',LIFECYCLE_TARGET_TAG='win_3.2.747',LIFECYCLE_BASELINE_TAG='win_3.2.742',EXACT742_LATE_HEALTH_RECOVERY='true')
        raw=json.dumps(request());exact.validate_routing(raw,env)
        with self.assertRaises(ValueError):exact.validate_routing('',env)
        for key,bad in [('EXACT742_LATE_HEALTH_RECOVERY','yes'),('INSTALLER_TIMEOUT_RECOVERY','true'),('NATIVE_REPEAT_COUNT','2'),('GITHUB_EVENT_NAME','workflow_call'),('LIFECYCLE_ARCHITECTURE','amd64'),('LIFECYCLE_TARGET_TAG','win_3.2.748')]:
            with self.subTest(field=key),self.assertRaises(ValueError):exact.validate_routing(raw,{**env,key:bad})
        with patch.dict(os.environ,{'EXACT742_LATE_HEALTH_RECOVERY':'true','EDR_RELEASE_PACKAGE_SCOPE':'full'},clear=True),patch.object(sys,'argv',['checkpoint','validate-publisher-routing','--tag','win_3.2.747']):
            with self.assertRaisesRegex(ValueError,'explicit exact'):exact.checkpoint.main()

    def test_maintenance_flag_is_fixed_exclusive_and_never_ignored(self):
        env=dict(GITHUB_EVENT_NAME='workflow_dispatch',LIFECYCLE_PACKAGE_SCOPE='full',LIFECYCLE_ARCHITECTURE='arm64',LIFECYCLE_TARGET_TAG='win_3.2.747',LIFECYCLE_BASELINE_TAG='win_3.2.742',EXACT742_SETUP_MAINTENANCE_RECOVERY='true')
        raw=json.dumps(request());exact.validate_routing(raw,env)
        with self.assertRaises(ValueError):exact.validate_routing('',env)
        for key,bad in [('EXACT742_SETUP_MAINTENANCE_RECOVERY','yes'),('EXACT742_LATE_HEALTH_RECOVERY','true'),('INSTALLER_TIMEOUT_RECOVERY','true'),('NATIVE_REPEAT_COUNT','2'),('GITHUB_EVENT_NAME','workflow_call'),('LIFECYCLE_ARCHITECTURE','amd64'),('LIFECYCLE_TARGET_TAG','win_3.2.748'),('LIFECYCLE_BASELINE_TAG','win_3.2.687'),('PUBLISHER_VALIDATION_REQUEST','legacy'),('CACHE_RECOVERY_SUBSET','true')]:
            with self.subTest(field=key),self.assertRaises(ValueError):exact.validate_routing(raw,{**env,key:bad})
        with patch.dict(os.environ,{'EXACT742_SETUP_MAINTENANCE_RECOVERY':'true','EDR_RELEASE_PACKAGE_SCOPE':'full'},clear=True),patch.object(sys,'argv',['checkpoint','validate-publisher-routing','--tag','win_3.2.747']):
            with self.assertRaisesRegex(ValueError,'explicit exact'):exact.checkpoint.main()
        self.assertIsNone(exact.validate_routing('',{'EXACT742_SETUP_MAINTENANCE_RECOVERY':'false','EXACT742_LATE_HEALTH_RECOVERY':'false'}))

    def test_storage_requires_explicit_exact_maintenance_case(self):
        env=dict(GITHUB_EVENT_NAME='workflow_dispatch',LIFECYCLE_PACKAGE_SCOPE='full',LIFECYCLE_ARCHITECTURE='arm64',LIFECYCLE_TARGET_TAG='win_3.2.747',LIFECYCLE_BASELINE_TAG='win_3.2.742',EXACT742_SETUP_MAINTENANCE_RECOVERY='true',EXACT742_STORAGE_READBACK='true')
        raw=json.dumps(request());exact.validate_routing(raw,env)
        for key,value in [('EXACT742_STORAGE_READBACK','yes'),('EXACT742_SETUP_MAINTENANCE_RECOVERY','false'),('EXACT742_LATE_HEALTH_RECOVERY','true'),('LIFECYCLE_ARCHITECTURE','amd64'),('LIFECYCLE_TARGET_TAG','win_3.2.748'),('NATIVE_REPEAT_COUNT','2')]:
            with self.subTest(key=key),self.assertRaises(ValueError):exact.validate_routing(raw,{**env,key:value})
        with self.assertRaises(ValueError):exact.validate_routing('',env)
        with patch.dict(os.environ,{'EXACT742_STORAGE_READBACK':'true','EDR_RELEASE_PACKAGE_SCOPE':'full'},clear=True),patch.object(sys,'argv',['checkpoint','validate-publisher-routing','--tag','win_3.2.747']):
            with self.assertRaisesRegex(ValueError,'explicit Setup'):exact.checkpoint.main()

    def test_exact_historical_signers_and_asset_set(self):
        for label in ('source','target'):
            rid,tag=exact.RELEASES[label]
            release=dict(id=rid,tag_name=tag,draft=False,prerelease=True,
                body='edr-private-transfer-v1\n'+json.dumps(exact.OWNERS[label]),
                assets=[{**a,'state':'uploaded'} for a in exact.ASSETS[label]])
            exact.validate_release(label,release)
            mutations=[('id',rid+1),('draft',True),('tag_name','wrong'),('body','edr-private-transfer-v1\n{}')]
            for key,bad in mutations:
                with self.subTest(label=label,key=key),self.assertRaises(ValueError):exact.validate_release(label,{**release,key:bad})
            for field in ('id','size','digest'):
                wrong=copy.deepcopy(release);wrong['assets'][0][field]=0 if field!='digest' else 'sha256:'+'0'*64
                with self.subTest(label=label,asset_field=field),self.assertRaises(ValueError):exact.validate_release(label,wrong)
            with self.assertRaises(ValueError):exact.validate_release(label,{**release,'assets':release['assets'][:-1]})

    def test_official_assets_are_not_changed_and_no_setup_can_run_on_rejection(self):
        with tempfile.TemporaryDirectory() as d,patch.object(exact.io_owner,'api') as api,patch.object(exact.io_owner,'fetch') as fetch:
            bad=request();bad['target_publisher_proof']['artifact_sha256']='0'*64
            with self.assertRaises(ValueError):exact.stage(bad,Path(d)/'inputs')
            api.assert_not_called();fetch.assert_not_called();self.assertFalse((Path(d)/'inputs').exists())

    def test_rejected_private_release_does_not_create_stage(self):
        with tempfile.TemporaryDirectory() as d,patch.object(exact.io_owner,'api',return_value={}),patch.object(exact.io_owner,'fetch') as fetch:
            with self.assertRaises(ValueError):exact.stage(request(),Path(d)/'inputs')
            fetch.assert_not_called()
            self.assertFalse((Path(d)/'inputs').exists())


class FirstHopBoundaryTests(unittest.TestCase):
    def fixture(self):
        env=dict(GITHUB_ACTIONS='true',RUNNER_ENVIRONMENT='github-hosted',RUNNER_ARCH='ARM64',
                 GITHUB_SHA='a'*40,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2',GITHUB_JOB='exact742')
        source={a['name']:a for a in exact.ASSETS['source']}
        identity=dict(install_dir=exact.INSTALL_DIR,runtime_mode='scheduled_task',
            agent_sha256=source['edr-agent-win_3.2.742-windows-arm64-FDSensor.exe']['digest'][7:],
            updater_sha256=exact.UPDATER_SHA,launcher_sha256=exact.LAUNCHER_SHA,native_integrity_sha256=exact.INTEGRITY_SHA)
        receipt=dict(schema='edr.exact-installed742.qualification-result.v1',complete=True,qualification_only=True,
            full_gate=False,full_gate_passed=False,deployment_authorized=False,source_version='3.2.742',target_version='3.2.747',
            architecture='arm64',runner_environment='github-hosted',harness_commit=env['GITHUB_SHA'],run_id='123',run_attempt='2',job='exact742',
            consumer_identity=identity,source_setup_sha256=source['edr-agent-win_3.2.742-windows-arm64-setup.exe']['digest'][7:],
            setup_output={k:identity[k] for k in ('updater_sha256','launcher_sha256','native_integrity_sha256')},
            config_sha256='b'*64,task_owner=dict(mode='scheduled_task',name='FDSecurityAgent',path='\\',xml='actual task XML',sddl='actual SDDL'),
            uninstall=dict(version='3.2.742',location=exact.INSTALL_DIR,key='actual key'))
        return receipt,env

    def test_only_same_fresh_hosted_arm_actual_setup_receipt(self):
        receipt,env=self.fixture();self.assertEqual(exact.qualification_consumer(receipt,env),receipt['consumer_identity'])
        for key,value in [('harness_commit','c'*40),('run_id','999'),('run_attempt','1'),('job','old-job'),
                ('runner_environment','self-hosted'),('architecture','amd64'),('target_version','3.2.748'),
                ('complete',False),('full_gate',True),('deployment_authorized',True),('config_sha256',''),
                ('source_setup_sha256','0'*64),('setup_output',{}),('task_owner',{}),('uninstall',{})]:
            with self.subTest(field=key),self.assertRaises(ValueError):exact.qualification_consumer({**receipt,key:value},env)
        for field in receipt['consumer_identity']:
            bad=copy.deepcopy(receipt);bad['consumer_identity'][field]='wrong'
            with self.subTest(identity=field),self.assertRaises(ValueError):exact.qualification_consumer(bad,env)
        for key,value in [('GITHUB_ACTIONS','false'),('RUNNER_ENVIRONMENT','self-hosted'),('RUNNER_ARCH','X64'),('GITHUB_SHA','')]:
            with self.subTest(environment=key),self.assertRaises(ValueError):exact.qualification_consumer(receipt,{**env,key:value})

    def test_pinned_file_rejects_changed_empty_symlink_or_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input';path.write_bytes(b'fixed')
            sha=hashlib.sha256(b'fixed').hexdigest();self.assertEqual(exact.pinned_file(path,sha),path)
            with self.assertRaises(ValueError):exact.pinned_file(path,sha,4)
            with self.assertRaises(ValueError):exact.pinned_file(path,'0'*64)
            link=Path(directory)/'link';link.symlink_to(path)
            with self.assertRaises(ValueError):exact.pinned_file(link,sha)
            path.write_bytes(b'')
            with self.assertRaises(ValueError):exact.pinned_file(path,hashlib.sha256(b'').hexdigest())

    def test_updater_adapter_accepts_only_original_eol_equivalence(self):
        actual=b'original source\n';packaged=b'original source\r\n'
        with patch.object(exact,'UPDATER_SHA',hashlib.sha256(actual).hexdigest()),patch.object(exact,'PACKAGED_UPDATER_SHA',hashlib.sha256(packaged).hexdigest()):
            exact.assert_updater_equivalence(packaged,actual)
            for changed_archive,changed_actual in [(packaged,packaged),(packaged,b'candidate source\n'),(b'candidate source\r\n',actual),(packaged+b'\r\n',actual)]:
                with self.assertRaises(ValueError):exact.assert_updater_equivalence(changed_archive,changed_actual)

    def test_wrapper_preserves_packaged_transition_and_actual_recovery(self):
        # File transport/crypto admission has separate real-media checks; exercise
        # this adapter with a disposable, byte-pinned consumer and producer double.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';target=root/'target';source.mkdir();target.mkdir()
            installed=root/'installed';installed.mkdir();actual=b'old updater\n';packaged=b'old updater\r\n'
            sha=lambda data:hashlib.sha256(data).hexdigest()
            receipt,env=self.fixture();receipt_path=root/'receipt.json';receipt_path.write_text(json.dumps(receipt))
            roles={};inventories={};proofs={}
            for label,version,folder in [('source','3.2.742',source),('target','3.2.747',target)]:
                prefix='edr-agent-win_'+version+'-windows-arm64-';inventories[label]=[]
                for role,suffix in [('setup','setup.exe'),('manifest','artifact-manifest.json'),('cms','artifact-manifest.json.p7s')]:
                    path=folder/(prefix+suffix);path.write_bytes(b'fixture');roles[label+'_'+role]=path
                archive=folder/(prefix+'exe.zip')
                with zipfile.ZipFile(archive,'w') as z:z.writestr('edr_agent_inplace_update.ps1',packaged)
                inventories[label].append(dict(name=archive.name,digest='sha256:'+exact.io_owner.digest(archive)))
                proof=folder/'publisher-verification.json';proof.write_text(json.dumps(dict(artifact_sha256='target-hash')))
                roles[label+'_proof']=proof;proofs[label]=str(proof)
            roles['source_runtime_archive']=source/'edr-agent-win_3.2.742-windows-arm64-exe.zip'
            for name,data in [('FDSensor.exe',b'agent'),('edr_agent_inplace_update.ps1',actual),('FDSensorTaskLaunch.ps1',b'launcher'),('native-package-integrity.json',b'integrity'),('agent.toml',b'config')]:
                (installed/name).write_bytes(data)
            consumer=dict(agent_sha256=sha(b'agent'),updater_sha256=sha(actual),launcher_sha256=sha(b'launcher'),native_integrity_sha256=sha(b'integrity'))
            receipt['config_sha256']=sha(b'config');receipt_path.write_text(json.dumps(receipt))
            staged=dict(schema='edr.exact-installed-742-to-747.inputs.v1',source_version='3.2.742',target_version='3.2.747',architecture='arm64',runtime_mode='scheduled_task',first_hop_inputs_staged=False,upgrade_input=None,storage_tools_input=None,
                source_setup_exe=str(roles['source_setup']),target_setup_exe=str(roles['target_setup']),source_publisher_proof=proofs['source'],target_publisher_proof=proofs['target'],
                file_bindings=[dict(role=k,path=str(v),sha256=exact.io_owner.digest(v),bytes=v.stat().st_size) for k,v in roles.items()])
            input_path=root/'lifecycle-inputs.json';input_path.write_text(json.dumps(staged))
            def producer(target,source,out,*args):
                out.mkdir();transition=dict(baseline_updater_sha256=sha(packaged),upgrade_class='installer_required',binary_sha256='target-hash')
                (out/'transition.json').write_text(json.dumps(transition));return transition
            with patch.object(exact,'INSTALL_DIR',str(installed)),patch.object(exact,'UPDATER_SHA',sha(actual)),patch.object(exact,'PACKAGED_UPDATER_SHA',sha(packaged)),patch.object(exact,'LAUNCHER_SHA',sha(b'launcher')),patch.object(exact,'INTEGRITY_SHA',sha(b'integrity')),patch.object(exact,'ASSETS',inventories),patch.object(exact,'qualification_consumer',return_value=consumer),patch.object(exact,'validate_request'),patch.object(exact,'check_manifest'),patch.object(exact.checkpoint,'prepare_lifecycle_upgrade',side_effect=producer):
                path=exact.prepare_first_hop(input_path,exact.io_owner.digest(input_path),receipt_path,exact.io_owner.digest(receipt_path),root/'out',env)
            output=json.loads(path.read_text());transition=json.loads((root/'out/transition.json').read_text())
            self.assertEqual(output['expected_recovery']['updater_sha256'],sha(actual))
            self.assertEqual(transition['baseline_updater_sha256'],sha(packaged))
            self.assertEqual(output['expected_recovery']['task_owner'],receipt['task_owner'])
            self.assertEqual(output['target_release_binding_sha256'],exact.io_owner.digest(root/'out/transition.json'))
            self.assertFalse(output['full_gate']);self.assertFalse(output['deployment_authorized'])

    def test_stale_receipt_fails_before_producer_or_source_mutation(self):
        receipt,env=self.fixture();receipt['run_attempt']='1'
        with tempfile.TemporaryDirectory() as directory,patch.object(exact.checkpoint,'prepare_lifecycle_upgrade') as producer:
            root=Path(directory);input_path=root/'inputs.json';input_path.write_text('{}')
            receipt_path=root/'receipt.json';receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError,'fresh harness'):
                exact.prepare_first_hop(input_path,exact.io_owner.digest(input_path),receipt_path,exact.io_owner.digest(receipt_path),root/'out',env)
            producer.assert_not_called();self.assertFalse((root/'out').exists())


if __name__=='__main__':unittest.main()
