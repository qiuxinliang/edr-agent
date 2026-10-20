"""Pure local negative checks; no GitHub, installer, Agent or real receipt."""
import importlib.util
import base64
import json
import re
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
SPEC=importlib.util.spec_from_file_location('prepare',Path(__file__).with_name('prepare_disposable_695.py'))
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
P698_PRODUCT_PINS=('release_id','handler_receipt_sha256','binary_sha256','headless_sha256','artifact_manifest_sha256','preflight_response_sha256','p5_sha256','runtime_identity_sha256')
P699_BINDING_PINS=('release_run', 'release_id', 'native_run', 'native_artifact_id', 'native_artifact_size', 'native_artifact_sha256', 'native_uncompressed_bytes', 'native_member_count', 'handler_receipt_sha256', 'binary_sha256', 'headless_sha256', 'artifact_manifest_sha256', 'preflight_response_sha256', 'p5_sha256', 'runtime_identity_sha256')
P701_BINDING_PINS=P699_BINDING_PINS
P702_BINDING_PINS=P699_BINDING_PINS
P703_BINDING_PINS=P699_BINDING_PINS
class Contracts(unittest.TestCase):
    def test_closed_runtime_mode_requires_exact_strings_before_io(self):
        for mode in ('service','scheduled_task'):
            self.assertEqual(M.runtime_mode(mode),mode)
        for mode in (None,True,1,'Service','auto','scheduled_task;public',''):
            with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'closed_recovery_runtime_mode'):
                M.runtime_mode(mode)
            with tempfile.TemporaryDirectory()as d,patch.object(M,'gh',side_effect=AssertionError('no external')):
                root=Path(d)/'fresh'
                with self.assertRaisesRegex(ValueError,'closed_recovery_runtime_mode'):
                    M.prepare(Path(d),root,'UNBOUND','UNBOUND','0','UNBOUND','697',mode)
                self.assertFalse(root.exists())
    def test_finalize_refuses_mode_mismatch_before_package_io(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);p,unused,pin=M.cohort('697')
            (root/'prepared.json').write_text(json.dumps({'source_sha':p['source'],'cohort_id':'697','cohort_catalog_sha256':pin,'runtime_mode':'service'}))
            with self.assertRaisesRegex(ValueError,'prepared_runtime_mode'):
                M.finalize(root,root,'697','scheduled_task')
    def test_runtime_modes_are_isolated_without_dispatch_input(self):
        text=(Path(__file__).resolve().parents[2]/'.github/workflows/windows-install-upgrade-rollback.yml').read_text()
        before,job=text.split('  recover-synthetic-owner:',1)
        self.assertNotIn('runtime_mode:',before)
        self.assertIn('      fail-fast: false\n      matrix:\n        runtime_mode: [service, scheduled_task]\n',job)
        self.assertIn('RECOVERY_RUNTIME_MODE: ${{ matrix.runtime_mode }}',job)
        self.assertEqual(job.count('--runtime-mode "$env:RECOVERY_RUNTIME_MODE"'),2)
        self.assertIn('outputs.id }}-${{ matrix.runtime_mode }}-metadata-',job)
        self.assertIn('test_recovery_task_contracts.ps1',job)
        self.assertIn('$meta.runtime_mode -cne $env:RECOVERY_RUNTIME_MODE',job)
        driver=Path(__file__).with_name('windows_cache_recovery_ci.ps1').read_text()
        self.assertIn("$runtimeMode=RecoveryMode $binding.runtime_mode",driver)
        self.assertIn("DeploymentMode=$script:runtimeMode",driver)
        self.assertIn("$params.ScheduledTaskName='FDSecurityAgent';$params.ScheduledTaskPath='\\'",driver)
        self.assertIn("RuntimeAction 'Start' 'repair-start' $repairNative",driver)
        self.assertIn('TaskNativeBinding $Native',driver)
        worker=driver[driver.index('function TaskWorkerSource('):driver.index('function TaskSamplerSource')]
        self.assertEqual(worker.count('TaskDefinitionMatches $definition $expected'),2)
        # Immutable product manifest still has its original service descriptor.
        self.assertIn("$raw[0].update.deployment_mode -eq 'service'",driver)
    def response(self):
        return {'code':'OK','message':'synthetic only','data':{'valid':True,'upgradeReady':True,'upgradeBlockers':[],
          'version':'3.2.695','arch':'arm64','platform':'windows','binarySha256':'a'*64,'signatureMode':'unsigned_integrity',
          'trustedSigner':False,'policySnapshot':'optional-signing-v1','packages':[{'packageType':'headless','sha256':'b'*64},{'packageType':'full_installer','sha256':'c'*64}]}}
    def verification(self):
        response=json.dumps(self.response())
        return {'schema':'edr.ci-original-handler-verification.v1','origin':'ci_original_handler_verification',
          'authenticated_platform_http':False,'verification_passed':True,'source_sha':M.SOURCE,'target_release_run':M.TARGET_RUN,
          'version':'3.2.695','arch':'arm64','handler_owner_sha256':M.HANDLER_SHA,'builder_owner_sha256':M.BUILDER_SHA,
          'binary_sha256':'a'*64,'headless_sha256':'b'*64,'manifest_sha256':'d'*64,'preflight_response_utf8':response,
          'preflight_response_sha256':M.digest(response.encode()),'p5_sha256':'c'*64,'db_or_artifactstore_written':False,
          'evidence_cache_opened':False,'product_binaries_executed':False}
    def check_verification(self,value):
        raw=json.dumps(value);return M.verified_handler_receipt(raw,M.digest(raw.encode()))
    def test_legacy_695_and_bound_697_are_separate(self):
        old,base,pin=M.cohort()
        self.assertEqual((old['source'],old['release_run'],old['native_run'],int(old['native_artifact_id'])),
          (M.SOURCE,M.TARGET_RUN,M.TOOL_RUN,M.TOOL_ID))
        self.assertEqual(old['tag'],'win_3.2.695');self.assertEqual(base['tag'],'win_3.2.692')
        self.assertEqual(pin,M.digest(M.cohort_catalog_raw()))
        draft=M.cohort('697',False)[0]
        self.assertEqual(draft['source'],'f672059aec426aafe00b216c482dc151b96226c9')
        self.assertEqual(draft['version'],'3.2.697')
        self.assertEqual(draft['native_run'],'39078106854')
        self.assertEqual(draft['release_run'],'39080074060')
        self.assertEqual(draft['release_id'],'416133839')
        self.assertEqual(draft['native_artifact_id'],'12118710280')
        self.assertEqual(M.cohort('697')[0],draft)
    def test_697_unbound_refuses_before_external_io_or_state(self):
        with tempfile.TemporaryDirectory()as d,patch.object(M,'gh',side_effect=AssertionError('external I/O forbidden'))as call:
            value=json.loads(M.cohort_catalog_raw());value['profiles']['697']['release_run']='UNBOUND'
            catalog=Path(d)/'missing-pin.json';catalog.write_text(json.dumps(value))
            root=Path(d)/'must-not-exist'
            with patch.object(M,'PROFILE_FILE',catalog),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):
                M.prepare(Path(d),root,'UNBOUND','UNBOUND','1','UNBOUND','697')
            self.assertFalse(root.exists());self.assertEqual(call.call_count,0)
    def test_698_profile_and_each_missing_product_pin_refuse_before_io(self):
        c,base,pin=M.cohort('698',False)
        self.assertEqual((c['source'],c['release_run'],c['native_run'],c['native_artifact_id']),
          ('ae8c293bf892f4cec7cf083977723f7c9666f6ce','39133741161','39104973569','12128098967'))
        self.assertEqual(c['native_artifact_sha256'],'fa18cc72103ad4b74d4f397d670a281afe3574ef36d2047927c3c4bc8e33719c')
        self.assertEqual(c['builder_owner_sha256'],M.BUILDER_SHA)
        self.assertEqual(M.cohort('698')[0],c)
        value=json.loads(M.cohort_catalog_raw());fixture=value['profiles']['698']
        for k in P698_PRODUCT_PINS:fixture[k]='8'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d,patch.object(M,'gh',side_effect=AssertionError('external forbidden'))as call:
            root=Path(d)/'must-not-exist';catalog=Path(d)/'temporary-missing-pin.json'
            for key in P698_PRODUCT_PINS:
                original=fixture[key];fixture[key]='UNBOUND';catalog.write_text(json.dumps(value))
                with patch.object(M,'PROFILE_FILE',catalog):
                    for mode in ('service','scheduled_task'):
                        with self.subTest(pin=key,mode=mode),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):
                            M.prepare(Path(d),root,'UNBOUND','UNBOUND','1','UNBOUND','698',mode)
                        with self.subTest(pin=key,mode=mode),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):
                            M.finalize(Path(d),root,'698',mode)
                fixture[key]=original
            self.assertFalse(root.exists());self.assertEqual(call.call_count,0)
    def test_698_every_unbound_pin_is_required_and_synthetic_routing_is_exact(self):
        # Temporary parser-only bytes are not a published artifact or real proof.
        value=json.loads(M.cohort_catalog_raw());c=value['profiles']['698']
        for k in P698_PRODUCT_PINS:c[k]='8'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d:
            catalog=Path(d)/'synthetic-parser-only.json';catalog.write_text(json.dumps(value))
            with patch.object(M,'PROFILE_FILE',catalog):
                self.assertEqual(M.cohort('698')[0],c)
                for k in P698_PRODUCT_PINS:
                    original=c[k];c[k]='UNBOUND';catalog.write_text(json.dumps(value))
                    with self.subTest(pin=k),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):M.cohort('698')
                    c[k]=original
    def test_698_cli_refuses_each_missing_pin_without_descriptor_or_product_io(self):
        import subprocess
        owner=Path(__file__).with_name('prepare_disposable_695.py').read_bytes()
        value=json.loads(M.cohort_catalog_raw());fixture=value['profiles']['698']
        for k in P698_PRODUCT_PINS:fixture[k]='8'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d:
            # The CLI reads its own fixed sibling catalog; no caller override is added.
            script=Path(d)/'prepare_disposable_695.py';script.write_bytes(owner)
            catalog=script.with_name('recovery_cohorts.json')
            for key in P698_PRODUCT_PINS:
                original=fixture[key];fixture[key]='UNBOUND';catalog.write_text(json.dumps(value))
                for selection in (['--cohort','698'],['--target-tag','win_3.2.698']):
                    with self.subTest(pin=key,selection=selection):
                        r=subprocess.run([sys.executable,'-I','-B',str(script),'profile',*selection],capture_output=True,timeout=3)
                        self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'')
                        self.assertEqual(r.stderr.decode('utf-8','strict').splitlines(),['disposable_preparation_failed:recovery_cohort_UNBOUND'])
                fixture[key]=original
    def test_699_known_identity_and_catalog_capacity(self):
        c,base,pin=M.cohort('699',False)
        self.assertEqual((c['source'],c['version'],c['tag']),('f00ae9ac5d6ee7b7b10e05179e9e6beb457ebc10','3.2.699','win_3.2.699'))
        self.assertEqual(c['builder_owner_sha256'],M.BUILDER_SHA)
        self.assertEqual(c['handler_owner_sha256'],M.HANDLER_SHA)
        self.assertLessEqual(len(M.cohort_catalog_raw()),16384)
        # The same test remains valid after Root binds real published identities.
        if any(c[k]=='UNBOUND' for k in P699_BINDING_PINS):
            with self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):M.cohort('699')
        else:self.assertEqual(M.cohort('699')[0],c)
    def test_699_each_missing_pin_refuses_prepare_and_finalize_before_io(self):
        value=json.loads(M.cohort_catalog_raw());fixture=value['profiles']['699']
        for k in P699_BINDING_PINS:fixture[k]='9'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d,patch.object(M,'gh',side_effect=AssertionError('no external'))as call:
            root=Path(d)/'must-not-exist';catalog=Path(d)/'temporary-missing699.json'
            for key in P699_BINDING_PINS:
                original=fixture[key];fixture[key]='UNBOUND';catalog.write_text(json.dumps(value))
                with patch.object(M,'PROFILE_FILE',catalog):
                    for mode in ('service','scheduled_task'):
                        with self.subTest(pin=key,mode=mode),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):
                            M.prepare(Path(d),root,'UNBOUND','UNBOUND','0','UNBOUND','699',mode)
                        with self.subTest(pin=key,mode=mode),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):
                            M.finalize(Path(d),root,'699',mode)
                fixture[key]=original
            self.assertFalse(root.exists());self.assertEqual(call.call_count,0)
    def test_699_cli_refuses_each_missing_pin_normal_and_optimized(self):
        import subprocess
        value=json.loads(M.cohort_catalog_raw());fixture=value['profiles']['699']
        for k in P699_BINDING_PINS:fixture[k]='9'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d:
            script=Path(d)/'prepare_disposable_695.py';script.write_bytes(Path(__file__).with_name(script.name).read_bytes())
            catalog=script.with_name('recovery_cohorts.json')
            for key in P699_BINDING_PINS:
                original=fixture[key];fixture[key]='UNBOUND';catalog.write_text(json.dumps(value))
                for flags in ([],['-O']):
                    for selection in (['--cohort','699'],['--target-tag','win_3.2.699']):
                        with self.subTest(pin=key,flags=flags,selection=selection):
                            r=subprocess.run([sys.executable,'-I','-B',*flags,str(script),'profile',*selection],capture_output=True,timeout=3)
                            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'')
                            self.assertEqual(r.stderr.decode('utf-8','strict').splitlines(),['disposable_preparation_failed:recovery_cohort_UNBOUND'])
                fixture[key]=original
    def test_699_parser_only_bound_routing_is_separate_from_actual_proof(self):
        value=json.loads(M.cohort_catalog_raw());c=value['profiles']['699']
        for k in P699_BINDING_PINS:c[k]='9'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d:
            catalog=Path(d)/'synthetic-parser-only699.json';catalog.write_text(json.dumps(value))
            with patch.object(M,'PROFILE_FILE',catalog):self.assertEqual(M.cohort('699')[0],c)

    # 701 parser-only fixtures never supply a published receipt or run recovery.
    def test_701_known_identity_and_catalog_capacity(self):
        c,base,pin=M.cohort('701',False)
        self.assertEqual((c['source'],c['version'],c['tag']),('b6a2c43cf611fe31bc3444fbd08ec3ca10839ab5','3.2.701','win_3.2.701'))
        self.assertEqual(c['builder_owner_sha256'],M.BUILDER_SHA)
        self.assertEqual(c['handler_owner_sha256'],M.HANDLER_SHA)
        self.assertEqual((c['release_run'],c['native_run'],c['native_artifact_id'],c['native_artifact_size']),('39279000100','39273349309','12197268927','1225356'))
        self.assertEqual((c['native_artifact_sha256'],c['native_uncompressed_bytes'],c['native_member_count']),('9e6d78b3381965d7bb0f27b829380d5e2255d0d16e92ffa873b472d459266f22','3044023','4'))
        self.assertLessEqual(len(M.cohort_catalog_raw()),16384)
        # The same test remains valid after Root binds real published identities.
        if any(c[k]=='UNBOUND' for k in P701_BINDING_PINS):
            with self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):M.cohort('701')
        else:self.assertEqual(M.cohort('701')[0],c)

    def test_701_each_missing_pin_refuses_prepare_and_finalize_before_io(self):
        value=json.loads(M.cohort_catalog_raw());fixture=value['profiles']['701']
        for k in P701_BINDING_PINS:fixture[k]='1'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d,patch.object(M,'gh',side_effect=AssertionError('no external'))as call:
            root=Path(d)/'must-not-exist';catalog=Path(d)/'temporary-missing701.json'
            for key in P701_BINDING_PINS:
                original=fixture[key];fixture[key]='UNBOUND';catalog.write_text(json.dumps(value))
                with patch.object(M,'PROFILE_FILE',catalog):
                    for mode in ('service','scheduled_task'):
                        with self.subTest(pin=key,mode=mode),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):
                            M.prepare(Path(d),root,'UNBOUND','UNBOUND','0','UNBOUND','701',mode)
                        with self.subTest(pin=key,mode=mode),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):
                            M.finalize(Path(d),root,'701',mode)
                fixture[key]=original
            self.assertFalse(root.exists());self.assertEqual(call.call_count,0)

    def test_701_cli_refuses_each_missing_pin_normal_and_optimized(self):
        import subprocess
        value=json.loads(M.cohort_catalog_raw());fixture=value['profiles']['701']
        for k in P701_BINDING_PINS:fixture[k]='1'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d:
            script=Path(d)/'prepare_disposable_695.py';script.write_bytes(Path(__file__).with_name(script.name).read_bytes())
            catalog=script.with_name('recovery_cohorts.json')
            for key in P701_BINDING_PINS:
                original=fixture[key];fixture[key]='UNBOUND';catalog.write_text(json.dumps(value))
                for flags in ([],['-O']):
                    for selection in (['--cohort','701'],['--target-tag','win_3.2.701']):
                        with self.subTest(pin=key,flags=flags,selection=selection):
                            r=subprocess.run([sys.executable,'-I','-B',*flags,str(script),'profile',*selection],capture_output=True,timeout=3)
                            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'')
                            self.assertEqual(r.stderr.decode('utf-8','strict').splitlines(),['disposable_preparation_failed:recovery_cohort_UNBOUND'])
                fixture[key]=original

    def test_701_parser_only_bound_routing_is_separate_from_actual_proof(self):
        value=json.loads(M.cohort_catalog_raw());c=value['profiles']['701']
        for k in P701_BINDING_PINS:c[k]='1'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d:
            catalog=Path(d)/'synthetic-parser-only701.json';catalog.write_text(json.dumps(value))
            with patch.object(M,'PROFILE_FILE',catalog):self.assertEqual(M.cohort('701')[0],c)


    # 702 parser-only fixtures never supply a published receipt or run recovery.
    def test_702_known_identity_and_catalog_capacity(self):
        c,base,pin=M.cohort('702',False)
        self.assertEqual((c['source'],c['version'],c['tag']),('ba634c7bf6a1851519931a95ce1df3a00309d871','3.2.702','win_3.2.702'))
        self.assertEqual(c['builder_owner_sha256'],M.BUILDER_SHA)
        self.assertEqual(c['handler_owner_sha256'],M.HANDLER_SHA)
        self.assertEqual((c['release_run'],c['native_run'],c['native_artifact_id'],c['native_artifact_size']),('39437943738','39433049545','12272800727','1239085'))
        self.assertEqual((c['native_artifact_sha256'],c['native_uncompressed_bytes'],c['native_member_count']),('a36c6658a396e12f2f4b29d718e6341f68191ea5b751f9641d9500eee476cb59','3089079','4'))
        self.assertLessEqual(len(M.cohort_catalog_raw()),16384)
        full=json.loads(M.cohort_catalog_raw());target=full['profiles']['702']
        for key in P702_BINDING_PINS:
            if target[key]=='UNBOUND':target[key]='f'*64 if key.endswith('_sha256')else '9'*20
        self.assertLessEqual(len((json.dumps(full,indent=2)+'\n').encode()),16384)
        # The same test remains valid after Root binds real published identities.
        if any(c[k]=='UNBOUND' for k in P702_BINDING_PINS):
            with self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):M.cohort('702')
        else:self.assertEqual(M.cohort('702')[0],c)

    def test_702_each_missing_pin_refuses_prepare_and_finalize_before_io(self):
        value=json.loads(M.cohort_catalog_raw());fixture=value['profiles']['702']
        for k in P702_BINDING_PINS:fixture[k]='1'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d,patch.object(M,'gh',side_effect=AssertionError('no external'))as call:
            root=Path(d)/'must-not-exist';catalog=Path(d)/'temporary-missing702.json'
            for key in P702_BINDING_PINS:
                original=fixture[key];fixture[key]='UNBOUND';catalog.write_text(json.dumps(value))
                with patch.object(M,'PROFILE_FILE',catalog):
                    for mode in ('service','scheduled_task'):
                        with self.subTest(pin=key,mode=mode),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):
                            M.prepare(Path(d),root,'UNBOUND','UNBOUND','0','UNBOUND','702',mode)
                        with self.subTest(pin=key,mode=mode),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):
                            M.finalize(Path(d),root,'702',mode)
                fixture[key]=original
            self.assertFalse(root.exists());self.assertEqual(call.call_count,0)

    def test_702_cli_refuses_each_missing_pin_normal_and_optimized(self):
        import subprocess
        value=json.loads(M.cohort_catalog_raw());fixture=value['profiles']['702']
        for k in P702_BINDING_PINS:fixture[k]='1'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d:
            script=Path(d)/'prepare_disposable_695.py';script.write_bytes(Path(__file__).with_name(script.name).read_bytes())
            catalog=script.with_name('recovery_cohorts.json')
            for key in P702_BINDING_PINS:
                original=fixture[key];fixture[key]='UNBOUND';catalog.write_text(json.dumps(value))
                for flags in ([],['-O']):
                    for selection in (['--cohort','702'],['--target-tag','win_3.2.702']):
                        with self.subTest(pin=key,flags=flags,selection=selection):
                            r=subprocess.run([sys.executable,'-I','-B',*flags,str(script),'profile',*selection],capture_output=True,timeout=3)
                            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'')
                            self.assertEqual(r.stderr.decode('utf-8','strict').splitlines(),['disposable_preparation_failed:recovery_cohort_UNBOUND'])
                fixture[key]=original

    def test_702_parser_only_bound_routing_is_separate_from_actual_proof(self):
        value=json.loads(M.cohort_catalog_raw());c=value['profiles']['702']
        for k in P702_BINDING_PINS:c[k]='1'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d:
            catalog=Path(d)/'synthetic-parser-only702.json';catalog.write_text(json.dumps(value))
            with patch.object(M,'PROFILE_FILE',catalog):self.assertEqual(M.cohort('702')[0],c)


    # 703 parser-only fixtures never supply a published receipt or run recovery.
    def test_703_known_identity_and_catalog_capacity(self):
        c,base,pin=M.cohort('703',False)
        self.assertEqual((c['source'],c['version'],c['tag']),('3710b8800ee43f9f4ac29bc73fb224137a51dab1','3.2.703','win_3.2.703'))
        self.assertEqual(c['builder_owner_sha256'],M.BUILDER_SHA)
        self.assertEqual(c['handler_owner_sha256'],M.HANDLER_SHA)
        self.assertLessEqual(len(M.cohort_catalog_raw()),16384)
        full=json.loads(M.cohort_catalog_raw());target=full['profiles']['703']
        for key in P703_BINDING_PINS:
            if target[key]=='UNBOUND':target[key]='f'*64 if key.endswith('_sha256')else '9'*20
        self.assertLessEqual(len((json.dumps(full,indent=2)+'\n').encode()),16384)
        # The same test remains valid after Root binds real published identities.
        if any(c[k]=='UNBOUND' for k in P703_BINDING_PINS):
            with self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):M.cohort('703')
        else:self.assertEqual(M.cohort('703')[0],c)

    def test_703_each_missing_pin_refuses_prepare_and_finalize_before_io(self):
        value=json.loads(M.cohort_catalog_raw());fixture=value['profiles']['703']
        for k in P703_BINDING_PINS:fixture[k]='1'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d,patch.object(M,'gh',side_effect=AssertionError('no external'))as call:
            root=Path(d)/'must-not-exist';catalog=Path(d)/'temporary-missing703.json'
            for key in P703_BINDING_PINS:
                original=fixture[key];fixture[key]='UNBOUND';catalog.write_text(json.dumps(value))
                with patch.object(M,'PROFILE_FILE',catalog):
                    for mode in ('service','scheduled_task'):
                        with self.subTest(pin=key,mode=mode),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):
                            M.prepare(Path(d),root,'UNBOUND','UNBOUND','0','UNBOUND','703',mode)
                        with self.subTest(pin=key,mode=mode),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):
                            M.finalize(Path(d),root,'703',mode)
                fixture[key]=original
            self.assertFalse(root.exists());self.assertEqual(call.call_count,0)

    def test_703_cli_refuses_each_missing_pin_normal_and_optimized(self):
        import subprocess
        value=json.loads(M.cohort_catalog_raw());fixture=value['profiles']['703']
        for k in P703_BINDING_PINS:fixture[k]='1'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d:
            script=Path(d)/'prepare_disposable_695.py';script.write_bytes(Path(__file__).with_name(script.name).read_bytes())
            catalog=script.with_name('recovery_cohorts.json')
            for key in P703_BINDING_PINS:
                original=fixture[key];fixture[key]='UNBOUND';catalog.write_text(json.dumps(value))
                for flags in ([],['-O']):
                    for selection in (['--cohort','703'],['--target-tag','win_3.2.703']):
                        with self.subTest(pin=key,flags=flags,selection=selection):
                            r=subprocess.run([sys.executable,'-I','-B',*flags,str(script),'profile',*selection],capture_output=True,timeout=3)
                            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'')
                            self.assertEqual(r.stderr.decode('utf-8','strict').splitlines(),['disposable_preparation_failed:recovery_cohort_UNBOUND'])
                fixture[key]=original

    def test_703_parser_only_bound_routing_is_separate_from_actual_proof(self):
        value=json.loads(M.cohort_catalog_raw());c=value['profiles']['703']
        for k in P703_BINDING_PINS:c[k]='1'*64 if k.endswith('_sha256')else '1'
        with tempfile.TemporaryDirectory()as d:
            catalog=Path(d)/'synthetic-parser-only703.json';catalog.write_text(json.dumps(value))
            with patch.object(M,'PROFILE_FILE',catalog):self.assertEqual(M.cohort('703')[0],c)



    def test_unknown_cohort_never_falls_back(self):
        for value in ('696','700','win_3.2.697','697;public','',697,None):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'unsupported_recovery_cohort'):M.cohort(value)
    def test_profile_cli_is_closed_and_exact_bound_cohort_has_descriptor(self):
        script=str(Path(__file__).with_name('prepare_disposable_695.py'))
        import subprocess
        for tag in ('win_3.2.696','win_3.2.695;public'):
            r=subprocess.run([sys.executable,'-I','-B',script,'profile','--target-tag',tag],capture_output=True,timeout=3)
            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'')
        for cid in ('695','697'):
            c=M.cohort(cid)[0]
            r=subprocess.run([sys.executable,'-I','-B',script,'profile','--target-tag',c['tag']],capture_output=True,timeout=3)
            self.assertEqual(r.returncode,0);self.assertEqual(r.stderr,b'')
            self.assertEqual(json.loads(r.stdout)['source_sha'],c['source'])
    def test_profile_catalog_rejects_unknown_fields_and_large_input(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)/'public-catalog.json';value=json.loads(M.cohort_catalog_raw())
            value['profiles']['695']['unexpected']='not allowed';p.write_text(json.dumps(value))
            with patch.object(M,'PROFILE_FILE',p),self.assertRaisesRegex(ValueError,'profile_shape'):M.cohort()
            p.write_bytes(b'x'*16385)
            with patch.object(M,'PROFILE_FILE',p),self.assertRaisesRegex(ValueError,'catalog_bound'):M.cohort()
    def test_shared_profile_go_and_workflow_consumers_are_bound(self):
        parent=Path(__file__).parent
        go=(parent/'verified_headless_p5_export_test.go').read_text()
        self.assertIn('//go:embed recovery_cohorts.json',go)
        self.assertIn('p5BindingCohort(b)',go)
        self.assertIn('"verified-p5-"+b.Version+"-"+b.Arch+".zip"',go)
        workflow=(parent.parents[1]/'.github/workflows/windows-install-upgrade-rollback.yml').read_text()
        self.assertIn('ref: ${{ steps.recovery-cohort.outputs.source }}',workflow)
        self.assertIn('profile --target-tag "$env:RECOVERY_TARGET_TAG"',workflow)
        self.assertIn('--cohort "$env:RECOVERY_COHORT"',workflow)
        self.assertIn('name: disposable-cache-recovery-${{ steps.recovery-cohort.outputs.id }}-${{ matrix.runtime_mode }}-metadata-',workflow)
    def test_fixed_original_handler_scope(self):
        v,raw,d,p=self.check_verification(self.verification())
        self.assertIs(v['authenticated_platform_http'],False);self.assertEqual(p['full_installer'],'c'*64)
    def test_raw_http_response_is_not_handler_verification(self):
        with self.assertRaisesRegex(ValueError,'scope_required'):self.check_verification(self.response())
    def test_changed_verification_scope_or_identity_rejected(self):
        for key,value in [('origin','authenticated_http'),('authenticated_platform_http',True),('verification_passed',False),
            ('source_sha','0'*40),('target_release_run','0'),('handler_owner_sha256','0'*64),('builder_owner_sha256','0'*64),
            ('db_or_artifactstore_written',True),('evidence_cache_opened',True),('product_binaries_executed',True),
            ('preflight_response_sha256','0'*64),('p5_sha256','0'*64),('binary_sha256','0'*64),('unexpected',True)]:
            v=self.verification();v[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.check_verification(v)
    def test_receipt_pin_required(self):
        raw=json.dumps(self.verification())
        with self.assertRaisesRegex(ValueError,'receipt_pin_required'):M.verified_handler_receipt(raw,'0'*64)
    def test_builder_carrier_roundtrip_only(self):
        # Synthetic carrier tests do not recreate the business builder.
        raw=b'public synthetic carrier';encoded=base64.b64encode(raw).decode()
        with patch.object(M,'BUILDER_SHA',M.digest(raw)):
            self.assertEqual(M.verified_builder_input(encoded),raw)
            for bad in [encoded+'\n',encoded[:-1],encoded+'=', 'non-ascii-\u00ff']:
                with self.subTest(value=bad),self.assertRaises(ValueError):M.verified_builder_input(bad)
        with self.assertRaisesRegex(ValueError,'fixed_original_builder_sha_required'):M.verified_builder_input(encoded)
    def test_owner_rejected_before_io(self):
        v=json.dumps(self.verification())
        with tempfile.TemporaryDirectory()as d,patch.object(M,'gh',side_effect=AssertionError('must not call GitHub')):
            target=Path(d)/'new'
            with self.assertRaisesRegex(ValueError,'base64_required'):M.prepare(Path(d),target,v,M.digest(v.encode()),'1','')
            self.assertFalse(target.exists())
    def test_synthetic_receipt_parser_only(self):
        d,p=M.verified_preflight(json.dumps(self.response()).encode());self.assertEqual(p['full_installer'],'c'*64)
    def test_incomplete_receipt_rejected(self):
        for key,value in [('valid',False),('upgradeReady',False),('upgradeBlockers',['synthetic blocker']),('policySnapshot','required-signing-v1'),('arch','amd64')]:
            j=self.response();j['data'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):M.verified_preflight(json.dumps(j).encode())
    def test_duplicate_json_key_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate_json_key'):M.strict_json(b'{"code":"OK","code":"OK"}')
    def test_unbound_before_any_io_or_directory_creation(self):
        with tempfile.TemporaryDirectory()as d,patch.object(M,'gh',side_effect=AssertionError('network must not run')):
            target=Path(d)/'new'
            with self.assertRaisesRegex(ValueError,'original_handler_receipt_pin_required'):M.prepare(Path(d),target,'UNBOUND','UNBOUND','1','UNBOUND')
            self.assertFalse(target.exists())
    def test_stdout_cap(self):
        with self.assertRaisesRegex(ValueError,'output_bound'):M.bounded_process([sys.executable,'-c','print("x"*100)'],10,2)
    def test_timeout_no_retry(self):
        with self.assertRaisesRegex(ValueError,'timeout_no_retry'):M.bounded_process([sys.executable,'-c','import time;time.sleep(5)'],100,.05)
    def test_403_never_prints_raw_stderr(self):
        with self.assertRaisesRegex(ValueError,'github_failed_403_no_retry_or_scope_expansion')as c:
            M.bounded_process([sys.executable,'-c','import sys;sys.stderr.write("HTTP 403 fake-private-token");sys.exit(1)'],100,2)
        self.assertNotIn('fake-private-token',str(c.exception))
    def test_no_fallback_after_missing_actions_read(self):
        with patch.object(M,'gh',side_effect=ValueError('read_only_github_failed_403_no_retry_or_scope_expansion'))as call:
            with self.assertRaisesRegex(ValueError,'403'):M.native_tools(Path('/unused'),None,None)
            self.assertEqual(call.call_count,1)
    def test_manual_workflow_scope(self):
        workflow=Path(__file__).resolve().parents[2]/'.github/workflows/windows-install-upgrade-rollback.yml'
        full=workflow.read_text();text=full[full.index('  recover-synthetic-owner:'): ]
        self.assertIn('    permissions:\n      contents: read\n      actions: read\n',text)
        self.assertIn('  native-lifecycle:\n    if: ${{ !inputs.cache_recovery_subset }}',full)
        self.assertIn('inputs.cache_recovery_subset == true',text)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.cache_recovery_subset == true && github.repository == 'qiuxinliang/edr-agent'",text)
        self.assertIn('runs-on: windows-11-arm',text);self.assertIn('timeout-minutes: 90',text)
        self.assertNotIn('secrets.',text);self.assertNotIn('write-all',text)
        self.assertIn('GH_TOKEN: ${{ github.token }}',text)
        for item in ('backend_builder_base64','handler_verification_json','handler_verification_sha256','higher_min_free_bytes'):
            self.assertIn('${{ inputs.'+item+' }}',text)
        # Dispatch data is passed through env, never concatenated as shell source.
        in_run=False
        for line in text.splitlines():
            if line.startswith('        run: |'):in_run=True;continue
            if in_run and line and not line.startswith('          '):in_run=False
            if in_run:self.assertNotIn('${{ inputs.',line)
        self.assertIn("'source-owner/full_installer.go'",text)
        self.assertIn("'zz_private_p5_export_test.go'",text)
        self.assertIn('retention-days: 7',text)
    def assert_recovery_execution_host(self,text):
        step=re.search(r'^      - name: Execute only disposable local rollback and normal repair subset\n(.*?)(?=^      - |\Z)',text,re.M|re.S)
        self.assertIsNotNone(step)
        # Native child exit observation is source-verified only under Core.
        self.assertEqual(re.findall(r'^        shell: (.+)$',step[1],re.M),['pwsh'])
    def test_manual_execution_uses_supported_powershell_core_host(self):
        workflow=Path(__file__).resolve().parents[2]/'.github/workflows/windows-install-upgrade-rollback.yml'
        text=workflow.read_text();self.assert_recovery_execution_host(text)
        header='      - name: Execute only disposable local rollback and normal repair subset\n'
        selected=header+'        shell: pwsh\n'
        self.assertEqual(text.count(selected),1)
        for replacement in [header,header+'        shell: powershell\n']:
            with self.subTest(shell=replacement),self.assertRaises(AssertionError):
                self.assert_recovery_execution_host(text.replace(selected,replacement,1))
    def assert_driver_supported_host(self,text):
        self.assertEqual(text.splitlines()[:2],['#Requires -Version 7.0','#Requires -PSEdition Core'])
    def test_driver_rejects_legacy_or_unspecified_host(self):
        text=Path(__file__).with_name('windows_cache_recovery_ci.ps1').read_text()
        self.assert_driver_supported_host(text)
        for bad in [text.replace('#Requires -Version 7.0\n','',1),
                    text.replace('#Requires -Version 7.0','#Requires -Version 5.1',1),
                    text.replace('#Requires -PSEdition Core\n','',1),
                    text.replace('#Requires -PSEdition Core','#Requires -PSEdition Desktop',1)]:
            with self.assertRaises(AssertionError):self.assert_driver_supported_host(bad)
    def test_process_scoped_legacy_child_helper_and_workflow_consumer(self):
        driver=Path(__file__).with_name('windows_cache_recovery_ci.ps1').read_text()
        helper=driver[driver.index('function StartWindowsPowerShellChild('):driver.index('function WaitProcess(')]
        self.assertIn("[Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process)",helper)
        self.assertIn("[Environment]::SetEnvironmentVariable('PSModulePath',$null,[EnvironmentVariableTarget]::Process)",helper)
        self.assertIn("finally {",helper)
        self.assertIn("[Environment]::SetEnvironmentVariable('PSModulePath',$previousModulePath,[EnvironmentVariableTarget]::Process)",helper)
        self.assertNotIn('EnvironmentVariableTarget]::Machine',helper);self.assertNotIn('EnvironmentVariableTarget]::User',helper)
        self.assertEqual(len(re.findall(r'^[ \t]+\$(?:owned|child)=StartWindowsPowerShellChild ',driver,re.M)),3)
        wait=driver[driver.index('function WaitProcess('):driver.index('function ServiceObserverError(')]
        self.assertNotIn('.Handle',wait)
        workflow=(Path(__file__).resolve().parents[2]/'.github/workflows/windows-install-upgrade-rollback.yml').read_text()
        check='      - name: Verify process-scoped Windows PowerShell child module environment\n'
        self.assertEqual(workflow.count(check),1)
        body=workflow[workflow.index(check):workflow.index('      - name: Execute only disposable local rollback and normal repair subset\n')]
        self.assertIn('        shell: pwsh\n        timeout-minutes: 2\n',body)
        self.assertIn("'tests/cache-recovery/test_windows_powershell_child_environment.ps1'",body)
        self.assertIn('-DriverSource $driver -DriverSha256 $driverSha',body)
        self.assertIn('if ($LASTEXITCODE -ne 0)',body)
        self.assertNotIn('CacheOwnedHandleForTest',body);self.assertNotIn('RequireCounterfactualFailureForTest',body)
        contract=Path(__file__).with_name('test_windows_powershell_child_environment.ps1').read_text()
        self.assertIn("  Probe 'original_parent_direct' $false $original $worker $(if($PSVersionTable.PSVersion.Major -eq 5){0}else{-1})\n  Probe 'isolated_parent_direct' $true $original $worker 0\n",contract)
        self.assertIn('if ($rows.Count -ne 9) {exit 3}',contract)
        self.assertIn('parent_default_modulepath_counterfactual_reproduced=$parentDefaultProven',contract)
        self.assertIn('if ($RequireCounterfactualFailureForTest -and -not $proven) {exit 3}',contract)
        self.assertTrue(contract.endswith('\nexit 0\n'))
    def assert_transport(self,argv,cap,seconds,endpoint,accept,expected_cap):
        self.assertEqual(argv,['gh','api','--method','GET',endpoint,'-H','Accept: '+accept])
        self.assertEqual(cap,expected_cap);self.assertEqual(seconds,150)
    def test_actions_zip_accept_json_preserves_binary_response(self):
        endpoint='repos/'+M.REPO+'/actions/artifacts/'+str(M.TOOL_ID)+'/zip';raw=bytes([0,255,0,10])
        def receiver(argv,cap,seconds):
            # Strict synthetic receiver: Actions download rejects release media type.
            if argv[-2:]!=['-H','Accept: application/vnd.github+json']:
                raise ValueError('read_only_github_failed_415_no_retry_or_scope_expansion')
            self.assert_transport(argv,cap,seconds,endpoint,'application/vnd.github+json',len(raw));return raw
        with patch.object(M,'bounded_process',side_effect=receiver)as call:
            self.assertEqual(M.gh(endpoint,len(raw),True),raw);self.assertEqual(call.call_count,1)
    def test_release_asset_keeps_octet_stream_and_binary_response(self):
        endpoint='repos/'+M.REPO+'/releases/assets/123';raw=bytes([0,255,0,10])
        def receiver(argv,cap,seconds):
            self.assert_transport(argv,cap,seconds,endpoint,'application/octet-stream',len(raw));return raw
        with patch.object(M,'bounded_process',side_effect=receiver):self.assertEqual(M.gh(endpoint,len(raw),True),raw)
    def test_metadata_explicit_json_accept_and_parse(self):
        endpoint='repos/'+M.REPO+'/actions/runs/'+M.TOOL_RUN+'/attempts/1'
        def receiver(argv,cap,seconds):
            self.assert_transport(argv,cap,seconds,endpoint,'application/vnd.github+json',1048576);return b'{"id":123}'
        with patch.object(M,'bounded_process',side_effect=receiver):self.assertEqual(M.gh(endpoint),{'id':123})
    def tool_receiver(self,calls,zip_body=None,zip_failure=False):
        prefix='repos/'+M.REPO
        def receiver(argv,cap,seconds):
            endpoint=argv[4];calls.append(endpoint)
            if endpoint==prefix+'/actions/runs/'+M.TOOL_RUN+'/attempts/1':
                self.assert_transport(argv,cap,seconds,endpoint,'application/vnd.github+json',1048576)
                return json.dumps({'id':int(M.TOOL_RUN),'run_attempt':1,'head_sha':M.SOURCE,'status':'completed','conclusion':'success'}).encode()
            if endpoint==prefix+'/actions/artifacts/'+str(M.TOOL_ID):
                self.assert_transport(argv,cap,seconds,endpoint,'application/vnd.github+json',1048576)
                return json.dumps({'id':M.TOOL_ID,'name':'evidence-native-tools-arm64-'+M.SOURCE,'size_in_bytes':M.TOOL_SIZE,
                  'digest':'sha256:'+M.TOOL_SHA,'expired':False,'workflow_run':{'id':int(M.TOOL_RUN),'head_sha':M.SOURCE}}).encode()
            self.assertEqual(endpoint,prefix+'/actions/artifacts/'+str(M.TOOL_ID)+'/zip')
            self.assert_transport(argv,cap,seconds,endpoint,'application/vnd.github+json',M.TOOL_SIZE)
            if zip_failure:raise ValueError('read_only_github_failed_415_no_retry_or_scope_expansion')
            return zip_body
        return receiver
    def test_actions_415_is_one_request_no_fallback_or_extract(self):
        calls=[]
        with tempfile.TemporaryDirectory()as d,patch.object(M,'bounded_process',side_effect=self.tool_receiver(calls,zip_failure=True)):
            root=Path(d)
            with self.assertRaisesRegex(ValueError,'github_actions_artifact_zip:read_only_github_failed_415_no_retry_or_scope_expansion'):
                M.native_tools(root,None,Path('/never-read'))
            self.assertEqual(calls,['repos/'+M.REPO+'/actions/runs/'+M.TOOL_RUN+'/attempts/1',
              'repos/'+M.REPO+'/actions/artifacts/'+str(M.TOOL_ID),'repos/'+M.REPO+'/actions/artifacts/'+str(M.TOOL_ID)+'/zip'])
            self.assertFalse((root/'native-tools').exists())
    def test_changed_tool_bytes_still_refused_before_extract(self):
        calls=[]
        with tempfile.TemporaryDirectory()as d,patch.object(M,'bounded_process',side_effect=self.tool_receiver(calls,zip_body=b'wrong synthetic archive')):
            root=Path(d)
            with self.assertRaisesRegex(ValueError,'tool_archive_full_hash_size'):M.native_tools(root,None,Path('/never-read'))
            self.assertEqual(len(calls),3);self.assertFalse((root/'native-tools').exists())
    def test_unsupported_binary_endpoint_refused_before_io(self):
        with patch.object(M,'bounded_process',side_effect=AssertionError('must not call GitHub')):
            with self.assertRaisesRegex(ValueError,'fixed_binary_endpoint_required'):M.gh('repos/'+M.REPO+'/unknown',1,True)
    def test_415_never_prints_raw_stderr(self):
        with self.assertRaisesRegex(ValueError,'github_failed_415_no_retry_or_scope_expansion')as c:
            M.bounded_process([sys.executable,'-c','import sys;sys.stderr.write("HTTP 415 fake-private-url");sys.exit(1)'],100,2)
        self.assertNotIn('fake-private-url',str(c.exception))
    def test_original_lazy_stage_imports_and_path_restore_on_validation_error(self):
        # Use the actual original stage owner and its siblings; only HTTP is a stub.
        script=Path(__file__).resolve().parents[2]/'scripts/windows_release_checkpoint.py'
        siblings=('windows_usb_bundle','verify_binary_hot_compatibility','windows_release_checkpoint')
        filtered=[p for p in sys.path if p!=str(script.parent)]
        with tempfile.TemporaryDirectory()as d,patch.dict(sys.modules),patch.object(sys,'path',filtered):
            for name in siblings:sys.modules.pop(name,None)
            before=list(sys.path);checkpoint=M.module(script,'original_checkpoint_contract')
            self.assertEqual(sys.path,before)
            tag='win_3.2.695';raw=b'public synthetic invalid stage input';assets=[]
            for arch in ('arm64','amd64'):
                for suffix in ('exe.zip','artifact-manifest.json','FDSensor.exe'):
                    assets.append({'id':len(assets)+1,'name':'edr-agent-'+tag+'-windows-'+arch+'-'+suffix,
                      'size':len(raw),'digest':'sha256:'+M.digest(raw)})
            info={'id':123,'assets':assets} # Deliberately not canonical release metadata.
            with patch.object(M,'release',return_value=info),patch.object(M,'gh',return_value=raw):
                with self.assertRaisesRegex(ValueError,'Release metadata tag, ID or publication state mismatch'):
                    M.download_headless(Path(d),checkpoint,tag,M.SOURCE,M.TARGET_RUN)
            self.assertEqual(sys.path,before)
            self.assertFalse((Path(d)/'target-runtime').exists())
    def test_module_load_failure_restores_complete_original_search_path(self):
        with tempfile.TemporaryDirectory()as d:
            owner=Path(d)/'broken.py';owner.write_text('import sys\nsys.path.append("synthetic module mutation")\nraise RuntimeError("synthetic failure")\n')
            before=list(sys.path)
            with self.assertRaisesRegex(RuntimeError,'synthetic failure'):M.module(owner,'broken_original')
            self.assertEqual(sys.path,before)
    def test_original_import_context_success_restores_complete_path(self):
        with tempfile.TemporaryDirectory()as d:
            owner=Path(d)/'owner.py';before=list(sys.path)
            with M.original_imports(owner):
                self.assertEqual(sys.path[0],str(owner.parent));sys.path.append('synthetic inner mutation')
            self.assertEqual(sys.path,before)
    def test_missing_module_cause_is_safe_qualified_name_only(self):
        exc=ModuleNotFoundError('private path and arbitrary message',name='windows_usb_bundle')
        self.assertEqual(M.failure_cause(exc),'missing_module:windows_usb_bundle')
        self.assertEqual(M.failure_cause(ModuleNotFoundError('private',name='safe.module_2')),'missing_module:safe.module_2')
    def test_unsafe_missing_module_name_is_not_exported(self):
        for name in (None,'private/path','private\nmodule','a'*129,'bad-name','token?secret'):
            with self.subTest(name=name):
                self.assertEqual(M.failure_cause(ModuleNotFoundError('private message',name=name)),'missing_module:unclassified')
    def test_other_exception_diagnostics_remain_sanitized(self):
        self.assertEqual(M.failure_cause(RuntimeError('private message')),'RuntimeError')
        self.assertEqual(M.failure_cause(ValueError('typed_known_cause')),'typed_known_cause')
    def test_binary_bytes_unchanged(self):
        raw=M.bounded_process([sys.executable,'-c','import sys;sys.stdout.buffer.write(bytes([0,255,0,10]))'],4,2)
        self.assertEqual(raw,bytes([0,255,0,10]))
if __name__=='__main__':unittest.main(verbosity=2)
