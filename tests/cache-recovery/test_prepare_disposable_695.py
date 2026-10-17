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
class Contracts(unittest.TestCase):
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
        self.assertIn("'zz_private_695_p5_export_test.go'",text)
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
        self.assertEqual(len(re.findall(r'^  \$(?:owned|child)=StartWindowsPowerShellChild ',driver,re.M)),2)
        wait=driver[driver.index('function WaitProcess('):driver.index('function ServiceAction(')]
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
