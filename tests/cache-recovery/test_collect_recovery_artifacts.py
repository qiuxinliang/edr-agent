"""Pure synthetic files only; no installer, native process, network or real DB."""
import hashlib
from contextlib import contextmanager
import importlib.util
import json
import os
import types
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
S=importlib.util.spec_from_file_location('collector',Path(__file__).with_name('collect_recovery_artifacts.py'))
M=importlib.util.module_from_spec(S);S.loader.exec_module(M)

class Contracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.source=self.root/('edr-cache-recovery-'+'a'*32);self.source.mkdir()
        self.output=self.root/('edr-cache-recovery-qa-'+'b'*32)
        self.target='1'*64;self.baseline='2'*64;self.package=str(self.root/'synthetic-public-p5.zip')
        stages={}
        for label,version,source,digest in [('target','3.2.695',M.SOURCE,self.target),('baseline','3.2.692','a978ec83deacf7cd78c273d82630b457c5f39251',self.baseline)]:
            p=self.root/(label+'.json');self.write(p,{'version':version,'source_commit':source,'target_arch':'arm64','agent_binary_sha256':digest});stages[label]={'stage_path':str(p),'stage_sha256':M.sha(p.read_bytes())}
        self.binding=self.root/'input.json';self.write(self.binding,{'schema':'edr.ci-cache-recovery-input.v1','prepared_only':False,'arch':'arm64','target':dict(stages['target'],source_sha=M.SOURCE),'baseline':stages['baseline'],'protocol5_package':{'path':self.package}})
        self.pin=M.sha(self.binding.read_bytes())
        summary={'schema':'edr.ci-cache-recovery-result.v1','input_sha256':self.pin,'target_source':M.SOURCE,'baseline':'win_3.2.692','status':'local_subset_passed','real_data_touched':False,'library_prepared_schema':True}
        for name in M.METADATA:self.write(self.source/name,summary if name=='recovery-subset-summary.json'else{'synthetic_metadata':True})
        for i,(label,(op,failed))in enumerate(M.LABELS.items()):
            task=str(i+1)*32
            self.write(self.source/(label+'.intent.json'),{'task_id':task,'command_id':'ci-cache-recovery-'+task,'operation':op,'class':'installer_required','expected_hash':self.target,'health_failure_requested':failed,'no_automatic_retry':True})
            self.write(self.source/(label+'.original-report.json'),{'target_version':'3.2.695','operation':op,'upgrade_class':'installer_required','expected_architecture':'arm64','expected_sha256':self.target,'runtime_manifest':self.package,'status':'synthetic_only'})
            self.write(self.source/(label+'.original-journal.json'),{'schema_version':2,'task_id':task,'command_id':'ci-cache-recovery-'+task,'hash':self.target,'version':'3.2.695','operation':op,'upgrade_class':'installer_required','artifact_id':'ci-cache-recovery-3.2.695'})
            (self.source/(label+'.stdout.log')).write_bytes(b'public synthetic stdout\n');(self.source/(label+'.stderr.log')).write_bytes(b'')
        self.write(self.source/'health-failed-upgrade.health-trigger.json',{'action':'stop_exact_owned_service','fixture_only':True,'actual_previous_sha256':self.baseline,'native':{'exe_sha256':self.target,'fixture_config_binding_verified':True,'service_config_argv_verified':True},'owner_snapshot_sha256':M.sha((self.source/'health-failed-upgrade-before-trigger.json').read_bytes())})
    def write(self,p,v):p.write_bytes((json.dumps(v)+'\n').encode())
    def collect(self):return M.collect(self.source,self.binding,self.pin,self.output,self.root)
    def mutate(self,name,key,value):
        p=self.source/name;j=json.loads(p.read_bytes());j[key]=value;self.write(p,j)
    @contextmanager
    def synthetic_bound_697(self):
        # This temporary public catalog tests routing only, never a published artifact.
        catalog=json.loads(M._PROFILE_OWNER.cohort_catalog_raw());c=catalog['profiles']['697']
        for key,value in c.items():
            if value=='UNBOUND':c[key]='7'*64 if key.endswith('_sha256')else '1'
        path=self.root/'synthetic-catalog.json';self.write(path,catalog)
        with patch.object(M._PROFILE_OWNER,'PROFILE_FILE',path):
            yield c,M.sha(path.read_bytes())
    def set_697_fixture(self,c,pin):
        binding=json.loads(self.binding.read_bytes());binding['cohort_id']='697';binding['cohort_catalog_sha256']=pin;binding['target']['source_sha']=c['source']
        stage=Path(binding['target']['stage_path']);value=json.loads(stage.read_bytes());value.update(version=c['version'],source_commit=c['source']);self.write(stage,value)
        binding['target']['stage_sha256']=M.sha(stage.read_bytes());self.write(self.binding,binding);self.pin=M.sha(self.binding.read_bytes())
        self.mutate('recovery-subset-summary.json','input_sha256',self.pin);self.mutate('recovery-subset-summary.json','target_source',c['source'])
        for label in M.LABELS:
            self.mutate(label+'.original-report.json','target_version',c['version'])
            self.mutate(label+'.original-journal.json','version',c['version'])
            self.mutate(label+'.original-journal.json','artifact_id','ci-cache-recovery-'+c['version'])
    def test_unbound_697_is_not_a_legacy_695_fallback(self):
        value=json.loads(self.binding.read_bytes());value['cohort_id']='697';value['target']['source_sha']='f672059aec426aafe00b216c482dc151b96226c9';self.write(self.binding,value);self.pin=M.sha(self.binding.read_bytes())
        catalog=json.loads(M._PROFILE_OWNER.cohort_catalog_raw());catalog['profiles']['697']['release_run']='UNBOUND'
        path=self.root/'missing-pin.json';self.write(path,catalog)
        with patch.object(M._PROFILE_OWNER,'PROFILE_FILE',path),self.assertRaisesRegex(ValueError,'cohort_UNBOUND'):self.collect()
        self.assertFalse(self.output.exists())
    def test_closed_synthetic_697_has_accurate_artifact_identity(self):
        with self.synthetic_bound_697()as(c,pin):
            self.set_697_fixture(c,pin);self.collect();result=json.loads((self.output/'manifest.json').read_bytes())
            self.assertEqual(result['target_version'],'3.2.697');self.assertEqual(result['target_source'],c['source'])
            self.assertEqual(len(result['files']),24);self.assertFalse(result['source_terminal_state_proven_by_collector'])
    def test_697_requires_exact_catalog_hash(self):
        with self.synthetic_bound_697()as(c,pin):
            self.set_697_fixture(c,pin)
            value=json.loads(self.binding.read_bytes());value.pop('cohort_catalog_sha256');self.write(self.binding,value);self.pin=M.sha(self.binding.read_bytes())
            with self.assertRaisesRegex(ValueError,'catalog_sha_mismatch'):self.collect()
            self.assertFalse(self.output.exists())
    def test_697_rejects_old_695_journal_and_profile_hash(self):
        with self.synthetic_bound_697()as(c,pin):
            self.set_697_fixture(c,pin);self.mutate('health-failed-upgrade.original-journal.json','version','3.2.695')
            with self.assertRaisesRegex(ValueError,'phase_journal_identity'):self.collect()
            self.assertFalse(self.output.exists())
        value=json.loads(self.binding.read_bytes());value['cohort_catalog_sha256']='0'*64;self.write(self.binding,value);self.pin=M.sha(self.binding.read_bytes())
        with self.synthetic_bound_697(),self.assertRaisesRegex(ValueError,'catalog_sha_mismatch'):self.collect()
    def test_fixed_complete_inventory_hashes_and_zero_stderr(self):
        r=self.collect();self.assertEqual(r['files'],24);self.assertFalse(r['recovery_pass_claimed'])
        j=json.loads((self.output/'manifest.json').read_bytes());self.assertTrue(j['complete_file_inventory'])
        for item in j['files']:
            raw=(self.output/item['name']).read_bytes();self.assertEqual(len(raw),item['bytes']);self.assertEqual(M.sha(raw),item['sha256'])
        self.assertLessEqual(sum(p.stat().st_size for p in self.output.iterdir()),M.TOTAL_CAP)
    def test_unknown_files_are_never_read_or_exported(self):
        for name in ('agent.log','agent.toml','cache.db','environment.json','parameters.xml'):(self.source/name).write_bytes(b'not an exportable file')
        self.collect();self.assertEqual(set(p.name for p in self.output.iterdir()),set(M.ALLOW)|{'manifest.json'})
    def test_failed_partial_keeps_missing_separate_from_did_not_occur(self):
        self.mutate('recovery-subset-summary.json','status','failed_or_unknown')
        for n in M.RAW:(self.source/n).unlink()
        self.collect();j=json.loads((self.output/'manifest.json').read_bytes())
        self.assertFalse(j['complete_file_inventory']);self.assertEqual(len(j['not_observed_files']),16);self.assertTrue(j['missing_does_not_mean_action_did_not_occur'])
    def test_passed_missing_raw_is_refused(self):
        (self.source/'normal-headless-repair.stderr.log').unlink()
        with self.assertRaisesRegex(ValueError,'passed_subset_missing'):self.collect()
        self.assertFalse(self.output.exists())
    def test_wrong_summary_identity(self):
        self.mutate('recovery-subset-summary.json','input_sha256','0'*64)
        with self.assertRaisesRegex(ValueError,'summary_identity'):self.collect()
    def test_wrong_journal_identity(self):
        self.mutate('normal-headless-repair.original-journal.json','task_id','0'*32)
        with self.assertRaisesRegex(ValueError,'journal_identity'):self.collect()
    def test_wrong_report_identity(self):
        self.mutate('normal-recovery-upgrade.original-report.json','runtime_manifest','unrelated.zip')
        with self.assertRaisesRegex(ValueError,'report_identity'):self.collect()
    def test_report_requires_its_intent(self):
        (self.source/'normal-headless-repair.intent.json').unlink()
        with self.assertRaisesRegex(ValueError,'without_intent'):self.collect()
    def test_empty_json_and_duplicate_keys(self):
        p=self.source/'seed-owner.json';p.write_bytes(b'')
        with self.assertRaisesRegex(ValueError,'empty_json'):self.collect()
        p.write_bytes(b'{"x":1,"x":2}')
        with self.assertRaisesRegex(ValueError,'duplicate_json_key'):self.collect()
    def test_oversize_refused_before_open(self):
        p=self.root/'large';p.write_bytes(b'x'*17)
        with patch.object(M.os,'open',side_effect=AssertionError('must not open')):
            with self.assertRaisesRegex(ValueError,'file_bound'):M.take(p,16)
    def test_aggregate_cap_refuses_all_output(self):
        with patch.object(M,'TOTAL_CAP',32):
            with self.assertRaisesRegex(ValueError,'aggregate_bytes_bound'):self.collect()
        self.assertFalse(self.output.exists())
    def test_manifest_bytes_also_count_toward_cap(self):
        total=sum((self.source/n).stat().st_size for n in M.ALLOW)
        with patch.object(M,'TOTAL_CAP',total+1):
            with self.assertRaisesRegex(ValueError,'aggregate_manifest'):self.collect()
        self.assertFalse(self.output.exists())
    def test_leaf_and_ancestor_symlink_refused(self):
        p=self.root/'link'
        try:p.symlink_to(self.binding)
        except OSError:
            if os.name=='nt':self.skipTest('host does not grant symlink creation; reparse attribute rejection is separately tested')
            raise
        with self.assertRaisesRegex(ValueError,'reparse'):M.take(p)
        q=self.root/'parent';q.symlink_to(self.source,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'reparse'):M.take(q/'seed-owner.json')
    def test_windows_reparse_attribute_refused(self):
        p=self.root/'attribute';p.write_bytes(b'x');real=Path.lstat
        def flagged(path):
            s=real(path)
            return types.SimpleNamespace(st_mode=s.st_mode,st_file_attributes=0x400)if path==p else s
        with patch.object(Path,'lstat',flagged):
            with self.assertRaisesRegex(ValueError,'reparse'):M.take(p)
    def test_file_growth_bounded_to_declared_size_plus_one(self):
        p=self.root/'growing';p.write_bytes(b'abc');real=M.os.fdopen;seen=[]
        class Reader:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):self.stream.__enter__();return self
            def __exit__(self,*a):return self.stream.__exit__(*a)
            def fileno(self):return self.stream.fileno()
            def read(self,n):
                seen.append(n)
                with p.open('ab')as f:f.write(b'defgh')
                return self.stream.read(n)
        with patch.object(M.os,'fdopen',side_effect=lambda *a,**k:Reader(real(*a,**k))):
            with self.assertRaisesRegex(ValueError,'file_changed'):M.take(p)
        self.assertEqual(seen,[4])
    def test_same_length_replacement_refused(self):
        p=self.root/'replace';p.write_bytes(b'abc');real=M.os.fdopen
        class Reader:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):self.stream.__enter__();return self
            def __exit__(self,*a):return self.stream.__exit__(*a)
            def fileno(self):return self.stream.fileno()
            def read(self,n):
                raw=self.stream.read(n);before=p.stat()
                with p.open('r+b')as f:f.write(b'xyz')
                os.utime(p,ns=(before.st_atime_ns,before.st_mtime_ns+1000000000));return raw
        with patch.object(M.os,'fdopen',side_effect=lambda *a,**k:Reader(real(*a,**k))):
            with self.assertRaisesRegex(ValueError,'file_changed'):M.take(p)
    @contextmanager
    def windows_stat_semantics(self,path,*,path_change=False,handle_change=False,
                               birth_change=False,missing_birth=False,wrong_handle_inode=False,windows=True):
        # A real file/FD/read with only the documented stat time semantics mocked.
        # Win lstat ctime may be birth; fstat ctime may be ChangeTime.
        real_lstat=Path.lstat;real_fstat=M.os.fstat;handle_calls=0
        def project(s,handle,after):
            values=dict(st_mode=s.st_mode,st_dev=s.st_dev,
              st_ino=s.st_ino+(1 if handle and wrong_handle_inode else 0),
              st_size=s.st_size,st_mtime_ns=s.st_mtime_ns,
              st_ctime_ns=(200 if handle else 100)+(1 if after and (handle_change if handle else path_change) else 0),
              st_file_attributes=getattr(s,'st_file_attributes',0))
            if not missing_birth:values['st_birthtime_ns']=100+(1 if after and birth_change else 0)
            return types.SimpleNamespace(**values)
        def lstat(p):
            s=real_lstat(p)
            return project(s,False,handle_calls>=2)if p==path else s
        def fstat(fd):
            nonlocal handle_calls
            handle_calls+=1
            return project(real_fstat(fd),True,handle_calls>=2)
        with patch.object(M,'WINDOWS_STAT',windows,create=True),patch.object(Path,'lstat',lstat),patch.object(M.os,'fstat',fstat):
            yield
    def test_windows_cross_api_only_ctime_difference_is_allowed(self):
        p=self.root/'windows-times';p.write_bytes(b'public synthetic')
        with self.windows_stat_semantics(p):self.assertEqual(M.take(p),b'public synthetic')
    def test_windows_path_ctime_change_is_refused(self):
        p=self.root/'path-change';p.write_bytes(b'abc')
        with self.windows_stat_semantics(p,path_change=True):
            with self.assertRaisesRegex(ValueError,'file_changed_during_bounded_read'):M.take(p)
    def test_windows_handle_ctime_change_is_refused(self):
        p=self.root/'handle-change';p.write_bytes(b'abc')
        with self.windows_stat_semantics(p,handle_change=True):
            with self.assertRaisesRegex(ValueError,'file_changed_during_bounded_read'):M.take(p)
    def test_windows_birthtime_required(self):
        p=self.root/'no-birth';p.write_bytes(b'abc')
        with self.windows_stat_semantics(p,missing_birth=True):
            with self.assertRaisesRegex(ValueError,'windows_birthtime_required'):M.take(p)
    def test_windows_birthtime_change_is_refused(self):
        p=self.root/'birth-change';p.write_bytes(b'abc')
        with self.windows_stat_semantics(p,birth_change=True):
            with self.assertRaisesRegex(ValueError,'file_changed_during_bounded_read'):M.take(p)
    def test_windows_different_handle_inode_is_refused(self):
        p=self.root/'different-handle';p.write_bytes(b'abc')
        with self.windows_stat_semantics(p,wrong_handle_inode=True):
            with self.assertRaisesRegex(ValueError,'opened_file_identity_changed'):M.take(p)
    def test_nonwindows_cross_api_ctime_difference_still_refused(self):
        p=self.root/'nonwindows-times';p.write_bytes(b'abc')
        with self.windows_stat_semantics(p,windows=False):
            with self.assertRaisesRegex(ValueError,'opened_file_identity_changed'):M.take(p)
    def test_existing_destination_never_overwritten(self):
        self.output.mkdir();(self.output/'sentinel').write_bytes(b'preserve')
        with self.assertRaisesRegex(ValueError,'exclusive_output'):self.collect()
        self.assertEqual((self.output/'sentinel').read_bytes(),b'preserve')
    def test_other_fixture_directory_refused(self):
        other=self.root/'unrelated';other.mkdir()
        with self.assertRaisesRegex(ValueError,'owned_fixture'):M.collect(other,self.binding,self.pin,self.output,self.root)

if __name__=='__main__':unittest.main(verbosity=2)
