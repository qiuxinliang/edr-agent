"""Bounded private CI-fixture QA evidence; fixed names, no directory scanning.
Never copies Agent logs/configs/databases/products/environments or credentials.
"""
import argparse
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import stat
import sys
import time

SOURCE='694a4f47cfd55a7c98f8dab62617520c0c6251b1'
FILE_CAP=1024*1024
TOTAL_CAP=8*1024*1024
WINDOWS_STAT=os.name=='nt'
SHA=re.compile('[0-9a-f]{64}')
LABELS={'health-failed-upgrade':('upgrade',True),'normal-recovery-upgrade':('upgrade',False),'normal-headless-repair':('repair',False)}
METADATA=('recovery-subset-summary.json','seed-owner.json','storage-floor-proof.json','692-before-upgrade.json',
          'health-failed-upgrade-before-trigger.json','health-failed-upgrade-after.json',
          'normal-recovery-upgrade-after.json','normal-headless-repair-after.json')
RAW=tuple(label+suffix for label in LABELS for suffix in ('.intent.json','.original-report.json','.original-journal.json','.stdout.log','.stderr.log'))+('health-failed-upgrade.health-trigger.json',)
ALLOW=METADATA+RAW


def need(ok,cause):
    if not ok:raise ValueError(cause)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(rows):
        out={}
        for k,v in rows:need(k not in out,'duplicate_json_key');out[k]=v
        return out
    return json.loads(raw.decode('utf-8-sig','strict'),object_pairs_hook=pairs,
                      parse_constant=lambda unused:(_ for _ in ()).throw(ValueError('json_constant')))


def no_reparse(path):
    need(path.is_absolute() and not str(path).startswith(('\\\\','//')),'local_absolute_path_required')
    for p in (path,*path.parents):
        s=p.lstat()
        need(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,'reparse_refused')


def identity(s):return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def cross_identity(s):
    if not WINDOWS_STAT:return identity(s)
    # Windows lstat ctime can mean birth while fstat ctime means ChangeTime.
    # Bind path to FD using birth, but retain each API's own ctime stability.
    birth=getattr(s,'st_birthtime_ns',None)
    need(type(birth)is int,'windows_birthtime_required')
    return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,birth)


def take(path,cap=FILE_CAP):
    no_reparse(path);before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and 0<=before.st_size<=cap,'file_bound_or_type')
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(path,flags)
    with os.fdopen(fd,'rb')as f:
        opened=os.fstat(f.fileno())
        need(cross_identity(opened)==cross_identity(before),'opened_file_identity_changed')
        raw=f.read(before.st_size+1)
        after_handle=os.fstat(f.fileno())
    no_reparse(path);after_path=path.lstat()
    need(len(raw)==before.st_size and identity(opened)==identity(after_handle) and identity(before)==identity(after_path) and
         cross_identity(before)==cross_identity(after_handle)==cross_identity(after_path),'file_changed_during_bounded_read')
    return raw


def save(path,raw):
    with path.open('xb')as f:f.write(raw);f.flush();os.fsync(f.fileno())


def read_binding(path,pin):
    need(type(pin)is str and SHA.fullmatch(pin),'binding_sha_shape');raw=take(path)
    need(sha(raw)==pin,'binding_sha_mismatch');b=strict_json(raw)
    need(b.get('schema')=='edr.ci-cache-recovery-input.v1' and b.get('prepared_only')is False and b.get('arch')=='arm64' and
         b.get('target',{}).get('source_sha')==SOURCE,'binding_scope')
    stages={}
    for which,version in (('target','3.2.695'),('baseline','3.2.692')):
        spec=b.get(which,{});raw=take(Path(spec.get('stage_path','')))
        need(type(spec.get('stage_sha256'))is str and sha(raw)==spec['stage_sha256'],'stage_sha_mismatch')
        v=strict_json(raw)
        need(v.get('version')==version and v.get('target_arch')=='arm64' and SHA.fullmatch(v.get('agent_binary_sha256','')),'stage_scope')
        stages[which]=v
    need(stages['target'].get('source_commit')==SOURCE,'target_source')
    need(stages['baseline'].get('source_commit')=='a978ec83deacf7cd78c273d82630b457c5f39251','baseline_source')
    return b,stages


def phase_identity(data,b,stages):
    target=stages['target']['agent_binary_sha256']
    for label,(operation,health_fail)in LABELS.items():
        key=label+'.intent.json';intent=strict_json(data[key])if key in data else None
        children=[label+s for s in ('.original-report.json','.original-journal.json','.stdout.log','.stderr.log')]
        need(intent is not None or not any(n in data for n in children),'phase_data_without_intent')
        if intent is None:continue
        task=intent.get('task_id');need(type(task)is str and re.fullmatch('[0-9a-f]{32}',task) and
            intent.get('command_id')=='ci-cache-recovery-'+task and intent.get('operation')==operation and
            intent.get('class')=='installer_required' and intent.get('expected_hash')==target and
            intent.get('health_failure_requested')is health_fail and intent.get('no_automatic_retry')is True,'phase_intent_identity')
        key=label+'.original-journal.json'
        if key in data:
            j=strict_json(data[key]);need(j.get('schema_version')==2 and type(j.get('schema_version'))is int and
              j.get('task_id')==task and j.get('command_id')==intent['command_id'] and j.get('hash')==target and
              j.get('version')=='3.2.695' and j.get('operation')==operation and j.get('upgrade_class')=='installer_required' and
              j.get('artifact_id')=='ci-cache-recovery-3.2.695','phase_journal_identity')
        key=label+'.original-report.json'
        if key in data:
            j=strict_json(data[key]);need(j.get('target_version')=='3.2.695' and j.get('operation')==operation and
              j.get('upgrade_class')=='installer_required' and j.get('expected_architecture')=='arm64' and
              j.get('expected_sha256')==target and type(j.get('runtime_manifest'))is str and
              ntpath.normcase(ntpath.normpath(j['runtime_manifest']))==ntpath.normcase(ntpath.normpath(b['protocol5_package']['path'])),'phase_report_identity')
    key='health-failed-upgrade.health-trigger.json'
    if key in data:
        j=strict_json(data[key]);n=j.get('native',{});snapshot='health-failed-upgrade-before-trigger.json'
        need('health-failed-upgrade.intent.json'in data and snapshot in data and j.get('action')=='stop_exact_owned_service' and j.get('fixture_only')is True and
          j.get('actual_previous_sha256')==stages['baseline']['agent_binary_sha256'] and n.get('exe_sha256')==target and
          n.get('fixture_config_binding_verified')is True and n.get('service_config_argv_verified')is True and
          j.get('owner_snapshot_sha256')==sha(data[snapshot]),'health_trigger_identity')


def collect(source,binding,pin,output,runner_temp):
    started=time.monotonic();no_reparse(runner_temp);no_reparse(source)
    need(source.parent==runner_temp and re.fullmatch('edr-cache-recovery-[0-9a-f]{32}',source.name),'owned_fixture_directory')
    need(output.parent==runner_temp and re.fullmatch('edr-cache-recovery-qa-[0-9a-f]{32}',output.name) and not output.exists(),'exclusive_output_directory')
    b,stages=read_binding(binding,pin)
    data={};missing=[];total=0
    for name in ALLOW:
        need(time.monotonic()-started<30,'collector_deadline')
        path=source/name
        try:raw=take(path)
        except FileNotFoundError:missing.append(name);continue
        need(raw or name.endswith('.log'),'empty_json_refused')
        total+=len(raw);need(total<=TOTAL_CAP,'aggregate_bytes_bound');data[name]=raw
    need('recovery-subset-summary.json'in data,'owned_summary_required')
    summary=strict_json(data['recovery-subset-summary.json'])
    need(summary.get('schema')=='edr.ci-cache-recovery-result.v1' and summary.get('input_sha256')==pin and summary.get('target_source')==SOURCE and
         summary.get('baseline')=='win_3.2.692' and summary.get('status')in ('local_subset_passed','failed_or_unknown') and
         summary.get('real_data_touched')is False and summary.get('library_prepared_schema')is True,'owned_summary_identity')
    for name in METADATA:
        if name in data:strict_json(data[name])
    phase_identity(data,b,stages)
    need(summary['status']!='local_subset_passed' or not missing,'passed_subset_missing_raw_evidence')
    manifest={'schema':'edr.ci-synthetic-recovery-artifacts.v1','purpose':'private_ci_fixture_raw_qa_evidence','input_sha256':pin,
      'target_source':SOURCE,'target_version':'3.2.695','baseline':'win_3.2.692','arch':'arm64',
      'recovery_status':summary['status'],'collector_status':'collected_fixed_whitelist','complete_file_inventory':not missing,
      'not_observed_files':missing,'source_terminal_state_proven_by_collector':False,
      'files':[{'name':name,'bytes':len(data[name]),'sha256':sha(data[name])}for name in ALLOW if name in data],
      'source_payload_bytes':total,'per_file_limit_bytes':FILE_CAP,'artifact_total_limit_bytes':TOTAL_CAP,
      'credentials_or_environment_or_real_agent_logs_exported':False,'evidence_db_or_config_or_product_exported':False,
      'private_ci_fixture_only':True,'missing_does_not_mean_action_did_not_occur':True}
    raw=(json.dumps(manifest,indent=2)+'\n').encode();need(len(raw)<=FILE_CAP and total+len(raw)<=TOTAL_CAP,'aggregate_manifest_bytes_bound')
    no_reparse(source);no_reparse(runner_temp);need(not output.exists(),'exclusive_output_directory');output.mkdir()
    for name in ALLOW:
        if name in data:save(output/name,data[name])
    save(output/'manifest.json',raw)
    return {'status':'fixed_ci_fixture_evidence_collected','recovery_status':summary['status'],'files':len(data),'missing_files':len(missing),
            'bytes_including_manifest':total+len(raw),'manifest_sha256':sha(raw),'recovery_pass_claimed':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--binding',type=Path,required=True)
    p.add_argument('--binding-sha256',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    need(os.name=='nt' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted','disposable_windows_ci_only')
    print(json.dumps(collect(a.source,a.binding,a.binding_sha256,a.output,Path(os.environ['RUNNER_TEMP']))))
if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('ci_fixture_collection_failed:'+str(exc)if isinstance(exc,ValueError)else'ci_fixture_collection_failed:'+type(exc).__name__,file=sys.stderr)
        sys.exit(1)
