"""Explicit disposable-CI preparation only; original checkpoint/builder/driver owners.
No catalog, endpoint, enrollment, S3, publish, permission mutation or retry.
"""
import argparse
from contextlib import contextmanager
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import zipfile
import io

REPO='qiuxinliang/edr-agent'
SHA=re.compile(r'[0-9a-f]{64}')
PROFILE_FILE=Path(__file__).with_name('recovery_cohorts.json')


def need(ok,cause):
    if not ok: raise ValueError(cause)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate_json_key');result[key]=value
        return result
    return json.loads(raw.decode('utf-8','strict'),object_pairs_hook=pairs,
                      parse_constant=lambda unused: (_ for _ in ()).throw(ValueError('json_constant')))


def cohort_catalog_raw():
    with PROFILE_FILE.open('rb')as f:raw=f.read(16385)
    need(0<len(raw)<=16384,'cohort_catalog_bound')
    return raw


def cohort(cohort_id='695',require_bound=True):
    # One checked-in QA data owner; no caller-selected file/source/run/URL.
    need(cohort_id in ('695','697','698'),'unsupported_recovery_cohort')
    raw=cohort_catalog_raw()
    catalog=strict_json(raw)
    need(type(catalog)is dict and set(catalog)=={'schema','baseline','profiles'} and catalog['schema']=='edr.ci-recovery-cohorts.v1' and
         type(catalog['profiles'])is dict and set(catalog['profiles'])=={'695','697','698'},'cohort_catalog_shape')
    c=catalog['profiles'][cohort_id]
    keys={'id','source','version','tag','release_run','release_id','native_run','native_artifact_id','native_artifact_size',
          'native_artifact_sha256','native_uncompressed_bytes','native_member_count','handler_owner_sha256','builder_owner_sha256',
          'handler_receipt_sha256','binary_sha256','headless_sha256','artifact_manifest_sha256','preflight_response_sha256','p5_sha256','runtime_identity_sha256'}
    need(type(c)is dict and set(c)==keys and all(type(v)is str for v in c.values()) and c['id']==cohort_id and
         c['version']=='3.2.'+cohort_id and c['tag']=='win_'+c['version'] and re.fullmatch('[0-9a-f]{40}',c['source']),'cohort_profile_shape')
    base=catalog['baseline'];need(type(base)is dict and set(base)=={'source','version','tag','release_run','release_id'} and
         all(type(v)is str for v in base.values()) and base['version']=='3.2.692' and base['tag']=='win_3.2.692' and
         re.fullmatch('[0-9a-f]{40}',base['source']) and all(re.fullmatch('[1-9][0-9]*',base[k]) for k in ('release_run','release_id')),'cohort_baseline_shape')
    if require_bound:
        need(all(v!='UNBOUND' for v in c.values()),'recovery_cohort_UNBOUND')
        need(all(SHA.fullmatch(c[k]) for k in c if k.endswith('_sha256')) and
             all(re.fullmatch('[1-9][0-9]*',c[k]) for k in ('release_run','release_id','native_run','native_artifact_id',
                 'native_artifact_size','native_uncompressed_bytes','native_member_count')),'cohort_pin_shape')
    return c,base,digest(raw)


# Backward-compatible defaults for existing 695 parser/unit consumers. Execution
# boundaries resolve the selected closed profile again, never mutate globals.
_DEFAULT,_BASELINE,_=cohort()
SOURCE=_DEFAULT['source'];BASELINE=_BASELINE['source'];TARGET_RUN=_DEFAULT['release_run']
TOOL_RUN=_DEFAULT['native_run'];TOOL_ID=int(_DEFAULT['native_artifact_id']);TOOL_SIZE=int(_DEFAULT['native_artifact_size'])
TOOL_SHA=_DEFAULT['native_artifact_sha256'];BUILDER_SHA=_DEFAULT['builder_owner_sha256'];HANDLER_SHA=_DEFAULT['handler_owner_sha256']


def bounded_process(argv,cap,seconds):
    """Only this child is killed; stdout/stderr cannot exceed in-memory caps."""
    child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    parts={'stdout':[], 'stderr':[]};overflow=[]
    def read(name,stream,maximum):
        left=maximum
        while True:
            raw=stream.read(min(65536,left+1))
            if not raw:break
            if len(raw)>left:
                overflow.append(name)
                try:child.kill()
                except ProcessLookupError:pass
                break
            parts[name].append(raw);left-=len(raw)
    threads=[threading.Thread(target=read,args=('stdout',child.stdout,cap)),
             threading.Thread(target=read,args=('stderr',child.stderr,8192))]
    for t in threads:t.start()
    try:
        code=child.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        child.kill();child.wait(timeout=10)
        for t in threads:t.join(timeout=10)
        raise ValueError('read_only_child_timeout_no_retry')
    finally:
        for t in threads:t.join(timeout=10)
        child.stdout.close();child.stderr.close()
    need(not any(t.is_alive() for t in threads),'read_only_child_reader_unfinished')
    need(not overflow,'read_only_child_output_bound')
    stderr=b''.join(parts['stderr'])
    if code:
        status=re.search(rb'HTTP ([0-9]{3})',stderr)
        raise ValueError('read_only_github_failed_'+(status[1].decode() if status else 'nonzero')+'_no_retry_or_scope_expansion')
    need(not stderr,'read_only_github_stderr_unclassified')
    return b''.join(parts['stdout'])


def gh(endpoint,cap=1048576,binary=False):
    prefix='repos/'+REPO+'/'
    need(endpoint.startswith(prefix),'fixed_repository_only')
    kind='metadata';accept='application/vnd.github+json'
    if binary:
        if re.fullmatch(re.escape(prefix)+r'releases/assets/[1-9][0-9]*',endpoint):
            kind='release_asset';accept='application/octet-stream'
        else:
            need(re.fullmatch(re.escape(prefix)+r'actions/artifacts/[1-9][0-9]*/zip',endpoint),'fixed_binary_endpoint_required')
            kind='actions_artifact_zip'
    elif re.fullmatch(re.escape(prefix)+r'actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*',endpoint):kind='actions_run_metadata'
    elif re.fullmatch(re.escape(prefix)+r'actions/artifacts/[1-9][0-9]*',endpoint):kind='actions_artifact_metadata'
    # Actions ZIP downloads require JSON Accept but still return binary bytes.
    args=['gh','api','--method','GET',endpoint,'-H','Accept: '+accept]
    try:raw=bounded_process(args,cap,150)
    except ValueError as exc:raise ValueError('github_'+kind+':'+str(exc))from None
    return raw if binary else strict_json(raw)


def save(path,raw):
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())


def json_save(path,value):save(path,(json.dumps(value,indent=2)+'\n').encode())


@contextmanager
def original_imports(path):
    before=list(sys.path);sys.path.insert(0,str(path.parent))
    try:yield
    finally:sys.path[:]=before


def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
    with original_imports(path):spec.loader.exec_module(m)
    return m


def failure_cause(exc):
    if isinstance(exc,ModuleNotFoundError):
        name=exc.name
        safe=type(name)is str and len(name)<=128 and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*',name)
        return 'missing_module:'+(name if safe else 'unclassified')
    return str(exc)if isinstance(exc,ValueError)else type(exc).__name__


def verified_preflight(raw,profile=None):
    profile=profile or cohort()[0]
    p=strict_json(raw)
    need(type(p)is dict and p.get('code')=='OK' and type(p.get('data'))is dict,'actual_preflight_required')
    d=p['data'];need(d.get('valid')is True and d.get('upgradeReady')is True and d.get('upgradeBlockers')==[] and
        d.get('version')==profile['version'] and d.get('arch')=='arm64' and d.get('platform')=='windows' and
        d.get('signatureMode')=='unsigned_integrity' and d.get('trustedSigner')is False and
        d.get('policySnapshot')=='optional-signing-v1','actual_preflight_not_ready_or_supported_unsigned_scope')
    packages=d.get('packages');need(type(packages)is list and len(packages)==2,'preflight_package_count')
    by={}
    for item in packages:
        need(type(item)is dict and item.get('packageType')in ('headless','full_installer') and
             item['packageType']not in by and type(item.get('sha256'))is str and SHA.fullmatch(item['sha256']),
             'preflight_package_identity');by[item['packageType']]=item['sha256']
    need(set(by)=={'headless','full_installer'} and SHA.fullmatch(d.get('binarySha256','')),'preflight_package_identity')
    return d,by


def verified_builder_input(value,profile=None):
    need(type(value)is str and 0<len(value)<=65536,'original_builder_base64_required')
    try:raw=base64.b64decode(value.encode('ascii','strict'),validate=True)
    except (ValueError,UnicodeError):raise ValueError('original_builder_base64_invalid')
    need(base64.b64encode(raw).decode('ascii')==value and len(raw)<=65536 and digest(raw)==(profile['builder_owner_sha256']if profile else BUILDER_SHA),
         'fixed_original_builder_sha_required')
    return raw


def verified_handler_receipt(value,expected_sha,profile=None):
    profile=profile or cohort()[0]
    need(type(expected_sha)is str and SHA.fullmatch(expected_sha),'original_handler_receipt_pin_required')
    raw=value.encode('utf-8','strict');need(0<len(raw)<=65536 and digest(raw)==expected_sha,'original_handler_receipt_pin_required')
    p=strict_json(raw)
    keys={'schema','origin','authenticated_platform_http','verification_passed','source_sha','target_release_run','version','arch',
          'handler_owner_sha256','builder_owner_sha256','binary_sha256','headless_sha256','manifest_sha256',
          'preflight_response_utf8','preflight_response_sha256','p5_sha256','db_or_artifactstore_written',
          'evidence_cache_opened','product_binaries_executed'}
    need(type(p)is dict and set(p)==keys and p.get('schema')=='edr.ci-original-handler-verification.v1' and
         p.get('origin')=='ci_original_handler_verification' and p.get('authenticated_platform_http')is False and
         p.get('verification_passed')is True and p.get('source_sha')==profile['source'] and p.get('target_release_run')==profile['release_run'] and
         p.get('version')==profile['version'] and p.get('arch')=='arm64' and p.get('handler_owner_sha256')==profile['handler_owner_sha256'] and
         p.get('builder_owner_sha256')==profile['builder_owner_sha256'] and p.get('db_or_artifactstore_written')is False and
         p.get('evidence_cache_opened')is False and p.get('product_binaries_executed')is False,
         'original_handler_verification_scope_required')
    need(all(type(p.get(k))is str and SHA.fullmatch(p[k]) for k in
         ('binary_sha256','headless_sha256','manifest_sha256','preflight_response_sha256','p5_sha256')),
         'original_handler_verification_hash_shape')
    need(type(p['preflight_response_utf8'])is str,'original_handler_response_required')
    response=p['preflight_response_utf8'].encode('utf-8','strict')
    need(0<len(response)<=32768 and digest(response)==p['preflight_response_sha256'],'original_handler_response_hash')
    d,packages=verified_preflight(response,profile)
    need(d['binarySha256']==p['binary_sha256'] and packages['headless']==p['headless_sha256'] and
         packages['full_installer']==p['p5_sha256'],'original_handler_response_identity')
    return p,response,d,packages


def release(tag,commit,run,baseline=False,profile=None):
    profile,base,unused=cohort(profile['id']if profile else '695')
    expected=base if baseline else profile
    need((tag,commit,run)==(expected['tag'],expected['source'],expected['release_run']),'fixed_cohort_release_identity')
    info=gh('repos/'+REPO+'/releases/tags/'+tag)
    need(info.get('tag_name')==tag and info.get('draft')is False and bool(info.get('published_at')),
         'published_exact_release_required_no_draft_permission')
    if not baseline:need(info.get('prerelease')is True and info.get('id')==int(profile['release_id']),'target_candidate_prerelease_required')
    if baseline:need(info.get('id')==int(base['release_id']),'exact692_release_id')
    # No broad release listing or GraphQL/draft access is needed.
    assets=gh('repos/'+REPO+'/releases/'+str(info['id'])+'/assets?per_page=100')
    need(type(assets)is list and 1<=len(assets)<=12,'bounded_exact_release_assets');info['assets']=assets
    obj=gh('repos/'+REPO+'/git/ref/tags/'+tag)['object']
    for unused in range(8):
        if obj.get('type')=='commit':break
        need(obj.get('type')=='tag' and re.fullmatch('[0-9a-f]{40}',obj.get('sha','')),'tag_object')
        obj=gh('repos/'+REPO+'/git/tags/'+obj['sha'])['object']
    need(obj.get('type')=='commit' and obj.get('sha')==commit,'exact_tag_commit')
    return info


def download_headless(root,checkpoint,tag,commit,run,baseline=False,profile=None):
    profile=profile or cohort()[0]
    info=release(tag,commit,run,baseline,profile)
    # Reuse the existing authoritative six-asset Headless publication contract.
    checkpoint.check_headless_remote_assets(info,{'tag':tag,'mode':'unsigned'},complete=True)
    directory=root/('baseline-download' if baseline else 'target-download');directory.mkdir()
    for suffix in ['exe.zip','artifact-manifest.json']:
        name='edr-agent-'+tag+'-windows-arm64-'+suffix;rows=[a for a in info['assets']if a.get('name')==name]
        need(len(rows)==1,'exact_asset_missing_or_duplicate');a=rows[0]
        need(type(a.get('id'))is int and a['id']>0 and type(a.get('size'))is int and 0<a['size']<=256*1024**2 and
            type(a.get('digest'))is str and re.fullmatch('sha256:[0-9a-f]{64}',a['digest']),'asset_immutable_metadata')
        raw=gh('repos/'+REPO+'/releases/assets/'+str(a['id']),a['size'],True)
        need(len(raw)==a['size'] and digest(raw)==a['digest'][7:],'asset_full_hash_size')
        save(directory/name,raw)
    metadata=root/('baseline-release.json'if baseline else 'target-release.json');json_save(metadata,info)
    # The original owner imports its sibling validators lazily during staging.
    with original_imports(Path(checkpoint.__file__)):
        stage=checkpoint.stage_headless(directory,root/('baseline-runtime'if baseline else 'target-runtime'),metadata,tag,'arm64',commit,REPO,
            expected_source_commit=None if baseline else commit,expected_run_id=None if baseline else run,
            published_baseline=baseline,target_tag=profile['tag']if baseline else None)
    json_save(root/('baseline-stage.json'if baseline else 'target-stage.json'),stage)
    return stage,directory


def native_tools(root,snapshot,stage_owner,profile=None):
    profile=cohort(profile['id']if profile else '695')[0]
    source=profile['source'];run_id=profile['native_run'];tool_id=int(profile['native_artifact_id'])
    tool_size=int(profile['native_artifact_size']);tool_sha=profile['native_artifact_sha256']
    run=gh('repos/'+REPO+'/actions/runs/'+run_id+'/attempts/1')
    need(run.get('id')==int(run_id) and run.get('run_attempt')==1 and run.get('head_sha')==source and
        run.get('status')=='completed' and run.get('conclusion')=='success','exact_passed_tool_run')
    a=gh('repos/'+REPO+'/actions/artifacts/'+str(tool_id))
    need(a.get('id')==tool_id and a.get('name')=='evidence-native-tools-arm64-'+source and
        a.get('size_in_bytes')==tool_size and a.get('digest')=='sha256:'+tool_sha and a.get('expired')is False and
        a.get('workflow_run',{}).get('id')==int(run_id) and a.get('workflow_run',{}).get('head_sha')==source,
        'exact_passed_tool_artifact')
    raw=gh('repos/'+REPO+'/actions/artifacts/'+str(tool_id)+'/zip',tool_size,True)
    need(len(raw)==tool_size and digest(raw)==tool_sha,'tool_archive_full_hash_size')
    out=root/'native-tools';out.mkdir()
    with zipfile.ZipFile(io.BytesIO(raw))as archive:
        files=archive.infolist();need(len(files)==int(profile['native_member_count']) and sum(f.file_size for f in files)==int(profile['native_uncompressed_bytes']),'tool_archive_inventory')
        for f in files:
            need(re.fullmatch('[a-z0-9_.-]+',f.filename) and not f.is_dir() and not((f.external_attr>>16)&0o170000)==0o120000 and
                not f.flag_bits&1 and 0<f.file_size<=64*1024**2 and f.file_size<=max(1,f.compress_size)*200,'tool_archive_path_bound')
            body=archive.read(f);need(len(body)==f.file_size,'tool_archive_size');save(out/f.filename,body)
    snapshot.validate_native_tools(out/'manifest.json',digest((out/'manifest.json').read_bytes()),stage_owner,digest(stage_owner.read_bytes()),'arm64',source,run_id)
    return out


def runtime_mode(value):
    need(type(value)is str and value in ('service','scheduled_task'),'closed_recovery_runtime_mode_required')
    return value


def prepare(workspace,root,receipt,receipt_sha,effective_floor,owner_b64,cohort_id='695',mode='service'):
    mode=runtime_mode(mode)
    profile,baseline_profile,profile_sha=cohort(cohort_id)
    need(not root.exists(),'fresh_private_output_required')
    verification,receipt_raw,d,packages=verified_handler_receipt(receipt,receipt_sha,profile)
    owner_raw=verified_builder_input(owner_b64,profile)
    need(receipt_sha==profile['handler_receipt_sha256'] and verification['p5_sha256']==profile['p5_sha256'] and
         verification['binary_sha256']==profile['binary_sha256'] and verification['headless_sha256']==profile['headless_sha256'] and
         verification['manifest_sha256']==profile['artifact_manifest_sha256'] and verification['preflight_response_sha256']==profile['preflight_response_sha256'],
         'exact_cohort_original_handler_pin')
    need(re.fullmatch('(0|[1-9][0-9]{0,12})',effective_floor) and int(effective_floor)<=1099511627776,'optional_explicit_higher_disk_floor_required')
    profile_raw=cohort_catalog_raw();need(digest(profile_raw)==profile_sha,'cohort_catalog_changed')
    root.mkdir();save(root/'preflight.json',receipt_raw);save(root/'original-handler-verification.json',receipt.encode('utf-8'))
    source_owner=root/'source-owner';source_owner.mkdir();owner=source_owner/'full_installer.go';save(owner,owner_raw);save(source_owner/'recovery_cohorts.json',profile_raw)
    checkpoint=module(workspace/'canonical-agent/scripts/windows_release_checkpoint.py','original_checkpoint')
    snapshot=module(workspace/'tests/cache-recovery/cache_recovery_snapshot.py','original_private_snapshot')
    stage_owner=workspace/'canonical-agent/scripts/stage_retention_native_tools.py';tool=native_tools(root,snapshot,stage_owner,profile)
    target,downloads=download_headless(root,checkpoint,profile['tag'],profile['source'],profile['release_run'],profile=profile)
    baseline,unused=download_headless(root,checkpoint,baseline_profile['tag'],baseline_profile['source'],baseline_profile['release_run'],True,profile)
    zip_path=downloads/('edr-agent-'+profile['tag']+'-windows-arm64-exe.zip')
    manifest=downloads/('edr-agent-'+profile['tag']+'-windows-arm64-artifact-manifest.json')
    need(digest(zip_path.read_bytes())==packages['headless'] and target['agent_binary_sha256']==d['binarySha256'] and target['runtime_identity_sha256']==profile['runtime_identity_sha256'] and
         digest(manifest.read_bytes())==verification['manifest_sha256'],'original_handler_download_binding')
    binding={'schema':'edr.private-verified-headless-p5-input.v1','prepared_only':False,'cohort_id':cohort_id,'cohort_catalog_sha256':profile_sha,'source_sha':profile['source'],'version':profile['version'],'arch':'arm64',
      'agent_sha256':target['agent_binary_sha256'],'runtime_identity_sha256':target['runtime_identity_sha256'],'builder_owner_sha256':digest(owner.read_bytes()),
      'headless':{'path':str(zip_path),'sha256':packages['headless'],'bytes':zip_path.stat().st_size},
      'preflight':{'path':str(root/'preflight.json'),'sha256':digest(receipt_raw),'bytes':len(receipt_raw)}}
    json_save(root/'p5-binding.json',binding)
    json_save(root/'overlay.json',{'Replace':{str(owner.with_name('zz_private_p5_export_test.go')):str(workspace/'tests/cache-recovery/verified_headless_p5_export_test.go')}})
    json_save(root/'prepared.json',{'schema':'edr.disposable-recovery-prepared.v1','runtime_mode':mode,'cohort_id':cohort_id,'cohort_catalog_sha256':profile_sha,'source_sha':profile['source'],'target_run':profile['release_run'],'tool_run':profile['native_run'],
      'verification_origin':'ci_original_handler_verification','authenticated_platform_http':False,
      'original_handler_verification_sha256':receipt_sha,'preflight_sha256':digest(receipt_raw),'builder_owner_sha256':profile['builder_owner_sha256'],'expected_p5_sha256':packages['full_installer'],'requested_min_free_bytes':effective_floor,'catalog_written':False,
      'endpoint_task_created':False,'recovery_started':False,'stage_owner_sha256':digest(stage_owner.read_bytes()),'native_manifest_sha256':digest((tool/'manifest.json').read_bytes())})


def finalize(workspace,root,cohort_id='695',mode='service'):
    mode=runtime_mode(mode)
    profile,baseline_profile,profile_sha=cohort(cohort_id)
    p=strict_json((root/'prepared.json').read_bytes());need(p['source_sha']==profile['source'] and p['cohort_id']==cohort_id and p['cohort_catalog_sha256']==profile_sha,'prepared_source')
    need(p.get('runtime_mode')==mode,'prepared_runtime_mode')
    package=root/('verified-p5-'+profile['version']+'-arm64.zip');need(package.is_file() and not package.is_symlink() and package.stat().st_size<=256*1024**2 and
        digest(package.read_bytes())==p['expected_p5_sha256'],'original_builder_output_preflight_hash_required')
    manifest=root/'target-download'/('edr-agent-'+profile['tag']+'-windows-arm64-artifact-manifest.json')
    stage=root/'target-stage.json';baseline=root/'baseline-stage.json';tools=root/'native-tools/manifest.json';owner=workspace/'canonical-agent/scripts/stage_retention_native_tools.py'
    j={'schema':'edr.ci-cache-recovery-input.v1','runtime_mode':mode,'prepared_only':False,'cohort_id':cohort_id,'cohort_catalog_sha256':profile_sha,'arch':'arm64','python_path':sys.executable,'python_sha256':digest(Path(sys.executable).read_bytes()),
       'snapshot_helper_sha256':digest((workspace/'tests/cache-recovery/cache_recovery_snapshot.py').read_bytes()),'requested_min_free_bytes':p['requested_min_free_bytes'],
       'baseline':{'stage_path':str(baseline),'stage_sha256':digest(baseline.read_bytes())},
       'target':{'source_sha':profile['source'],'stage_path':str(stage),'stage_sha256':digest(stage.read_bytes()),'artifact_manifest_path':str(manifest),'artifact_manifest_sha256':digest(manifest.read_bytes())},
       'protocol5_package':{'path':str(package),'sha256':p['expected_p5_sha256'],'builder_owner':'edr-backend/platform/internal/installer/full_installer.go','builder_output_verified_by_caller':True},
       'native_tools':{'manifest_path':str(tools),'manifest_sha256':digest(tools.read_bytes()),'run_id':profile['native_run'],'validation_owner_path':str(owner),'validation_owner_sha256':digest(owner.read_bytes())}}
    json_save(root/'recovery-input.json',j)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['profile','prepare','finalize']);parser.add_argument('--workspace',type=Path);parser.add_argument('--output',type=Path);selection=parser.add_mutually_exclusive_group();selection.add_argument('--cohort',choices=['695','697','698'],default='695');selection.add_argument('--target-tag');parser.add_argument('--runtime-mode',choices=['service','scheduled_task'],default='service');args=parser.parse_args()
    need(args.mode=='profile' or args.target_tag is None,'target_tag_descriptor_only')
    if args.target_tag is not None:
        matches=[key for key in ('695','697','698')if cohort(key,False)[0]['tag']==args.target_tag]
        need(len(matches)==1,'unsupported_recovery_target_tag');args.cohort=matches[0]
    profile,unused,profile_sha=cohort(args.cohort)
    if args.mode=='profile':
        print(json.dumps({'cohort_id':args.cohort,'source_sha':profile['source'],'tag':profile['tag'],'version':profile['version'],'cohort_catalog_sha256':profile_sha}));return
    need(args.workspace is not None and args.output is not None,'workspace_and_output_required')
    need(os.name=='nt' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted','disposable_windows_ci_only')
    args.output.resolve().relative_to(Path(os.environ['RUNNER_TEMP']).resolve())
    if args.mode=='prepare':
        need(bool(os.environ.get('GH_TOKEN')),'existing_read_token_missing_no_new_permission')
        prepare(args.workspace.resolve(),args.output.resolve(),os.environ.get('P5_HANDLER_VERIFICATION_JSON',''),os.environ.get('P5_HANDLER_VERIFICATION_SHA256',''),os.environ.get('P5_HIGHER_MIN_FREE_BYTES','0'),os.environ.get('P5_BACKEND_OWNER_BASE64',''),args.cohort,args.runtime_mode)
    else:finalize(args.workspace.resolve(),args.output.resolve(),args.cohort,args.runtime_mode)
    print(json.dumps({'status':'prepared_inputs_only'if args.mode=='prepare'else'bound_original_builder_output','real_recovery_pass_claimed':False,'catalog_or_endpoint_task':False}))

if __name__=='__main__':
    try:main()
    except Exception as exc:
        # Avoid third-party HTTP text, URLs, bodies, credentials or path dumps.
        print('disposable_preparation_failed:'+failure_cause(exc),file=sys.stderr)
        sys.exit(1)
