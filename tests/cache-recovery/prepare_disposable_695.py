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
SOURCE='694a4f47cfd55a7c98f8dab62617520c0c6251b1'
BASELINE='a978ec83deacf7cd78c273d82630b457c5f39251'
TARGET_RUN='39054352162'
TOOL_RUN='39051197046'
TOOL_ID=12107948816
TOOL_SIZE=1202069
TOOL_SHA='35e66cef15bd99617a52ac0d066f129f0864b262af0f3398eadac5ccd505f91b'
BUILDER_SHA='695c9a0de7d9fe7714918147982aec29aa8061c058702a427a9dee268f2e43a9'
HANDLER_SHA='96b52a37672645e79607a4ed33365abe0d88dada7667237aa6aa59cbd154027f'
SHA=re.compile(r'[0-9a-f]{64}')


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


def verified_preflight(raw):
    p=strict_json(raw)
    need(type(p)is dict and p.get('code')=='OK' and type(p.get('data'))is dict,'actual_preflight_required')
    d=p['data'];need(d.get('valid')is True and d.get('upgradeReady')is True and d.get('upgradeBlockers')==[] and
        d.get('version')=='3.2.695' and d.get('arch')=='arm64' and d.get('platform')=='windows' and
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


def verified_builder_input(value):
    need(type(value)is str and 0<len(value)<=65536,'original_builder_base64_required')
    try:raw=base64.b64decode(value.encode('ascii','strict'),validate=True)
    except (ValueError,UnicodeError):raise ValueError('original_builder_base64_invalid')
    need(base64.b64encode(raw).decode('ascii')==value and len(raw)<=65536 and digest(raw)==BUILDER_SHA,
         'fixed_original_builder_sha_required')
    return raw


def verified_handler_receipt(value,expected_sha):
    need(type(expected_sha)is str and SHA.fullmatch(expected_sha),'original_handler_receipt_pin_required')
    raw=value.encode('utf-8','strict');need(0<len(raw)<=65536 and digest(raw)==expected_sha,'original_handler_receipt_pin_required')
    p=strict_json(raw)
    keys={'schema','origin','authenticated_platform_http','verification_passed','source_sha','target_release_run','version','arch',
          'handler_owner_sha256','builder_owner_sha256','binary_sha256','headless_sha256','manifest_sha256',
          'preflight_response_utf8','preflight_response_sha256','p5_sha256','db_or_artifactstore_written',
          'evidence_cache_opened','product_binaries_executed'}
    need(type(p)is dict and set(p)==keys and p.get('schema')=='edr.ci-original-handler-verification.v1' and
         p.get('origin')=='ci_original_handler_verification' and p.get('authenticated_platform_http')is False and
         p.get('verification_passed')is True and p.get('source_sha')==SOURCE and p.get('target_release_run')==TARGET_RUN and
         p.get('version')=='3.2.695' and p.get('arch')=='arm64' and p.get('handler_owner_sha256')==HANDLER_SHA and
         p.get('builder_owner_sha256')==BUILDER_SHA and p.get('db_or_artifactstore_written')is False and
         p.get('evidence_cache_opened')is False and p.get('product_binaries_executed')is False,
         'original_handler_verification_scope_required')
    need(all(type(p.get(k))is str and SHA.fullmatch(p[k]) for k in
         ('binary_sha256','headless_sha256','manifest_sha256','preflight_response_sha256','p5_sha256')),
         'original_handler_verification_hash_shape')
    need(type(p['preflight_response_utf8'])is str,'original_handler_response_required')
    response=p['preflight_response_utf8'].encode('utf-8','strict')
    need(0<len(response)<=32768 and digest(response)==p['preflight_response_sha256'],'original_handler_response_hash')
    d,packages=verified_preflight(response)
    need(d['binarySha256']==p['binary_sha256'] and packages['headless']==p['headless_sha256'] and
         packages['full_installer']==p['p5_sha256'],'original_handler_response_identity')
    return p,response,d,packages


def release(tag,commit,run,baseline=False):
    info=gh('repos/'+REPO+'/releases/tags/'+tag)
    need(info.get('tag_name')==tag and info.get('draft')is False and bool(info.get('published_at')),
         'published_exact_release_required_no_draft_permission')
    if not baseline:need(info.get('prerelease')is True,'target_candidate_prerelease_required')
    if baseline:need(info.get('id')==415024985,'exact692_release_id')
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


def download_headless(root,checkpoint,tag,commit,run,baseline=False):
    info=release(tag,commit,run,baseline)
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
            published_baseline=baseline,target_tag='win_3.2.695'if baseline else None)
    json_save(root/('baseline-stage.json'if baseline else 'target-stage.json'),stage)
    return stage,directory


def native_tools(root,snapshot,stage_owner):
    run=gh('repos/'+REPO+'/actions/runs/'+TOOL_RUN+'/attempts/1')
    need(run.get('id')==int(TOOL_RUN) and run.get('run_attempt')==1 and run.get('head_sha')==SOURCE and
        run.get('status')=='completed' and run.get('conclusion')=='success','exact_passed_tool_run')
    a=gh('repos/'+REPO+'/actions/artifacts/'+str(TOOL_ID))
    need(a.get('id')==TOOL_ID and a.get('name')=='evidence-native-tools-arm64-'+SOURCE and
        a.get('size_in_bytes')==TOOL_SIZE and a.get('digest')=='sha256:'+TOOL_SHA and a.get('expired')is False and
        a.get('workflow_run',{}).get('id')==int(TOOL_RUN) and a.get('workflow_run',{}).get('head_sha')==SOURCE,
        'exact_passed_tool_artifact')
    raw=gh('repos/'+REPO+'/actions/artifacts/'+str(TOOL_ID)+'/zip',TOOL_SIZE,True)
    need(len(raw)==TOOL_SIZE and digest(raw)==TOOL_SHA,'tool_archive_full_hash_size')
    out=root/'native-tools';out.mkdir()
    with zipfile.ZipFile(io.BytesIO(raw))as archive:
        files=archive.infolist();need(len(files)==4 and sum(f.file_size for f in files)==2968759,'tool_archive_inventory')
        for f in files:
            need(re.fullmatch('[a-z0-9_.-]+',f.filename) and not f.is_dir() and not((f.external_attr>>16)&0o170000)==0o120000 and
                not f.flag_bits&1 and 0<f.file_size<=64*1024**2 and f.file_size<=max(1,f.compress_size)*200,'tool_archive_path_bound')
            body=archive.read(f);need(len(body)==f.file_size,'tool_archive_size');save(out/f.filename,body)
    snapshot.validate_native_tools(out/'manifest.json',digest((out/'manifest.json').read_bytes()),stage_owner,digest(stage_owner.read_bytes()),'arm64',SOURCE,TOOL_RUN)
    return out


def prepare(workspace,root,receipt,receipt_sha,effective_floor,owner_b64):
    need(not root.exists(),'fresh_private_output_required')
    verification,receipt_raw,d,packages=verified_handler_receipt(receipt,receipt_sha)
    owner_raw=verified_builder_input(owner_b64)
    need(re.fullmatch('(0|[1-9][0-9]{0,12})',effective_floor) and int(effective_floor)<=1099511627776,'optional_explicit_higher_disk_floor_required')
    root.mkdir();save(root/'preflight.json',receipt_raw);save(root/'original-handler-verification.json',receipt.encode('utf-8'))
    source_owner=root/'source-owner';source_owner.mkdir();owner=source_owner/'full_installer.go';save(owner,owner_raw)
    checkpoint=module(workspace/'canonical-agent/scripts/windows_release_checkpoint.py','original_checkpoint')
    snapshot=module(workspace/'tests/cache-recovery/cache_recovery_snapshot.py','original_private_snapshot')
    stage_owner=workspace/'canonical-agent/scripts/stage_retention_native_tools.py';tool=native_tools(root,snapshot,stage_owner)
    target,downloads=download_headless(root,checkpoint,'win_3.2.695',SOURCE,TARGET_RUN)
    baseline,unused=download_headless(root,checkpoint,'win_3.2.692',BASELINE,'38912075743',True)
    zip_path=downloads/'edr-agent-win_3.2.695-windows-arm64-exe.zip'
    manifest=downloads/'edr-agent-win_3.2.695-windows-arm64-artifact-manifest.json'
    need(digest(zip_path.read_bytes())==packages['headless'] and target['agent_binary_sha256']==d['binarySha256'] and
         digest(manifest.read_bytes())==verification['manifest_sha256'],'original_handler_download_binding')
    binding={'schema':'edr.private-verified-headless-p5-input.v1','prepared_only':False,'source_sha':SOURCE,'version':'3.2.695','arch':'arm64',
      'agent_sha256':target['agent_binary_sha256'],'runtime_identity_sha256':target['runtime_identity_sha256'],'builder_owner_sha256':digest(owner.read_bytes()),
      'headless':{'path':str(zip_path),'sha256':packages['headless'],'bytes':zip_path.stat().st_size},
      'preflight':{'path':str(root/'preflight.json'),'sha256':digest(receipt_raw),'bytes':len(receipt_raw)}}
    json_save(root/'p5-binding.json',binding)
    json_save(root/'overlay.json',{'Replace':{str(owner.with_name('zz_private_695_p5_export_test.go')):str(workspace/'tests/cache-recovery/verified_headless_p5_export_test.go')}})
    json_save(root/'prepared.json',{'schema':'edr.disposable-recovery-prepared.v1','source_sha':SOURCE,'target_run':TARGET_RUN,'tool_run':TOOL_RUN,
      'verification_origin':'ci_original_handler_verification','authenticated_platform_http':False,
      'original_handler_verification_sha256':receipt_sha,'preflight_sha256':digest(receipt_raw),'builder_owner_sha256':BUILDER_SHA,'expected_p5_sha256':packages['full_installer'],'requested_min_free_bytes':effective_floor,'catalog_written':False,
      'endpoint_task_created':False,'recovery_started':False,'stage_owner_sha256':digest(stage_owner.read_bytes()),'native_manifest_sha256':digest((tool/'manifest.json').read_bytes())})


def finalize(workspace,root):
    p=strict_json((root/'prepared.json').read_bytes());need(p['source_sha']==SOURCE,'prepared_source')
    package=root/'verified-p5-3.2.695-arm64.zip';need(package.is_file() and not package.is_symlink() and package.stat().st_size<=256*1024**2 and
        digest(package.read_bytes())==p['expected_p5_sha256'],'original_builder_output_preflight_hash_required')
    manifest=root/'target-download/edr-agent-win_3.2.695-windows-arm64-artifact-manifest.json'
    stage=root/'target-stage.json';baseline=root/'baseline-stage.json';tools=root/'native-tools/manifest.json';owner=workspace/'canonical-agent/scripts/stage_retention_native_tools.py'
    j={'schema':'edr.ci-cache-recovery-input.v1','prepared_only':False,'arch':'arm64','python_path':sys.executable,'python_sha256':digest(Path(sys.executable).read_bytes()),
       'snapshot_helper_sha256':digest((workspace/'tests/cache-recovery/cache_recovery_snapshot.py').read_bytes()),'requested_min_free_bytes':p['requested_min_free_bytes'],
       'baseline':{'stage_path':str(baseline),'stage_sha256':digest(baseline.read_bytes())},
       'target':{'source_sha':SOURCE,'stage_path':str(stage),'stage_sha256':digest(stage.read_bytes()),'artifact_manifest_path':str(manifest),'artifact_manifest_sha256':digest(manifest.read_bytes())},
       'protocol5_package':{'path':str(package),'sha256':p['expected_p5_sha256'],'builder_owner':'edr-backend/platform/internal/installer/full_installer.go','builder_output_verified_by_caller':True},
       'native_tools':{'manifest_path':str(tools),'manifest_sha256':digest(tools.read_bytes()),'run_id':TOOL_RUN,'validation_owner_path':str(owner),'validation_owner_sha256':digest(owner.read_bytes())}}
    json_save(root/'recovery-input.json',j)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['prepare','finalize']);parser.add_argument('--workspace',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    need(os.name=='nt' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted','disposable_windows_ci_only')
    args.output.resolve().relative_to(Path(os.environ['RUNNER_TEMP']).resolve())
    if args.mode=='prepare':
        need(bool(os.environ.get('GH_TOKEN')),'existing_read_token_missing_no_new_permission')
        prepare(args.workspace.resolve(),args.output.resolve(),os.environ.get('P5_HANDLER_VERIFICATION_JSON',''),os.environ.get('P5_HANDLER_VERIFICATION_SHA256',''),os.environ.get('P5_HIGHER_MIN_FREE_BYTES','0'),os.environ.get('P5_BACKEND_OWNER_BASE64',''))
    else:finalize(args.workspace.resolve(),args.output.resolve())
    print(json.dumps({'status':'prepared_inputs_only'if args.mode=='prepare'else'bound_original_builder_output','real_recovery_pass_claimed':False,'catalog_or_endpoint_task':False}))

if __name__=='__main__':
    try:main()
    except Exception as exc:
        # Avoid third-party HTTP text, URLs, bodies, credentials or path dumps.
        print('disposable_preparation_failed:'+failure_cause(exc),file=sys.stderr)
        sys.exit(1)
