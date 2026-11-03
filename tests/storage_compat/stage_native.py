"""Stage four source-pinned test executables using the existing native DLL owner.

`stage` proves the closed PE/DLL bundle then runs native cross-version readback.
`bind` rechecks the downloaded bundle and creates the local driver input paths.
Neither operation publishes a product, invokes Setup, or changes a live database.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
_prepare_spec=importlib.util.spec_from_file_location('edr_storage_compat_prepare',Path(__file__).with_name('prepare.py'))
_prepare=importlib.util.module_from_spec(_prepare_spec);_prepare_spec.loader.exec_module(_prepare)
PINS=_prepare.PINS
TEST_CONFIGURATION={'CMAKE_BUILD_TYPE':'StorageCompat',
                    'CMAKE_MAP_IMPORTED_CONFIG_STORAGECOMPAT':'Release;',
                    'CMAKE_MSVC_RUNTIME_LIBRARY':'MultiThreadedDLL'}


def need(ok,cause):
    if not ok:raise ValueError(cause)


def owner(repo):
    path=repo/'scripts/stage_retention_native_tools.py'
    spec=importlib.util.spec_from_file_location('storage_compat_native_owner',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def dump_json(path,value):
    with path.open('x',encoding='utf-8') as f:f.write(json.dumps(value,indent=2,sort_keys=True)+'\n')


def test_configuration(cache_text):
    """Exact non-product config: Release or generic imported libraries, /MD CRT."""
    result={}
    for key,value in TEST_CONFIGURATION.items():
        entries=re.findall(r'(?m)^'+re.escape(key)+r':(?:STRING|UNINITIALIZED)=(.*)$',cache_text)
        need(entries==[value],'storage_test_configuration_'+key)
        result[key]=value
    return result


def stage(args):
    own=owner(args.repo);deadline=time.monotonic()+180
    need(not args.output.exists(),'output_must_be_new')
    own.real_path(args.output.parent,directory=True)
    need(re.fullmatch('[0-9a-f]{40}',args.harness_commit) is not None,'harness_commit')
    need(all(re.fullmatch('[1-9][0-9]*',x) for x in (args.run_id,args.run_attempt)),'run_identity')
    need(subprocess.check_output(['git','-C',str(args.repo),'rev-parse','HEAD'],text=True).strip()==args.harness_commit,'harness_head_mismatch')
    compiler,dumpbin=own.real_path(args.compiler),own.real_path(args.dumpbin)
    need(compiler.parent==dumpbin.parent,'compiler_dumpbin_owner')
    prefix=own.real_path(args.dependency_prefix,directory=True)
    redist=own.real_path(args.msvc_redist_root,directory=True)
    archdir=own.real_path(redist/({'amd64':'x64','arm64':'arm64'}[args.architecture]),directory=True)
    crt_dirs=list(archdir.glob('Microsoft.VC*.CRT'));need(len(crt_dirs)==1,'single_crt_owner')
    dlls={}
    for label,directory in [('vcpkg/bin',prefix/'bin'),('msvc-crt',crt_dirs[0])]:
        for name,path in own.dll_index(own.real_path(directory,directory=True)).items():
            need(name not in dlls,'ambiguous_dll');dlls[name]=(path,label+'/'+path.name)
    args.output.mkdir();files=[];roles={}
    for role,build in [('legacy',args.legacy_build),('candidate',args.candidate_build)]:
        build=own.real_path(build,directory=True);cache=own.real_path(build/'CMakeCache.txt')
        text=cache.read_text(encoding='utf-8')
        configuration=test_configuration(text)
        compilers=re.findall(r'(?m)^CMAKE_C_COMPILER:(?:FILEPATH|STRING)=(.+)$',text)
        need(len(compilers)==1 and own.real_path(compilers[0])==compiler,'cmake_compiler_owner')
        source_manifest=args.source_manifests/(role+'-source.json')
        source=json.loads(source_manifest.read_text(encoding='utf-8'))
        need(source.get('schema')=='edr.test.storage-compat-source.v1' and source.get('source_commit')==PINS[role],'source_manifest_identity')
        source_dirs=re.findall(r'(?m)^CMAKE_HOME_DIRECTORY:INTERNAL=(.+)$',text)
        need(len(source_dirs)==1,'cmake_source_owner');source_dir=own.real_path(source_dirs[0],directory=True)
        for relative,expected in source['files_before_test_overlay'].items():
            path=own.real_path(source_dir/relative)
            expected=source['cmake_overlay_sha256'] if relative=='CMakeLists.txt' else expected
            need(hashlib.sha256(path.read_bytes()).hexdigest()==expected,'source_changed_after_export')
        for relative in ('vcpkg.json','vcpkg-configuration.json','dependencies.lock.json','scripts/bootstrap_pinned_vcpkg.ps1'):
            need(own.digest(args.repo/relative)==source['files_before_test_overlay'][relative],'dependency_owner_differs_from_pinned_source')
        for name,expected in source['overlay'].items():
            need(hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()==expected,'adapter_changed_after_export')
        pending=[(own.real_path(build/('storage_compat_'+kind+'.exe')),'build/storage_compat_'+kind+'.exe') for kind in ('cache','queue')]
        copied={};total=0;directory=args.output/role;directory.mkdir()
        while pending:
            path,origin=pending.pop(0);name=path.name.lower()
            if name in copied:continue
            need(len(copied)<own.MAX_FILES and time.monotonic()<deadline,'dependency_bounds')
            digest=own.digest(path);need(own.pe_machine(path)==own.MACHINES[args.architecture],'pe_architecture')
            imports=own.imports(path,dumpbin,deadline);total+=path.stat().st_size;need(total<=own.MAX_TOTAL,'dependency_size')
            item={'path':role+'/'+name,'bytes':path.stat().st_size,'sha256':digest,'machine':own.MACHINES[args.architecture],
                  'imports':imports,'origin':origin}
            with path.open('rb') as read,(directory/name).open('xb') as write:shutil.copyfileobj(read,write,1024**2)
            need(own.digest(path)==digest and own.digest(directory/name)==digest,'dependency_changed')
            copied[name]=item;files.append(item)
            for dependency in imports:
                if dependency not in own.OS_DLLS:
                    need(dependency in dlls,'unresolved_dependency_'+dependency);pending.append(dlls[dependency])
        roles[role]={'source_commit':PINS[role]}
        for kind in ('cache','queue'):
            path=role+'/storage_compat_'+kind+'.exe'
            roles[role][kind+'_path']=path
            roles[role][kind+'_sha256']=copied['storage_compat_'+kind+'.exe']['sha256']
        provenance={'source_manifest':source,'cmake_cache_sha256':own.digest(cache),
                    'test_configuration':configuration,'production_build':False}
        dump_json(directory/'source.json',provenance)
        files.append({'path':role+'/source.json','bytes':(directory/'source.json').stat().st_size,'sha256':own.digest(directory/'source.json')})
    result_dir=args.output.parent/(args.output.name+'-native-readback')
    runner=Path(__file__).resolve().with_name('run_cross_version.py')
    result=subprocess.run([sys.executable,str(runner),'--legacy-bin',str(args.output/'legacy'),
                           '--candidate-bin',str(args.output/'candidate'),'--output',str(result_dir)],
                          capture_output=True,text=True,timeout=240)
    need(result.returncode==0,'native_cross_version_failed_'+result.stderr[-500:])
    result_json=json.loads((result_dir/'summary.json').read_text(encoding='utf-8'))
    need(result_json.get('passed') is True and result_json.get('native_windows') is True and result_json.get('source_commits')==PINS,'native_receipt_identity')
    need(result_json.get('native_machine')==own.MACHINES[args.architecture],'native_execution_architecture')
    evidence=args.output/'evidence';evidence.mkdir()
    for path in sorted(result_dir.iterdir()):
        if path.is_file() and (path.name.endswith('.stdout.json') or path.name.endswith('.stderr.txt') or path.name=='summary.json'):
            need(path.stat().st_size<=1024**2,'evidence_size');destination=evidence/path.name
            with path.open('rb') as read,destination.open('xb') as write:shutil.copyfileobj(read,write)
            files.append({'path':'evidence/'+path.name,'bytes':destination.stat().st_size,'sha256':hashlib.sha256(destination.read_bytes()).hexdigest()})
    manifest={'schema':'edr.windows.storage-compat-bundle.v1','architecture':args.architecture,
              'harness_commit':args.harness_commit,'run_id':args.run_id,'run_attempt':args.run_attempt,
              'source_commits':PINS,'roles':roles,'files':files,'native_cross_version_passed':True,
              'installed_agent_lifecycle':False,'product_payload':False,
              'test_configuration':configuration,
              'provenance':{'compiler_sha256':own.digest(compiler),'dumpbin_sha256':own.digest(dumpbin),
                            'native_dependency_owner_sha256':own.digest(args.repo/'scripts/stage_retention_native_tools.py'),
                            'dependencies_lock_sha256':own.digest(args.repo/'dependencies.lock.json'),
                            'vcpkg_status_sha256':own.digest(prefix.parent/'vcpkg/status')}}
    dump_json(args.output/'manifest.json',manifest)
    verify(args.repo,args.output,args.architecture,args.harness_commit,args.run_id,args.run_attempt)
    print(json.dumps({'staged':True,'native_cross_version_passed':True,'manifest':str(args.output/'manifest.json'),
                      'manifest_sha256':hashlib.sha256((args.output/'manifest.json').read_bytes()).hexdigest()}))


def verify(repo,bundle,architecture,harness_commit,run_id,run_attempt):
    own=owner(repo);bundle=own.real_path(bundle,directory=True);manifest_path=own.real_path(bundle/'manifest.json')
    need(manifest_path.stat().st_size<=1024**2,'manifest_size');m=json.loads(manifest_path.read_text(encoding='utf-8'))
    need(m.get('schema')=='edr.windows.storage-compat-bundle.v1' and m.get('architecture')==architecture,'bundle_architecture_schema')
    need(m.get('harness_commit')==harness_commit and m.get('run_id')==run_id and m.get('run_attempt')==run_attempt,'bundle_owner_identity')
    need(m.get('source_commits')==PINS and m.get('native_cross_version_passed') is True and m.get('product_payload') is False,'bundle_source_scope')
    need(m.get('test_configuration')==TEST_CONFIGURATION,'bundle_test_configuration')
    need(isinstance(m.get('files'),list) and 4<=len(m['files'])<=160,'file_count')
    seen={};total=0
    for item in m['files']:
        relative=item.get('path','');need(re.fullmatch(r'(legacy|candidate|evidence)/[A-Za-z0-9_.-]+',relative) is not None and relative not in seen,'bundle_path')
        path=own.real_path(bundle/relative);need(path.stat().st_size==item['bytes'] and 0<=item['bytes']<=own.MAX_FILE,'bundle_file_size')
        total+=item['bytes'];need(total<=own.MAX_TOTAL*2,'bundle_total_size')
        need(hashlib.sha256(path.read_bytes()).hexdigest()==item['sha256'],'bundle_file_hash');seen[relative]=item
        if 'machine' in item:
            need(own.pe_machine(path)==own.MACHINES[architecture]==item['machine'],'bundle_pe_machine')
            imports=item.get('imports');need(isinstance(imports,list) and imports and len(imports)==len(set(imports)) and all(own.DLL_NAME.fullmatch(x) for x in imports),'bundle_imports')
    need(total<=own.MAX_TOTAL*2,'bundle_total_size')
    actual={p.relative_to(bundle).as_posix() for p in bundle.rglob('*') if p.is_file()}
    need(actual==set(seen)|{'manifest.json'},'bundle_extra_or_missing_file')
    for role in PINS:
        entry=m['roles'][role];need(entry['source_commit']==PINS[role],'role_source')
        for kind in ('cache','queue'):
            relative=role+'/storage_compat_'+kind+'.exe'
            need(entry[kind+'_path']==relative and relative in seen and entry[kind+'_sha256']==seen[relative]['sha256'],'role_tool_binding')
        for relative,item in seen.items():
            if relative.startswith(role+'/') and 'machine' in item:
                for dep in item['imports']:
                    need(dep in own.OS_DLLS or role+'/'+dep in seen,'bundle_dependency_closure')
    return m


def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='action',required=True)
    for action in ('stage','bind'):
        q=sub.add_parser(action)
        for name in ('repo','output'):q.add_argument('--'+name,type=Path,required=True)
        q.add_argument('--architecture',choices=('amd64','arm64'),required=True)
        for name in ('harness-commit','run-id','run-attempt'):q.add_argument('--'+name,required=True)
        if action=='stage':
            for name in ('legacy-build','candidate-build','source-manifests','dependency-prefix','msvc-redist-root','compiler','dumpbin'):
                q.add_argument('--'+name,type=Path,required=True)
        else:
            q.add_argument('--bundle',type=Path,required=True);q.add_argument('--python-path',type=Path,required=True)
    args=p.parse_args()
    if args.action=='stage':stage(args)
    else:
        m=verify(args.repo,args.bundle,args.architecture,args.harness_commit,args.run_id,args.run_attempt)
        own=owner(args.repo);python=own.real_path(args.python_path)
        probe=subprocess.run([str(python),'-I','-c','import sqlite3,tomllib; print("storage-reader-runtime-v1")'],capture_output=True,text=True,timeout=15)
        need(probe.returncode==0 and probe.stdout.strip()=='storage-reader-runtime-v1','python_snapshot_runtime')
        bound={'schema':'edr.windows.storage-compat-tools.v1','architecture':args.architecture,'python_path':str(python)}
        for role in PINS:
            bound[role]=dict(m['roles'][role])
            for kind in ('cache','queue'):bound[role][kind+'_path']=str((args.bundle/bound[role][kind+'_path']).resolve())
        dump_json(args.output,bound);print(json.dumps({'bound':True,'output':str(args.output)}))

if __name__=='__main__':main()
