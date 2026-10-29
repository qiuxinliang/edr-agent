#!/usr/bin/env python3
"""Same-policy local cache comparison; no live stores, transport or deployment.

Exports the baseline, freezes current source, alternates identical workloads,
and reports every measured increase without a hidden tolerance. Runtime/CPU
and RSS variation are measurements, not proof of a universal zero-cost claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess

from retention_comparison_support import (SOURCES, QUEUE_SOURCES, compiler_flags,
    compile_command, compiler_identity, dependencies, execute_benchmark,
    export_git_snapshot, failure_report, includes, runtime_environment,
    verify_git_snapshot, storage_reservation_sources)

IO_COUNTERS=('sqlite_read_bytes','sqlite_write_bytes','sqlite_syncs')
IO_PHASES=('startup','producer','recall','close')
PROFILES=('ordinary','unique','replay','fanout','file_ordinary','file_unique',
          'file_replay','file_fanout','file_overlap')
DIGESTS=('post_inventory_sha256','saved_inventory_sha256','recall_sha256','reopened_recall_sha256')


def observable_inventory(variants):
    if set(variants)!= {'baseline','current'} or not variants['baseline'] or \
       len(variants['baseline'])!=len(variants['current']):
        raise ValueError('Need nonempty paired baseline/current observations')
    correctness=('candidates','post_refs','rejected','recall_rows','reopened_recall_rows','dangling_refs')
    inventories={k:sorted({s[k] for rows in variants.values() for s in rows}) for k in DIGESTS}
    # Every sample must agree: a median can hide one missing fact in seven runs.
    equal=all(len(ids)==1 for ids in inventories.values()) and all(
        len({s[k] for rows in variants.values() for s in rows})==1 for k in correctness)
    required={v:all(all(int(s[k])==1 for k in ('required_pre','required_post','required_command'))
                    for s in rows) for v,rows in variants.items()}
    return equal,required,inventories


def repeated_recall_consistency(variants):
    return {variant:bool(rows) and all(
        int(row['recall_queries'])==64 and row['recall_consistent']=='1' and
        row['recall_first_mismatch_query']=='0' for row in rows)
        for variant,rows in variants.items()}


def profile_status(equal,required,recovery,repeated_recall):
    if not all(recovery.values()):return 'WORKLOAD_RECOVERY_FAILED'
    if not all(required.values()):return 'REQUIRED_FACTS_MISSING'
    if not all(repeated_recall.values()):return 'REPEATED_RECALL_DIFFERENCE'
    return 'MEASURED_NOT_UNIVERSAL_PROOF' if equal else 'CORRECTNESS_DIFFERENCE_REQUIRES_REVIEW'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--baseline',required=True)
    parser.add_argument('--current-ref',help='Optional immutable ref for an A/A calibration')
    parser.add_argument('--runs',type=int,default=5)
    parser.add_argument('--profiles',nargs='+',choices=PROFILES,default=list(PROFILES),
                        help='Select bounded synthetic workloads; each uses independent stores')
    parser.add_argument('--cc',default=os.environ.get('CC','cl' if os.name=='nt' else 'cc'))
    parser.add_argument('--dependency-prefix',type=Path)
    args=parser.parse_args()
    if len(set(args.profiles))!=len(args.profiles):parser.error('Duplicate profiles are not allowed')
    repo=Path(__file__).resolve().parents[1];out=args.output.resolve()
    if out==repo or repo in out.parents or not 1<=args.runs<=30:
        parser.error('Use an external empty directory and 1..30 runs')
    if out.exists() and any(out.iterdir()):parser.error('Output directory is not empty')
    out.mkdir(parents=True,exist_ok=True);stage=failure_report(out)
    baseline=subprocess.check_output(['git','rev-parse',args.baseline+'^{commit}'],cwd=repo,text=True).strip()
    harness=['evidence_cache_cost_comparison.c','evidence_retention_comparison.c','retention_benchmark_support.h']
    for name in harness:shutil.copyfile(repo/'tests'/name,out/name)
    dep_inc,libs,dep_hashes=dependencies(args.dependency_prefix)
    metadata={'baseline':baseline,'current_ref':args.current_ref,'runs':args.runs,
        'compiler':compiler_identity(args.cc),'harness_sha256':{name:sha(out/name) for name in harness},
        'dependency_sha256':dep_hashes,'budget_mib':8,'queue_budget_mib':8,
        'budget_scope':'configured per-store logical budget; not a DB+WAL+SHM physical hard ceiling',
        'recent_hours':1,'selected_hours':1,
        'input_events_per_profile':{p:50000 if p in ('ordinary','file_ordinary') else 512 for p in args.profiles},
        'profiles':args.profiles,'recall_requests_per_profile':64,
        'file_workloads':'ordinary=distinct benign bin paths; unique=distinct process generations and DLL paths; replay=identical source; fanout=32 owners+480 ordinary writes; overlap=128 owners interleaved with 384 ordinary writes',
        'correctness_scope':'all retained candidate core fields/artifact bodies, post owner/fact relations, all 64 live authorized rows/digests checked against the first, and reopened authorized rows; independent pre/post/command witness including exact endpoint and birth strings outside cost measurement',
        'scope':'synthetic cache+queue open, producer, authorized recall and close; no network',
        'io_scope':'SQLite-issued VFS bytes/sync calls, not physical device I/O',
        'io_phases':{'startup':'cache and queue open',
                     'producer':'fixed producer workload only; excludes startup and requested recall',
                     'recall':'64 explicit authorized recall requests; not regular collection',
                     'close':'status read and cache/queue close; retained separately to reconcile original totals'},
        'timing_scope':'real host CPU/wall time from startup through close includes all 64 query JSON digest checks; individual recall latency surrounds only the query call; SQL inventory, workload reopen/query and independent witness excluded; no universal zero-overhead proof',
        'instrumentation_scope':'producer includes identical per-event clock and filesystem stat probes in both variants; not an uninstrumented full Agent',
        'physical_peak_scope':'sampled DB/WAL/SHM apparent byte total after each input; not whole-filesystem allocated bytes or an atomic peak',
        'rss_scope':'process high-water RSS sampled after SQL inventory verification, so includes that allocation; workload reopen and independent witness are later and excluded; zero means unavailable on Windows',
        'lock_scope':'existing module log2 histograms, single producer and sequential queries; no contention stress',
        'unmeasured':['real server cost','regular endpoint upload rate','device I/O','real detection/sensor pipeline','whole filesystem peak','concurrent query/producer contention']}
    (out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    trees={};bindings={};frozen={};binaries={}
    for variant in ('baseline','current'):
        stage['stage']='snapshot_'+variant
        tree=out/variant;tree.mkdir();trees[variant]=tree
        ref=baseline if variant=='baseline' else args.current_ref
        if ref:
            bindings[variant]=export_git_snapshot(repo,ref,tree,('src','include','third_party'),out/(variant+'-binding.json'))
        else:
            for folder in ('src','include','third_party'):shutil.copytree(repo/folder,tree/folder)
        frozen[variant]={p.relative_to(tree).as_posix():sha(p) for p in tree.rglob('*') if p.is_file()}
        (out/(variant+'-source-hashes.json')).write_text(json.dumps(frozen[variant],sort_keys=True,indent=2)+'\n')
        defines=['EDR_AGENT_VERSION_STRING="cost-comparison"','EDR_HAVE_LZ4=1','EDR_HAVE_ZSTD=1',
            'EDR_HAVE_NANOPB=1','EDR_HAVE_SQLITE=1','EDR_LOCAL_EVIDENCE_CACHE_TESTING=1',
            'PB_FIELD_32BIT=1','BENCH_REAL_QUEUE=1','BENCH_HAS_PARENT_CONTEXT_BINDING=1',
            'BENCH_SOURCE="same-policy"','BENCH_SELECTED_HOURS=1']
        if storage_reservation_sources(tree):defines+=['BENCH_HAS_STORAGE_RESERVATION=1']
        flags=compiler_flags(defines,[out,*includes(tree),*dep_inc])
        if os.name!='nt':flags+=['-O2']
        binary=out/(variant+'-cost'+('.exe' if os.name=='nt' else ''));binaries[variant]=binary
        sources=SOURCES+QUEUE_SOURCES+storage_reservation_sources(tree)
        command=compile_command(args.cc,flags,[out/harness[0],*[tree/p for p in sources]],binary,libs)
        (out/(variant+'-compile.json')).write_text(json.dumps(command,indent=2)+'\n')
        stage['stage']='compile_'+variant
        with (out/(variant+'-build.log')).open('w') as log:
            subprocess.run(command,cwd=out,stdout=log,stderr=subprocess.STDOUT,timeout=180,check=True)
        stage['stage']='oracle_self_test_'+variant
        directory=out/(variant+'-oracle-self-test');directory.mkdir()
        result=execute_benchmark([str(binary),'--oracle-self-test'],directory,
            runtime_environment(directory,args.dependency_prefix),30)
        if result['exit_code']!=0 or result['timed_out'] or \
           (directory/'stdout.log').read_text().strip()!='cost_oracle_self_test=passed':
            raise RuntimeError('Cost oracle self-test failed: '+variant)
    profiles=args.profiles;samples={p:{v:[] for v in binaries} for p in profiles}
    stage['stage']='execute'
    for run in range(args.runs):
        for profile in profiles:
            for variant in (('baseline','current') if run%2==0 else ('current','baseline')):
                directory=out/f'{profile}-{variant}-{run}';directory.mkdir()
                result=execute_benchmark([str(binaries[variant]),profile],directory,runtime_environment(directory,args.dependency_prefix),60)
                if result['exit_code']!=0 or result['timed_out']:raise RuntimeError('Cost workload failed: '+str(directory))
                lines=[s for s in (directory/'stdout.log').read_text().splitlines() if s.startswith('evidence_cost ')]
                if len(lines)!=1:raise RuntimeError('Missing cost result')
                values=dict(item.split('=',1) for item in lines[0].split()[1:])
                for counter in IO_COUNTERS:
                    if sum(int(values[phase+'_'+counter]) for phase in IO_PHASES)!=int(values[counter]):
                        raise RuntimeError('SQLite phase counts do not reconcile: '+counter+' '+str(directory))
                samples[profile][variant].append(values)
    summary={};stage['stage']='compare'
    for profile,variants in samples.items():
        identities={(s['input_sha256'],s['input_count'],s['sqlite_version']) for rows in variants.values() for s in rows}
        if len(identities)!=1:raise RuntimeError('Input/runtime differs between variants')
        medians={variant:{k:statistics.median(float(s[k]) for s in rows) for k in rows[0]
                         if k not in ('profile','input_sha256','sqlite_version',*DIGESTS)} for variant,rows in variants.items()}
        equal,required,inventories=observable_inventory(variants)
        recovery={v:all(s['reopen_ok']=='1' and s['reopened_query_ok']=='1' for s in rows)
                  for v,rows in variants.items()}
        repeated_recall=repeated_recall_consistency(variants)
        cost=('cpu_seconds','wall_seconds','entry_p95_us','entry_p99_us','recall_p95_us','recall_p99_us',
              'producer_cpu_seconds','producer_wall_seconds','lock_wait_p95_ns','lock_wait_p99_ns',
              'lock_hold_p95_ns','lock_hold_p99_ns','sqlite_read_bytes','sqlite_write_bytes',
              'sqlite_syncs','physical_peak_bytes','peak_rss_bytes')
        cost+=tuple(phase+'_'+counter for phase in IO_PHASES for counter in IO_COUNTERS)
        changes={k:{'before':medians['baseline'][k],'after':medians['current'][k],
                    'delta':medians['current'][k]-medians['baseline'][k],
                    'ratio':medians['current'][k]/medians['baseline'][k] if medians['baseline'][k] else None}
                 for k in cost}
        summary[profile]={'input_sha256':next(iter(identities))[0],'medians':medians,
            'inventory_digests':inventories,'required_facts_after_reopen':required,
            'workload_recovery':recovery,
            'repeated_recall_consistency':repeated_recall,
            'first_recall_mismatch_queries':{v:[int(s['recall_first_mismatch_query']) for s in rows]
                                            for v,rows in variants.items()},
            'same_observable_inventory':equal,'costs':changes,
            'paired_cost_deltas':{k:[float(after[k])-float(before[k])
                                      for before,after in zip(variants['baseline'],variants['current'])] for k in cost},
            'sqlite_io_by_phase':{phase:{counter:changes[phase+'_'+counter] for counter in IO_COUNTERS}
                                  for phase in IO_PHASES},
            'observed_increases':[k for k in cost if changes[k]['delta']>0],
            'status':profile_status(equal,required,recovery,repeated_recall)}
    stage['stage']='verify_frozen_sources'
    for variant,tree in trees.items():
        if variant in bindings:verify_git_snapshot(tree,bindings[variant])
        for p,h in frozen[variant].items():
            if sha(tree/p)!=h:raise RuntimeError('Frozen source changed')
    for path,h in dep_hashes.items():
        if sha(path)!=h:raise RuntimeError('Dependency changed')
    (out/'samples.json').write_text(json.dumps(samples,indent=2)+'\n')
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    for profile,result in summary.items():
        print(json.dumps({'profile':profile,'same_observable_inventory':result['same_observable_inventory'],
                          'status':result['status'],'workload_recovery':result['workload_recovery'],
                          'required_facts_after_reopen':result['required_facts_after_reopen'],
                          'observed_increases':result['observed_increases']}),flush=True)
    return 0 if all(r['status']=='MEASURED_NOT_UNIVERSAL_PROOF' for r in summary.values()) else 1


if __name__=='__main__':raise SystemExit(main())
