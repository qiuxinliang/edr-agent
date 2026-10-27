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


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--baseline',required=True)
    parser.add_argument('--current-ref',help='Optional immutable ref for an A/A calibration')
    parser.add_argument('--runs',type=int,default=5)
    parser.add_argument('--cc',default=os.environ.get('CC','cl' if os.name=='nt' else 'cc'))
    parser.add_argument('--dependency-prefix',type=Path)
    args=parser.parse_args()
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
        'dependency_sha256':dep_hashes,'budget_mib':8,'recent_hours':1,'selected_hours':1,
        'input_events_per_profile':{'ordinary':50000,'unique':512,'replay':512,'fanout':512},'recall_requests_per_profile':64,
        'scope':'synthetic cache+queue open, producer, authorized recall and close; no network',
        'io_scope':'SQLite-issued VFS bytes/sync calls, not physical device I/O',
        'io_phases':{'startup':'cache and queue open',
                     'producer':'fixed producer workload only; excludes startup and requested recall',
                     'recall':'64 explicit authorized recall requests; not regular collection',
                     'close':'status read and cache/queue close; retained separately to reconcile original totals'},
        'timing_scope':'real host CPU/wall time; isolated same inputs; no universal zero-overhead proof',
        'rss_scope':'process high-water RSS on POSIX; zero means unavailable on Windows',
        'lock_scope':'existing module log2 histograms, single producer and sequential queries; no contention stress',
        'unmeasured':['real server cost','regular endpoint upload rate','device I/O']}
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
    profiles=('ordinary','unique','replay','fanout');samples={p:{v:[] for v in binaries} for p in profiles}
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
                         if k not in ('profile','input_sha256','sqlite_version')} for variant,rows in variants.items()}
        correctness=('candidates','refs','rejected','recall_rows','dangling_refs')
        equal=all(medians['baseline'][k]==medians['current'][k] for k in correctness)
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
            'same_observable_inventory':equal,'costs':changes,
            'sqlite_io_by_phase':{phase:{counter:changes[phase+'_'+counter] for counter in IO_COUNTERS}
                                  for phase in IO_PHASES},
            'observed_increases':[k for k in cost if changes[k]['delta']>0],
            'status':'MEASURED_NOT_UNIVERSAL_PROOF' if equal else 'CORRECTNESS_DIFFERENCE_REQUIRES_REVIEW'}
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
                          'observed_increases':result['observed_increases']}),flush=True)


if __name__=='__main__':main()
