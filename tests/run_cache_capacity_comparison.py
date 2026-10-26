#!/usr/bin/env python3
"""Source-bound synthetic 512/768/1024 MiB comparison; never opens a live DB.

Large, distinct command facts deliberately fill the protected working set.
This is capacity sensitivity, not an estimate of a real endpoint's workload.
The simulated event/active clock remains below the 72-hour protection floor.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from retention_comparison_support import (
    SOURCES, QUEUE_SOURCES, dependencies, compiler_flags, compile_command,
    includes, runtime_environment, execute_benchmark, export_git_snapshot,
    verify_git_snapshot, failure_report, compiler_identity,
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', default='10bdba0c1e12f0f06a8023bcf3cc22c497c76a40')
    parser.add_argument('--count', type=int, default=6000)
    parser.add_argument('--timeout-seconds', type=int, default=1800)
    parser.add_argument('--cc', default=os.environ.get('CC', 'cl' if os.name == 'nt' else 'cc'))
    parser.add_argument('--dependency-prefix', type=Path)
    parser.add_argument('--native-machine', choices=('amd64', 'arm64'))
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    if out == repo or repo in out.parents or out.exists():
        parser.error('A fresh output directory outside the checkout is required')
    if not 2 <= args.count <= 6000 or not 1 <= args.timeout_seconds <= 3600:
        parser.error('count must be 2..6000 and timeout 1..3600 seconds')
    out.mkdir(mode=0o700, parents=True)
    failure = failure_report(out)
    revision = subprocess.check_output(['git', 'rev-parse', args.baseline+'^{commit}'], cwd=repo, text=True, timeout=30).strip()
    old, current = out/'baseline', out/'current'
    old.mkdir()
    failure['stage'] = 'freeze_sources'
    binding = export_git_snapshot(repo, revision, old, ('src', 'include', 'third_party'), out/'baseline-source-binding.json')
    for folder in ('src', 'include', 'third_party'):
        shutil.copytree(repo/folder, current/folder)
    for name in ('cache_capacity_comparison.c', 'evidence_retention_comparison.c', 'retention_benchmark_support.h'):
        shutil.copyfile(repo/'tests'/name, out/name)
    closure = {name: {str(p.relative_to(source)): sha(p) for p in source.rglob('*') if p.is_file()}
               for name, source in [('baseline', old), ('current', current)]}
    dep_includes, libraries, dep_hashes = dependencies(args.dependency_prefix)
    metadata = {'baseline_revision': revision, 'current_head': subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
        'current_is_working_tree_snapshot': True, 'source_hashes': closure, 'compiler': compiler_identity(args.cc),
        'dependency_sha256': dep_hashes, 'input_candidates': args.count, 'retention_hours': 72,
        'harness_sha256': sha(out/'cache_capacity_comparison.c'), 'runner_sha256': sha(Path(__file__)),
        'measurement_inputs_sha256': {name: sha(repo/'tests'/name) for name in
            ('cache_capacity_comparison.c','evidence_retention_comparison.c','retention_benchmark_support.h','retention_comparison_support.py')},
        'synthetic': True, 'scope': 'Native storage APIs with isolated files; fake event/active clock, no network or actions; VFS issued I/O is not device I/O',
        'limitation': 'Uniform 96000-byte subject and parent commands deliberately overload protected storage; physical peak sampled after each input/poll, not an instantaneous peak; not a representative endpoint distribution or a 72-hour soak'}
    (out/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    results = []
    for label, source in [('baseline', old), ('current', current)]:
        failure['stage'] = 'compile_'+label
        binary = out/(label+'-capacity'+('.exe' if os.name == 'nt' else ''))
        defines = ['EDR_HAVE_SQLITE=1','EDR_LOCAL_EVIDENCE_CACHE_TESTING=1','EDR_HAVE_LZ4=1',
            'EDR_HAVE_ZSTD=1','EDR_HAVE_NANOPB=1','PB_FIELD_32BIT=1','EDR_AGENT_VERSION_STRING="capacity-comparison"',
            'BENCH_SOURCE="'+label+'"','BENCH_SELECTED_HOURS=72','BENCH_REAL_QUEUE=1','BENCH_HAS_PARENT_CONTEXT_BINDING=1']
        flags = compiler_flags(defines, [out, *includes(source), *dep_includes], args.native_machine)
        if os.name != 'nt': flags += ['-O2']
        command = compile_command(args.cc, flags, [out/'cache_capacity_comparison.c', *[source/p for p in SOURCES+QUEUE_SOURCES]], binary, libraries)
        (out/(label+'-compile.json')).write_text(json.dumps(command,indent=2)+'\n')
        with (out/(label+'-build.log')).open('x') as log:
            subprocess.run(command, check=True, cwd=out, stdout=log, stderr=subprocess.STDOUT, timeout=180)
        for capacity in (512, 768, 1024):
            failure['stage'] = 'execute_'+label+'_'+str(capacity)
            run = out/(label+'-'+str(capacity)); run.mkdir(mode=0o700)
            execution = execute_benchmark([str(binary), str(capacity), str(args.count)], run,
                runtime_environment(run, args.dependency_prefix), args.timeout_seconds)
            if execution['exit_code'] != 0 or execution['timed_out']:
                raise RuntimeError('Bounded capacity experiment failed; partial evidence retained')
            lines = [line for line in (run/'stdout.log').read_text().splitlines() if line.startswith('capacity_benchmark ')]
            if len(lines) != 1: raise RuntimeError('Missing unique capacity result')
            values = dict(x.split('=',1) for x in lines[0].split()[1:])
            row = {'source': label, **{k: v if k == 'input_sha256' else float(v) if k.endswith('seconds') else int(v) for k,v in values.items()}}
            results.append(row)
            (out/'partial-results.json').write_text(json.dumps(results,indent=2)+'\n')
            print(json.dumps(row), flush=True)
    if len({row['input_sha256'] for row in results}) != 1:
        raise RuntimeError('Input identity differs across variants')
    failure['stage'] = 'verify_source_closure'
    verify_git_snapshot(old, binding)
    for label, source in [('baseline', old), ('current', current)]:
        for name, expected in closure[label].items():
            if sha(source/name) != expected: raise RuntimeError('Frozen source changed')
    for name, expected in dep_hashes.items():
        if sha(Path(name)) != expected: raise RuntimeError('Dependency changed')
    (out/'summary.json').write_text(json.dumps({'status':'complete','synthetic':True,'results':results},indent=2)+'\n')


if __name__ == '__main__':
    main()
