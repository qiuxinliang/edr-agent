#!/usr/bin/env python3
"""Synthetic local evidence comparison against untouched Git source.

Same 8 MiB budget, 1 h recent window, 192 candidates + 48 low severity context
facts over 8 simulated hours. Current selected windows: 1 h and 4 h. Measures
queryable parent-chain completeness, event window, DB/WAL/SHM samples, process
CPU, and SQLite VFS issued read/write/sync counts (not hardware I/O).

  python3 tests/run_evidence_retention_comparison.py --output /tmp/evidence-compare

Requires a C compiler, SQLite and zstd development libraries. No network,
production data, checkout/ref changes, or deletion of existing output files.
The only test substitutes are a controlled clock/resource-pressure flag and
unrelated action/network side effects. All linked baseline production files
and headers are byte-checked against the requested commit before compilation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import statistics
import subprocess
import re
from retention_comparison_support import (dependencies, compiler_flags, compile_command,
    runtime_environment, verify_native, compiler_identity, execute_benchmark,
    failure_report, export_git_snapshot, verify_git_snapshot)

SOURCES = [
    'src/preprocess/detection_decision.c', 'src/preprocess/detection_profile.c',
    'src/preprocess/behavior_from_slot.c', 'src/detection/policy_v2.c',
    'src/storage/local_evidence_cache.c', 'src/storage/evidence_context_store.c',
    'src/storage/evidence_cache_migration.c', 'src/forensic/process_tree_cache.c',
    'src/preprocess/behavior_record.c', 'src/preprocess/p0_rule_match.c',
    'src/preprocess/windows_event_policy.c', 'src/preprocess/windows_file_identity.c',
    'src/preprocess/p0_rule_ir_stub.c', 'src/command/sha256.c',
    'src/serialize/behavior_proto.c', 'third_party/nanopb/pb_encode.c',
    'third_party/cjson/cJSON.c', 'src/preprocess/p0_terminal_identity.c',
    'src/transport/egress_batch_policy.c', 'src/transport/egress_request_policy.c',
    'src/transport/egress_purpose_json.c', 'src/proto/edr/v1/event.pb.c',
    'third_party/nanopb/pb_common.c', 'third_party/nanopb/pb_decode.c',
    'third_party/lz4/lz4.c', 'src/core/validation_trace.c',
]
QUEUE_SOURCES = ['src/storage/queue_sqlite.c', 'src/transport/report_events_ack.c']

def run(command, **kwargs):
    kwargs.setdefault("timeout", 180)
    return subprocess.run(command, check=True, **kwargs)

def capture(command, **kwargs):
    kwargs.setdefault("timeout", 30)
    return subprocess.check_output(command, **kwargs)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def parent_binding_api(header):
    """Detect the actual inline API in each frozen production header."""
    text = header.read_text(encoding='utf-8')
    text = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  ' ', text, flags=re.S)
    return bool(re.search(r'\bstatic\s+inline\s+void\s+edr_behavior_bind_parent_context\s*'
                          r'\(\s*EdrBehaviorRecord\s*\*\s*\w+\s*\)\s*\{', text))

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--baseline', default='6bedb86bf9811bc304f4c97fdd62212ef437423f')
parser.add_argument('--runs', type=int, default=5)
parser.add_argument('--cc', default=os.environ.get('CC', 'cl' if os.name == 'nt' else 'cc'))
parser.add_argument('--dependency-prefix', type=Path)
parser.add_argument('--native-machine', choices=('amd64', 'arm64'))
args = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
out = args.output.resolve()
if out == repo or repo in out.parents or args.runs < 1 or args.runs > 100:
    parser.error('Use an external output directory and 1..100 runs.')
if out.exists() and any(out.iterdir()):
    parser.error('Use an empty output directory; existing data is never removed.')
out.mkdir(parents=True, exist_ok=True)
failure = failure_report(out)
failure['stage'] = 'baseline_revision'
revision = capture(['git', 'rev-parse', args.baseline + '^{commit}'], cwd=repo, text=True).strip()
old, current = out/'baseline', out/'current'
old.mkdir()
failure['stage'] = 'baseline_export'
baseline_binding = export_git_snapshot(repo, revision, old, ('src', 'include', 'third_party'),
                                      out/'baseline-source-binding.json')
failure['stage'] = 'current_snapshot'
for folder in ('src', 'include', 'third_party'):
    shutil.copytree(repo/folder, current/folder)
harness = out/'evidence_retention_comparison.c'
harness.write_bytes((repo/'tests/evidence_retention_comparison.c').read_bytes())
(out/'retention_benchmark_support.h').write_bytes((repo/'tests/retention_benchmark_support.h').read_bytes())
defines = ['EDR_AGENT_VERSION_STRING="3.2.642"', 'EDR_HAVE_LZ4=1',
           'EDR_HAVE_ZSTD=1', 'EDR_HAVE_NANOPB=1', 'EDR_HAVE_SQLITE=1',
           'EDR_LOCAL_EVIDENCE_CACHE_TESTING=1', 'PB_FIELD_32BIT=1']
failure['stage'] = 'dependency_resolution'
dependency_includes, dependency, dependency_hashes = dependencies(args.dependency_prefix)
failure['stage'] = 'compiler_identity'
metadata = {'baseline_revision': revision,
            'baseline_source_binding_sha256': digest((out/'baseline-source-binding.json').read_bytes()),
            'current_head': capture(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
            'current_is_working_tree_snapshot': True, 'harness_sha256': digest(harness.read_bytes()),
            'runs': args.runs, 'metrics_are_synthetic': True,
            'runner_sha256': digest(Path(__file__).read_bytes()),
            'measurement_header_sha256': digest((out/'retention_benchmark_support.h').read_bytes()),
            'runner_support_sha256': digest((repo/'tests/retention_comparison_support.py').read_bytes()),
            'dependency_sha256': dependency_hashes, 'native_machine_required': args.native_machine,
            'compiler': compiler_identity(args.cc),
            'measurement_scope': 'Cache open, writes and maintenance through close; final forensic SQL inventory excluded from CPU/I/O counters',
            'cpu_clock': 'GetProcessTimes' if os.name == 'nt' else 'getrusage',
            'wall_clock': 'QueryPerformanceCounter' if os.name == 'nt' else 'CLOCK_MONOTONIC',
            'io_boundary': 'SQLite-issued VFS bytes and optional Windows process-issued bytes; not device I/O',
            'time_boundary': '8 simulated event hours, not an 8-hour wall-clock soak',
            'source_api_features': {}}
(out/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
summaries = {}
frozen_sources = []
for name, source, selected in [('old',old,1), ('current_1h',current,1), ('current_4h',current,4)]:
    failure['stage'] = 'variant_prepare'
    sources = SOURCES + (QUEUE_SOURCES if source == current else [])
    selected_defines = list(defines)
    binding_header = source/'include/edr/behavior_record.h'
    binding_api = parent_binding_api(binding_header)
    if source == current and not binding_api:
        raise RuntimeError('Current source requires its real parent-context binding API')
    selected_defines += ['BENCH_HAS_PARENT_CONTEXT_BINDING='+str(int(binding_api))]
    metadata['source_api_features'][name] = {
        'parent_context_binding_api': binding_api,
        'behavior_record_header_sha256': digest(binding_header.read_bytes()),
        'fixture_behavior': 'call_production_inline' if binding_api else 'legacy_tuple_source_unchanged'}
    (out/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    if source == current:
        selected_defines += ['BENCH_REAL_QUEUE=1', 'BENCH_SOURCE="current"',
                    'BENCH_SELECTED_HOURS='+str(selected)]
    include_paths = [source/folder for folder in
        ('.','include','third_party/cjson','third_party/nanopb','src/proto','third_party/lz4')]
    binary = out/(name+'_benchmark'+('.exe' if os.name == 'nt' else ''))
    flags = compiler_flags(selected_defines, [out, *include_paths, *dependency_includes], args.native_machine)
    command = compile_command(args.cc, flags, [harness, *[source/p for p in sources]], binary, dependency)
    (out/(name+'-compile.json')).write_text(json.dumps(command,indent=2)+'\n')
    hashes = {p.relative_to(source).as_posix():digest(p.read_bytes())
              for p in source.rglob('*') if p.is_file() and not p.is_symlink()}
    frozen_sources.append((source, hashes))
    (out/(name+'-source-sha256.json')).write_text(json.dumps(hashes,sort_keys=True,indent=2)+'\n')
    failure['stage'] = 'compile'
    with (out/(name+'-build.log')).open('w') as log:
        run(command, cwd=out, stdout=log, stderr=subprocess.STDOUT)
    failure['stage'] = 'execute_and_validate'
    samples=[]
    with (out/(name+'-runs.log')).open('w') as log:
        for index in range(args.runs):
            synthetic=out/('synthetic-'+name+'-'+str(index)); synthetic.mkdir()
            execution=execute_benchmark([str(binary)],synthetic,
                runtime_environment(synthetic,args.dependency_prefix),60)
            stdout=(synthetic/'stdout.log').read_text(encoding='utf-8')
            log.write(stdout);log.flush()
            if execution['exit_code']!=0 or execution['timed_out']:
                raise RuntimeError('Benchmark failed; partial output and terminal status preserved: '+str(synthetic))
            lines=[x for x in stdout.splitlines() if x.startswith('retention_value_benchmark ')]
            if len(lines)!=1:raise RuntimeError('Missing benchmark output: '+name)
            values=dict(item.split('=',1) for item in lines[0].split()[1:])
            verify_native(binary, values, args.native_machine)
            samples.append(values)
    sums={key:statistics.median((float if key.endswith('seconds') or key=='sqlite_write_amplification' else int)(row[key]) for row in samples)
          for key in samples[0] if key not in ('source','input_sha256','sqlite_version')}
    sums['input_sha256']=samples[0]['input_sha256']
    sums['sqlite_version']=samples[0]['sqlite_version']
    if any(row['input_sha256']!=sums['input_sha256'] or row['sqlite_version']!=sums['sqlite_version'] for row in samples):
        raise RuntimeError('Nonidentical benchmark inputs')
    summaries[name]=sums
    print(json.dumps({'variant':name,'median':sums}),flush=True)
if len({x['input_sha256'] for x in summaries.values()}) != 1:
    raise RuntimeError('Baseline and current input digests differ')
failure['stage'] = 'verify_frozen_sources'
verify_git_snapshot(old, baseline_binding)
for source, hashes in frozen_sources:
    for relative, expected in hashes.items():
        if digest((source/relative).read_bytes()) != expected:
            raise RuntimeError('Frozen source changed during comparison: '+relative)
for path, expected in dependency_hashes.items():
    if digest(Path(path).read_bytes()) != expected:
        raise RuntimeError('Dependency changed during comparison: '+path)
(out/'summary.json').write_text(json.dumps(summaries,indent=2)+'\n')
