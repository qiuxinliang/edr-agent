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
import io
import json
import os
import posixpath
from pathlib import Path
import shlex
import shutil
import statistics
import subprocess
import tarfile

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

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--baseline', default='6bedb86bf9811bc304f4c97fdd62212ef437423f')
parser.add_argument('--runs', type=int, default=5)
parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
args = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
out = args.output.resolve()
if out == repo or repo in out.parents or args.runs < 1 or args.runs > 100:
    parser.error('Use an external output directory and 1..100 runs.')
if out.exists() and any(out.iterdir()):
    parser.error('Use an empty output directory; existing data is never removed.')
out.mkdir(parents=True, exist_ok=True)
revision = capture(['git', 'rev-parse', args.baseline + '^{commit}'], cwd=repo, text=True).strip()
old, current = out/'baseline', out/'current'
old.mkdir()
archive = capture(['git', 'archive', revision, 'src', 'include', 'third_party'], cwd=repo)
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    # git archive contains trusted tracked source paths, no external inputs.
    for member in tar.getmembers():
        if member.name.startswith('/') or '..' in Path(member.name).parts:
            raise RuntimeError('Unexpected archive path')
        if member.issym():
            target = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), member.linkname))
            if target.startswith('/') or target == '..' or target.startswith('../'):
                raise RuntimeError('Archive symlink escapes source snapshot')
        elif not (member.isfile() or member.isdir()):
            raise RuntimeError('Unsupported archive entry')
    tar.extractall(old)
for folder in ('src', 'include', 'third_party'):
    shutil.copytree(repo/folder, current/folder)
harness = out/'evidence_retention_comparison.c'
harness.write_bytes((repo/'tests/evidence_retention_comparison.c').read_bytes())
# Verify the complete exported baseline (including transitive headers), not a
# hybrid of old C and new headers. Ignore directories; no source is patched.
for path in old.rglob('*'):
    if path.is_file() and not path.is_symlink():
        relative = path.relative_to(old).as_posix()
        expected = capture(['git', 'show', revision + ':' + relative], cwd=repo)
        if path.read_bytes() != expected:
            raise RuntimeError('Baseline source mismatch: ' + relative)
flags = ['-g', '-std=c11', '-D_DEFAULT_SOURCE', '-Wall', '-Wextra',
         '-Wno-unused-parameter', '-Wno-unused-function', '-UNDEBUG',
         '-DEDR_AGENT_VERSION_STRING="3.2.642"', '-DEDR_HAVE_LZ4=1',
         '-DEDR_HAVE_ZSTD=1', '-DEDR_HAVE_NANOPB=1', '-DEDR_HAVE_SQLITE=1',
         '-DEDR_LOCAL_EVIDENCE_CACHE_TESTING=1', '-DPB_FIELD_32BIT=1']
try:
    dependency = shlex.split(capture(
        ['pkg-config', '--cflags', '--libs', 'sqlite3', 'libzstd'], text=True, stderr=subprocess.DEVNULL))
except (FileNotFoundError, subprocess.CalledProcessError):
    dependency = ['-lsqlite3', '-lzstd']
    if Path('/opt/homebrew/include').is_dir():
        dependency = ['-isystem', '/opt/homebrew/include', '-L/opt/homebrew/lib',
                      '-Wl,-rpath,/opt/homebrew/lib', *dependency]
metadata = {'baseline_revision': revision,
            'current_head': capture(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
            'current_is_working_tree_snapshot': True, 'harness_sha256': digest(harness.read_bytes()),
            'runs': args.runs, 'metrics_are_synthetic': True}
(out/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
summaries = {}
for name, source, selected in [('old',old,1), ('current_1h',current,1), ('current_4h',current,4)]:
    sources = SOURCES + (QUEUE_SOURCES if source == current else [])
    command = [args.cc, *flags]
    if source == current:
        command += ['-DBENCH_REAL_QUEUE=1', '-DBENCH_SOURCE="current"',
                    '-DBENCH_SELECTED_HOURS='+str(selected),
                    '-DBENCH_OPEN(path,selected)=edr_local_evidence_cache_open_with_policy(path,8,1,selected)']
    for folder in ('.','include','third_party/cjson','third_party/nanopb','src/proto','third_party/lz4'):
        command += ['-I'+str(source/folder)]
    binary = out/(name+'_benchmark')
    command += [str(harness), *[str(source/p) for p in sources], '-o', str(binary),
                *dependency, '-lm', '-pthread']
    (out/(name+'-compile.json')).write_text(json.dumps(command,indent=2)+'\n')
    hashes = {p.relative_to(source).as_posix():digest(p.read_bytes())
              for p in source.rglob('*') if p.is_file() and not p.is_symlink()}
    (out/(name+'-source-sha256.json')).write_text(json.dumps(hashes,sort_keys=True,indent=2)+'\n')
    with (out/(name+'-build.log')).open('w') as log:
        run(command, cwd=out, stdout=log, stderr=subprocess.STDOUT)
    samples=[]
    with (out/(name+'-runs.log')).open('w') as log:
        for index in range(args.runs):
            result=run([str(binary)],cwd=out,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
            log.write(result.stdout);log.flush()
            (out/(name+'-run-'+str(index)+'-stderr.log')).write_text(result.stderr)
            lines=[x for x in result.stdout.splitlines() if x.startswith('retention_value_benchmark ')]
            if len(lines)!=1:raise RuntimeError('Missing benchmark output: '+name)
            values=dict(item.split('=',1) for item in lines[0].split()[1:])
            samples.append(values)
    sums={key:statistics.median((float if key in ('cpu_seconds','sqlite_write_amplification') else int)(row[key]) for row in samples)
          for key in samples[0] if key not in ('source','input_sha256')}
    sums['input_sha256']=samples[0]['input_sha256']
    if any(row['input_sha256']!=sums['input_sha256'] for row in samples):
        raise RuntimeError('Nonidentical benchmark inputs')
    summaries[name]=sums
    print(json.dumps({'variant':name,'median':sums}),flush=True)
if len({x['input_sha256'] for x in summaries.values()}) != 1:
    raise RuntimeError('Baseline and current input digests differ')
(out/'summary.json').write_text(json.dumps(summaries,indent=2)+'\n')
