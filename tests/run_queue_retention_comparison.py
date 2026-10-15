#!/usr/bin/env python3
"""Source-bound synthetic queue comparison on POSIX or native Windows.

Equal 1 MiB logical budgets, 1 h target and real BAT1/codec inputs across 12
simulated windows. --scenarios unique replay high_severity adds exact replay
and priority-3 pressure cases; every retained 128 KiB wire is compared exactly.
Windows requires the existing locked vcpkg prefix and initialized MSVC owner.
No release, installer, live Agent paths, network requests or existing DB removal.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from retention_comparison_support import (CODEC_SOURCES, compiler_flags,
    compile_command, dependencies, digest, includes, runtime_environment, verify_native, compiler_identity, execute_benchmark)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--codec-build', type=Path, help='Existing real codec build, required on POSIX')
parser.add_argument('--baseline', default='0ae3fb28e553223358db1a83ebd26432336af9e7')
parser.add_argument('--cc', default=os.environ.get('CC', 'cl' if os.name == 'nt' else 'cc'))
parser.add_argument('--dependency-prefix', type=Path)
parser.add_argument('--native-machine', choices=('amd64', 'arm64'))
parser.add_argument('--scenarios', nargs='+', choices=('unique', 'replay', 'high_severity', 'owner_loss'), default=['unique'])
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
out = args.output.resolve()
if out == root or root in out.parents or (out.exists() and any(out.iterdir())):
    parser.error('Use a new external synthetic output directory; existing data is never removed.')
if len(set(args.scenarios)) != len(args.scenarios):
    parser.error('Each scenario may run once per variant; duplicate scenarios are not allowed.')
if os.name != 'nt' and not args.codec_build:
    parser.error('Build the real codec first and pass --codec-build on POSIX.')
out.mkdir(parents=True, exist_ok=True)
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
baseline = subprocess.check_output(['git', 'rev-parse', args.baseline+'^{commit}'], cwd=root, text=True).strip()
source = out/'source'
for folder in ('src', 'include', 'third_party'):
    shutil.copytree(root/folder, source/folder)
for name in ('queue_retention_comparison.c', 'retention_benchmark_support.h'):
    (out/name).write_bytes((root/'tests'/name).read_bytes())
source_hashes = {p.relative_to(source).as_posix(): digest(p) for p in source.rglob('*')
                 if p.is_file() and not p.is_symlink()}
(out/'current-source-sha256.json').write_text(json.dumps(source_hashes, sort_keys=True, indent=2)+'\n')
dep_includes, libraries, dep_hashes = dependencies(args.dependency_prefix)
defines = ['EDR_HAVE_SQLITE=1', 'EDR_STORAGE_QUEUE_TESTING=1', 'PB_FIELD_32BIT=1',
           'EDR_HAVE_LZ4=1', 'EDR_HAVE_ZSTD=1', 'EDR_AGENT_VERSION_STRING="3.2.642"']

def build(command, path, cwd):
    with path.open('x', encoding='utf-8') as log:
        subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)

if os.name == 'nt' and not args.codec_build:
    codec = out/'codec'; codec.mkdir()
    objects = codec/'objects'; objects.mkdir()
    flags = compiler_flags(defines, [*includes(source), *dep_includes], args.native_machine)
    compile_codec = [args.cc, *flags, '/c', '/Fo'+str(objects)+os.sep,
                     *[str(source/p) for p in CODEC_SOURCES]]
    build(compile_codec, codec/'compile.log', codec)
    library = codec/'edr_egress_policy.lib'
    link_codec = ['lib', '/nologo', '/OUT:'+str(library),
                  *[str(objects/(Path(p).stem+'.obj')) for p in CODEC_SOURCES]]
    build(link_codec, codec/'archive.log', codec)
    (codec/'commands.json').write_text(json.dumps([compile_codec, link_codec], indent=2)+'\n')
else:
    name = 'edr_egress_policy.lib' if os.name == 'nt' else 'libedr_egress_policy.a'
    original_library = args.codec_build.resolve()/name
    if not original_library.is_file():
        parser.error('Missing real codec library: '+str(original_library))
    library = out/name; shutil.copyfile(original_library, library)
metadata = {'current_head': head, 'baseline_revision': baseline,
    'baseline_scope': 'Original queue_sqlite.c and storage_queue.h; shared current codec, support and other headers as in the existing comparison protocol',
    'codec_sha256': digest(library), 'dependency_sha256': dep_hashes,
    'harness_sha256': digest(out/'queue_retention_comparison.c'),
    'runner_sha256': digest(Path(__file__)),
    'measurement_header_sha256': digest(out/'retention_benchmark_support.h'),
    'runner_support_sha256': digest(root/'tests/retention_comparison_support.py'),
    'native_machine_required': args.native_machine, 'scenarios': args.scenarios,
    'compiler': compiler_identity(args.cc),
    'measurement_scope': 'Open, ingress, per-window forensic inventory and terminal readback; final close excluded',
    'pressure_matrix_domain': 'Typed local queue owners and exact replays; not candidate selection or investigation pins',
    'input_hash_scope': 'All external offered wires followed by terminal; actual source commit/retry counts, attempted-stream SHA and retry-stream SHA are independent and may differ before/after',
    'owner_scope': 'One exact failed snapshot/latch is retained without overwrite and retried per offered-input turn after cleanup. Remaining offers are explicitly deferred while pending. owner_loss deliberately omits this RAM handoff. This is not the full eight-slot/250ms P0 producer or its concurrency.',
    'cpu_clock': 'GetProcessTimes' if os.name == 'nt' else 'getrusage',
    'wall_clock': 'QueryPerformanceCounter' if os.name == 'nt' else 'CLOCK_MONOTONIC',
    'io_boundary': 'SQLite-issued VFS bytes and optional Windows process-issued bytes; not device I/O',
    'time_boundary': '12 simulated retention windows, not a twelve-hour wall-clock soak'}
(out/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
# Observe the actual nine transactional categories, independently of trigger
# updates. This appended test helper never recalibrates or changes the ledger.
ledger_helper = r'''
uint64_t benchmark_total_changes(void) { return (uint64_t)sqlite3_total_changes(s_db); }
int benchmark_ledger_categories_verified(void) {
#ifdef LOCAL_TYPED
  QueueCapacityLedger actual, expected = {{0},{0},0};
  const char *queries[] = {
    "SELECT retention_class,SUM(" QUEUE_LEDGER_EVENT_COST("") "),COUNT(*) FROM event_queue GROUP BY retention_class",
    "SELECT 4,SUM(" QUEUE_LEDGER_JOURNAL_COST("") "),COUNT(*) FROM enforcement_terminal_journal HAVING COUNT(*)>0",
    "SELECT " QUEUE_LEDGER_DEFERRED_CATEGORY("") ",SUM(" QUEUE_LEDGER_DEFERRED_COST("") "),COUNT(*) FROM p0_deferred_match GROUP BY " QUEUE_LEDGER_DEFERRED_CATEGORY(""),
    "SELECT 7,COUNT(*)*512,COUNT(*) FROM queue_projection_relations HAVING COUNT(*)>0",
    "SELECT 8,SUM(" QUEUE_LEDGER_META_COST("") "),COUNT(*) FROM queue_meta HAVING COUNT(*)>0"
  };
  if(!queue_capacity_ledger_read_locked(&actual,NULL)) return 0;
  for(unsigned i=0;i<sizeof(queries)/sizeof(queries[0]);i++) {
    sqlite3_stmt *st=NULL;
    if(sqlite3_prepare_v2(s_db,queries[i],-1,&st,NULL)!=SQLITE_OK) return 0;
    int rc;
    while((rc=sqlite3_step(st))==SQLITE_ROW) {
      int category=sqlite3_column_int(st,0);
      if(category<0 || category>=9 || sqlite3_column_int64(st,1)<0 || sqlite3_column_int64(st,2)<0) {sqlite3_finalize(st);return 0;}
      expected.bytes[category]+=(uint64_t)sqlite3_column_int64(st,1);
      expected.rows[category]+=(uint64_t)sqlite3_column_int64(st,2);
    }
    sqlite3_finalize(st);if(rc!=SQLITE_DONE) return 0;
  }
  for(unsigned i=0;i<9;i++) if(actual.bytes[i]!=expected.bytes[i] || actual.rows[i]!=expected.rows[i]) return 0;
  return 9;
#else
  return -1; /* This historical queue has no nine-category ledger. */
#endif
}
'''
results = {}
for name, revision in [('baseline_662', baseline), ('current', None)]:
    work = out/name; (work/'include/edr').mkdir(parents=True)
    def contents(path):
        return subprocess.check_output(['git','show',revision+':'+path],cwd=root) if revision else (source/path).read_bytes()
    original = contents('src/storage/queue_sqlite.c')
    (work/'queue_sqlite.original.c').write_bytes(original)
    marker = b'#include <time.h>'
    if original.count(marker) != 1:
        raise RuntimeError('Expected exactly one queue time-header hook')
    # Bind only the queue's calls, after CRT declarations/macros have loaded.
    hooked = original.replace(marker, marker+b'\n#undef time\nextern time_t benchmark_time(time_t *);\n#define time benchmark_time', 1)
    (work/'queue_sqlite.c').write_bytes(hooked+ledger_helper.encode())
    header = contents('include/edr/storage_queue.h')
    (work/'include/edr/storage_queue.h').write_bytes(header)
    binary = work/('queue_comparison'+('.exe' if os.name == 'nt' else ''))
    flags = compiler_flags(defines+(['LOCAL_TYPED=1'] if not revision else []),
                           [work/'include', out, *includes(source), *dep_includes], args.native_machine)
    command = compile_command(args.cc, flags,
        [out/'queue_retention_comparison.c', work/'queue_sqlite.c', source/'src/core/time_util.c',
         source/'src/transport/report_events_ack.c'], binary, [str(library), *libraries])
    (work/'compile-command.json').write_text(json.dumps(command, indent=2)+'\n')
    (work/'source-binding.json').write_text(json.dumps({'source_sha256':hashlib.sha256(original).hexdigest(),
        'header_sha256':hashlib.sha256(header).hexdigest(), 'instrumented_sha256':digest(work/'queue_sqlite.c'),
        'time_binding':'After the one existing time.h include; only queue calls use the fixed fixture clock',
        'ledger_helper':'Read-only SUM/COUNT against each of nine actual categories; no recalibration'},indent=2)+'\n')
    build(command, work/'build.log', work)
    for scenario in args.scenarios:
        data = work/('synthetic-'+scenario); data.mkdir()
        execution = execute_benchmark([str(binary), str(data/'synthetic.db'), scenario],
            data, runtime_environment(data,args.dependency_prefix),150)
        result = {'variant':name, 'scenario':scenario, 'source_revision':revision or head+'+working-tree',
            'queue_source_sha256':hashlib.sha256(original).hexdigest(), 'exe_sha256':digest(binary),
            'wall_seconds':execution['wall_seconds'], 'exit_code':execution['exit_code'],
            'timed_out':execution['timed_out'], 'log':str(data/'stdout.log'),
            'log_sha256':digest(data/'stdout.log')}
        if execution['exit_code']!=0 or execution['timed_out']:
            raise RuntimeError('Comparison failed; retain failure logs: '+str(data))
        rows = [json.loads(line) for line in (data/'stdout.log').read_text().splitlines()]
        if len(rows)!=13 or [x.get('window') for x in rows[:-1]]!=list(range(12)):
            raise RuntimeError('Missing exact twelve-window inventory and final measurement')
        final = rows[-1]; verify_native(binary, final, args.native_machine)
        if rows[-2]['total_admitted']+rows[-2]['total_rejected']+final['producer_deferred']!=final['input_records']:
            raise RuntimeError('Offered input missing an explicit attempted/deferred outcome')
        if final['source_commit_calls']!=rows[-2]['total_admitted']+rows[-2]['total_rejected']+final['retry_commit_calls']:
            raise RuntimeError('Actual source commit and retry accounting mismatch')
        if any(row['source_upload_calls'] or row['retained_rows']!=row['chain_complete_rows'] or not row['integrity_ok'] for row in rows[:-1]):
            raise RuntimeError('Retained chain, integrity or no-local-upload invariant failed')
        if not revision and scenario!='owner_loss' and (rows[-2]['freshest_age_s']>3600 or
                final['owner_recovery_required'] or not final['retry_succeeded']):
            raise RuntimeError('Exact-snapshot retry did not sustain fresh bounded queue rotation')
        if not revision and (not final['terminal20_admitted'] or not final['terminal20_exact_readable'] or
                             any(row['ledger_categories_verified']!=9 for row in rows[:-1])):
            raise RuntimeError('Current queue reserve or nine-category ledger invariant failed')
        if revision and final['terminal20_admitted']:
            raise RuntimeError('Historical queue no longer reproduces the blocked terminal')
        results[name+'/'+scenario]={'execution':result,'windows':rows[:-1],'measurement':final}
        print(json.dumps({'variant':name,'scenario':scenario,'exit_code':0,
                          'last_window':rows[-2],'measurement':final}),flush=True)
for scenario in args.scenarios:
    before = results['baseline_662/'+scenario]['measurement']
    after = results['current/'+scenario]['measurement']
    if before['input_stream_sha256']!=after['input_stream_sha256'] or before['input_records']!=after['input_records']:
        raise RuntimeError('Before/after encoded input streams differ: '+scenario)
for path, expected in dep_hashes.items():
    if digest(path)!=expected:
        raise RuntimeError('Dependency changed during comparison: '+path)
for relative, expected in source_hashes.items():
    if digest(source/relative)!=expected:
        raise RuntimeError('Frozen source changed during comparison: '+relative)
(out/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
