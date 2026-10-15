#!/usr/bin/env python3
"""Synthetic-only queue comparison. Requires the already-built real-codec library.

The same real protobuf BAT1 inputs, 1 MiB logical budget, 1 h window, 48 unique
128 KiB records over 12 simulated windows. time() is replaced identically in
both queue builds; no production database, network, checkout or Git ref changes.
SQLite total_changes and OS block counts are explicitly write/I/O proxies.

Example:
  python3 tests/run_queue_retention_comparison.py --output /tmp/queue-comparison-new \
      --codec-build /tmp/edr-cache-assessment-egress-build

"""
import argparse, hashlib, json, pathlib, subprocess, time

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',type=pathlib.Path,required=True,help='New synthetic output directory outside the repository')
parser.add_argument('--codec-build',type=pathlib.Path,required=True,help='CMake build directory containing libedr_egress_policy.a')
parser.add_argument('--baseline',default='0ae3fb28e553223358db1a83ebd26432336af9e7')
args=parser.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
out=args.output.resolve()
assert out!=root and root not in out.parents, 'Keep generated fixtures and binaries outside the repository.'
assert not out.exists() or not any(out.iterdir()), 'Use an empty output directory; existing data is never removed.'
out.mkdir(parents=True,exist_ok=True)
baseline=args.baseline
library=args.codec_build.resolve()/'libedr_egress_policy.a'
assert library.is_file(), 'Build test_queue_recovery first to obtain the actual codec library.'
for name,revision in [('baseline_662',baseline),('current',None)]:
    work=out/name; (work/'include/edr').mkdir(parents=True,exist_ok=True)
    def contents(path):
        return subprocess.check_output(['git','show',f'{revision}:{path}'],cwd=root) if revision else (root/path).read_bytes()
    source=contents('src/storage/queue_sqlite.c')
    (work/'queue_sqlite.c').write_bytes(source+b'\nuint64_t benchmark_total_changes(void) { return (uint64_t)sqlite3_total_changes(s_db); }\n')
    (work/'include/edr/storage_queue.h').write_bytes(contents('include/edr/storage_queue.h'))
    binary=work/'queue_comparison'
    command=['cc','-std=c11','-D_DEFAULT_SOURCE','-DEDR_HAVE_SQLITE=1','-DEDR_STORAGE_QUEUE_TESTING=1',
             '-DPB_FIELD_32BIT=1','-DEDR_HAVE_LZ4=1','-Dtime=benchmark_time']
    if not revision:command+=['-DLOCAL_TYPED=1']
    for folder in [work/'include',root/'include',root/'third_party/cjson',root/'third_party/nanopb',root/'src/proto',root/'third_party/lz4']:
        command+=['-I',str(folder)]
    command += [str(root/'tests/queue_retention_comparison.c'),str(work/'queue_sqlite.c'),str(root/'src/core/time_util.c'),
                str(root/'src/transport/report_events_ack.c'),str(library),'-L/opt/homebrew/lib','-lzstd','-lsqlite3','-lpthread','-lm','-o',str(binary)]
    (work/'compile-command.json').write_text(json.dumps(command,ensure_ascii=False,indent=2)+'\n')
    with (work/'build.log').open('w') as log:subprocess.run(command,cwd=work,stdout=log,stderr=subprocess.STDOUT,check=True)
    db=work/'synthetic.db'
    started=time.monotonic()
    with (work/'results.jsonl').open('w') as output,(work/'stderr.log').open('w') as error:
        run=subprocess.run([str(binary),str(db)],cwd=work,stdout=output,stderr=error)
    result={'variant':name,'source_revision':revision or subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()+'+working-tree',
            'queue_source_sha256':hashlib.sha256(source).hexdigest(),'wall_seconds':round(time.monotonic()-started,6),
            'exit_code':run.returncode,'log':str(work/'results.jsonl')}
    print(json.dumps(result,ensure_ascii=False),flush=True)
    if run.returncode:raise SystemExit(run.returncode)
