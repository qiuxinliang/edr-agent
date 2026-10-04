#!/usr/bin/env python3
"""Compile real Windows owners, including SQLite branches; link policy tests.

This compiler probe never executes a test or alters runtime/release feature
requirements. System headers may supply portable declaration-only headers;
linked Windows tests use repository sources and MinGW Windows system libraries.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', required=True)
    parser.add_argument('--compiler', default='x86_64-w64-mingw32-gcc')
    parser.add_argument('--objdump', default='x86_64-w64-mingw32-objdump')
    parser.add_argument('--sqlite-include', required=True)
    parser.add_argument('--openssl-include', required=True)
    parser.add_argument('--pcre2-include', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = Path(args.build_dir).resolve()
    if build == root or root in build.parents:
        parser.error('Use an isolated build directory outside the checkout.')
    for executable in (args.compiler, args.objdump):
        if not shutil.which(executable):
            parser.error(f'Required cross tool unavailable: {executable}')
    for directory, header in ((args.sqlite_include,'sqlite3.h'),
                              (args.openssl_include,'openssl/ssl.h'),
                              (args.pcre2_include,'pcre2.h')):
        if not (Path(directory) / header).is_file():
            parser.error(f'Required declaration header unavailable: {header}')
    build.mkdir(parents=True, exist_ok=True)
    common = [args.compiler, '-std=gnu11', '-O0', '-g', '-Wall', '-Wextra',
              '-Werror=implicit-function-declaration', '-DPB_FIELD_32BIT=1',
              '-DEDR_HAVE_NANOPB=1', '-DEDR_HAVE_LZ4=1']
    for include in ('include','src/proto','third_party/nanopb','third_party/cjson','third_party/lz4'):
        common += ['-I', str(root / include)]
    # Isolate the portable SQLite declaration: an SDK include directory must
    # not shadow MinGW's stdlib/system headers with host-platform headers.
    portable = build / 'declaration_headers'
    portable.mkdir(exist_ok=True)
    shutil.copyfile(Path(args.sqlite_include) / 'sqlite3.h', portable / 'sqlite3.h')
    common += ['-I',str(portable),'-I',args.openssl_include,'-I',args.pcre2_include]
    owners = ('src/main.c','src/core/agent.c',
              'src/storage/queue_sqlite.c','src/storage/queue_maintenance.c',
              'src/storage/local_evidence_cache.c','src/preprocess/preprocess_pipeline.c',
              'src/pmfe/pmfe_engine.c','src/pmfe/pmfe_etw_preprocess.c',
              'src/forensic/deep_collector.c','src/transport/ingest_http.c',
              'src/preprocess/p0_rule_ir.c','src/preprocess/p0_rule_direct_emit.c',
              'src/preprocess/behavior_from_slot.c','src/serialize/behavior_proto.c',
              'src/serialize/behavior_alert_emit.c',
              'tests/test_queue_recovery.c','tests/test_local_evidence_cache_candidate.c',
              'tests/test_egress_tls_client.c','tests/test_pmfe_lifecycle.c')
    outputs = []

    def run(command):
        subprocess.run(command, check=True, cwd=root)

    for source in owners:
        obj = build / (source.replace('/', '_') + '.obj')
        timing_hook = ['-DEDR_PMFE_LIFECYCLE_TESTING=1'] if source == 'tests/test_pmfe_lifecycle.c' else []
        run(common + timing_hook + ['-DEDR_HAVE_SQLITE=1','-DEDR_HAVE_OPENSSL_HTTP=1',
                      '-DEDR_HAVE_OPENSSL_FL=1','-DPCRE2_STATIC=1',
                      '-DEDR_TEST_EXTENDED_EGRESS=1','-DEDR_STORAGE_QUEUE_TESTING=1',
                      '-DEDR_LOCAL_EVIDENCE_CACHE_TESTING=1',
                      '-c', str(root / source), '-o', str(obj)])
        outputs.append(obj)
    policy = ('src/preprocess/p0_terminal_identity.c','src/command/sha256.c','src/transport/egress_batch_policy.c','src/transport/egress_request_policy.c',
              'src/proto/edr/v1/event.pb.c','third_party/nanopb/pb_common.c',
              'third_party/nanopb/pb_decode.c','third_party/nanopb/pb_encode.c','third_party/cjson/cJSON.c','third_party/lz4/lz4.c')
    codec = ('src/serialize/behavior_proto.c','src/preprocess/detection_decision.c',
             'src/preprocess/detection_profile.c','src/preprocess/behavior_record.c',
             'src/detection/policy_v2.c')
    tests = {
        'test_egress_batch_policy': ('tests/test_egress_batch_policy.c',) + codec,
        'test_egress_request_policy': ('tests/test_egress_request_policy.c',),
        'test_deep_collector_manifest': ('tests/test_deep_collector_manifest.c',
            'src/platform/windows_spawn_lock.c'),
    }
    for name, sources in tests.items():
        exe = build / (name + '.exe')
        run(common + [str(root / src) for src in sources + policy] +
            ['-lws2_32','-lbcrypt','-lwinhttp','-lcrypt32','-ladvapi32','-o',str(exe)])
        outputs.append(exe)
    for output in outputs:
        machine = subprocess.check_output([args.objdump,'-f',str(output)], text=True)
        if 'i386:x86-64' not in machine:
            raise RuntimeError(f'Unexpected target architecture: {output.name}')
    print(json.dumps({'passed': True, 'scope': 'Windows cross compilation and test linking only',
        'native_tests_executed': False, 'production_connections': 0,
        'artifacts': [{'name': p.name,'bytes': p.stat().st_size,
                       'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in outputs]},
        sort_keys=True))


if __name__ == '__main__':
    main()
