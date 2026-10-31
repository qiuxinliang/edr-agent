"""Exercise the real cost clock and its historical counterfactual, offline only."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from retention_comparison_support import (SOURCES, QUEUE_SOURCES, compiler_flags,
    compile_command, compiler_identity, dependencies, digest, execute_benchmark,
    failure_report, includes, runtime_environment, storage_reservation_sources,
    verify_native)


HOOKS = r'''
#include <assert.h>
static unsigned clock_metric_calls;
#ifdef _WIN32
#include <windows.h>
static BOOL WINAPI clock_process_times(HANDLE p,LPFILETIME a,LPFILETIME b,LPFILETIME c,LPFILETIME d) {
  ++clock_metric_calls;return GetProcessTimes(p,a,b,c,d);
}
static BOOL WINAPI clock_process_io(HANDLE p,PIO_COUNTERS io) {
  ++clock_metric_calls;return GetProcessIoCounters(p,io);
}
static BOOL WINAPI clock_process_arch(HANDLE p,USHORT *a,USHORT *b) {
  ++clock_metric_calls;return IsWow64Process2(p,a,b);
}
#define GetProcessTimes clock_process_times
#define GetProcessIoCounters clock_process_io
#define IsWow64Process2 clock_process_arch
#else
#include <sys/resource.h>
static int clock_process_usage(int who,struct rusage *usage) {
  ++clock_metric_calls;return getrusage(who,usage);
}
#define getrusage clock_process_usage
#endif
'''
CHECK = r'''
int main(int argc,char **argv) {
  if(argc==2 && !strcmp(argv[1],"--clock-contract")) {
    clock_metric_calls=0;
    double a=cost_now(),b=cost_now();
    unsigned polluted=clock_metric_calls;
    RetentionBenchMetrics phase=retention_bench_metrics();
    unsigned phase_calls=clock_metric_calls-polluted;
    printf("clock_contract polluted_calls=%u phase_calls=%u monotonic=%d process_io_available=%d native_machine=%u process_machine=%u\n",
        polluted,phase_calls,b>=a,phase.process_io_available,phase.native_machine,phase.process_machine);
    return polluted==0 && b>=a && phase_calls>0 ? 0 : 86;
  }
  return cost_original_main(argc,argv);
}
'''


def instrument(source, historical=False):
    signature = 'int main(int argc, char **argv) {'
    if source.count(signature) != 1:
        raise ValueError('Cost fixture entry point changed; review the contract')
    if historical:
        begin = source.index('static double cost_now(void) {')
        end = source.index('typedef struct { uint64_t reads, writes, syncs; }', begin)
        source = source[:begin] + ('static double cost_now(void) {\n'
                 '  return retention_bench_metrics().wall_seconds;\n}\n') + source[end:]
    return HOOKS + source.replace(signature, 'int cost_original_main(int argc, char **argv) {') + CHECK


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--dependency-prefix', type=Path)
    parser.add_argument('--native-machine', choices=('amd64', 'arm64'))
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    if out == repo or repo in out.parents or out.exists():
        parser.error('Use a new external diagnostic directory')
    if os.name == 'nt' and (not args.native_machine or not args.dependency_prefix):
        parser.error('Native Windows needs its actual architecture and locked dependencies')
    out.mkdir(parents=True)
    stage = failure_report(out)
    source_path = repo/'tests/evidence_cache_cost_comparison.c'
    source = source_path.read_text(encoding='utf-8')
    for name in ('evidence_retention_comparison.c', 'retention_benchmark_support.h'):
        shutil.copyfile(repo/'tests'/name, out/name)
    dep_inc, libs, dep_hashes = dependencies(args.dependency_prefix)
    cc = 'cl' if os.name == 'nt' else os.environ.get('CC', 'cc')
    metadata = {'source_sha': subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
        'harness_sha256': digest(source_path), 'compiler': compiler_identity(cc),
        'dependencies': dep_hashes, 'native_machine': args.native_machine,
        'historical_change': 'Only cost_now is replaced with its pre-adf380b3 body',
        'runtime_deadline_seconds': 150, 'automatic_retry': False,
        'scope': 'Synthetic test fixture; not a product or latency acceptance run'}
    (out/'binding.json').write_text(json.dumps(metadata,indent=2)+'\n')
    defines = ['EDR_AGENT_VERSION_STRING="cost-clock-contract"','EDR_HAVE_LZ4=1',
        'EDR_HAVE_ZSTD=1','EDR_HAVE_NANOPB=1','EDR_HAVE_SQLITE=1',
        'EDR_LOCAL_EVIDENCE_CACHE_TESTING=1','PB_FIELD_32BIT=1','BENCH_REAL_QUEUE=1',
        'BENCH_HAS_PARENT_CONTEXT_BINDING=1','BENCH_SOURCE="same-policy"',
        'BENCH_SELECTED_HOURS=1','BENCH_HAS_STORAGE_RESERVATION=1']
    flags = compiler_flags(defines,[out,*includes(repo),*dep_inc],args.native_machine)
    if os.name != 'nt': flags += ['-O2']
    binaries = {}
    for variant in ('before','after'):
        stage['stage'] = 'compile_'+variant
        path = out/(variant+'.c');path.write_text(instrument(source,variant=='before'),encoding='utf-8')
        binary = out/(variant+('.exe' if os.name=='nt' else ''))
        command = compile_command(cc,flags,[path,*[repo/p for p in SOURCES+QUEUE_SOURCES+storage_reservation_sources(repo)]],binary,libs)
        (out/(variant+'-compile.json')).write_text(json.dumps(command,indent=2)+'\n')
        with (out/(variant+'-build.log')).open('w') as log:
            subprocess.run(command,cwd=out,stdout=log,stderr=subprocess.STDOUT,timeout=180,check=True)
        binaries[variant] = binary
    deadline = time.monotonic()+150
    observations = []
    for name,variant,profile in [('before','before','--clock-contract'),
            ('after','after','--clock-contract'),('oracle','after','--oracle-self-test'),
            ('ordinary','after','ordinary'),('file_ordinary','after','file_ordinary'),
            ('fanout','after','fanout')]:
        stage['stage'] = 'execute_'+name
        directory = out/name if name not in binaries else out/(name+'-run')
        directory.mkdir()
        remaining = min(30,deadline-time.monotonic())
        if remaining<=0: raise RuntimeError('Combined runtime deadline exhausted')
        result = execute_benchmark([str(binaries[variant]),profile],directory,
                                  runtime_environment(directory,args.dependency_prefix),remaining)
        if result['timed_out'] or result['exit_code'] != (86 if name=='before' else 0):
            raise RuntimeError('Unexpected clock contract exit: '+name)
        text = (directory/'stdout.log').read_text(encoding='utf-8')
        values = {}
        if profile=='--clock-contract':
            lines=[line for line in text.splitlines() if line.startswith('clock_contract ')]
            if len(lines)!=1: raise RuntimeError('Missing clock observation')
            values=dict(x.split('=',1) for x in lines[0].split()[1:])
            expected = 3 if os.name=='nt' else 1
            if int(values['phase_calls'])!=expected or values['monotonic']!='1' or \
                    int(values['polluted_calls'])!=(2*expected if name=='before' else 0):
                raise RuntimeError('Metric hooks or counterfactual did not match')
            if args.native_machine: verify_native(binaries[variant],values,args.native_machine)
        elif profile=='--oracle-self-test':
            if text.strip()!='cost_oracle_self_test=passed': raise RuntimeError('Oracle self-test failed')
        else:
            lines=[line for line in text.splitlines() if line.startswith('evidence_cost ')]
            if len(lines)!=1: raise RuntimeError('Missing workload observation')
            values=dict(x.split('=',1) for x in lines[0].split()[1:])
            if any(values[k]!='1' for k in ('required_pre','required_post','required_command',
                    'recall_consistent','reopen_ok','reopened_query_ok')) or values['dangling_refs']!='0':
                raise RuntimeError('Cost workload correctness failed')
            if profile in ('ordinary','file_ordinary') and any(values['producer_'+k]!='0' for k in
                    ('sqlite_read_bytes','sqlite_write_bytes','sqlite_syncs')):
                raise RuntimeError('Ordinary workload gained persistent I/O')
        observations.append({'case':name,'binary_sha256':digest(binaries[variant]),
                             'execution':result,'values':values})
    (out/'result.json').write_text(json.dumps({'status':'PASS','observations':observations},indent=2)+'\n')
    print(json.dumps({'status':'PASS','cases':len(observations),'native_machine':args.native_machine}))


if __name__=='__main__': main()
