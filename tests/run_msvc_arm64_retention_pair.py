"""Run the pinned 749/751 Windows retention CTest on one MSVC ARM64 runner."""
import argparse
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

REVISIONS = {
    '749': '1ec49f21a50da2cccccdf50b1637298ac55bb673',
    '751': 'ec7f14f5ee5c876269cb5562f0fe30e5a37f39ed',
}
TEST = 'local_evidence_cache_retention'
DEADLINE = 150
WATCHDOG = DEADLINE + 25
MAX_REPORT_INPUT_BYTES = 8 * 1024 * 1024
ARM64 = 0xAA64
EXPECTED_CASES = 59  # Both pinned trees contain 60 entries, one available only in --suite all.
WORK_DATABASES = (
    'local_evidence_cache_write_budget.sqlite',
    'local_evidence_cache_post_context_replay.sqlite',
    'local_evidence_cache_owner_set.sqlite',
    'local_evidence_cache_owner_maximum.sqlite',
    'local_evidence_cache_shared_context_fanout.sqlite',
    'local_evidence_cache_stable_enrichment.sqlite',
)
WORK_FILES = frozenset(db + suffix for db in WORK_DATABASES for suffix in ('', '-wal', '-shm', '-journal'))
CASE_EVENT = re.compile(
    r'^cache-case (begin|ok) suite=retention case=(test_[a-z0-9_]+\([0-9u]*\))'
    r'(?: elapsed_ms=([0-9]{1,12}))?\s*$', re.MULTILINE | re.ASCII)
SUITE_OK = re.compile(r'^cache-suite ok suite=retention cases=([0-9]{1,3})\s*$', re.MULTILINE)


class PairError(RuntimeError):
    pass


EXPECTED_ERRORS = (PairError, OSError, ValueError, KeyError, ET.ParseError, subprocess.TimeoutExpired)


def require(condition, cause):
    if not condition:
        raise PairError(cause)


def safe_error(error):
    result = {'cause': str(error) if isinstance(error, PairError) else type(error).__name__}
    if isinstance(error, OSError):
        result['os_error'] = getattr(error, 'winerror', None) or error.errno
    return result


def windows_api(kernel, name, result_type, *argument_types):
    function = getattr(kernel, name)
    function.argtypes = argument_types
    function.restype = result_type
    return function


class JobAccounting(ctypes.Structure):
    _fields_ = [
        ('times', ctypes.c_int64 * 4), ('page_faults', wintypes.DWORD),
        ('total_processes', wintypes.DWORD), ('active_processes', wintypes.DWORD),
        ('terminated_processes', wintypes.DWORD),
    ]


class JobBasicLimit(ctypes.Structure):
    _fields_ = [
        ('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
        ('flags', wintypes.DWORD), ('min_working_set', ctypes.c_size_t),
        ('max_working_set', ctypes.c_size_t), ('active_limit', wintypes.DWORD),
        ('affinity', ctypes.c_size_t), ('priority', wintypes.DWORD),
        ('scheduling_class', wintypes.DWORD),
    ]


class JobExtendedLimit(ctypes.Structure):
    _fields_ = [
        ('basic', JobBasicLimit), ('io_counters', ctypes.c_uint64 * 6),
        ('process_memory_limit', ctypes.c_size_t), ('job_memory_limit', ctypes.c_size_t),
        ('peak_process_memory', ctypes.c_size_t), ('peak_job_memory', ctypes.c_size_t),
    ]


def wincheck(result):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result


class WinHost:
    def __init__(self):
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        H, D, P, S, B = wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.LPWSTR, wintypes.BOOL
        self.create_job = windows_api(self.kernel, 'CreateJobObjectW', H, P, S)
        self.set_job = windows_api(self.kernel, 'SetInformationJobObject', B, H, ctypes.c_int, P, D)
        self.query_job = windows_api(self.kernel, 'QueryInformationJobObject', B, H, ctypes.c_int, P, D, P)
        self.open_process = windows_api(self.kernel, 'OpenProcess', H, D, B, D)
        self.assign = windows_api(self.kernel, 'AssignProcessToJobObject', B, H, H)
        self.terminate = windows_api(self.kernel, 'TerminateJobObject', B, H, D)
        self.close = windows_api(self.kernel, 'CloseHandle', B, H)
        self.current_process = windows_api(self.kernel, 'GetCurrentProcess', H)
        self.machine = windows_api(self.kernel, 'IsWow64Process2', B, H, P, P)
        self.volume_path = windows_api(self.kernel, 'GetVolumePathNameW', B, S, S, D)
        self.volume_name = windows_api(self.kernel, 'GetVolumeNameForVolumeMountPointW', B, S, S, D)
        self.temp_path = windows_api(self.kernel, 'GetTempPathW', D, D, S)

    def temp_directory(self):
        path = ctypes.create_unicode_buffer(260)  # Mirrors the fixture's MAX_PATH resolver.
        length = wincheck(self.temp_path(len(path), path))
        require(length < len(path), 'win32_temp_path_too_long')
        return Path(path.value).resolve(strict=True)

    def native_machine(self):
        process, native = wintypes.USHORT(), wintypes.USHORT()
        wincheck(self.machine(self.current_process(), ctypes.byref(process), ctypes.byref(native)))
        return native.value

    def volume(self, path):
        mount, name = ctypes.create_unicode_buffer(32768), ctypes.create_unicode_buffer(64)
        wincheck(self.volume_path(str(path), mount, len(mount)))
        wincheck(self.volume_name(mount, name, len(name)))
        return name.value.casefold()

    @contextmanager
    def job(self):
        job = wincheck(self.create_job(None, None))
        try:
            limits = JobExtendedLimit()
            limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            wincheck(self.set_job(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
            yield job
        finally:
            wincheck(self.close(job))

    def track(self, job, pid):
        # PROCESS_SET_QUOTA and PROCESS_TERMINATE are required by the job API.
        process = wincheck(self.open_process(0x0100 | 0x0001, False, pid))
        try:
            wincheck(self.assign(job, process))
        finally:
            wincheck(self.close(process))

    def job_counts(self, job):
        accounting = JobAccounting()
        wincheck(self.query_job(job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None))
        return accounting.total_processes, accounting.active_processes


def ctest_environment(parent, scratch):
    # Match the native gate's EDR override removal and control inherited CTest
    # options. Preserve PATH and the rest of the release gate environment.
    env = {key: value for key, value in parent.items()
           if not key.upper().startswith(('EDR_', 'CTEST_')) and key.upper() not in ('TEMP', 'TMP')}
    env.update(TEMP=str(scratch), TMP=str(scratch))
    return env


def pe_machine(path):
    with path.open('rb') as binary:
        header = binary.read(64)
        require(len(header) == 64 and header[:2] == b'MZ', 'fixture_not_pe')
        binary.seek(struct.unpack_from('<I', header, 60)[0])
        signature = binary.read(6)
    require(len(signature) == 6 and signature[:4] == b'PE\x00\x00', 'fixture_not_pe')
    return struct.unpack_from('<H', signature, 4)[0]


def sha256(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def command_output(command, env=None, cwd=None):
    result = subprocess.run(command, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=30)
    require(result.returncode == 0, 'inventory_or_source_command_failed')
    return result.stdout


def selection(ctest, build):
    return [str(ctest), '--test-dir', str(build), '-C', 'Release', '-R', '^' + TEST + '$']


def inspect_build(build, revision, ctest, env):
    cache = dict(re.findall(r'^([A-Za-z0-9_]+):[A-Z]+=(.*)$',
                            (build / 'CMakeCache.txt').read_text(encoding='utf-8'), re.MULTILINE))
    require(cache.get('CMAKE_BUILD_TYPE') == 'Release' and cache.get('CMAKE_GENERATOR') == 'Ninja',
            'build_is_not_ninja_release')
    source = Path(cache.get('CMAKE_HOME_DIRECTORY', ''))
    require(source.is_absolute(), 'missing_configured_source')
    actual = command_output(['git', 'rev-parse', 'HEAD'], cwd=source).decode('ascii').strip()
    require(actual == revision, 'source_revision_mismatch')
    status = command_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=source)
    require(not status.strip(), 'tracked_source_changed')
    compiler_files = list((build / 'CMakeFiles').glob('*/CMakeCCompiler.cmake'))
    require(len(compiler_files) == 1, 'msvc_metadata_missing_or_ambiguous')
    compiler = compiler_files[0].read_text(encoding='utf-8')
    require('set(CMAKE_C_COMPILER_ID "MSVC")' in compiler, 'build_is_not_msvc')
    compiler_path = re.search(r'set\(CMAKE_C_COMPILER "([^"\n]+)"\)', compiler)
    require(compiler_path is not None, 'msvc_binary_missing')
    version = re.search(r'set\(CMAKE_C_COMPILER_VERSION "([0-9.]+)"\)', compiler)
    require(version is not None, 'msvc_version_missing')
    inventory = json.loads(command_output(selection(ctest, build) + ['--show-only=json-v1'], env))
    tests = inventory.get('tests', [])
    require(len(tests) == 1 and tests[0].get('name') == TEST, 'unexpected_ctest_selection')
    test = tests[0]
    command = test.get('command', [])
    require(len(command) == 3 and command[1:] == ['--suite', 'retention'], 'wrong_suite_entry')
    binary = Path(command[0]).resolve(strict=True)
    require(binary.parent == build / 'tests' and binary.name == 'test_local_evidence_cache_candidate.exe',
            'wrong_fixture_binary')
    properties = {prop['name']: prop['value'] for prop in test.get('properties', [])}
    require(properties.get('TIMEOUT') == DEADLINE, 'ctest_deadline_changed')
    require(Path(properties.get('WORKING_DIRECTORY', '')).resolve() == build, 'ctest_working_directory_changed')
    require(properties.get('RESOURCE_LOCK') == ['local_evidence_cache_fixture'], 'ctest_resource_lock_changed')
    require(not any(properties.get(option) for option in
                    ('DISABLED', 'ENVIRONMENT', 'ENVIRONMENT_MODIFICATION', 'WILL_FAIL', 'FIXTURES_REQUIRED',
                     'FIXTURES_SETUP', 'FIXTURES_CLEANUP', 'PASS_REGULAR_EXPRESSION', 'SKIP_REGULAR_EXPRESSION')),
            'unexpected_ctest_runtime_overrides')
    require(pe_machine(binary) == ARM64, 'fixture_is_not_arm64')
    return binary, {'commit': actual, 'binary_sha256': sha256(binary), 'msvc_version': version[1],
                    'msvc_sha256': sha256(Path(compiler_path[1]))}


def bind_sqlite(dumpbin, binary, pinned, digest):
    imports = command_output([str(dumpbin), '/dependents', str(binary)]).decode('ascii', errors='replace')
    require(re.search(r'^\s*sqlite3\.dll\s*$', imports, re.IGNORECASE | re.MULTILINE),
            'fixture_does_not_import_sqlite3')
    require(not binary.with_name(binary.name + '.local').exists(), 'fixture_dll_redirection_present')
    local = binary.with_name('sqlite3.dll')
    # The app-local copy has precedence in the standard Windows DLL search
    # order. Both copies must come from the same verified Release installation.
    if not local.exists():
        with pinned.open('rb') as source, local.open('xb') as destination:
            shutil.copyfileobj(source, destination)
    require(local.is_file() and not local.is_symlink() and sha256(local) == digest,
            'fixture_app_local_sqlite_mismatch')
    return local


def work_state(build):
    # CTest itself writes its logs and bookkeeping inside Testing.
    state = {}
    for entry in build.iterdir():
        if entry.name == 'Testing':
            continue
        info = entry.lstat()
        state[entry.name] = (info.st_mode, info.st_size, info.st_mtime_ns,
                             getattr(info, 'st_file_attributes', 0))
    return state


def clean_work(build, initial):
    current = work_state(build)
    new_files = set(current) - set(initial)
    require(new_files <= WORK_FILES, 'unexpected_fixture_work_directory_outputs')
    for name in new_files:
        mode, _, _, attributes = current[name]
        require(stat.S_ISREG(mode) and not attributes & 0x0400, 'unsafe_fixture_output_type')
    for name in sorted(new_files):
        (build / name).unlink()
    require(work_state(build) == initial, 'fixture_work_directory_not_restored')
    return len(new_files)


def run_owned(host, args, environment, console):
    # The worker blocks on its pipe until it belongs to the job. CTest and any
    # fixture grandchildren therefore cannot start outside the tracked tree.
    with host.job() as job, console.open('xb') as log:
        worker = subprocess.Popen(
            [sys.executable, '-B', str(Path(__file__).resolve()), '--job-child', *args],
            env=environment, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
        try:
            host.track(job, worker.pid)
            worker.stdin.write(b'1')
            worker.stdin.close()
            try:
                code = worker.wait(timeout=WATCHDOG)
            except subprocess.TimeoutExpired:
                code = None
            total, active = host.job_counts(job)
            tree_exited_at_ctest_exit = active == 0
            if active:
                wincheck(host.terminate(job, 1))
                worker.wait(timeout=5)
                deadline = time.monotonic() + 5
                while active and time.monotonic() < deadline:
                    time.sleep(0.05)
                    _, active = host.job_counts(job)
            return code, not active, tree_exited_at_ctest_exit, total
        finally:
            if worker.poll() is None:
                worker.kill()
                worker.wait(timeout=5)
            if not worker.stdin.closed:
                worker.stdin.close()


def read_bounded(path):
    with path.open('rb') as source:
        result = source.read(MAX_REPORT_INPUT_BYTES + 1)
    require(len(result) <= MAX_REPORT_INPUT_BYTES, 'ctest_output_limit_exceeded')
    return result


def progress(log):
    completed = []
    current = None
    for entry, name, elapsed in CASE_EVENT.findall(log):
        if entry == 'begin':
            require(current is None and not elapsed, 'invalid_case_progress')
            current = name
        else:
            require(current == name and elapsed, 'invalid_case_progress')
            completed.append((name, int(elapsed)))
            current = None
    require(len(completed) <= EXPECTED_CASES, 'unexpected_case_count')
    return {
        'completed': [{'case': name, 'ms': ms} for name, ms in completed],
        'active_case': current,
    }


def classify(code, junit, log, seen=None):
    tests = junit.findall('testcase')
    require(junit.tag == 'testsuite' and len(tests) == 1 and tests[0].get('name') == TEST,
            'unexpected_junit_selection')
    test = tests[0]
    seconds = float(test.get('time', 'nan'))
    require(math.isfinite(seconds) and 0 <= seconds <= WATCHDOG, 'invalid_ctest_timing')
    status = test.get('status')
    failure = test.find('failure')
    message = failure.get('message', '') if failure is not None else ''
    if seen is None:
        seen = progress(log)
    suites = SUITE_OK.findall(log)
    if code == 0:
        require(status == 'run' and failure is None and test.find('skipped') is None and
                suites == [str(EXPECTED_CASES)] and len(seen['completed']) == EXPECTED_CASES and
                seen['active_case'] is None, 'suite_completion_unproven')
        outcome = 'pass'
    elif re.search(r'assertion failed|assertion failure|assertion [^\r\n]{0,150} failed',
                   log, re.IGNORECASE):
        outcome = 'assertion_failure'
    elif (message == 'Timeout' and status == 'fail' and DEADLINE - 1 <= seconds <= DEADLINE + 5 and
          seen['active_case'] is not None and not suites):
        outcome = 'timeout'
    elif seen['active_case'] or seen['completed']:
        outcome = 'fixture_failure'
    else:
        outcome = 'environment_or_fixture_start_failure'
    return {'outcome': outcome, 'ctest_seconds': round(seconds, 3), **seen}


def fingerprint(path):
    if not path.is_file():
        return None
    current = path.stat()
    return current.st_ino, current.st_mtime_ns, current.st_size


def execute_leg(host, build, initial, ctest, binary, sqlite, binding, scratch_root, destination, leg):
    require(work_state(build) == initial, 'fixture_work_directory_differs_from_first_run')
    destination.mkdir()
    scratch = Path(tempfile.mkdtemp(prefix='ret-pair-', dir=scratch_root))
    require(host.volume(scratch) == host.volume(scratch_root), 'fixture_temp_volume_changed')
    require(sha256(binary) == binding['binary_sha256'], 'fixture_binary_changed')
    require(sha256(sqlite) == binding['sqlite_sha256'], 'fixture_app_local_sqlite_mismatch')
    environment = ctest_environment(os.environ, scratch)
    junit = destination / 'ctest.xml'
    console = destination / 'ctest-console.log'
    last_test = build / 'Testing' / 'Temporary' / 'LastTest.log'
    prior = fingerprint(last_test)
    args = selection(ctest, build) + ['--parallel', '1', '--output-on-failure', '--no-tests=error',
                                     '--timeout', str(DEADLINE), '--output-junit', str(junit)]
    started = time.monotonic()
    code, exited, exited_without_cleanup, processes = run_owned(host, args, environment, console)
    leg.update(exit_code=code, wall_seconds=round(time.monotonic() - started, 3),
               processes_seen=processes, process_tree_exited=exited)
    require(exited, 'process_tree_exit_unproven')
    try:
        fresh_log = fingerprint(last_test) not in (None, prior)
        if fresh_log:
            log_bytes = read_bounded(last_test)
            (destination / 'LastTest.log').write_bytes(log_bytes)
            log = log_bytes.decode('utf-8', errors='replace')
            seen = progress(log)
            leg.update(seen)
        require(code is not None, 'ctest_harness_watchdog')
        require(exited_without_cleanup, 'fixture_process_survived_ctest')
        require(fresh_log and junit.is_file(), 'ctest_results_missing_or_stale')
        require(console.stat().st_size <= MAX_REPORT_INPUT_BYTES, 'ctest_output_limit_exceeded')
        leg.update(classify(code, ET.fromstring(read_bounded(junit)), log, seen))
        if leg['outcome'] in ('pass', 'timeout'):
            require(processes >= 3, 'ctest_fixture_process_unproven')
    except EXPECTED_ERRORS as error:
        # Preserve the first failure even if a subsequent cleanup also fails.
        leg['result_failure'] = safe_error(error)
    try:
        leg['work_fixture_files_removed'] = clean_work(build, initial)
        shutil.rmtree(scratch)
        leg['clean_synthetic_state'] = True
    except EXPECTED_ERRORS as error:
        leg['cleanup_failure'] = safe_error(error)
        raise
    require('result_failure' not in leg, 'ctest_result_incomplete')
    require(sha256(binary) == binding['binary_sha256'], 'fixture_binary_changed')
    require(sha256(sqlite) == binding['sqlite_sha256'], 'fixture_app_local_sqlite_mismatch')


def decision(legs):
    outcomes = [leg['outcome'] for leg in legs]
    if len(outcomes) != 4 or any(outcome not in ('pass', 'timeout') for outcome in outcomes):
        return 'inconclusive'
    pair = [outcomes[:2], outcomes[2:][::-1]]
    if pair == [['pass', 'timeout']] * 2:
        return 'candidate_timeout_reproduced'
    if pair == [['timeout', 'pass']] * 2:
        return 'baseline_timeout_reproduced'
    if pair == [['timeout', 'timeout']] * 2:
        return 'both_versions_timeout'
    if pair == [['pass', 'pass']] * 2:
        return 'both_versions_complete'
    return 'order_or_run_variability'


def save_report(output, report):
    temporary = output / 'comparison.tmp'
    temporary.write_text(json.dumps(report, separators=(',', ':')) + '\n', encoding='utf-8')
    temporary.replace(output / 'comparison.json')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-build', type=Path, required=True)
    parser.add_argument('--candidate-build', type=Path, required=True)
    parser.add_argument('--scratch-root', type=Path, required=True)
    parser.add_argument('--sqlite-dll', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(os.name == 'nt', 'native_windows_required')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'test': TEST, 'configuration': 'Release', 'deadline_seconds': DEADLINE,
              'harness_watchdog_seconds': WATCHDOG, 'bindings': {}, 'legs': []}
    stage = 'host'
    leg = None
    try:
        host = WinHost()
        require(host.native_machine() == ARM64, 'native_arm64_host_required')
        ctest = Path(shutil.which('ctest.exe') or '').resolve()
        require(ctest.is_file(), 'ctest_not_found')
        dumpbin = shutil.which('dumpbin.exe')
        require(dumpbin is not None, 'dumpbin_not_found')
        pinned = args.sqlite_dll.resolve(strict=True)
        require(pinned.name.lower() == 'sqlite3.dll' and pe_machine(pinned) == ARM64, 'sqlite_not_arm64')
        sqlite_digest = sha256(pinned)
        report['ctest_sha256'] = sha256(ctest)
        scratch = args.scratch_root.resolve(strict=True)
        formal_temp = (Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
                       if os.environ.get('GITHUB_ACTIONS') == 'true' else host.temp_directory())
        require(scratch.is_dir() and host.volume(scratch) == host.volume(formal_temp),
                'scratch_volume_differs_from_formal_gate')
        builds = {'749': args.baseline_build.resolve(strict=True),
                  '751': args.candidate_build.resolve(strict=True)}
        baseline_volume = host.volume(builds['749'])
        require(builds['749'] != builds['751'] and baseline_volume == host.volume(builds['751']),
                'build_directories_do_not_share_one_volume')
        report.update(native_machine='arm64', same_build_volume=True, same_formal_temp_volume=True,
                      build_and_temp_share_volume=(baseline_volume == host.volume(scratch)))
        binaries, dlls, initial = {}, {}, {}
        for version, build in builds.items():
            stage = 'inspect_' + version
            binaries[version], report['bindings'][version] = inspect_build(
                build, REVISIONS[version], ctest, ctest_environment(os.environ, scratch))
            dlls[version] = bind_sqlite(dumpbin, binaries[version], pinned, sqlite_digest)
            report['bindings'][version].update(sqlite_sha256=sqlite_digest, sqlite_source='app_local_import')
            initial[version] = work_state(build)
            require(not WORK_FILES.intersection(initial[version]), 'preexisting_fixture_work_files')
        stage = 'compare_toolchain'
        require(all(report['bindings']['749'][key] == report['bindings']['751'][key]
                    for key in ('msvc_version', 'msvc_sha256')), 'compiler_identity_mismatch')
        for index, version in enumerate(('749', '751', '751', '749'), 1):
            stage = 'execute_leg'
            leg = {'position': index, 'version': version}
            report['legs'].append(leg)
            require(sha256(ctest) == report['ctest_sha256'], 'ctest_executable_changed')
            execute_leg(host, builds[version], initial[version], ctest, binaries[version], dlls[version],
                        report['bindings'][version], scratch, output / f'{index}-{version}', leg)
            save_report(output, report)
            if leg['outcome'] not in ('pass', 'timeout'):
                break
    except EXPECTED_ERRORS as error:
        report['failure'] = {'stage': stage, **safe_error(error)}
        if leg is not None:
            if 'outcome' in leg:
                leg['ctest_outcome_before_harness_failure'] = leg['outcome']
            leg['outcome'] = 'harness_or_integrity_failure'
    report['decision'] = decision(report['legs'])
    save_report(output, report)
    print(json.dumps(report, separators=(',', ':')))
    return 1 if report['decision'] == 'inconclusive' else 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--job-child':
        sys.exit(subprocess.call(sys.argv[2:], stdin=subprocess.DEVNULL)
                 if sys.stdin.buffer.read(1) == b'1' else 2)
    sys.exit(main())
