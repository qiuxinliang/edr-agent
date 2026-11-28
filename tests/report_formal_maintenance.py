"""Export only allow-listed numeric/boolean status from a disposable hosted run."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess


STATES = {'skipped': 0, 'success': 1, 'failure': 2, 'cancelled': 3}
LAYERS = ('runner', 'admission', 'publisher', 'compiler', 'p0_inputs', 'p0_verification',
          'cache_key', 'cache_restore', 'dependencies', 'storage_tools', 'p0_cleanup',
          'installed_chain')
STAGES = (
    'install-legacy-migration-baseline',
    'legacy-seed',
    'legacy-installed',
    'migrate-legacy-full-setup',
    'migrated-baseline',
    'baseline-local-updater',
    'old-updater-upgrade',
    'updater-target',
    'updater-target-append',
    'updater-target-new-data',
    'rollback-formal-baseline',
    'rollback-formal-baseline-data',
    'rollback-formal-legacy',
    'rollback-formal-legacy-data',
    'uninstall-formal-recovered-source',
    # These positions are public report IDs; append new stages.
    'native-admission',
)
ADMISSION_STATUS_SCHEMA = 'edr.formal-maintenance-admission-status.v1'
EXIT_CODE = re.compile(r'\b(?:exit code |exit=)(-?\d{1,10})\b')
STORAGE_CAUSE = (
    'cache_owner_open', 'cache_owner_write', 'cache_query_target_not_found',
    'queue_owner_open', 'queue_owner_write', 'queue_readback_missing',
    'persisted_wire_changed', 'legacy_candidate_admission',
)
SEED_TIMEOUT_STEPS = (
    ('initial-config', 20),
    ('legacy-seed-stop', 35),
    ('legacy-seed-cache-seed', 20),
    ('legacy-seed-queue-seed', 20),
    ('legacy-seed-restart', 35),
)
RUNTIME_ACTION_PHASES = (
    'engine_enter', 'get_owner_begin', 'get_owner_returned',
    'owner_action_enter', 'owner_action_returned', 'wait_completed',
)
WINDOWS_HOST = os.name == 'nt'


def admission_failure_code(path):
    if path is None:
        return 0
    try:
        if not path.is_file():
            return 0
        with path.open('rb') as stream:
            raw = stream.read(1025)
        if len(raw) > 1024:
            return 0
        status = json.loads(raw)
    except (OSError, ValueError):
        return 0
    if (not isinstance(status, dict) or set(status) != {'schema', 'cause_code'}
            or status['schema'] != ADMISSION_STATUS_SCHEMA):
        return 0
    code = status['cause_code']
    return code if type(code) is int and 0 <= code <= 7 else 0


def native_status(native, architecture, mode):
    if native is None:
        return {}, False, 0, 0, 0, ''
    if (native.get('schema') != 'edr.agent.setup-exe.lifecycle.v1'
            or native.get('formal_maintenance_validation') is not True
            or native.get('architecture') != architecture
            or native.get('runtime_mode') != mode
            or native.get('legacy_migration_version') != '3.2.687'
            or native.get('baseline_version') != '3.2.752'
            or native.get('target_version') != '3.2.753'):
        raise ValueError('native summary does not bind the requested maintenance chain')
    statuses = {}
    exit_code = failure_line = storage_cause = 0
    detail = ''
    for event in native['events']:
        name, status = event.get('stage'), event.get('status')
        if name in STAGES and status == 'verified':
            statuses[name] = 1
        if name == 'lifecycle' and status == 'failed':
            last = native.get('last_stage')
            if last in STAGES:
                statuses[last] = 2
            line = native.get('failure_line')
            if type(line) is int and 0 < line <= 100000:
                failure_line = line
            value = event.get('detail')
            if isinstance(value, str):
                detail = value
            code = EXIT_CODE.search(detail)
            if code:
                exit_code = int(code.group(1))
            for index, cause in enumerate(STORAGE_CAUSE, 1):
                if 'cause='+cause in detail:
                    storage_cause = index
                    break
            break
    # Earlier native receipts did not emit the new admission milestone.
    passed = (native.get('status') == 'succeeded'
              and statuses.get('native-admission', 1) == 1
              and all(statuses.get(stage) == 1 for stage in STAGES if stage != 'native-admission'))
    return statuses, passed, failure_line, exit_code, storage_cause, detail


def has_reparse_attribute(info):
    return bool(getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def runtime_action_phase(native_summary, mode, label):
    if native_summary is None:
        return 0
    summary = native_summary.absolute()
    if summary.name != 'summary.json' or '..' in summary.parts:
        return 0
    trace = summary.parent / 'storage-compat-legacy-updater' / (label+'.stderr.log')
    try:
        for parent in trace.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or has_reparse_attribute(info):
                return 0
        source = summary.lstat()
        info = trace.lstat()
        if (not stat.S_ISREG(source.st_mode) or has_reparse_attribute(source)
                or not stat.S_ISREG(info.st_mode) or has_reparse_attribute(info)
                or not 0 < info.st_size <= 4096):
            return 0
        with trace.open('rb') as stream:
            live = os.fstat(stream.fileno())
            if not os.path.samestat(info, live) or has_reparse_attribute(live):
                return 0
            raw = stream.read(4097)
        if len(raw) != info.st_size:
            return 0
    except OSError:
        return 0

    phases = RUNTIME_ACTION_PHASES if mode == 'service' else (
        'engine_enter', 'owner_action_enter', 'owner_action_returned')
    lines = raw.replace(b'\r\n', b'\n').split(b'\n')
    if lines.pop() != b'' or not 0 < len(lines) <= len(phases):
        return 0
    expected = [('lifecycle_runtime_action phase='+phase).encode('ascii') for phase in phases[:len(lines)]]
    return RUNTIME_ACTION_PHASES.index(phases[len(lines)-1])+1 if lines == expected else 0


def seed_timeout(native, mode, outcome, detail, native_summary):
    if (native is None or outcome != STATES['failure'] or native.get('status') != 'failed'
            or native.get('last_stage') != 'legacy-seed' or mode not in ('service', 'scheduled_task')):
        return 0, 0, 0
    for step, (label, budget) in enumerate(SEED_TIMEOUT_STEPS, 1):
        if detail == f'storage child exceeded its finite deadline: label={label} budget_seconds={budget}':
            phase = runtime_action_phase(native_summary, mode, label) if step in (2, 5) else 0
            return step, budget, phase
    return 0, 0, 0


def service_state_after_timeout(native_summary, evidence):
    outcomes = evidence['layer_outcomes']
    if (not WINDOWS_HOST or evidence['scheduled_task'] or evidence['timeout_step'] != 2
            or evidence['runtime_action_phase'] < 4 or outcomes['runner'] != STATES['success']
            or outcomes['installed_chain'] != STATES['failure']):
        return 0
    expected_environment = {
        'GITHUB_ACTIONS': 'true',
        'GITHUB_EVENT_NAME': 'workflow_dispatch',
        'GITHUB_REPOSITORY': 'qiuxinliang/edr-agent',
        'GITHUB_REF': 'refs/heads/codex/verify-687-752-753-maintenance',
        'RUNNER_ENVIRONMENT': 'github-hosted',
    }
    if any(os.environ.get(key) != value for key, value in expected_environment.items()):
        return 0
    runner_temp = Path(os.environ.get('RUNNER_TEMP', ''))
    expected_summary = runner_temp / 'formal-maintenance-native' / 'summary.json'
    if not runner_temp.is_absolute() or native_summary != expected_summary:
        return 0
    try:
        result = subprocess.run([r'C:\Windows\System32\sc.exe', 'queryex', 'FDSecurityAgent'],
                                capture_output=True, timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        return 0
    if result.returncode or len(result.stdout) > 4096:
        return 0
    states = re.findall(rb'^[ \t]*STATE[ \t]*:[ \t]*([1-7])(?:[ \t]+[A-Z_]+)?[ \t]*\r?$',
                        result.stdout, re.M)
    return int(states[0]) if len(states) == 1 else 0


def report(architecture, mode, layers, native, admission_status=None, native_summary=None):
    outcomes = {name: STATES.get(layers.get(name), 0) for name in LAYERS}
    stages, passed, line, exit_code, storage_cause, detail = native_status(native, architecture, mode)
    step, budget, phase = seed_timeout(native, mode, outcomes['installed_chain'], detail, native_summary)
    passed = passed and all(state == 1 for state in outcomes.values())
    return {
        'report_version': 1,
        'native_architecture': {'amd64': 0x8664, 'arm64': 0xaa64}[architecture],
        'scheduled_task': mode == 'scheduled_task',
        'legacy_build': 687,
        'baseline_build': 752,
        'target_build': 753,
        'layer_outcomes': outcomes,
        'stage_outcomes': {name.replace('-', '_'): stages.get(name, 0) for name in STAGES},
        'first_failed_layer': next((i for i, name in enumerate(LAYERS, 1) if outcomes[name] in (2, 3)), 0),
        'admission_cause_code': admission_failure_code(admission_status) if outcomes['admission'] == 2 else 0,
        'first_native_failure_stage': next((i for i, name in enumerate(STAGES, 1) if stages.get(name) == 2), 0),
        'failure_line': line,
        'reported_exit_code': exit_code,
        'storage_cause_code': storage_cause,
        'timeout_step': step,
        'timeout_budget_seconds': budget,
        'runtime_action_phase': phase,
        'service_state_after_timeout': 0,
        'protocol6_materialized_locally': stages.get('baseline-local-updater') == 1,
        'original_updater_execution_verified': stages.get('old-updater-upgrade') == 1,
        'platform_capability_receipt_observed': False,
        'platform_signed_command_delivery_observed': False,
        'phase2_retirement_storage_exercised': False,
        'passed': passed,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--mode', choices=('service', 'scheduled_task'), required=True)
    parser.add_argument('--native-summary', type=Path, required=True)
    parser.add_argument('--admission-status', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('outcomes', nargs=len(LAYERS))
    args = parser.parse_args()
    native = None
    if args.native_summary.is_file():
        with args.native_summary.open(encoding='utf-8') as stream:
            native = json.load(stream)
    layers = dict(zip(LAYERS, args.outcomes))
    result = report(args.arch, args.mode, layers, native, args.admission_status, args.native_summary)
    result['service_state_after_timeout'] = service_state_after_timeout(args.native_summary, result)
    text = json.dumps(result, indent=2)+'\n'
    args.output.write_text(text, encoding='utf-8')
    print(text, end='')
    fail = result['first_native_failure_stage']
    if fail:
        print('Native maintenance failed at '+STAGES[fail-1])
    code = result['storage_cause_code']
    if code:
        print('Storage owner failure '+STORAGE_CAUSE[code-1])
    if layers['installed_chain'] == 'success' and not result['passed']:
        raise SystemExit('Native chain returned success without complete maintenance evidence')


if __name__ == '__main__':
    main()
