"""Export only allow-listed numeric/boolean status from a disposable hosted run."""
import argparse
import json
from pathlib import Path
import re


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
)
EXIT_CODE = re.compile(r'\b(?:exit code |exit=)(-?\d{1,10})\b')
STORAGE_CAUSE = (
    'cache_owner_open', 'cache_owner_write', 'cache_query_target_not_found',
    'queue_owner_open', 'queue_owner_write', 'queue_readback_missing',
    'persisted_wire_changed', 'legacy_candidate_admission',
)


def native_status(native, architecture, mode):
    if native is None:
        return {}, False, 0, 0, 0
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
            detail = event.get('detail') or ''
            code = EXIT_CODE.search(detail)
            if code:
                exit_code = int(code.group(1))
            for index, cause in enumerate(STORAGE_CAUSE, 1):
                if 'cause='+cause in detail:
                    storage_cause = index
                    break
    passed = native.get('status') == 'succeeded' and all(statuses.get(stage) == 1 for stage in STAGES)
    return statuses, passed, failure_line, exit_code, storage_cause


def report(architecture, mode, layers, native):
    outcomes = {name: STATES.get(layers.get(name), 0) for name in LAYERS}
    stages, passed, line, exit_code, storage_cause = native_status(native, architecture, mode)
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
        'first_native_failure_stage': next((i for i, name in enumerate(STAGES, 1) if stages.get(name) == 2), 0),
        'failure_line': line,
        'reported_exit_code': exit_code,
        'storage_cause_code': storage_cause,
        'protocol6_materialized_locally': stages.get('baseline-local-updater') == 1,
        'original_updater_execution_verified': stages.get('old-updater-upgrade') == 1,
        'platform_capability_receipt_observed': False,
        'platform_signed_command_delivery_observed': False,
        'passed': passed,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--mode', choices=('service', 'scheduled_task'), required=True)
    parser.add_argument('--native-summary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('outcomes', nargs=len(LAYERS))
    args = parser.parse_args()
    native = None
    if args.native_summary.is_file():
        with args.native_summary.open(encoding='utf-8') as stream:
            native = json.load(stream)
    layers = dict(zip(LAYERS, args.outcomes))
    result = report(args.arch, args.mode, layers, native)
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
