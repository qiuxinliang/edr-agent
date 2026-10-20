"""One opt-in CI library backlog experiment; never Service or Agent acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

SLOTS = (128, 1024, 8192)
LOG_CAP = 1024 * 1024
DIRECTORY_CAP = 256 * 1024 * 1024
OVERALL_SECONDS = 270
PARENT_SECONDS = 90
FINALIZE_RESERVE_SECONDS = 5
PRODUCER_PINS = {
    'tests/pipeline_stop_diag/fixture-main.inc':
        ('69b3ebc9191c814b27c50bfe2d51c3fedb5e8b197c57b82492cab97113e12ea1', 'a5d0be60967997b33de8575299765e07b70bd093d7133a1c1638f29f4c2d4c33'),
    'tests/pipeline_stop_diag/windows_parent.inc':
        ('d174c6ead743b6896321509f32b7437885db45b42abd858ea5ccdbf0f532cc20', '9d3937817ba684c021d8b545c1796a57dbef77a5d2950fc14bf89a0b176b35a6'),
}

PARENT_CAUSES = ('combined_log_cap', 'exit_unknown', 'final_fixture_guard', 'final_log_unknown', 'fixture_guard', 'fresh_fixture', 'job_not_naturally_empty', 'job_unknown', 'log_metadata_unknown', 'owned_child_create_assign_resume', 'preflight', 'running', 'shared_work_budget_exhausted', 'wait_unknown', 'worker_deadline', 'worker_complete', 'worker_nonzero')


class ContractError(RuntimeError):
    pass


def need(ok, code):
    if not ok:
        raise ContractError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_int(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def failure_code(error):
    return str(error) if isinstance(error, ContractError) else 'unexpected_' + type(error).__name__


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')
    need(len(raw) <= 65536, 'receipt_metadata_cap')
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'receipt_short_write')
        stream.flush()
        os.fsync(stream.fileno())


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=unique,
        parse_constant=lambda unused: (_ for _ in ()).throw(ContractError('nonfinite_json')))


def take(path, cap=LOG_CAP):
    before = path.stat()
    need(path.is_file() and not path.is_symlink() and 0 <= before.st_size <= cap,
         'fixed_log_size_or_type')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    after = path.stat()
    need((before.st_ino, before.st_size, before.st_mtime_ns) ==
         (after.st_ino, after.st_size, after.st_mtime_ns) and len(raw) == after.st_size,
         'fixed_log_changed_or_oversize')
    return raw


def only(records, kind):
    rows = [row for row in records if row.get('kind') == kind]
    need(len(rows) == 1, 'worker_' + kind + '_inventory')
    return rows[0]


def validate_backlog_extra(records, slots, profile, drain, require_resolved=True):
    offered = only(records, 'pipeline_diag_backlog_input')
    cost = only(records, 'pipeline_diag_backlog_cost')
    state = only(records, 'pipeline_diag_backlog_source_state')
    need(set(offered) == {'kind', 'slots', 'bus_capacity_slots', 'slot_size_bytes',
         'bus_payload_array_bytes', 'cache_budget_mb', 'queue_budget_mb',
         'mixed_type_count_each', 'input_sha256', 'all_input_dispositions_verified'},
         'backlog_input_fields')
    need(type(offered['slots']) is int and offered['slots'] == slots and
         type(offered['bus_capacity_slots']) is int and offered['bus_capacity_slots'] == slots and
         exact_int(offered['slot_size_bytes'], 1) and
         type(offered['bus_payload_array_bytes']) is int and
         offered['bus_payload_array_bytes'] == slots * offered['slot_size_bytes'] and
         type(offered['mixed_type_count_each']) is int and offered['mixed_type_count_each'] == slots // 4 and
         type(offered['cache_budget_mb']) is int and offered['cache_budget_mb'] == 512 and
         type(offered['queue_budget_mb']) is int and offered['queue_budget_mb'] == 512 and
         type(offered['input_sha256']) is str and
         re.fullmatch('[0-9a-f]{64}', offered['input_sha256']) is not None and
         offered['input_sha256'] == drain.get('input_sha256') and
         offered['all_input_dispositions_verified'] is False, 'backlog_input_contract')
    need(set(cost) == {'kind', 'slots', 'elapsed_ns', 'vfs_read_bytes', 'vfs_write_bytes',
         'vfs_syncs', 'thread_cpu_known', 'thread_kernel_100ns', 'thread_user_100ns',
         'thread_cpu_before_error', 'thread_cpu_after_error', 'cpu_counter_regressed', 'scope'},
         'backlog_cost_fields')
    need(type(cost['slots']) is int and cost['slots'] == slots and
         cost['scope'] == 'same_thread_preprocess_main' and
         type(cost['thread_cpu_known']) is bool and type(cost['cpu_counter_regressed']) is bool and
         all(exact_int(cost[key]) for key in ('elapsed_ns', 'vfs_read_bytes', 'vfs_write_bytes', 'vfs_syncs')) and
         all(exact_int(cost[key], 0, (1 << 32) - 1) for key in ('thread_cpu_before_error', 'thread_cpu_after_error')),
         'backlog_cost_contract')
    need(cost['elapsed_ns'] == drain.get('elapsed_ns') and
         all(exact_int(drain.get(key)) and cost[key] <= drain[key]
             for key in ('vfs_read_bytes', 'vfs_write_bytes', 'vfs_syncs')),
         'backlog_cost_drain_relation')
    if cost['thread_cpu_known']:
        need(not cost['cpu_counter_regressed'] and
             cost['thread_cpu_before_error'] == cost['thread_cpu_after_error'] == 0 and
             exact_int(cost['thread_kernel_100ns']) and exact_int(cost['thread_user_100ns']),
             'backlog_known_cpu_contract')
    else:
        need(cost['thread_kernel_100ns'] is None and cost['thread_user_100ns'] is None,
             'backlog_unknown_cpu_not_zero')
    need(set(state) == {'kind', 'slots', 'source_only_retry_pending',
         'source_only_backpressure_failed_delta', 'source_only_retry_capacity_exhausted_delta',
         'source_only_loss_detected', 'source_only_terminal_unhealthy', 'source_only_unhealthy_families',
         'deferred_storage_failures', 'deferred_retry_degraded', 'necessary_source_owners_seeded',
         'necessary_source_bytes_unchanged', 'all_input_dispositions_verified', 'required_owner_unresolved'},
         'backlog_source_state_fields')
    need(type(state['slots']) is int and state['slots'] == slots and
         all(exact_int(state[key]) for key in ('source_only_retry_pending',
             'source_only_backpressure_failed_delta', 'source_only_retry_capacity_exhausted_delta',
             'deferred_storage_failures')) and
         exact_int(state['source_only_unhealthy_families'], 0, (1 << 32) - 1) and
         all(exact_int(state[key], 0, 1) for key in ('source_only_loss_detected',
             'source_only_terminal_unhealthy', 'deferred_retry_degraded')) and
         exact_int(state['necessary_source_owners_seeded'], 1) and
         state['necessary_source_owners_seeded'] == drain['necessary_source_owners_seeded'] and
         state['necessary_source_bytes_unchanged'] is True and
         state['all_input_dispositions_verified'] is False and
         type(state['required_owner_unresolved']) is bool, 'backlog_source_state_contract')
    # A transient backpressure failure may subsequently recover. Cumulative
    # deferred failures lack the pre-seed baseline here; never invent a delta.
    # The source-pinned producer computes the full unresolved predicate.
    resolved = (state['required_owner_unresolved'] is False and
         state['source_only_retry_pending'] == 0 and
         state['source_only_retry_capacity_exhausted_delta'] == 0 and
         state['source_only_loss_detected'] == 0 and state['deferred_retry_degraded'] == 0)
    if require_resolved:
        need(resolved, 'backlog_required_owner_unresolved')
    return dict(input=offered, cost=cost, source_state=state, owner_resolved=resolved)


def validate_worker(records, slots, profile, require_resolved=True):
    # These are the existing default16 validator's observable requirements,
    # specialized only for the explicit backlog N and its additional receipts.
    need(all(type(row) is dict for row in records), 'worker_object_rows')
    drain = only(records, 'pipeline_diag_drain_end')
    complete = only(records, 'pipeline_diag_worker_complete')
    evidence = only(records, 'pipeline_diag_evidence_stop')
    need(all(type(evidence.get(key)) is int and evidence[key] == 0
             for key in ('shutdown_timeouts', 'terminal_unhealthy', 'slots_used')),
         'evidence_worker_stop_unknown_or_unhealthy')
    need(complete.get('cleanup_returned') is True, 'worker_complete')
    need(type(drain.get('slots')) is int and drain['slots'] == slots and
         type(drain.get('completed_slots')) is int and drain['completed_slots'] == slots and
         drain.get('real_ir_ready') is (profile == 'ready') and
         drain.get('real_sqlite') is True and
         exact_int(drain.get('necessary_source_owners_seeded'), 1) and
         drain.get('necessary_source_bytes_unchanged') is True and
         type(drain.get('actions_observed')) is int and drain['actions_observed'] == 0 and
         drain.get('process_evidence_worker_windows_thread_started') is True and
         drain.get('network_transport_initialized') is False and
         drain.get('source_ack_inferred') is False and
         drain.get('ave_initialized') is False and
         drain.get('all_input_dispositions_verified') is False and
         drain.get('stop_set_before_worker') is True and drain.get('loop_returned') is True and
         drain.get('timings_inclusive') is True and
         drain.get('win_actor_branch_compiled') is True, 'worker_isolated_coverage')
    stages = [row for row in records if row.get('kind') == 'pipeline_diag_stage']
    need([row.get('stage') for row in stages] == list(range(1, 40)), 'stage_inventory')
    need(all(all(exact_int(row.get(key)) for key in ('calls', 'inclusive_total_ns', 'max_ns')) and
             row['max_ns'] <= row['inclusive_total_ns'] for row in stages), 'stage_numeric_contract')
    for index in (7, 8, 27, 28):
        need(exact_int(stages[index - 1].get('calls'), 1), 'windows_core_branch_not_entered')
    extra = validate_backlog_extra(records, slots, profile, drain, require_resolved)
    return dict(profile=profile, slots=slots, input_sha256=drain.get('input_sha256'),
                real_ir_ready=profile == 'ready', all_input_dispositions_verified=False,
                necessary_source_owners_seeded=drain['necessary_source_owners_seeded'],
                necessary_seed_owner_bytes_unchanged=True, extra=extra,
                drain={key:drain[key] for key in ('slots', 'completed_slots', 'elapsed_ns',
                    'vfs_read_bytes', 'vfs_write_bytes', 'vfs_syncs', 'stop_set_before_worker',
                    'loop_returned', 'timings_inclusive')},
                stages=[{key:row[key] for key in ('stage','calls','inclusive_total_ns','max_ns')} for row in stages])


def collect_profile(case, slots, code, result):
    streams = result.setdefault('streams', {})
    combined = 0
    bodies = {}
    for name in ('parent.stdout.log', 'parent.stderr.log'):
        raw = take(case / name)
        combined += len(raw)
        need(combined <= LOG_CAP, 'all_group_stream_log_cap')
        streams[name] = dict(bytes=len(raw), sha256=sha(raw))
        bodies[name] = raw
    need(not bodies['parent.stderr.log'], 'unexpected_parent_stderr')
    rows = [parse(line) for line in bodies['parent.stdout.log'].splitlines()]
    parent_keys = {'schema','cause','profile','accepted','child_pid','child_birth_filetime',
        'child_exit_known','child_exit_code','job_natural_zero','termination_attempted',
        'cleanup_verified','parent_deadline_exceeded','elapsed_ms','stdout_bytes','stderr_bytes',
        'fixture_sampled_peak_bytes','fixture_final_sample_bytes','fixture_samples','last_error_diagnostic_only'}
    need(1 <= len(rows) <= 2 and all(type(row) is dict and set(row)==parent_keys for row in rows),
         'parent_object_rows')
    need([row['profile'] for row in rows] == ['ready','missing'][:len(rows)], 'parent_profile_order')
    need(all(row['schema']=='edr.private.pipeline-parent.v1' and row['cause'] in PARENT_CAUSES and
             all(type(row[key]) is bool for key in ('accepted','child_exit_known','job_natural_zero',
                 'termination_attempted','cleanup_verified','parent_deadline_exceeded')) and
             exact_int(row['child_pid'],0,(1<<32)-1) and exact_int(row['child_birth_filetime']) and
             type(row['child_exit_code']) is int and -(1<<31)<=row['child_exit_code']<(1<<31) and
             all(exact_int(row[key]) for key in ('elapsed_ms','stdout_bytes','stderr_bytes',
                 'fixture_sampled_peak_bytes','fixture_final_sample_bytes','fixture_samples','last_error_diagnostic_only'))
             for row in rows), 'parent_closed_fields')
    # The parent is already terminal and these closed numeric rows are valid
    # even when a child needed termination. Preserve that failure boundary
    # before refusing to read any worker streams.
    result['parent_rows'] = rows
    need(all(row.get('cleanup_verified') is True and row.get('job_natural_zero') is True and
             row.get('child_exit_known') is True and row.get('termination_attempted') is False
             for row in rows), 'parent_worker_quiescence_unknown')
    # Hash all available known worker streams even when an early worker fails.
    # Missing streams are recorded as absent, never fabricated empty success.
    for profile in ('ready', 'missing'):
        for stream in ('stdout', 'stderr'):
            name = 'pipeline-stop-' + str(slots) + '-' + profile + '/worker.' + stream + '.log'
            path = case / name
            if profile not in [row['profile'] for row in rows]:
                streams[name] = dict(status='not_read_unproven_worker_quiescence')
                continue
            if not path.exists():
                streams[name] = dict(present=False)
                continue
            raw = take(path)
            combined += len(raw)
            need(combined <= LOG_CAP, 'all_group_stream_log_cap')
            streams[name] = dict(present=True, bytes=len(raw), sha256=sha(raw))
            bodies[name] = raw
    result['combined_stream_bytes'] = combined
    worker_results = result.setdefault('workers', [])
    for profile, row in zip(('ready', 'missing'), rows):
        need(type(row) is dict and row.get('schema') == 'edr.private.pipeline-parent.v1' and
             row.get('profile') == profile and row.get('cause') in ('worker_complete','worker_nonzero'),
             'parent_profile_identity')
        for key in ('child_exit_known', 'job_natural_zero', 'cleanup_verified'):
            need(row.get(key) is True, 'parent_' + key)
        need(row.get('termination_attempted') is False and
             row.get('parent_deadline_exceeded') is False and
             type(row.get('child_exit_code')) is int and
             exact_int(row.get('child_pid'), 1) and
             exact_int(row.get('child_birth_filetime'), 1), 'parent_terminal_contract')
        need(exact_int(row.get('elapsed_ms'), 0, 90000) and
             exact_int(row.get('fixture_sampled_peak_bytes'), 0, DIRECTORY_CAP) and
             exact_int(row.get('fixture_final_sample_bytes'), 0, DIRECTORY_CAP),
             'parent_time_or_directory_guard')
        worker_bodies = {}
        for stream in ('stdout', 'stderr'):
            name = 'pipeline-stop-' + str(slots) + '-' + profile + '/worker.' + stream + '.log'
            need(name in bodies, 'expected_worker_stream_missing')
            raw = bodies[name]
            need(type(row.get(stream + '_bytes')) is int and len(raw) == row[stream + '_bytes'],
                 'parent_stream_length_mismatch')
            worker_bodies[stream] = raw
        records = [parse(line) for line in worker_bodies['stdout'].splitlines()]
        worker_results.append(validate_worker(records, slots, profile, require_resolved=False))
    need(type(code) is int and code == 0, 'parent_exit_nonzero_or_unknown')
    need(len(rows) == 2, 'two_parent_receipts_required')
    need(all(row.get('accepted') is True and row['child_exit_code']==0 and row['cause']=='worker_complete' for row in rows), 'parent_accepted')
    need(all(row['extra']['owner_resolved'] for row in worker_results), 'backlog_required_owner_unresolved')


def profile_identity(identity, slots):
    profile = dict(slots=slots, order=['ready', 'missing'],
                   event_mix=['process_create', 'net_connect', 'file_write', 'file_read'],
                   event_count_each=slots // 4, stop_set_before_worker=True,
                   input_is_synthetic=True, historical_events_replayed=False,
                   all_input_dispositions_verified=False)
    canonical = json.dumps(profile, sort_keys=True, separators=(',', ':')).encode('ascii')
    return dict(identity, slots=slots, input_profile=profile, input_profile_sha256=sha(canonical))


def copy_proofs(repo, case):
    files = (
        ('contract-build/tests/pipeline-stop-generated/SOURCE-TRANSFORM-v2.json', 'source-transform-v2.json'),
        ('contract-build/tests/pipeline-stop-source-closure-Release.txt', 'source-closure-Release.txt'),
    )
    result = {}
    for source, name in files:
        raw = take(repo / source, 131072)
        with (case / name).open('xb') as stream:
            need(stream.write(raw) == len(raw), 'proof_copy_short_write')
            stream.flush()
            os.fsync(stream.fileno())
        need(take(case / name, 131072) == raw, 'proof_copy_bytes_changed')
        result[name] = dict(bytes=len(raw), sha256=sha(raw))
    return result


def run_one(case, exe, identity, slots, deadline, popen, clock):
    case.mkdir(exist_ok=False)
    one = profile_identity(identity, slots)
    save(case / 'intent.json', one)
    started = clock()
    child = None
    code = None
    failure = None
    terminal_known = False
    kill_requested = False
    try:
        with (case / 'parent.stdout.log').open('xb') as output, (case / 'parent.stderr.log').open('xb') as error:
            try:
                child = popen([str(exe), '--backlog' + str(slots)], cwd=case,
                              stdout=output, stderr=error)
                code = child.wait(timeout=min(PARENT_SECONDS, max(0, deadline - clock())))
                terminal_known = child.poll() is not None
            except BaseException as problem:
                failure = 'parent_' + type(problem).__name__
            finally:
                if child is not None and child.poll() is None:
                    try:
                        kill_requested = True
                        child.kill()
                        code = child.wait(timeout=max(0, min(FINALIZE_RESERVE_SECONDS, deadline - clock())))
                        terminal_known = child.poll() is not None
                    except BaseException as problem:
                        failure = failure or 'parent_terminal_unknown_' + type(problem).__name__
    except BaseException as problem:
        failure = failure or failure_code(problem)
    data = {}
    try:
        need(terminal_known, 'parent_terminal_unknown')
        # Killing the parent can close its Job asynchronously. Do not read or
        # parse descendants' streams without the C owner's quiescence receipt.
        need(not kill_requested and failure is None, 'parent_terminal_or_cleanup_unknown')
        collect_profile(case, slots, code, data)
    except BaseException as problem:
        failure = failure or failure_code(problem)
    result = dict(one, status='passed' if failure is None else 'failed_or_unknown',
                  accepted=failure is None, failure=failure,
                  parent_pid=child.pid if child else None, parent_returncode=code,
                  parent_terminal_known=terminal_known, outer_kill_requested=kill_requested,
                  elapsed_seconds=clock() - started, **data)
    save(case / 'receipt.json', result)
    return result


def run_profiles(case, exe, identity, popen=subprocess.Popen, clock=time.monotonic, started=None, proof_repo=None):
    started = clock() if started is None else started
    deadline = started + OVERALL_SECONDS
    case.mkdir(exist_ok=False)
    if proof_repo is not None:
        identity = dict(identity, copied_source_proofs=copy_proofs(proof_repo, case))
    save(case / 'intent.json', dict(identity, profiles=list(SLOTS),
        overall_seconds=OVERALL_SECONDS, finalize_reserve_seconds=FINALIZE_RESERVE_SECONDS,
        complete_parent_window_seconds=PARENT_SECONDS, worker_work_ms=85000,
        parent_total_ms=90000, log_cap_per_group=LOG_CAP,
        log_cap_all_groups=3 * LOG_CAP, directory_cap_per_group=DIRECTORY_CAP,
        directory_cap_all_groups=3 * DIRECTORY_CAP, budget_scope='isolated_ci_only'))
    results = []
    unstarted = []
    first_failure = None
    for index, slots in enumerate(SLOTS):
        if first_failure is not None:
            unstarted.append(dict(slots=slots, reason='prior_profile_failed_or_unknown'))
            continue
        if deadline - FINALIZE_RESERVE_SECONDS - clock() < PARENT_SECONDS:
            first_failure = 'full_next_profile_window_unavailable'
            unstarted.append(dict(slots=slots, reason='not_started_budget'))
            continue
        try:
            result = run_one(case / ('backlog-' + str(slots)), exe, identity, slots,
                             deadline, popen, clock)
        except BaseException as problem:
            result = dict(slots=slots, accepted=False, failure=failure_code(problem),
                          elapsed_seconds=clock() - started)
        results.append(result)
        if not result['accepted']:
            first_failure = result['failure']
    elapsed = clock() - started
    if elapsed > OVERALL_SECONDS:
        first_failure = first_failure or 'overall_deadline_exceeded'
    accepted = first_failure is None and len(results) == 3 and not unstarted
    receipt = dict(identity, accepted=accepted, failure=first_failure,
        started_profiles=[result['slots'] for result in results], not_started=unstarted,
        profile_outcomes=[dict(slots=result['slots'], accepted=result['accepted'],
            failure=result['failure'], elapsed_seconds=result['elapsed_seconds']) for result in results],
        elapsed_seconds=elapsed, overall_seconds=OVERALL_SECONDS,
        real_service_or_endpoint_executed=False, full_agent_acceptance=False,
        shutdown_rollback_proven=False, historical_events_replayed=False)
    save(case / 'receipt.json', receipt)
    return receipt


def main(argv=None):
    started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--arch', choices=('arm64',), required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--run-attempt', required=True)
    args = parser.parse_args(argv)
    need(re.fullmatch('[0-9a-f]{40}', args.source_sha) is not None, 'source_identity')
    need(re.fullmatch('[1-9][0-9]{0,19}', args.run_id) is not None and
         re.fullmatch('[1-9][0-9]{0,8}', args.run_attempt) is not None, 'run_identity')
    exe = args.repo / 'contract-build/tests/test_preprocess_stop_boundary.exe'
    raw = take(exe, 64 * 1024 * 1024)
    sources = ['tests/pipeline_stop_diag/fixture-main.inc',
               'tests/pipeline_stop_diag/windows_parent.inc',
               'tests/pipeline_stop_diag/generate_diagnostic_source.py',
               'tests/pipeline_stop_diag/Target.cmake']
    pins = {name: sha(take(args.repo / name)) for name in sources}
    need(all(pins[name] in values for name, values in PRODUCER_PINS.items()),
         'backlog_producer_source_pin')
    identity = dict(schema='edr.ci-pipeline-backlog-profiles.v1',
        source_sha=args.source_sha, run_id=args.run_id, run_attempt=args.run_attempt,
        arch=args.arch, exe_sha256=sha(raw), source_pins=pins, automatic_retry=False,
        production_binary_executed=False, service_or_endpoint_executed=False,
        network_transport_initialized=False, ave_initialized=False,
        real_sqlite=True, ir_profiles=['ready', 'missing'],
        process_evidence_windows_worker=True, test_policy_deny_hook=True,
        complete_agent_or_recovery_acceptance=False)
    result = run_profiles(args.case, exe, identity, started=started, proof_repo=args.repo)
    print(json.dumps({key: result[key] for key in ('accepted', 'failure', 'started_profiles', 'not_started')},
                     sort_keys=True), flush=True)
    return 0 if result['accepted'] else 1


if __name__ == '__main__':
    try:
        exit_code = main()
    except BaseException as problem:
        print(json.dumps(dict(accepted=False, failure=failure_code(problem)), sort_keys=True), flush=True)
        exit_code = 1
    raise SystemExit(exit_code)
