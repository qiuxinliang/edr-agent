"""Check evidence completeness and public report disclosure boundaries."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import report_formal_maintenance as exporter
from report_formal_maintenance import LAYERS, STAGES, report


PUBLISHED_STAGES = (
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


def raw_summary(last_stage='uninstall-formal-recovered-source'):
    return {
        'schema': 'edr.agent.setup-exe.lifecycle.v1',
        'formal_maintenance_validation': True,
        'status': 'succeeded',
        'architecture': 'arm64',
        'runtime_mode': 'scheduled_task',
        'legacy_migration_version': '3.2.687',
        'baseline_version': '3.2.752',
        'target_version': '3.2.753',
        'last_stage': last_stage,
        'events': [{'stage': name, 'status': 'verified', 'detail': 'private fixture detail'}
                   for name in ('native-admission', *PUBLISHED_STAGES)],
    }


def legacy_seed_failure(detail, mode='service'):
    native = raw_summary('legacy-seed')
    native.update(architecture='amd64', runtime_mode=mode, status='failed', failure_line=23)
    native['events'] = native['events'][:2] + [{'stage': 'lifecycle', 'status': 'failed', 'detail': detail}]
    return native


def timeout_detail(label, seconds):
    return f'storage child exceeded its finite deadline: label={label} budget_seconds={seconds}'


def timeout_fields(receipt):
    return tuple(receipt[key] for key in ('timeout_step', 'timeout_budget_seconds', 'runtime_action_phase'))


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.layers = dict.fromkeys(LAYERS, 'success')

    def report(self, native):
        return report('arm64', 'scheduled_task', self.layers, native)

    def report_cli(self, directory, status=None, native=None):
        output = directory / 'public-report.json'
        summary = directory / 'summary.json'
        if native:
            summary.write_text(json.dumps(native), encoding='utf-8')
        args = [sys.executable, '-B', str(Path(__file__).with_name('report_formal_maintenance.py')),
                '--arch', native['architecture'] if native else 'arm64',
                '--mode', native['runtime_mode'] if native else 'scheduled_task',
                '--native-summary', str(summary),
                '--output', str(output)]
        if status is not None:
            args += ['--admission-status', str(status)]
        args += [self.layers[name] for name in LAYERS]
        completed = subprocess.run(args, check=True, text=True, capture_output=True, timeout=10)
        return json.loads(output.read_text(encoding='utf-8')), completed.stdout

    def test_reports_only_numeric_and_boolean_fields_and_local_capability(self):
        result = self.report(raw_summary())
        self.assertTrue(result['passed'])
        self.assertTrue(result['protocol6_materialized_locally'])
        self.assertTrue(result['original_updater_execution_verified'])
        self.assertFalse(result['platform_capability_receipt_observed'])
        self.assertFalse(result['platform_signed_command_delivery_observed'])
        for item in result.values():
            leaves = item.values() if isinstance(item, dict) else (item,)
            self.assertTrue(all(type(value) in (bool, int) for value in leaves))
        self.assertNotIn('private fixture detail', str(result))

    def test_original_failed_stage_preserves_past_and_marks_future_unexecuted(self):
        failed = 'old-updater-upgrade'
        result = raw_summary(failed)
        result.update(status='failed', failure_line=120)
        stop = next(i for i, event in enumerate(result['events']) if event['stage'] == failed)
        result['events'] = result['events'][:stop] + [
            {'stage': 'lifecycle', 'status': 'failed', 'detail': 'updater failed with exit code 22'}]
        self.layers['installed_chain'] = 'failure'
        evidence = self.report(result)
        self.assertFalse(evidence['passed'])
        self.assertTrue(evidence['protocol6_materialized_locally'])
        self.assertFalse(evidence['original_updater_execution_verified'])
        self.assertEqual(evidence['stage_outcomes']['old_updater_upgrade'], 2)
        self.assertEqual(evidence['first_native_failure_stage'], 7)
        self.assertEqual(evidence['stage_outcomes']['rollback_formal_baseline_data'], 0)
        self.assertEqual(evidence['reported_exit_code'], 22)

    def test_succeeded_without_actual_restore_readback_fails_closed(self):
        result = raw_summary()
        result['events'] = [event for event in result['events'] if event['stage'] != 'rollback-formal-legacy-data']
        self.assertFalse(self.report(result)['passed'])

    def test_admission_failure_has_no_native_success(self):
        self.layers.update(admission='failure', publisher='skipped', installed_chain='skipped')
        evidence = self.report(None)
        self.assertFalse(evidence['passed'])
        self.assertEqual(evidence['first_failed_layer'], 2)
        self.assertEqual(evidence['admission_cause_code'], 0)
        self.assertTrue(all(value == 0 for value in evidence['stage_outcomes'].values()))

    def test_public_stage_ids_and_previous_native_receipt_remain_compatible(self):
        self.assertEqual(STAGES, (*PUBLISHED_STAGES, 'native-admission'))
        previous = raw_summary()
        del previous['events'][0]
        evidence = self.report(previous)
        self.assertTrue(evidence['passed'])
        self.assertEqual(evidence['report_version'], 1)
        self.assertEqual(evidence['stage_outcomes']['native_admission'], 0)

        rejected = raw_summary('native-admission')
        rejected.update(status='failed', events=[{'stage': 'lifecycle', 'status': 'failed'}])
        self.layers['installed_chain'] = 'failure'
        evidence = self.report(rejected)
        self.assertEqual(evidence['first_native_failure_stage'], 16)
        self.assertEqual(evidence['stage_outcomes']['install_legacy_migration_baseline'], 0)

    def test_admission_status_reports_two_distinct_rejection_boundaries(self):
        self.layers = dict.fromkeys(LAYERS, 'skipped')
        self.layers.update(runner='success', admission='failure')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            status = directory / 'admission-status.json'
            for cause in (1, 4):
                with self.subTest(cause=cause):
                    status.write_text(json.dumps({
                        'schema': 'edr.formal-maintenance-admission-status.v1',
                        'cause_code': cause,
                    }), encoding='utf-8')
                    evidence, _ = self.report_cli(directory, status)
                    self.assertEqual(evidence['admission_cause_code'], cause)
                    self.assertEqual(evidence['first_failed_layer'], 2)
                    self.assertEqual(evidence['first_native_failure_stage'], 0)
                    self.assertFalse(evidence['passed'])

    def test_missing_or_unrecognized_admission_status_remains_unobserved(self):
        self.layers = dict.fromkeys(LAYERS, 'skipped')
        self.layers.update(runner='success', admission='failure')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            status = directory / 'admission-status.json'
            self.assertEqual(self.report_cli(directory, status)[0]['admission_cause_code'], 0)
            self.assertEqual(self.report_cli(directory)[0]['admission_cause_code'], 0)
            for fields in ({'cause_code': 8}, {'cause_code': True}, {'schema': 'other'},
                           {'private': 'unpublishable fixture detail'}):
                receipt = {'schema': 'edr.formal-maintenance-admission-status.v1', 'cause_code': 1}
                receipt.update(fields)
                status.write_text(json.dumps(receipt), encoding='utf-8')
                evidence, public_output = self.report_cli(directory, status)
                self.assertEqual(evidence['admission_cause_code'], 0)
                self.assertNotIn('unpublishable fixture detail', public_output)

    def test_older_mock_or_other_architecture_cannot_be_used_as_evidence(self):
        result = raw_summary()
        result.update(legacy_migration_version='3.2.723', architecture='amd64')
        with self.assertRaisesRegex(ValueError, 'does not bind'):
            self.report(result)

    def test_observed_service_failure_remains_failed_when_timeout_details_unavailable(self):
        self.layers['installed_chain'] = 'failure'
        native = legacy_seed_failure('')
        evidence = report('amd64', 'service', self.layers, native)
        self.assertEqual(evidence['first_native_failure_stage'], 2)
        self.assertEqual(evidence['failure_line'], 23)
        self.assertEqual(evidence['reported_exit_code'], 0)
        self.assertEqual(evidence['storage_cause_code'], 0)
        self.assertEqual(evidence['stage_outcomes']['install_legacy_migration_baseline'], 1)
        self.assertEqual(evidence['stage_outcomes']['legacy_seed'], 2)
        self.assertEqual(evidence['stage_outcomes']['legacy_installed'], 0)
        self.assertEqual(timeout_fields(evidence), (0, 0, 0))
        self.assertFalse(evidence['passed'])

    def test_successful_task_receipt_does_not_gain_timeout_from_saved_files(self):
        native = raw_summary()
        native['architecture'] = 'amd64'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            traces = directory / 'storage-compat-legacy-updater'
            traces.mkdir()
            (traces / 'legacy-seed-stop.stderr.log').write_text(
                'lifecycle_runtime_action phase=engine_enter\n', encoding='ascii')
            evidence, _ = self.report_cli(directory, native=native)
        self.assertTrue(evidence['passed'])
        self.assertTrue(all(value == 1 for value in evidence['stage_outcomes'].values()))
        self.assertEqual(timeout_fields(evidence), (0, 0, 0))

    def test_exact_timeout_child_and_budget_codes(self):
        self.layers['installed_chain'] = 'failure'
        for step, (label, seconds) in enumerate((
            ('initial-config', 20), ('legacy-seed-stop', 35), ('legacy-seed-cache-seed', 20),
            ('legacy-seed-queue-seed', 20), ('legacy-seed-restart', 35),
        ), 1):
            with self.subTest(label=label):
                native = legacy_seed_failure(timeout_detail(label, seconds))
                result = report('amd64', 'service', self.layers, native)
                self.assertEqual(timeout_fields(result), (step, seconds, 0))

    def test_cache_timeout_wins_even_when_finally_restarts_the_runtime(self):
        self.layers['installed_chain'] = 'failure'
        native = legacy_seed_failure(timeout_detail('legacy-seed-cache-seed', 20))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            traces = directory / 'storage-compat-legacy-updater'
            traces.mkdir()
            (traces / 'legacy-seed-restart.stdout.json').write_text('{"status":"completed"}', encoding='ascii')
            (traces / 'legacy-seed-restart.stderr.log').write_text(''.join(
                f'lifecycle_runtime_action phase={phase}\n' for phase in (
                    'engine_enter', 'get_owner_begin', 'get_owner_returned',
                    'owner_action_enter', 'owner_action_returned', 'wait_completed')), encoding='ascii')
            evidence, _ = self.report_cli(directory, native=native)
            self.assertEqual(timeout_fields(evidence), (3, 20, 0))
            native['events'].append({'stage': 'lifecycle', 'status': 'failed',
                                     'detail': timeout_detail('legacy-seed-restart', 35)})
            evidence, _ = self.report_cli(directory, native=native)
            self.assertEqual(timeout_fields(evidence), (3, 20, 0))

    def test_timeout_must_match_first_failed_seed_event_and_exact_text(self):
        self.layers['installed_chain'] = 'failure'
        good = timeout_detail('legacy-seed-stop', 35)
        for detail in (timeout_detail('not-an-owned-label', 35), timeout_detail('legacy-seed-stop', 20),
                       good+' private-data', 'private-data '+good, good+'\n'):
            with self.subTest(detail=detail):
                native = legacy_seed_failure(detail)
                result = report('amd64', 'service', self.layers, native)
                self.assertEqual(timeout_fields(result), (0, 0, 0))
        native = legacy_seed_failure(good)
        native['last_stage'] = 'baseline-local-updater'
        self.assertEqual(timeout_fields(report('amd64', 'service', self.layers, native)), (0, 0, 0))
        native['last_stage'] = 'legacy-seed'
        self.layers['installed_chain'] = 'success'
        self.assertEqual(timeout_fields(report('amd64', 'service', self.layers, native)), (0, 0, 0))

    def test_action_trace_must_be_from_matching_native_summary_path_and_mode(self):
        self.layers['installed_chain'] = 'failure'
        native = legacy_seed_failure(timeout_detail('legacy-seed-stop', 35))

        def mark(name):
            return b'lifecycle_runtime_action phase=' + name + b'\r\n'

        service_prefix = b''.join(map(mark, (b'engine_enter', b'get_owner_begin', b'get_owner_returned',
                                             b'owner_action_enter')))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            summary_root = directory / 'native-evidence'
            summary_root.mkdir()
            decoy = directory / 'storage-compat-legacy-updater'
            decoy.mkdir()
            (decoy / 'legacy-seed-stop.stderr.log').write_bytes(service_prefix)
            native['install_dir'] = str(directory)
            result, text = self.report_cli(summary_root, native=native)
            self.assertEqual(timeout_fields(result), (2, 35, 0))
            self.assertNotIn(str(directory), text)

            real = summary_root / 'storage-compat-legacy-updater'
            real.mkdir()
            trace = real / 'legacy-seed-stop.stderr.log'
            trace.write_bytes(service_prefix)
            result, _ = self.report_cli(summary_root, native=native)
            self.assertEqual(timeout_fields(result), (2, 35, 4))
            native['runtime_mode'] = 'scheduled_task'
            result, _ = self.report_cli(summary_root, native=native)
            self.assertEqual(timeout_fields(result), (2, 35, 0))
            trace.write_bytes(mark(b'engine_enter') + mark(b'owner_action_enter'))
            result, _ = self.report_cli(summary_root, native=native)
            self.assertEqual(timeout_fields(result), (2, 35, 4))

            for malformed in (b'', b'x' * 4097, mark(b'engine_enter') + b'private-data\n',
                              mark(b'owner_action_enter'), mark(b'engine_enter') * 2, b'\xff'):
                trace.write_bytes(malformed)
                result, text = self.report_cli(summary_root, native=native)
                self.assertEqual(timeout_fields(result), (2, 35, 0))
                self.assertNotIn('private-data', text)
            trace.unlink()
            try:
                trace.symlink_to(decoy / 'legacy-seed-stop.stderr.log')
            except (OSError, NotImplementedError):
                return  # Host privilege for symlink creation is optional.
            native['runtime_mode'] = 'service'
            result, _ = self.report_cli(summary_root, native=native)
            self.assertEqual(timeout_fields(result), (2, 35, 0))

    def test_scm_observation_is_a_scoped_read_only_status_and_preserves_failure(self):
        self.layers['installed_chain'] = 'failure'
        native = legacy_seed_failure(timeout_detail('legacy-seed-stop', 35))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            native_root = directory / 'formal-maintenance-native'
            native_root.mkdir()
            summary = native_root / 'summary.json'
            summary.write_text(json.dumps(native), encoding='utf-8')
            traces = native_root / 'storage-compat-legacy-updater'
            traces.mkdir()
            trace = traces / 'legacy-seed-stop.stderr.log'
            markers = ''.join('lifecycle_runtime_action phase='+phase+'\n' for phase in (
                'engine_enter', 'get_owner_begin', 'get_owner_returned', 'owner_action_enter'))
            trace.write_text(markers, encoding='ascii')
            env = {
                'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'GITHUB_REPOSITORY': 'qiuxinliang/edr-agent',
                'GITHUB_REF': 'refs/heads/codex/verify-687-752-753-maintenance',
                'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_TEMP': str(directory),
                'SystemRoot': r'\\untrusted\Windows',
            }

            def invoke_cli(source):
                public = directory / 'public-report.json'
                argv = ['report_formal_maintenance.py', '--arch', 'amd64', '--mode', 'service',
                        '--native-summary', str(source), '--output', str(public),
                        *(self.layers[name] for name in LAYERS)]
                stdout = StringIO()
                with mock.patch.object(sys, 'argv', argv), redirect_stdout(stdout):
                    exporter.main()
                text = stdout.getvalue()
                self.assertNotIn('987654', text)
                self.assertNotIn('private subprocess stderr', text)
                return json.loads(public.read_text(encoding='utf-8'))

            with mock.patch.object(exporter, 'WINDOWS_HOST', True), mock.patch.dict(exporter.os.environ, env), \
                    mock.patch.object(exporter.subprocess, 'run') as sc:
                sc.return_value = subprocess.CompletedProcess([], 0, b'''
SERVICE_NAME: FDSecurityAgent\r
        STATE              : 3  STOP_PENDING\r
        PID                : 987654\r
''', b'private subprocess stderr')
                evidence = report('amd64', 'service', self.layers, native, native_summary=summary)
                self.assertEqual(evidence['service_state_after_timeout'], 0)
                sc.assert_not_called()
                evidence = invoke_cli(summary)
                self.assertFalse(evidence['passed'])
                self.assertEqual(timeout_fields(evidence), (2, 35, 4))
                self.assertEqual(evidence['service_state_after_timeout'], 3)
                self.assertNotIn('987654', str(evidence))
                self.assertNotIn('private subprocess stderr', str(evidence))
                sc.assert_called_once_with([r'C:\Windows\System32\sc.exe', 'queryex',
                                            'FDSecurityAgent'], capture_output=True, timeout=2)
                for bad in (b'NOT STATE : 3', b'STATE : 8', b'STATE : 3\nSTATE : 4\n'):
                    sc.return_value = subprocess.CompletedProcess([], 0, bad, b'')
                    evidence = invoke_cli(summary)
                    self.assertEqual(evidence['service_state_after_timeout'], 0)
                sc.side_effect = subprocess.TimeoutExpired('sc.exe', 2)
                evidence = invoke_cli(summary)
                self.assertEqual(evidence['service_state_after_timeout'], 0)
                for override in ({'RUNNER_ENVIRONMENT': 'self-hosted'},
                                 {'GITHUB_REF': 'refs/heads/main'}, {'RUNNER_TEMP': 'relative'}):
                    sc.reset_mock()
                    with mock.patch.dict(exporter.os.environ, override):
                        evidence = invoke_cli(summary)
                    self.assertEqual(evidence['service_state_after_timeout'], 0)
                    sc.assert_not_called()
                sc.reset_mock()
                decoy_root = directory / 'runner-unit-test'
                decoy_traces = decoy_root / 'storage-compat-legacy-updater'
                decoy_traces.mkdir(parents=True)
                decoy_summary = decoy_root / 'summary.json'
                decoy_summary.write_text(json.dumps(native), encoding='utf-8')
                (decoy_traces / trace.name).write_bytes(trace.read_bytes())
                evidence = invoke_cli(decoy_summary)
                self.assertEqual(timeout_fields(evidence), (2, 35, 4))
                self.assertEqual(evidence['service_state_after_timeout'], 0)
                sc.assert_not_called()

                trace.write_text(markers.split('lifecycle_runtime_action phase=owner_action_enter')[0],
                                 encoding='ascii')
                evidence = invoke_cli(summary)
                self.assertEqual(timeout_fields(evidence), (2, 35, 3))
                self.assertEqual(evidence['service_state_after_timeout'], 0)
                sc.assert_not_called()


if __name__ == '__main__':
    unittest.main()
