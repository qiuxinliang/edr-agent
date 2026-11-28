"""Check evidence completeness and public report disclosure boundaries."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.layers = dict.fromkeys(LAYERS, 'success')

    def report(self, native):
        return report('arm64', 'scheduled_task', self.layers, native)

    def report_cli(self, directory, status=None):
        output = directory / 'public-report.json'
        args = [sys.executable, '-B', str(Path(__file__).with_name('report_formal_maintenance.py')),
                '--arch', 'arm64', '--mode', 'scheduled_task', '--native-summary', str(directory / 'missing.json'),
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


if __name__ == '__main__':
    unittest.main()
