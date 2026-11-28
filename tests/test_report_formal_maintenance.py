"""Check evidence completeness and public report disclosure boundaries."""
import unittest

from report_formal_maintenance import LAYERS, STAGES, report


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
        'events': [{'stage': name, 'status': 'verified', 'detail': 'private fixture detail'} for name in STAGES],
    }


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.layers = dict.fromkeys(LAYERS, 'success')

    def report(self, native):
        return report('arm64', 'scheduled_task', self.layers, native)

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
        result['events'] = result['events'][:STAGES.index(failed)] + [
            {'stage': 'lifecycle', 'status': 'failed', 'detail': 'updater failed with exit code 22'}]
        self.layers['installed_chain'] = 'failure'
        evidence = self.report(result)
        self.assertFalse(evidence['passed'])
        self.assertTrue(evidence['protocol6_materialized_locally'])
        self.assertFalse(evidence['original_updater_execution_verified'])
        self.assertEqual(evidence['stage_outcomes']['old_updater_upgrade'], 2)
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
        self.assertTrue(all(value == 0 for value in evidence['stage_outcomes'].values()))

    def test_older_mock_or_other_architecture_cannot_be_used_as_evidence(self):
        result = raw_summary()
        result.update(legacy_migration_version='3.2.723', architecture='amd64')
        with self.assertRaisesRegex(ValueError, 'does not bind'):
            self.report(result)


if __name__ == '__main__':
    unittest.main()
