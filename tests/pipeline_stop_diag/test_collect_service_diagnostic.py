"""Offline metadata contracts only. No Service or Agent is executed."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'collector', Path(__file__).with_name('collect_service_diagnostic.py'))
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source, self.token = 'a' * 40, 'b' * 32
        self.case = self.root / ('edr-ci-service-' + self.token)
        self.case.mkdir()
        self.out = self.root / ('service-stop-qa-' + self.token)
        self.intent = dict(source_sha=self.source, token=self.token)
        self.result = dict(self.intent, schema='edr.ci-isolated-service-diagnostic.v1',
                           whole_recovery_accepted=False,
                           diagnostic_agent_not_release=True, stop_result=None,
                           diagnostic_accepted=False)
        self.write('intent.json', self.intent)
        self.write('result.json', self.result)

    def write(self, name, value):
        (self.case / name).write_text(json.dumps(value))

    def collect(self):
        return M.collect(self.case, self.out, self.root, self.source, self.token)

    def test_failure_metadata_does_not_read_or_export_raw_logs_or_db(self):
        (self.case / 'agent.log').write_bytes(b'private event body')
        (self.case / 'cache.db').write_bytes(b'private evidence')
        result = self.collect()
        self.assertFalse(result['diagnostic_claimed_accepted'])
        self.assertEqual({p.name for p in self.out.iterdir()},
                         {'intent.json', 'result.json', 'manifest.json'})

    def test_frozen_original_is_preserved_and_cannot_be_promoted(self):
        frozen = dict(schema='edr.ci-service-stop-frozen.v1', wait_ms=45000,
                      observation_can_change_result=False, status='returned_nonzero')
        self.write('stop-result-frozen.json', frozen)
        self.result.update(stop_result=frozen, diagnostic_accepted=True)
        self.write('result.json', self.result)
        with self.assertRaisesRegex(ValueError, 'accepted_without_original_stop_success'):
            self.collect()
        self.assertFalse(self.out.exists())

    def test_frozen_mismatch_refuses(self):
        self.result['stop_result'] = {'status': 'returned_zero'}
        self.write('result.json', self.result)
        with self.assertRaisesRegex(ValueError, 'original_stop_result_mismatch'):
            self.collect()

    def test_completed_diagnostic_keeps_original_bytes_and_limited_scope(self):
        frozen = dict(schema='edr.ci-service-stop-frozen.v1', wait_ms=45000,
                      observation_can_change_result=False, status='returned_zero')
        self.write('stop-result-frozen.json', frozen)
        self.result.update(stop_result=frozen, diagnostic_accepted=True)
        self.write('result.json', self.result)
        result = self.collect()
        self.assertTrue(result['diagnostic_claimed_accepted'])
        self.assertFalse(result['full_service_rollback_accepted'])
        for name in ('intent.json', 'result.json', 'stop-result-frozen.json'):
            self.assertEqual((self.case / name).read_bytes(), (self.out / name).read_bytes())

    def test_aggregate_cap_applies_before_output(self):
        for name in M.ALLOWED:
            value = self.intent if name == 'intent.json' else self.result if name == 'result.json' else {}
            self.write(name, dict(value, padding='x' * 100000))
        with self.assertRaisesRegex(ValueError, 'metadata_total_cap'):
            self.collect()
        self.assertFalse(self.out.exists())

    def test_source_or_scope_change_refuses_before_output(self):
        self.result['source_sha'] = 'c' * 40
        self.write('result.json', self.result)
        with self.assertRaisesRegex(ValueError, 'bound_intent_and_result_required'):
            self.collect()

    def test_oversize_metadata_is_not_read(self):
        (self.case / 'result.json').write_bytes(b' ' * (M.FILE_CAP + 1))
        with self.assertRaisesRegex(ValueError, 'metadata_file_cap'):
            self.collect()

    def test_metadata_symlink_refuses(self):
        (self.case / 'result.json').unlink()
        (self.case / 'result.json').symlink_to(self.case / 'intent.json')
        with self.assertRaisesRegex(ValueError, 'reparse_refused'):
            self.collect()

    def test_duplicate_json_keys_refuse(self):
        (self.case / 'result.json').write_text('{"token":"b","token":"c"}')
        with self.assertRaisesRegex(ValueError, 'duplicate_json_key'):
            self.collect()


if __name__ == '__main__':
    unittest.main()
