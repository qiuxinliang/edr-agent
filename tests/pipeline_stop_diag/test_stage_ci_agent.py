"""Pure failure projection contracts; no service, source-owner IO or subprocesses."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('stage_projection_only',
                                            Path(__file__).with_name('stage_ci_agent.py'))
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)  # __main__ is not entered.


class FailureProjectionTests(unittest.TestCase):
    def test_fixed_value_error(self):
        row = stage.failure_projection(ValueError('dependency_file_count_cap'))
        self.assertEqual(row['cause_code'], 'dependency_file_count_cap')
        self.assertEqual(row['exception_type'], 'builtins.ValueError')
        self.assertIsNone(row['hresult'])

    def test_owner_literal_maps_to_fixed_code(self):
        row = stage.failure_projection(ValueError('dumpbin dependency inspection failed'))
        self.assertEqual(row['cause_code'], 'owner_dumpbin_failed')

    def test_unknown_value_error_text_not_exported(self):
        row = stage.failure_projection(ValueError('private_lowercase_atom'))
        self.assertEqual(row['cause_code'], 'unknown')
        self.assertNotIn('private_lowercase_atom', repr(row))

    def test_non_value_error_never_formats_message(self):
        class NoText(RuntimeError):
            def __str__(self):
                raise AssertionError('exception text must not be formatted')
        row = stage.failure_projection(NoText('private data'))
        self.assertEqual(row['cause_code'], 'unknown')
        self.assertNotIn('private data', repr(row))

    def test_payload_with_multiple_args_not_exported(self):
        row = stage.failure_projection(ValueError('dependency_file_count_cap', 'private'))
        self.assertEqual(row['cause_code'], 'unknown')
        self.assertNotIn('private', repr(row))

    def test_exact_five_key_schema(self):
        row = stage.failure_projection(OSError('private/path'))
        self.assertEqual(set(row), {'schema', 'origin', 'exception_type', 'hresult', 'cause_code'})
        self.assertEqual(row['schema'], 'edr.ci-owned-failure.v1')
        self.assertEqual(row['origin'], 'python_stage')


if __name__ == '__main__':
    unittest.main()
