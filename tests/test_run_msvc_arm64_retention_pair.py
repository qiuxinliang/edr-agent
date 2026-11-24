import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import run_msvc_arm64_retention_pair as pair


class RetentionPairTests(unittest.TestCase):
    def test_outcome_requires_both_orders_and_consistent_observations(self):
        def decision(*outcomes):
            return pair.decision([{'outcome': outcome} for outcome in outcomes])

        self.assertEqual(decision('pass', 'timeout'), 'inconclusive')
        self.assertEqual(decision('pass', 'timeout', 'timeout', 'pass'), 'candidate_timeout_reproduced')
        self.assertEqual(decision('timeout', 'pass', 'pass', 'timeout'), 'baseline_timeout_reproduced')
        self.assertEqual(decision('pass', 'timeout', 'pass', 'timeout'), 'order_or_run_variability')
        self.assertEqual(decision('pass', 'pass', 'pass', 'pass'), 'both_versions_complete')
        self.assertEqual(decision('timeout', 'timeout', 'timeout', 'timeout'), 'both_versions_timeout')
        self.assertEqual(decision('pass', 'assertion_failure'), 'inconclusive')

    def test_environment_retains_shared_inputs_and_replaces_fixture_temp(self):
        env = pair.ctest_environment(
            {'PATH': 'shared', 'SystemRoot': 'root', 'TMP': 'old', 'Temp': 'old',
             'EDR_CONFIG_FILE': 'ignored', 'ctest_parallel_level': '8'}, 'scratch')
        self.assertEqual(env, {'PATH': 'shared', 'SystemRoot': 'root', 'TEMP': 'scratch', 'TMP': 'scratch'})

    def test_cleanup_restores_only_verified_new_synthetic_work_files(self):
        with tempfile.TemporaryDirectory() as root:
            build = Path(root)
            owner = build / 'build.ninja'
            owner.write_text('existing', encoding='utf-8')
            initial = pair.work_state(build)
            fixture = build / sorted(pair.WORK_FILES)[0]
            fixture.touch()
            (build / 'Testing').mkdir()
            self.assertEqual(pair.clean_work(build, initial), 1)
            self.assertEqual(owner.read_text(encoding='utf-8'), 'existing')
            self.assertEqual(pair.work_state(build), initial)
            fixture.touch()
            unrelated = build / 'unknown.sqlite'
            unrelated.touch()
            with self.assertRaisesRegex(pair.PairError, 'unexpected_fixture_work_directory_outputs'):
                pair.clean_work(build, initial)
            self.assertTrue(fixture.exists())
            self.assertTrue(unrelated.exists())

    def test_progress_rejects_missing_completion_boundary(self):
        with self.assertRaisesRegex(pair.PairError, 'invalid_case_progress'):
            pair.progress('cache-case ok suite=retention case=test_fake() elapsed_ms=1\n')

    @unittest.skipUnless(shutil.which('ctest'), 'CTest is required for native result-format checks')
    def test_real_ctest_junit_distinguishes_timeout_assertion_setup_and_pass(self):
        cases = {
            'pass': (
                'test_first()', 'cache-case ok suite=retention case=test_first() elapsed_ms=3\n'
                'cache-suite ok suite=retention cases=1\n', 'pass'),
            'timeout': ('test_first()', '', 'timeout'),
            'assertion': ('test_first()', 'Assertion failed: synthetic check\n', 'assertion_failure'),
            'setup': (None, '', 'environment_or_fixture_start_failure'),
        }
        ctest = shutil.which('ctest')
        for name, (case, message, expected) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                build = Path(temporary).resolve()
                fixture = build / 'fixture.py'
                fixture.write_text(
                    'import sys, time\n'
                    + (f'print("cache-case begin suite=retention case={case}", flush=True)\n' if case else '')
                    + f'print({message!r}, file=sys.stderr, flush=True)\n'
                    + ('time.sleep(5)\n' if name == 'timeout' else '')
                    + f'sys.exit({0 if name == "pass" else 1})\n',
                    encoding='utf-8')
                (build / 'CTestTestfile.cmake').write_text(
                    f'add_test({pair.TEST} "{Path(sys.executable).as_posix()}" "{fixture.as_posix()}")\n'
                    f'set_tests_properties({pair.TEST} PROPERTIES TIMEOUT 1)\n', encoding='utf-8')
                junit = build / 'ctest.xml'
                command = pair.selection(ctest, build) + ['--output-on-failure', '--no-tests=error',
                                                         '--output-junit', str(junit)]
                if os.name == 'nt':
                    console = build / 'ctest-console.log'
                    with patch.object(pair, 'WATCHDOG', 8):
                        code, exited, clean_exit, processes = pair.run_owned(
                            pair.WinHost(), command, os.environ.copy(), console)
                    output = console.read_bytes()
                    self.assertTrue(exited and clean_exit, output)
                    self.assertGreaterEqual(processes, 3, output)
                else:
                    result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                            capture_output=True, timeout=8, check=False)
                    code, output = result.returncode, result.stdout
                log = (build / 'Testing' / 'Temporary' / 'LastTest.log').read_text(encoding='utf-8')
                with patch.object(pair, 'DEADLINE', 1), patch.object(pair, 'EXPECTED_CASES', 1):
                    outcome = pair.classify(code, ET.parse(junit).getroot(), log)
                self.assertEqual(outcome['outcome'], expected, output)
                self.assertEqual(outcome['active_case'], case if name in ('timeout', 'assertion') else None)
                if name == 'pass':
                    self.assertEqual(outcome['completed'], [{'case': case, 'ms': 3}])


if __name__ == '__main__':
    unittest.main()
