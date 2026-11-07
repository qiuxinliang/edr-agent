"""Local runner contracts; native execution and the Win32 API are boundaries."""
import contextlib
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

import run_retention_cost_diagnostic as diagnostic


class WindowsTempOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def resolve(self, value, returned=None):
        def native(capacity, buffer):
            self.assertEqual(capacity, 260)
            buffer.value = value
            return len(value) if returned is None else returned
        api = Mock(side_effect=native)
        library = SimpleNamespace(GetTempPathW=api)
        with patch.object(ctypes, 'WinDLL', return_value=library, create=True) as loader, \
                patch.object(ctypes, 'get_last_error', return_value=5, create=True):
            result = diagnostic.windows_contract_temp_path()
        loader.assert_called_once_with('kernel32', use_last_error=True)
        api.assert_called_once()
        self.assertEqual(api.argtypes, [diagnostic.wintypes.DWORD, diagnostic.wintypes.LPWSTR])
        self.assertEqual(api.restype, diagnostic.wintypes.DWORD)
        return result

    def test_original_win32_owner_not_python_temp_precedence(self):
        with patch.dict(os.environ, {'TEMP': '/wrong-env-temp', 'TMP': '/other-temp'}):
            self.assertEqual(self.resolve(str(self.root)), self.root)

    def test_api_failure_has_no_fallback(self):
        with self.assertRaises(OSError) as failure:
            self.resolve('', 0)
        self.assertEqual(failure.exception.errno, 5)

    def test_truncated_relative_missing_or_non_directory_paths_fail(self):
        file = self.root / 'ordinary-file'
        file.write_bytes(b'not a directory')
        for value, returned in [(str(self.root), 260), ('relative', None),
                                (str(self.root / 'missing'), None), (str(file), None)]:
            with self.subTest(value=value), self.assertRaises((RuntimeError, OSError)):
                self.resolve(value, returned)


class RetentionDiagnosticRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.build = self.root / 'build'
        self.runner_temp = self.root / 'runner-temp'
        self.native_temp = self.root / 'native-temp'
        self.output = self.root / 'output'
        for p in (self.build / 'tests', self.runner_temp, self.native_temp):
            p.mkdir(parents=True)
        self.exe = self.build / 'tests/test_local_evidence_cache_candidate.exe'
        self.exe.write_bytes(b'synthetic native-execution boundary')
        self.env = {'GITHUB_ACTIONS': 'true', 'GITHUB_SHA': 'a' * 40,
                    'RUNNER_TEMP': str(self.runner_temp), 'TEMP': '/incorrect-env-temp',
                    'TMP': '/incorrect-env-tmp', 'EDR_EVIDENCE_CACHE_PATH': 'must-not-inherit'}
        self.result = {'exit_code': 0, 'timed_out': False, 'wall_seconds': 1.25}
        self.calls = []

    def execute(self, argv, directory, env, timeout):
        self.calls.append((argv, directory, dict(env), timeout))
        self.assertEqual(argv, [str(self.exe), '--retention-cost-diagnostic'])
        self.assertEqual(timeout, 150)
        # Real filesystem ownership/copying/binding paths are exercised; only
        # launching the Windows executable is replaced in this host regression.
        (directory / 'stdout.log').write_bytes(b'fixed-stage partial or complete output\n')
        (directory / 'stderr.log').write_bytes(b'')
        (directory / 'execution.json').write_text(json.dumps(self.result), encoding='utf-8')
        (Path(env['TEMP']) / 'retained-synthetic.db').write_bytes(b'synthetic fixture')
        return dict(self.result)

    def run_mode(self, preserve=False, native_error=None, attribution=False):
        argv = ['--build-dir', str(self.build), '--output', str(self.output)]
        if preserve:
            argv.append('--preserve-contract-volumes')
        if attribution:
            argv.append('--sync-attribution')
        with patch.dict(os.environ, self.env, clear=True), \
                patch.object(diagnostic, 'os', SimpleNamespace(name='nt', environ=os.environ)), \
                patch.object(diagnostic, 'windows_contract_temp_path', return_value=self.native_temp,
                             side_effect=native_error) as owner, \
                patch.object(diagnostic, 'execute_benchmark', side_effect=self.execute) as execute, \
                contextlib.redirect_stdout(io.StringIO()):
            diagnostic.main(argv)
        return owner, execute

    def binding(self):
        return json.loads((self.output / 'binding.json').read_text())

    def test_default_remains_single_runner_scratch_and_one_150s_execution(self):
        owner, execute = self.run_mode()
        owner.assert_not_called()
        execute.assert_called_once()
        argv, work, env, timeout = self.calls[0]
        self.assertEqual(work.parent, self.runner_temp)
        self.assertEqual(Path(env['TEMP']), work)
        self.assertEqual(env['TMP'], env['TMPDIR'])
        self.assertNotIn('EDR_EVIDENCE_CACHE_PATH', env)
        binding = self.binding()
        self.assertEqual(binding['scratch'], str(work))
        self.assertEqual(binding['layout_mode'], 'legacy_single_scratch')
        self.assertEqual(binding['binary_sha256'], hashlib.sha256(self.exe.read_bytes()).hexdigest())
        self.assertFalse(binding['sync_attribution'])

    def test_attribution_selects_and_binds_only_the_isolated_executable(self):
        self.exe = self.build / 'tests/test_retention_sync_attribution.exe'
        self.exe.write_bytes(b'isolated SQLite scope probe')
        _, execute = self.run_mode(True, attribution=True)
        execute.assert_called_once()
        binding = self.binding()
        self.assertTrue(binding['sync_attribution'])
        self.assertEqual(binding['binary_name'], self.exe.name)
        self.assertEqual(binding['binary_sha256'], hashlib.sha256(self.exe.read_bytes()).hexdigest())

    def test_missing_attribution_binary_never_falls_back_to_contract(self):
        with self.assertRaisesRegex(SystemExit, 'executable missing'):
            self.run_mode(True, attribution=True)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.output.exists())

    def test_new_mode_preserves_two_roots_and_retains_files(self):
        owner, execute = self.run_mode(True)
        owner.assert_called_once_with()
        execute.assert_called_once()
        _, work, env, _ = self.calls[0]
        temporary = Path(env['TEMP'])
        self.assertEqual(work.parent, self.build)
        self.assertEqual(temporary.parent, self.native_temp)
        self.assertNotEqual(work, temporary)
        self.assertEqual(env['TEMP'], env['TMP'])
        self.assertEqual(env['TEMP'], env['TMPDIR'])
        self.assertNotIn('EDR_EVIDENCE_CACHE_PATH', env)
        self.assertTrue((temporary / 'retained-synthetic.db').exists())
        self.assertTrue((work / 'stdout.log').exists())
        binding = self.binding()
        self.assertEqual(binding['work_directory'], str(work))
        self.assertEqual(binding['temp_directory'], str(temporary))
        self.assertEqual(binding['contract_work_directory'], str(self.build))
        self.assertEqual(binding['contract_temp_directory'], str(self.native_temp))
        self.assertEqual(binding['temp_path_owner'], 'GetTempPathW')
        self.assertFalse(binding['physical_device_identity_proven'])
        self.assertFalse(binding['automatic_retry'])
        self.assertFalse(binding['release_gate_overridden'])
        self.assertEqual(binding['deadline_seconds'], 150)
        for name in ('stdout.log', 'stderr.log', 'execution.json'):
            self.assertEqual((work / name).read_bytes(), (self.output / name).read_bytes())

    def test_failed_temp_owner_stops_before_native_execution_or_directory_creation(self):
        with self.assertRaises(OSError):
            self.run_mode(True, OSError(5, 'native temp owner unavailable'))
        self.assertEqual(self.calls, [])
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.build.glob('retention-cost-work-*')), [])

    def test_native_failure_and_timeout_keep_first_receipts_without_retry(self):
        for exit_code, timed_out in [(7, False), (None, True)]:
            with self.subTest(exit_code=exit_code, timed_out=timed_out):
                self.output = self.root / ('timeout' if timed_out else 'failure')
                self.result.update(exit_code=exit_code, timed_out=timed_out)
                before = len(self.calls)
                with self.assertRaisesRegex(SystemExit, 'did not complete'):
                    self.run_mode(True)
                self.assertEqual(len(self.calls), before + 1)
                binding = self.binding()
                self.assertTrue(Path(binding['work_directory']).is_dir())
                self.assertTrue((Path(binding['temp_directory']) / 'retained-synthetic.db').is_file())
                self.assertEqual(json.loads((self.output / 'execution.json').read_text()), self.result)

    def test_existing_output_is_not_reused_and_no_execution_occurs(self):
        self.output.mkdir()
        (self.output / 'first-failure').write_bytes(b'preserve')
        with self.assertRaises(FileExistsError):
            self.run_mode(True)
        self.assertEqual(self.calls, [])
        self.assertEqual((self.output / 'first-failure').read_bytes(), b'preserve')

    def test_non_windows_ci_is_rejected(self):
        with patch.object(diagnostic, 'os', SimpleNamespace(name='posix', environ=self.env)), \
                self.assertRaisesRegex(SystemExit, 'native Windows CI'):
            diagnostic.main(['--build-dir', str(self.build), '--output', str(self.output)])
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
