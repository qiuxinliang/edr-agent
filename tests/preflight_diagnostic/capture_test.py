"""Run with python -m unittest discover -p capture_test.py in this directory."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("capture", Path(__file__).with_name("capture.py"))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.install = self.root / "install"
        self.install.mkdir()
        (self.install / "agent.toml").write_bytes(b"# private synthetic configuration\n")
        self.offline = {}
        parser = mock.patch.object(capture, "parse_offline", side_effect=lambda raw: dict(self.offline))
        parser.start()
        self.addCleanup(parser.stop)
        env = mock.patch.dict(os.environ, {"EDR_EVIDENCE_CACHE_PATH": ""})
        env.start()
        self.addCleanup(env.stop)
        budget = mock.patch.object(capture, "FLOOR", 0)
        budget.start()
        self.addCleanup(budget.stop)
        self.args = argparse.Namespace(stage="before", install_dir=self.install,
            probe_root=self.root / "tools", output_root=self.root / "receipt",
            failure="original Setup preflight 12", baseline_exe=self.root / "723.exe",
            stable_copy_on_change=False)

    def before(self):
        return capture.collect(self.args)

    def fake_run(self, root, label, command, cwd, seconds, deadline):
        self.calls.append((label, command, cwd, seconds))
        if label.startswith(("live-", "stable-")):
            value = dict(result=-1, elapsed_ms=201,
                         first_failure=dict(api="sqlite3_step", sqlite_primary_code=5))
            (root / (label + ".stdout")).write_text(json.dumps(value))
        return dict(exit=12 if label == "original-723-cli" else 0, timeout=False)

    def after(self):
        self.args.stage = "after"
        self.calls = []
        with mock.patch.object(capture, "run_logged", side_effect=self.fake_run):
            return capture.collect(self.args)

    def test_before_reads_no_sql_and_starts_no_process(self):
        with mock.patch.object(sqlite3, "connect", side_effect=AssertionError("SQL forbidden")), \
                mock.patch.object(capture.subprocess, "Popen", side_effect=AssertionError("process forbidden")):
            result = self.before()
        self.assertFalse(result["sql_executed"])
        self.assertEqual(set(self.args.output_root.iterdir()), {self.args.output_root / "before.json"})
        self.assertEqual((self.install / "agent.toml").read_bytes(), b"# private synthetic configuration\n")

    def test_loader_defaults_and_path_priority(self):
        default = capture.identify(self.install)
        self.assertEqual(default["effective_budget_mb"], 128)
        self.assertIn("Program Files", default["path"])
        self.offline.update(evidence_cache_path="evidence/from-config.db", evidence_cache_max_size_mb=512)
        value = capture.identify(self.install)
        self.assertEqual(value["path"], str(self.install / "evidence/from-config.db"))
        os.environ["EDR_EVIDENCE_CACHE_PATH"] = "override.db"
        self.assertEqual(capture.identify(self.install)["path"], str(self.install / "override.db"))
        self.offline["evidence_cache_path"] = ""
        os.environ["EDR_EVIDENCE_CACHE_PATH"] = ""
        self.assertEqual(capture.identify(self.install)["path"], str(self.install / "local_evidence_cache.db"))

    def test_budget_matches_loader_including_zero(self):
        for raw, configured, effective in ((0, 0, 128), (512, 512, 512), (True, 128, 128),
                                             (-1, 128, 128), (2**31, 128, 128), ("512", 128, 128)):
            with self.subTest(raw=raw):
                self.offline["evidence_cache_max_size_mb"] = raw
                value = capture.identify(self.install)
                self.assertEqual((value["configured_budget_mb"], value["effective_budget_mb"]),
                                 (configured, effective))

    def test_overlong_config_path_rejected(self):
        self.offline["evidence_cache_path"] = "x" * 1024
        with self.assertRaisesRegex(ValueError, "unsupported configuration path"):
            capture.identify(self.install)

    def test_before_cannot_overwrite(self):
        self.before()
        with self.assertRaises(FileExistsError):
            self.before()

    def test_failures_preserved_and_live_tools_use_exact_path_and_budget(self):
        self.offline.update(evidence_cache_path="controlled.db", evidence_cache_max_size_mb=512)
        self.before()
        result = self.after()
        self.assertEqual(result["first_failure"], self.args.failure)
        self.assertEqual(result["diagnostics"]["original_723_cli"]["exit"], 12)
        self.assertEqual(result["diagnostics"]["trace"]["inspection"]["result"], -1)
        self.assertEqual(result["diagnostics"]["trace"]["inspection"]["first_failure"]["sqlite_primary_code"], 5)
        self.assertEqual([call[3] for call in self.calls], [20, 6, 6])
        self.assertEqual(self.calls[0][1][1:4], ["--storage-space-preflight", "--config", str(self.install / "agent.toml")])
        self.assertEqual(self.calls[1][1][1:], [str(self.install / "controlled.db"), "512"])
        self.assertEqual(self.calls[2][1][1:], self.calls[1][1][1:])
        self.assertTrue(all(call[2] == self.install for call in self.calls))
        self.assertEqual(json.loads((self.args.output_root / "original-failure.json").read_text()),
                         {"reason": self.args.failure})

    def test_changed_config_stops_diagnostics_preserves_original_failure(self):
        self.before()
        (self.install / "agent.toml").write_bytes(b"changed synthetic input")
        result = self.after()
        self.assertEqual(self.calls, [])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["first_failure"], self.args.failure)

    def test_changed_environment_stops_diagnostics(self):
        self.before()
        os.environ["EDR_EVIDENCE_CACHE_PATH"] = "changed.db"
        self.assertEqual(self.after()["status"], "incomplete")
        self.assertEqual(self.calls, [])

    def test_changed_live_file_recorded_before_any_optional_copy(self):
        self.offline["evidence_cache_path"] = "controlled.db"
        self.before()
        (self.install / "controlled.db").write_bytes(b"new committed input")
        result = self.after()
        self.assertTrue(result["live_changed_before_diagnostics"])
        self.assertTrue(result["live_changed"])
        self.assertNotIn("stable_copy", result)

    def test_after_cannot_overwrite(self):
        self.before()
        self.after()
        with self.assertRaisesRegex(ValueError, "retries are disabled"):
            self.after()

    def test_missing_image_retains_original_cause(self):
        self.before()
        self.args.stage = "after"
        result = capture.collect(self.args)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["first_failure"], self.args.failure)
        self.assertEqual(result["diagnostic_error"]["type"], "FileNotFoundError")

    def executable(self, body):
        path = self.root / "producer"
        path.write_text("#!" + sys.executable + "\n" + body)
        path.chmod(0o700)
        return path

    @unittest.skipIf(os.name == "nt", "host process boundary test uses a POSIX shebang")
    def test_process_timeout_and_logs_have_bounds(self):
        root = self.args.output_root
        root.mkdir()
        path = self.executable("import time; print('began',flush=True); time.sleep(10)\n")
        value = capture.run_logged(root, "timeout", [str(path)], self.install, .1, time.monotonic()+2)
        self.assertTrue(value["timeout"])
        self.assertNotEqual(value["exit"], 0)
        self.assertEqual(value["stdout_bytes"], (root / "timeout.stdout").stat().st_size)
        path.write_text("#!" + sys.executable + "\nprint('x'*600000)\n")
        value = capture.run_logged(root, "excess", [str(path)], self.install, 1, time.monotonic()+2)
        self.assertTrue(value["output_limit"])
        self.assertLessEqual((root / "excess.stdout").stat().st_size, capture.LOG_LIMIT)

    def test_reserve_rejects_before_launch(self):
        self.args.output_root.mkdir()
        with mock.patch.object(capture, "FLOOR", 2**63), mock.patch.object(capture.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(ValueError, "disk reserve"):
                capture.run_logged(self.args.output_root, "budget", ["unused"], self.install, 6, time.monotonic()+10)
            popen.assert_not_called()

    def test_before_reserve_rejects_before_any_directory_write(self):
        with mock.patch.object(capture, "FLOOR", 2**63):
            with self.assertRaisesRegex(ValueError, "original disk reserve"):
                self.before()
        self.assertFalse(self.args.output_root.exists())

    def test_scope_rejects_non_ci_non_windows_and_other_installation(self):
        with mock.patch.object(capture.sys, "platform", "darwin"):
            with self.assertRaisesRegex(ValueError, "Windows GitHub Actions"):
                capture.verify_ci_scope(self.args)
        with mock.patch.object(capture.sys, "platform", "win32"), mock.patch.dict(
                os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "qiuxinliang/edr-agent"}):
            with self.assertRaisesRegex(ValueError, "fixed rollback-baseline"):
                capture.verify_ci_scope(self.args)

    def test_consistent_copy_reads_wal_and_preserves_source_and_probe_failure(self):
        if capture.shutil.disk_usage(self.root).free < 2 * 1024**3 + 16 * 1024**2:
            self.skipTest("original 2 GiB backup reserve unavailable")
        source = self.install / "wal.db"
        connection = sqlite3.connect(source)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE fact(value TEXT)")
        connection.execute("INSERT INTO fact VALUES('committed WAL fact')")
        connection.commit()
        previous = {suffix: capture.digest(Path(str(source)+suffix), time.monotonic()+3)
                    for suffix in ("", "-wal")}
        self.args.output_root.mkdir()
        self.args.selected = {"configured_budget_mb": 128}
        self.calls = []
        real_run = capture.run_logged
        def run(root, label, command, cwd, seconds, deadline):
            if label == "backup":
                return real_run(root, label, command, cwd, seconds, deadline)
            return self.fake_run(root, label, command, cwd, seconds, deadline)
        with mock.patch.object(capture, "run_logged", side_effect=run):
            result = capture.stable_copy(self.args, source, self.args.output_root, time.monotonic()+10)
        self.assertTrue(result["completed"])
        self.assertIn("no original-CI causal proof", result["scope"])
        self.assertEqual(result["probes"]["trace"]["inspection"]["result"], -1)
        current = {suffix: capture.digest(Path(str(source)+suffix), time.monotonic()+3) for suffix in previous}
        self.assertEqual(previous, current)
        copied = sqlite3.connect(self.args.output_root / "stable.db")
        try:
            self.assertEqual(copied.execute("SELECT value FROM fact").fetchall(), [("committed WAL fact",)])
        finally:
            copied.close()


if __name__ == "__main__":
    unittest.main()
