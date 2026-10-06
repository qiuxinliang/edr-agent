"""SQLite ownership regression; no TLS, client process or network is mocked
as successful. The deliberately failing baseline client isolates main's
resource lifetime before TemporaryDirectory removes its database files.
"""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "egress_receiver", Path(__file__).with_name("test_egress_tls_receiver.py"))
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


class ReceiverResourcesTest(unittest.TestCase):
    @staticmethod
    def database_only_receiver(root, certificate, database):
        class DatabaseOnly:
            observations = []
            errors = []
            config_receipts = []
            server_port = 1

            def finish(self):
                pass

        server = DatabaseOnly()
        server.database = database
        with contextlib.closing(sqlite3.connect(database)) as db, db:
            db.execute("CREATE TABLE receipt(batch_id TEXT PRIMARY KEY,sha TEXT,observations INTEGER)")
            db.execute("CREATE TABLE p0_association(alert_created INTEGER)")
        return server

    def test_checkpoint_child_failure_is_reported_without_dumping_stderr(self):
        class FailedChild:
            def __init__(self, arguments, *, stdout, stderr, **kwargs):
                stderr.write(b'synthetic TLS check failed: edr_ingest_http_post_heartbeat() == 0\n'
                             b'synthetic TLS check failed: private arbitrary expression\n'
                             b'private arbitrary log content\n')
                stderr.flush()

            def poll(self):
                return 1

        with tempfile.TemporaryDirectory(prefix="edr-receiver-diagnostics-") as temporary, \
             patch.object(receiver, "Receiver", self.database_only_receiver), \
             patch.object(receiver.subprocess, "Popen", FailedChild):
            report = receiver.crash_restart_scenario("unused", Path(temporary))
        self.assertEqual(report["client_exit"], 1)
        self.assertEqual(report["received_requests"], 0)  # No HTTP was performed.
        diagnostic = report["diagnostic"]
        self.assertEqual(diagnostic["stage"], "checkpoint")
        self.assertEqual(diagnostic["error_type"], "RuntimeError")
        self.assertFalse(diagnostic["child_running_at_failure"])
        self.assertEqual(diagnostic["child_exit_at_failure"], 1)
        self.assertEqual(diagnostic["failed_assertions"], ["heartbeat_receipt"])
        self.assertEqual(diagnostic["unknown_assertions"], 1)
        self.assertEqual(len(diagnostic["stderr_sha256"]), 64)
        self.assertNotIn("private arbitrary", json.dumps(report))

    def test_ninth_failure_preserves_first_eight_reports_and_failure_exit(self):
        # Every fake client fails; this checks diagnostic ownership only and
        # never represents mocked HTTP, receipt or crash recovery as success.
        failed_client = subprocess.CompletedProcess([], 1, stdout="", stderr="")
        output = io.StringIO()
        with patch.object(receiver, "openssl_certificates"), \
             patch.object(receiver, "Receiver", self.database_only_receiver), \
             patch.object(receiver.subprocess, "run", return_value=failed_client), \
             patch.object(receiver, "crash_restart_scenario", side_effect=OSError("private detail")), \
             patch("sys.argv", ["receiver", "--client", "unused"]), \
             contextlib.redirect_stdout(output):
            self.assertEqual(receiver.main(), 1)
        report = json.loads(output.getvalue())
        self.assertFalse(report["passed"])
        self.assertEqual(len(report["scenarios"]), 9)
        self.assertTrue(all(item["client_exit"] == 1 for item in report["scenarios"]))
        self.assertEqual(report["scenarios"][-1]["diagnostic"]["stage"], "crash_owner_cleanup")
        self.assertNotIn("private detail", output.getvalue())

    def test_main_closes_sqlite_before_removing_temporary_databases(self):
        original_connect = sqlite3.connect
        opened = []

        class ObservedConnection(sqlite3.Connection):
            closed = False

            def close(self):
                super().close()
                self.closed = True

        def tracked_connect(*args, **kwargs):
            kwargs["factory"] = ObservedConnection
            connection = original_connect(*args, **kwargs)
            opened.append(connection)  # Prevent GC from hiding an unclosed owner.
            return connection

        class CheckedTemporaryDirectory(tempfile.TemporaryDirectory):
            def __exit__(directory, kind, value, traceback):
                unclosed = [connection for connection in opened if not connection.closed]
                try:
                    self.assertEqual(len(unclosed), 0,
                        "main retains SQLite handles when temporary database cleanup begins")
                finally:
                    # A failing regression must itself clean up on Windows.
                    for connection in unclosed:
                        connection.close()
                    super().__exit__(kind, value, traceback)

        class DatabaseOnlyReceiver:
            def __init__(server, root, certificate, database):
                server.database = database
                server.observations = []
                server.errors = []
                server.config_receipts = []
                server.server_port = 1
                with contextlib.closing(original_connect(database)) as db, db:
                    db.execute("CREATE TABLE receipt(batch_id TEXT PRIMARY KEY,sha TEXT,observations INTEGER)")

            def finish(server):
                pass

        failed_client = subprocess.CompletedProcess([], 1, stdout="", stderr="")
        with patch.object(receiver.sqlite3, "connect", tracked_connect), \
             patch.object(receiver.tempfile, "TemporaryDirectory", CheckedTemporaryDirectory), \
             patch.object(receiver, "openssl_certificates"), \
             patch.object(receiver, "Receiver", DatabaseOnlyReceiver), \
             patch.object(receiver.subprocess, "run", return_value=failed_client), \
             patch("sys.argv", ["receiver", "--client", "unused", "--baseline"]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(receiver.main(), 1)  # The baseline remains a failure.
        self.assertEqual(len(opened), 3)
        self.assertTrue(all(connection.closed for connection in opened))


if __name__ == "__main__":
    unittest.main()
