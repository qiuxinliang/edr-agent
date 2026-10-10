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
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "egress_receiver", Path(__file__).with_name("test_egress_tls_receiver.py"))
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


class AlertParentProjectionTest(unittest.TestCase):
    """Synthetic oracle inputs only; the real C client owns TLS integration."""
    @staticmethod
    def frame(version, parent=21, state=1, json_parent=Ellipsis):
        def varint(value):
            data = bytearray()
            while value > 127:
                data.append((value & 127) | 128)
                value >>= 7
            return bytes(data + bytes([value]))

        def scalar(tag, value):
            return varint(tag << 3) + varint(value)

        subject = {
            "subject_type": "detection_context",
            "evaluation_basis": {
                "schema": "agent_detection_basis_v1", "owner": "ave_behavior_pipeline",
                "predicate_matched": True, "threshold_met": True,
                "pid": 42, "timestamp_ns": "1700000000000000000",
                "event_count": 1, "last_event_type": 9,
                "behavior_flags": 4294967295, "threshold": 0.8,
                "tactic_probs_computed": False,
            },
            "detection_context": {
                "process": {"pid": 42, "parent_pid": parent},
                "engine": "ave", "rule_id": "behavior_anomaly",
            },
        }
        if json_parent is None:
            del subject["detection_context"]["process"]["parent_pid"]
        elif json_parent is not Ellipsis:
            subject["detection_context"]["process"]["parent_pid"] = json_parent
        encoded = json.dumps(subject, separators=(",", ":")).encode()
        alert = varint(1 << 3 | 5) + struct.pack("<f", 0.9) + \
            scalar(6, 1700000000000000000) + scalar(7, 42) + \
            varint(11 << 3 | 2) + varint(len(encoded)) + encoded
        frame = {4: [70], 5: [1700000000000000000], 6: [42], 40: [alert], 69: [version]}
        if version == 3:
            frame[7], frame[73] = [parent], [state]
        return frame

    def test_frozen_v2_and_known_v3_parent_are_accepted(self):
        self.assertTrue(receiver.is_proven_alert(self.frame(2)))
        self.assertTrue(receiver.is_proven_alert(self.frame(3)))
        integral_json = self.frame(3, parent=21.0)
        integral_json[7] = [21]
        self.assertTrue(receiver.is_proven_alert(integral_json))
        explicit_nested_zero = self.frame(3)
        explicit_nested_zero[40][0] += b"\x60\x00"  # BehaviorAlert.ppid=0 (tag12).
        self.assertTrue(receiver.is_proven_alert(explicit_nested_zero))

    def test_unknown_and_explicit_zero_are_distinct_valid_v3_inputs(self):
        for state in (0, 2, 3):
            with self.subTest(state=state):
                self.assertTrue(receiver.is_proven_alert(self.frame(3, parent=0, state=state)))

    def test_complete_v3_parent_contract_matrix(self):
        accepted = 0
        for state in (None, 0, 1, 2, 3, 4):
            for mode in (0, 1, 2):
                parent = 4242 if mode == 2 else 0
                for alias in (None, 0, 4242, 99):
                    frame = self.frame(3, parent=parent, state=state, json_parent=alias)
                    if state is None:
                        del frame[73]
                    if mode == 0:
                        del frame[7]
                    expected = state is not None and (state == 4 or
                        (parent != 0 if state == 1 else parent == 0)) and (alias is None or alias == parent)
                    with self.subTest(state=state, mode=mode, alias=alias):
                        actual = receiver.is_proven_alert(frame)
                        self.assertEqual(actual, expected)
                        accepted += actual
        self.assertEqual(accepted, 20)

    def test_parent_state_version_and_alias_conflicts_are_rejected(self):
        cases = [self.frame(4), self.frame(3, parent=0, state=1),
                 self.frame(3, state=0), self.frame(3, state=9)]
        old = self.frame(2)
        old[73] = [1]
        cases.append(old)
        missing = self.frame(3)
        del missing[73]
        cases.append(missing)
        alias = self.frame(3)
        alias[7] = [22]
        cases.append(alias)
        duplicate = self.frame(3)
        duplicate[73] = [1, 1]
        cases.append(duplicate)
        nested_conflict = self.frame(3)
        nested_conflict[40][0] += b"\x60\x16"  # BehaviorAlert.ppid=22 (tag12).
        cases.append(nested_conflict)
        nested_duplicate = self.frame(3)
        nested_duplicate[40][0] += b"\x60\x00\x60\x00"
        cases.append(nested_duplicate)
        cases.append(self.frame(3, parent=1 << 32))
        json_boolean = self.frame(3, parent=False, state=0)
        json_boolean[7] = [0]
        cases.append(json_boolean)
        fractional_json = self.frame(3, parent=21.5)
        fractional_json[7] = [21]
        cases.append(fractional_json)
        boolean_state = self.frame(3, parent=0, state=False)
        cases.append(boolean_state)
        for index, frame in enumerate(cases):
            with self.subTest(index=index):
                self.assertFalse(receiver.is_proven_alert(frame))


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

    def test_final_failure_preserves_all_prior_reports_and_failure_exit(self):
        # Every fake client fails; this checks diagnostic ownership only and
        # never represents mocked HTTP, receipt or crash recovery as success.
        failed_client = subprocess.CompletedProcess([], 1, stdout="", stderr="")

        def fail_client_with_unused_signing_fixture(arguments, **kwargs):
            if arguments[0] == "unused":
                return failed_client
            # main now prepares signed-command inputs before invoking the
            # deliberately failing client. These bytes are never verified or
            # sent: this test owns only resource cleanup and failure reports.
            self.assertIn(arguments[1], ("genpkey", "pkey", "pkeyutl"))
            output_path = Path(kwargs["cwd"]) / arguments[arguments.index("-out") + 1]
            output_path.write_bytes(b"unused signing fixture")
            return subprocess.CompletedProcess(arguments, 0)

        original_modes = [
            "positive", "positive-ip", "positive-v2", "wrong-ca", "wrong-host",
            "positive-pmfe", "positive-journal", "positive-p0-journal",
            "positive-command",
        ]
        download_modes = ["positive-update-download-x64", "positive-update-download-arm64",
                          "wrong-update-download-ca", "wrong-update-download-host"]
        for flags, expected_modes in (
            ([], original_modes + download_modes + ["positive-crash-restart"]),
            (["--exclude-update-download"], original_modes + ["positive-crash-restart"]),
            (["--update-download-only"], download_modes),
        ):
            with self.subTest(flags=flags):
                output = io.StringIO()
                with patch.object(receiver, "openssl_certificates"), \
                     patch.object(receiver, "Receiver", self.database_only_receiver), \
                     patch.object(receiver.subprocess, "run", side_effect=fail_client_with_unused_signing_fixture), \
                     patch.object(receiver, "crash_restart_scenario", side_effect=OSError("private detail")), \
                     patch("sys.argv", ["receiver", "--client", "unused", *flags]), \
                     contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(receiver.main(), 1)
                report = json.loads(output.getvalue())
                self.assertFalse(report["passed"])
                self.assertEqual([item["mode"] for item in report["scenarios"]], expected_modes)
                self.assertTrue(all(item["client_exit"] == 1 for item in report["scenarios"]))
                for item in report["scenarios"]:
                    if item["mode"] == "positive-crash-restart":
                        self.assertEqual(item["diagnostic"]["stage"], "crash_owner_cleanup")
                    else:
                        self.assertEqual(item["received_requests"], 0)
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
