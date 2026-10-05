"""SQLite ownership regression; no TLS, client process or network is mocked
as successful. The deliberately failing baseline client isolates main's
resource lifetime before TemporaryDirectory removes its database files.
"""
import contextlib
import importlib.util
import io
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
