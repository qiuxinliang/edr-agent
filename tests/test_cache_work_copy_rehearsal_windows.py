"""Finite public synthetic Windows tests for the existing cache test EXE.

No baseline or EXE is bundled. Requires a newly built candidate test EXE and an
operator-created secure fixed root. Does not install, enroll, query an endpoint,
or read a production path. Each invocation is one fresh synthetic experiment.
"""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import unittest
import uuid

ROOT = Path(r"C:\EDR_RETENTION_SYNTHETIC_20261017")
CONFIG = None


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def readonly_work(path):
    # Work only. mode=ro observes an existing WAL; process exit is not evidence
    # that WAL is empty. SQLite may create/read SHM here in the approved work.
    # The frozen baseline is never a SQLite input to this consumer.
    if path.name != "work.db" or path.parent.name != "work":
        raise ValueError("work-only readonly consumer")
    path.relative_to(ROOT)
    if path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("reparse work refused")
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)


class SyntheticWorkCopyTests(unittest.TestCase):
    def setUp(self):
        # This is an explicit Windows synthetic runner, not a generic discovery
        # fixture. Discovery must not touch the root or dereference CONFIG=None.
        if CONFIG is None:
            self.skipTest("explicit --synthetic-only runner invocation required; not behavior acceptance")

    def seed(self, invalid_clock=False):
        token = uuid.uuid4().hex
        directory = ROOT / ("copy-rehearsal-" + token)
        directory.mkdir(mode=0o700)
        baseline = directory / "baseline.db"
        fd = os.open(baseline, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(baseline)) as db, db:
            db.execute("CREATE TABLE public_fixture(k INTEGER PRIMARY KEY,v BLOB)")
            db.execute("INSERT INTO public_fixture VALUES(1,?)", (b"public-synthetic-owner",))
            db.execute("CREATE TABLE metrics(minute_unix INTEGER,endpoint_id TEXT,"
                       "metric_name TEXT,value INTEGER,PRIMARY KEY(minute_unix,endpoint_id,metric_name))")
            db.execute("INSERT INTO metrics VALUES(0,'','local_retention_v1_active_ms',?)",
                       ("invalid" if invalid_clock else 123456,))
        self.assertLess(baseline.stat().st_size, 1024 * 1024)
        content = {
            "schema": "edr.test.normal-open-work-copy.v1", "token": token,
            "source_commit": CONFIG.source, "exe_sha256": sha(CONFIG.exe),
            "baseline_sha256": sha(baseline), "baseline_bytes": baseline.stat().st_size,
            "budget_mb": 512, "recent_hours": 72, "selected_hours": 72,
        }
        return token, directory, content

    def invoke(self, token, directory, content, *, raw=None, approval=None):
        data = (json.dumps(content, separators=(",", ":")) if raw is None else raw).encode("ascii")
        with (directory / "manifest.json").open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        before = (sha(directory / "baseline.db"), (directory / "baseline.db").stat())
        result = subprocess.run([str(CONFIG.exe), "--normal-open-work-copy", token,
                                 approval or hashlib.sha256(data).hexdigest()],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=90, check=False)
        self.assertLessEqual(len(result.stdout), 4096)
        self.assertEqual(result.stderr, b"")
        report = json.loads(result.stdout.decode("ascii"))
        self.assertEqual(report["exit_code"], result.returncode)
        self.assertFalse(report["migration_accepted"])
        self.assertFalse(report["owner_semantic_integrity_proven"])
        self.assertFalse(report["physical_peak_measured"])
        self.assertEqual(sha(directory / "baseline.db"), before[0])
        self.assertEqual((directory / "baseline.db").stat().st_ino, before[1].st_ino)
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(Path(str(directory / "baseline.db") + suffix).exists())
        return result.returncode, report

    def test_valid_copy_real_clock_and_public_data(self):
        token, directory, content = self.seed()
        rc, r = self.invoke(token, directory, content)
        self.assertEqual(rc, 0)
        self.assertTrue(r["owner_called"])
        self.assertTrue(r["real_clock_providers"])
        self.assertEqual(r["baseline_before_sha256"], r["baseline_after_sha256"])
        self.assertEqual(r["clock_valid"], 1)
        self.assertGreaterEqual(r["retention_active_ms"], 123456)
        with closing(readonly_work(directory / "work" / "work.db")) as db:
            self.assertEqual(db.execute("SELECT v FROM public_fixture WHERE k=1").fetchone()[0],
                             b"public-synthetic-owner")
            active = db.execute("SELECT value FROM metrics WHERE minute_unix=0 AND endpoint_id=''"
                                " AND metric_name='local_retention_v1_active_ms'").fetchone()[0]
            self.assertGreaterEqual(active, 123456)

    def test_bad_clock_is_failure_not_migration_success(self):
        token, directory, content = self.seed(invalid_clock=True)
        rc, r = self.invoke(token, directory, content)
        self.assertEqual(rc, 1)
        self.assertTrue(r["owner_called"])
        self.assertEqual(r["owner_open_rc"], -1)
        self.assertEqual(r["cause"], "owner_open_failed")
        self.assertEqual(r["clock_valid"], 0)
        with closing(readonly_work(directory / "work" / "work.db")) as db:
            self.assertEqual(db.execute("SELECT v FROM public_fixture WHERE k=1").fetchone()[0],
                             b"public-synthetic-owner")
            self.assertIn("alert_context_protect_until_active_ms",
                          [row[1] for row in db.execute("PRAGMA table_info(p0_candidates)")])

    def test_external_approval_sha_required(self):
        t, d, c = self.seed()
        rc, r = self.invoke(t, d, c, approval="0" * 64)
        self.assertEqual(rc, 2)
        self.assertFalse(r["owner_called"])
        self.assertFalse((d / "work").exists())

    def test_pathlike_or_unbound_arguments_are_refused_before_io(self):
        for token, approval in (("../baseline.db", "0" * 64),
                                ("UNBOUND", "0" * 64),
                                ("0" * 32, "UNBOUND")):
            with self.subTest(token_shape=token):
                out = subprocess.run([str(CONFIG.exe), "--normal-open-work-copy", token, approval],
                                     capture_output=True, timeout=90, check=False)
                self.assertEqual(out.returncode, 2)
                self.assertFalse(json.loads(out.stdout)["owner_called"])

    def test_closed_manifest_negative_cases(self):
        for kind in ("missing", "extra", "duplicate", "wrong_token", "wrong_exe", "wrong_sha",
                     "wrong_size", "oversize", "bool_size", "raise_budget", "lower_hours", "escaped_string"):
            with self.subTest(kind=kind):
                t, d, c = self.seed()
                raw = None
                if kind == "missing": del c["source_commit"]
                elif kind == "extra": c["approved"] = True
                elif kind == "duplicate": raw = json.dumps(c)[:-1] + ',"budget_mb":512}'
                elif kind == "wrong_token": c["token"] = "0" * 32
                elif kind == "wrong_exe": c["exe_sha256"] = "0" * 64
                elif kind == "wrong_sha": c["baseline_sha256"] = "0" * 64
                elif kind == "wrong_size": c["baseline_bytes"] += 1
                elif kind == "oversize": c["baseline_bytes"] = 512 * 1024 * 1024 + 1
                elif kind == "bool_size": c["baseline_bytes"] = True
                elif kind == "raise_budget": c["budget_mb"] = 513
                elif kind == "lower_hours": c["recent_hours"] = 1
                elif kind == "escaped_string": raw = json.dumps(c).replace('"source_commit"', '"source_\\u0063ommit"')
                rc, r = self.invoke(t, d, c, raw=raw)
                self.assertEqual(rc, 2)
                self.assertFalse(r["owner_called"])

    def test_sidecar_refused_without_open(self):
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                t, d, c = self.seed()
                sidecar = Path(str(d / "baseline.db") + suffix)
                # invoke's no-sidecar postcondition is intentionally inapplicable.
                # Use a separate explicit call; existing input remains visible.
                # No deletion or repair is done by the EXE.
                data = json.dumps(c).encode("ascii")
                (d / "manifest.json").write_bytes(data)
                sidecar.write_bytes(b"public synthetic sidecar")
                before = sha(d / "baseline.db")
                out = subprocess.run([str(CONFIG.exe), "--normal-open-work-copy", t,
                                      hashlib.sha256(data).hexdigest()],
                                     capture_output=True, timeout=90, check=False)
                self.assertEqual(out.returncode, 2)
                r = json.loads(out.stdout)
                self.assertFalse(r["owner_called"])
                self.assertEqual(sha(d / "baseline.db"), before)
                self.assertTrue(sidecar.exists())

    def test_existing_work_is_not_overwritten(self):
        t, d, c = self.seed()
        (d / "work").mkdir()
        sentinel = d / "work" / "public-sentinel"
        sentinel.write_bytes(b"unchanged")
        rc, r = self.invoke(t, d, c)
        self.assertEqual(rc, 2)
        self.assertFalse(r["owner_called"])
        self.assertEqual(sentinel.read_bytes(), b"unchanged")

    def test_hardlinked_baseline_is_refused(self):
        t, d, c = self.seed()
        # Extra link is outside the case, but still only in the secure synthetic root.
        link = ROOT / ("synthetic-link-" + uuid.uuid4().hex)
        os.link(d / "baseline.db", link)
        rc, r = self.invoke(t, d, c)
        self.assertEqual(rc, 2)
        self.assertFalse(r["owner_called"])
        self.assertTrue(link.exists())


def main():
    global CONFIG
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--synthetic-only", action="store_true", required=True)
    CONFIG = parser.parse_args()
    if sys.platform != "win32" or not re.fullmatch("[0-9a-f]{40}", CONFIG.source):
        raise SystemExit("requires Windows and exact source identity; no fixture was created")
    for path in (ROOT, CONFIG.exe):
        s = path.lstat()
        if s.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise SystemExit("reparse input refused")
    if not ROOT.is_dir() or not CONFIG.exe.is_file():
        raise SystemExit("requires operator-secured synthetic root and compiled test EXE")
    unittest.main(argv=[sys.argv[0]], verbosity=2)


if __name__ == "__main__":
    main()
