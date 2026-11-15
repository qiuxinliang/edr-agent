import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("retain_updater", Path(__file__).with_name("retain_updater.py"))
retain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retain)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve()
        self.source = self.repo / "setup-exe-evidence"
        self.source.mkdir()
        self.destination = self.repo / "preflight-diagnostic-evidence" / "updater"
        disk = mock.patch.object(retain.shutil, "disk_usage", return_value=SimpleNamespace(free=10 * 1024**3))
        disk.start()
        self.addCleanup(disk.stop)

    def seed(self):
        for name in retain.FILES:
            (self.source / name).write_bytes(("synthetic " + name).encode())

    def report(self):
        value = retain.retain(self.repo)
        manifest = self.destination / "manifest.json"
        self.assertEqual(json.loads(manifest.read_text()), value)
        self.assertLessEqual(manifest.stat().st_size, retain.MANIFEST_LIMIT)
        self.assertLessEqual(sum(p.stat().st_size for p in self.destination.iterdir()),
                             4 * retain.FILE_LIMIT + retain.MANIFEST_LIMIT)
        return value

    def test_exact_four_files_and_original_hashes(self):
        self.seed()
        (self.source / "unrelated-secret.json").write_text("never read or copy")
        value = self.report()
        self.assertEqual(value["retention_status"], "collected")
        self.assertIsNone(value["first_error"])
        self.assertEqual(value["scope"], "retention only; identity/result not validated")
        self.assertEqual({p.name for p in self.destination.iterdir()}, {*retain.FILES, "manifest.json"})
        for item in value["items"]:
            raw = (self.source / item["name"]).read_bytes()
            self.assertEqual((self.destination / item["name"]).read_bytes(), raw)
            self.assertEqual(item["original_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(item["retained"]["offset"], 0)

    def test_missing_is_explicit(self):
        (self.source / retain.FILES[0]).write_bytes(b"{}")
        value = self.report()
        self.assertEqual(value["retention_status"], "collected_with_gaps")
        self.assertIsNone(value["first_error"])
        self.assertEqual([r["status"] for r in value["items"]], ["retained", "missing", "missing", "missing"])

    def test_missing_source_directory_is_four_missing_files(self):
        self.source.rmdir()
        value = self.report()
        self.assertEqual([r["status"] for r in value["items"]], ["missing"] * 4)

    def test_oversize_json_omitted_and_logs_have_exact_tail_ranges(self):
        raw = b"start" + b"x" * retain.FILE_LIMIT + b"end"
        for name in retain.FILES:
            (self.source / name).write_bytes(raw)
        value = self.report()
        self.assertEqual(value["retention_status"], "collected_with_gaps")
        for item in value["items"]:
            self.assertEqual(item["source"]["bytes"], len(raw))
            self.assertIsNone(item["original_sha256"])
            path = self.destination / item["name"]
            if item["name"].endswith(".json"):
                self.assertEqual(item["status"], "omit_oversize")
                self.assertFalse(path.exists())
            else:
                self.assertEqual(item["status"], "retained_tail")
                self.assertTrue(item["truncated"])
                self.assertEqual(item["retained"]["offset"], len(raw) - retain.FILE_LIMIT)
                self.assertEqual(path.read_bytes(), raw[-retain.FILE_LIMIT:])
                self.assertEqual(item["retained"]["sha256"], hashlib.sha256(raw[-retain.FILE_LIMIT:]).hexdigest())
                self.assertEqual(item["retained"]["hash_scope"], "retained tail")

    def test_exact_limit_is_complete_including_empty_file(self):
        self.seed()
        (self.source / retain.FILES[0]).write_bytes(b"x" * retain.FILE_LIMIT)
        (self.source / retain.FILES[2]).write_bytes(b"")
        value = self.report()
        self.assertEqual(value["retention_status"], "collected")
        self.assertEqual(value["items"][2]["original_sha256"], hashlib.sha256(b"").hexdigest())

    def test_existing_destination_is_never_overwritten(self):
        self.destination.mkdir(parents=True)
        marker = self.destination / "original"
        marker.write_bytes(b"preserved")
        with self.assertRaises(FileExistsError):
            retain.retain(self.repo)
        self.assertEqual(list(self.destination.iterdir()), [marker])
        self.assertEqual(marker.read_bytes(), b"preserved")

    def test_source_change_preserves_completed_item_and_first_error(self):
        self.seed()
        reader = retain.source_bytes
        def mutate(path, original, offset):
            if path.name == retain.FILES[1]:
                path.write_bytes(b"replacement")
            return reader(path, original, offset)
        with mock.patch.object(retain, "source_bytes", side_effect=mutate):
            value = self.report()
        self.assertEqual(value["retention_status"], "failed")
        self.assertEqual(value["first_error"]["file"], retain.FILES[1])
        self.assertEqual([r["status"] for r in value["items"]],
                         ["retained", "error", "not_attempted", "not_attempted"])
        self.assertTrue((self.destination / retain.FILES[0]).exists())
        self.assertFalse((self.destination / retain.FILES[1]).exists())

    def test_permission_failure_is_not_missing_or_success(self):
        self.seed()
        with mock.patch.object(retain, "source_bytes", side_effect=PermissionError(13, "synthetic denial")):
            value = self.report()
        self.assertEqual(value["retention_status"], "failed")
        self.assertEqual(value["first_error"]["type"], "PermissionError")
        self.assertEqual(value["first_error"]["errno"], 13)
        self.assertEqual(value["items"][0]["status"], "error")

    def test_reparse_file_is_rejected_without_read(self):
        path = mock.Mock()
        path.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=1024)
        with self.assertRaisesRegex(ValueError, "reparse"):
            retain.regular_metadata(path)

    def test_write_denial_keeps_first_failure_and_full_source_digest(self):
        self.seed()
        save = retain.save_bytes
        def deny(target, raw):
            if target.name == retain.FILES[1]:
                raise PermissionError(13, "synthetic destination denial")
            return save(target, raw)
        with mock.patch.object(retain, "save_bytes", side_effect=deny):
            value = self.report()
        self.assertEqual(value["retention_status"], "failed")
        self.assertEqual(value["first_error"]["phase"], "destination_write")
        self.assertEqual(value["items"][1]["original_sha256"],
                         hashlib.sha256((self.source / retain.FILES[1]).read_bytes()).hexdigest())
        self.assertTrue((self.destination / retain.FILES[0]).exists())
        self.assertFalse((self.destination / retain.FILES[1]).exists())

    def test_cli_rejects_arbitrary_path_arguments_and_non_ci(self):
        with mock.patch.object(retain.sys, "argv", ["retain_updater.py", "--source", "other"]), \
                mock.patch.object(retain, "retain") as collector:
            with self.assertRaisesRegex(ValueError, "no arbitrary path"):
                retain.main()
            collector.assert_not_called()
        with mock.patch.object(retain.sys, "argv", ["retain_updater.py"]), \
                mock.patch.object(retain.sys, "platform", "darwin"), \
                mock.patch.object(retain, "retain") as collector:
            with self.assertRaisesRegex(ValueError, "fixed Windows synthetic-CI"):
                retain.main()
            collector.assert_not_called()

    def test_disk_floor_writes_failure_manifest_without_copying(self):
        self.seed()
        free = retain.FLOOR + retain.MANIFEST_LIMIT + retain.ALLOCATION_ALLOWANCE
        with mock.patch.object(retain.shutil, "disk_usage", return_value=SimpleNamespace(free=free)), \
                mock.patch.object(retain, "source_bytes") as reader:
            value = self.report()
        self.assertEqual(value["retention_status"], "failed")
        self.assertEqual(value["first_error"]["phase"], "retention_admission")
        reader.assert_not_called()
        self.assertEqual({p.name for p in self.destination.iterdir()}, {"manifest.json"})

    def test_floor_cannot_fit_manifest_creates_nothing(self):
        with mock.patch.object(retain.shutil, "disk_usage", return_value=SimpleNamespace(free=retain.FLOOR)):
            with self.assertRaisesRegex(OSError, "retention manifest"):
                retain.retain(self.repo)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
