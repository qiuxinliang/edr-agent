"""Synthetic trees only; the inventory never mutates or reads file contents."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("inventory", Path(__file__).parents[1] / "scripts/evidence_storage_inventory.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InventoryTest(unittest.TestCase):
    def test_all_categories_sparse_hardlink_and_overlap(self):
        with tempfile.TemporaryDirectory(prefix="edr-inventory-") as root:
            names = ["cache.db", "cache.db-wal", "cache.db-shm", "upload_x.pending",
                     "upload_y.pending.done", "upload_z.pending.failed", "archive.tgz",
                     "archive.tgz.tmp.1", "manifest.json", "unclassified.bin"]
            for name in names:
                Path(root, name).write_bytes(b"evidence-fixture")
            sparse = Path(root, "sparse.dmp")
            with sparse.open("wb") as output:
                output.truncate(4 * 1024 * 1024)
            os.link(sparse, Path(root, "hardlink.dmp"))
            report = module.inventory([root, str(sparse)], include_files=True)
            self.assertTrue(report["complete"])
            self.assertEqual(report["duplicate_objects"], 2)
            self.assertEqual(sum(x["apparent_bytes"] for x in report["files"]), report["apparent_bytes"])
            self.assertEqual(sum(x["allocated_bytes"] for x in report["files"]), report["allocated_bytes"])
            self.assertEqual(report["categories"]["outbox_metadata"]["objects"], 3)
            self.assertEqual(report["categories"]["temporary"]["objects"], 1)
            self.assertIn("other", report["categories"])
            self.assertEqual(report["stat_calls"], len(names) + 4)
            print(json.dumps({k: report[k] for k in ("entries", "stat_calls", "apparent_bytes", "allocated_bytes", "elapsed_ms")}))

    def test_unknown_bounded_and_no_links(self):
        with tempfile.TemporaryDirectory(prefix="edr-inventory-") as root:
            Path(root, "file").write_bytes(b"fixture")
            report = module.inventory([root], max_entries=1)
            self.assertFalse(report["complete"])
            self.assertEqual(report["stat_calls"], 1)
            with patch.object(module.os, "stat", side_effect=PermissionError(13, "denied")):
                report = module.inventory([root])
            self.assertFalse(report["complete"])
            self.assertTrue(report["totals_are_lower_bounds"])
            self.assertEqual(report["errors"][0]["reason"], "stat_13")
            if hasattr(os, "symlink") and os.name != "nt":
                os.symlink(root, Path(root, "loop"))
                report = module.inventory([root])
                self.assertFalse(report["complete"])
                self.assertEqual(report["entries"], 3)
                self.assertIn("link_or_reparse_not_followed", [e["reason"] for e in report["errors"]])


if __name__ == "__main__":
    unittest.main()
