"""Negative controls for the portable TDH alias gate; native payload tests own execution order."""
import importlib.util
from pathlib import Path
import re
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tdh_order", ROOT / "scripts/verify_tdh_property_try_order.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class TDHPropertyTryOrderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "src/collector/etw_tdh_win.c"
        self.source.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "src/collector/etw_tdh_win.c", self.source)
        shutil.copytree(ROOT / "fixtures/tdh", self.root / "fixtures/tdh")
        self.original = self.source.read_text(encoding="utf-8")

    def replace_array(self, name, values):
        body = "".join('{L"' + value + '", "fixture"},' for value in values)
        source, count = re.subn(
            r"static\s+const\s+EdrPropTry\s+" + name + r"\s*\[\s*\]\s*=\s*\{.*?\};",
            lambda _: "static const EdrPropTry " + name + "[] = {" + body + "};",
            self.original,
            flags=re.S,
        )
        self.assertEqual(count, 1)
        self.source.write_text(source, encoding="utf-8")

    def test_current_separate_identity_and_text_tables_pass(self):
        self.assertEqual(gate._check_orders(self.root),
                         {"proc_try": 20, "proc_identity_try": 10, "file_try": 4})

    def test_removing_or_reordering_any_table_alias_fails(self):
        for name in ("proc_try", "proc_identity_try", "file_try"):
            values = gate._parse_c_wstr_array(self.original, name)
            for changed in (values[:-1], [values[1], values[0], *values[2:]]):
                with self.subTest(table=name, values=changed):
                    self.replace_array(name, changed)
                    with self.assertRaisesRegex(ValueError, name + " order differs"):
                        gate._check_orders(self.root)

    def test_missing_identity_table_fails(self):
        self.source.write_text(self.original.replace("EdrPropTry proc_identity_try[]",
                                                   "EdrPropTry removed_identity_table[]"),
                               encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "array proc_identity_try not found"):
            gate._check_orders(self.root)

    def test_missing_fixture_fails_instead_of_skipping(self):
        for name in ("kernel_process_prop_try_v1.txt", "kernel_process_identity_try_v1.txt",
                     "kernel_file_prop_try_v1.txt"):
            with self.subTest(fixture=name):
                path = self.root / "fixtures/tdh" / name
                original = path.read_bytes()
                path.unlink()
                with self.assertRaises(FileNotFoundError):
                    gate._check_orders(self.root)
                path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
