#!/usr/bin/env python3
"""Focused rollback tests for the P0 release publisher."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "prepare_p0_release_bundle.py"
SPEC = importlib.util.spec_from_file_location("prepare_p0_release_bundle", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class PublishStagedFilesTest(unittest.TestCase):
    def test_publishes_all_changed_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_final = root / "first.txt"
            second_final = root / "second.txt"
            first_stage = root / "first.stage"
            second_stage = root / "second.stage"
            first_final.write_text("old-first", encoding="utf-8")
            second_final.write_text("old-second", encoding="utf-8")
            first_stage.write_text("new-first", encoding="utf-8")
            second_stage.write_text("new-second", encoding="utf-8")

            self.assertEqual(
                prepare.publish_staged_files(
                    [(first_stage, first_final), (second_stage, second_final)]
                ),
                2,
            )
            self.assertEqual(first_final.read_text(encoding="utf-8"), "new-first")
            self.assertEqual(second_final.read_text(encoding="utf-8"), "new-second")

    def test_restores_prior_files_when_later_replace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_final = root / "first.txt"
            second_final = root / "second.txt"
            first_stage = root / "first.stage"
            second_stage = root / "second.stage"
            first_final.write_text("old-first", encoding="utf-8")
            second_final.write_text("old-second", encoding="utf-8")
            first_stage.write_text("new-first", encoding="utf-8")
            second_stage.write_text("new-second", encoding="utf-8")

            original_replace = prepare.os.replace
            fail_once = True

            def fail_second_replace(source: object, destination: object) -> None:
                nonlocal fail_once
                if Path(destination) == second_final and fail_once:
                    fail_once = False
                    raise OSError("injected second publish failure")
                original_replace(source, destination)

            with mock.patch.object(prepare.os, "replace", side_effect=fail_second_replace):
                with self.assertRaisesRegex(RuntimeError, "prior files restored"):
                    prepare.publish_staged_files(
                        [(first_stage, first_final), (second_stage, second_final)]
                    )

            self.assertEqual(first_final.read_text(encoding="utf-8"), "old-first")
            self.assertEqual(second_final.read_text(encoding="utf-8"), "old-second")


if __name__ == "__main__":
    unittest.main()
