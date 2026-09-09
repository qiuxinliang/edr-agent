#!/usr/bin/env python3
"""Focused rollback tests for the P0 release publisher."""

from __future__ import annotations

import importlib.util
import hashlib
import json
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


class VerifyBundleTest(unittest.TestCase):
    def write_bundle(self, root: Path, *, crlf: bool = False, declared_sha: str | None = None) -> tuple[Path, Path, Path]:
        version = "bundle-v1"
        plain = root / "p0_rule_bundle_ir_v1.json"
        manifest = root / "p0_rule_bundle_manifest.json"
        sensor = root / "sensor_interest_manifest.json"
        plain_bytes = (json.dumps({"rules_bundle_version": version, "rule_count": 1}, indent=2) + "\n").encode()
        if crlf:
            plain_bytes = plain_bytes.replace(b"\n", b"\r\n")
        plain.write_bytes(plain_bytes)
        manifest.write_bytes((json.dumps({"rules_bundle_version": version, "rule_count": 1}) + "\n").encode())
        sensor.write_bytes((json.dumps({
            "rules_bundle_version": version,
            "p0_artifact_rule_count": 1,
            "p0_artifact_sha256": declared_sha or hashlib.sha256(plain_bytes).hexdigest(),
        }) + "\n").encode())
        return plain, manifest, sensor

    def test_accepts_exact_lf_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(prepare.verify_bundle(*self.write_bundle(Path(directory))), "bundle-v1")

    def test_rejects_windows_crlf_before_encryption(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "must use LF line endings"):
                prepare.verify_bundle(*self.write_bundle(Path(directory), crlf=True))

    def test_rejects_sensor_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "does not match SensorInterest authority"):
                prepare.verify_bundle(
                    *self.write_bundle(Path(directory), declared_sha="0" * 64)
                )


if __name__ == "__main__":
    unittest.main()
