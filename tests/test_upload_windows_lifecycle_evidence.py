"""Exercise private lifecycle evidence retention without network or release writes."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import upload_windows_lifecycle_evidence as evidence


class LifecycleEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.destination = self.base / "bundle"
        self.owner = evidence.identity("123", "2", "a" * 40, "win_3.2.621", "arm64")

    def fixture(self):
        for directory in evidence.EVIDENCE_DIRS:
            root = self.workspace / directory
            root.mkdir()
            (root / "summary.json").write_text('{"status":"succeeded"}')
        backup = self.workspace / "setup-exe-evidence" / "repair-baseline-backup"
        backup.mkdir()
        (backup / "agent.toml").write_bytes(b"private diagnostic content; do not print")
        return backup

    def test_preserves_complete_relative_tree_and_hash_receipt(self):
        self.fixture()
        files, receipt = evidence.build_bundle(self.workspace, self.destination, self.owner, "success")
        self.assertEqual(receipt["owner"], self.owner)
        self.assertEqual(receipt["job_status"], "success")
        self.assertEqual(receipt["missing_directories"], [])
        self.assertEqual(receipt["file_count"], 3)
        self.assertEqual(json.loads(files[1].read_text()), receipt)
        self.assertEqual(receipt["archive"]["sha256"], evidence.digest(files[0]))
        with zipfile.ZipFile(files[0]) as archive:
            self.assertEqual(set(archive.namelist()), {item["path"] for item in receipt["files"]})
            for item in receipt["files"]:
                actual = archive.read(item["path"])
                self.assertEqual(item["size"], len(actual))
                self.assertEqual(item["sha256"], hashlib.sha256(actual).hexdigest())
            self.assertIn(b"private diagnostic", archive.read("setup-exe-evidence/repair-baseline-backup/agent.toml"))

    def test_private_draft_owner_and_no_sensitive_output(self):
        self.fixture()
        publisher = Mock(return_value={"id": 789})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            release, receipt = evidence.publish_evidence(self.workspace, self.destination, self.owner, "success", publisher)
        self.assertEqual(release["id"], 789)
        args, kwargs = publisher.call_args
        self.assertEqual(args[:2], ("edr-evidence-123-2-arm64", self.owner))
        self.assertEqual(len(args[2]), 2)
        self.assertEqual(kwargs, {"prerelease": False})
        self.assertIn(receipt["archive"]["sha256"], output.getvalue())
        self.assertNotIn("private diagnostic content", output.getvalue())
        self.assertNotIn("agent.toml", output.getvalue())

    def test_upload_failure_does_not_silently_discard_local_evidence(self):
        self.fixture()
        publisher = Mock(side_effect=RuntimeError("private upload unavailable"))
        with self.assertRaisesRegex(RuntimeError, "private upload unavailable"):
            evidence.publish_evidence(self.workspace, self.destination, self.owner, "failure", publisher)
        self.assertEqual(len(list(self.destination.iterdir())), 2)
        publisher.assert_called_once()

    def test_real_transport_contract_keeps_both_files_in_private_draft(self):
        import usb_release_transport as transport
        self.fixture()
        state = {"release": None, "assets": {}}

        def api(path, data=None, method=None):
            if path == "":
                return {"private": True}
            if path.startswith("releases?"):
                return [state["release"]] if state["release"] else []
            if path == "releases" and data:
                state["release"] = dict(data, id=4321)
                return state["release"]
            if path == "releases/4321/assets?per_page=100":
                return list(state["assets"].values())
            self.fail(f"Unexpected transport API: {path} {method}")

        def upload(command, **kwargs):
            self.assertEqual(command[:3], ["gh", "release", "upload"])
            self.assertEqual(command[-2:], ["--repo", "qiuxinliang/edr-agent-signing"])
            path = Path(command[4])
            state["assets"][path.name] = dict(name=path.name, size=path.stat().st_size,
                digest="sha256:" + evidence.digest(path), id=len(state["assets"]) + 1, state="uploaded")
            return SimpleNamespace(returncode=0)

        with patch.object(transport, "api", side_effect=api), patch.object(transport.subprocess, "run", side_effect=upload), contextlib.redirect_stdout(io.StringIO()):
            evidence.publish_evidence(self.workspace, self.destination, self.owner, "success", transport.publish_files)
        self.assertTrue(state["release"]["draft"])
        self.assertEqual(state["release"]["make_latest"], "false")
        self.assertEqual(len(state["assets"]), 2)
        self.assertIn('"target_tag": "win_3.2.621"', state["release"]["body"])

    def test_early_failure_retains_explicit_missing_evidence_receipt(self):
        files, receipt = evidence.build_bundle(self.workspace, self.destination, self.owner, "failure")
        self.assertEqual(receipt["missing_directories"], list(evidence.EVIDENCE_DIRS))
        self.assertEqual(receipt["file_count"], 0)
        self.assertEqual(receipt["job_status"], "failure")
        with zipfile.ZipFile(files[0]) as archive:
            self.assertEqual(archive.namelist(), [])

    def test_success_cannot_claim_absent_evidence(self):
        with self.assertRaisesRegex(ValueError, "missing required evidence"):
            evidence.build_bundle(self.workspace, self.destination, self.owner, "success")
        self.assertFalse(self.destination.exists())

    def test_failed_job_keeps_available_directory(self):
        root = self.workspace / "setup-exe-evidence"
        root.mkdir()
        (root / "failure.log").write_text("native failure")
        files, receipt = evidence.build_bundle(self.workspace, self.destination, self.owner, "failure")
        self.assertEqual(receipt["missing_directories"], ["runtime-evidence"])
        with zipfile.ZipFile(files[0]) as archive:
            self.assertEqual(archive.read("setup-exe-evidence/failure.log"), b"native failure")

    def test_invalid_identity_rejected(self):
        valid = dict(run_id="123", attempt="1", commit="a" * 40, target_tag="win_3.2.621", architecture="amd64")
        for field, value in (("run_id", "../123"), ("attempt", "0"), ("commit", "latest"),
                             ("target_tag", "latest"), ("architecture", "../outside"), ("repository", "fork/edr-agent")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                evidence.identity(**dict(valid, **{field: value}))

    def test_missing_dedicated_release_token_fails_before_collection(self):
        argv = ["upload_windows_lifecycle_evidence.py", "--target-tag", "win_3.2.621", "--arch", "arm64",
                "--job-status", "failure", "--output-dir", str(self.destination)]
        with patch.object(sys, "argv", argv), patch.dict(os.environ, {"GH_TOKEN": ""}):
            with self.assertRaisesRegex(RuntimeError, "USB_SIGNING_RELEASE_TOKEN"):
                evidence.main()
        self.assertFalse(self.destination.exists())

    def test_links_cannot_exfiltrate_outside_evidence(self):
        self.fixture()
        outside = self.base / "secret.txt"
        outside.write_text("outside secret")
        link = self.workspace / "runtime-evidence" / "link"
        for target, directory in ((outside, False), (self.base, True)):
            with self.subTest(directory=directory):
                try:
                    link.symlink_to(target, target_is_directory=directory)
                except OSError as exc:
                    self.skipTest(f"symlinks unavailable: {exc}")
                try:
                    with self.assertRaisesRegex(ValueError, "links|reparse"):
                        evidence.collect_files(self.workspace)
                finally:
                    link.unlink()

    def test_hardlinked_files_are_rejected(self):
        self.fixture()
        source = self.base / "secret.txt"
        source.write_text("outside secret")
        os.link(source, self.workspace / "runtime-evidence" / "linked.log")
        with self.assertRaisesRegex(ValueError, "non-linked"):
            evidence.collect_files(self.workspace)

    def test_reparse_attributes_are_rejected(self):
        item = Mock()
        item.lstat.return_value = SimpleNamespace(st_mode=0o100644, st_file_attributes=0x400)
        with self.assertRaisesRegex(ValueError, "reparse"):
            evidence.regular_stat(item)

    def test_size_and_file_bounds_fail_without_partial_omission(self):
        self.fixture()
        for setting, value in (("MAX_BYTES", 1), ("MAX_FILES", 1)):
            with self.subTest(setting=setting), patch.object(evidence, setting, value):
                with self.assertRaisesRegex(ValueError, "no files were omitted"):
                    evidence.build_bundle(self.workspace, self.destination, self.owner, "failure")
                self.assertFalse(self.destination.exists())

    def test_existing_output_is_not_overwritten(self):
        self.fixture()
        self.destination.mkdir()
        existing = self.destination / "owned.txt"
        existing.write_text("preserve")
        with self.assertRaises(FileExistsError):
            evidence.build_bundle(self.workspace, self.destination, self.owner, "success")
        self.assertEqual(existing.read_text(), "preserve")

    def test_source_mutation_during_zip_is_rejected(self):
        self.fixture()
        original_fstat = os.fstat
        calls = []

        def changed_stat(fd):
            result = original_fstat(fd)
            calls.append(fd)
            if len(calls) == 2:
                return SimpleNamespace(st_size=result.st_size, st_mtime_ns=result.st_mtime_ns + 1)
            return result

        with patch.object(evidence.os, "fstat", side_effect=changed_stat):
            with self.assertRaisesRegex(ValueError, "changed while archiving"):
                evidence.build_bundle(self.workspace, self.destination, self.owner, "success")


if __name__ == "__main__":
    unittest.main()
