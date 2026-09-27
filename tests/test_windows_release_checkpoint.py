"""Behavioral release identity/retry tests; GitHub is the only mocked boundary."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("checkpoint", ROOT / "scripts/windows_release_checkpoint.py")
cp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cp)
gate_spec = importlib.util.spec_from_file_location("gate", ROOT / "tests/test_windows_release_gate.py")
gate = importlib.util.module_from_spec(gate_spec)
gate_spec.loader.exec_module(gate)
SOURCE = dict(tag="win_3.2.999", commit="a" * 40, repository="owner/agent", run_id="1234",
              mode="unsigned", upgrade_class="auto")


class FakeGitHub:
    repository = "owner/agent"

    def __init__(self):
        self.info = None
        self.commit = None
        self.uploads = []
        self.downloads = []
        self.blobs = {}
        self.artifacts = []
        self.checkpoint = None
        self.upload_error = None

    def tag_commit(self, tag):
        return self.commit

    def release(self, tag):
        return copy.deepcopy(self.info)

    def call(self, *args):
        if args[:2] == ("release", "create"):
            self.info = dict(draft=True, body=args[args.index("--notes") + 1], assets=[])
            self.commit = args[args.index("--target") + 1]
        elif args[0] == "api":
            return json.dumps([{"artifacts": self.artifacts}])
        elif args[:2] == ("run", "download"):
            directory = Path(args[args.index("--dir") + 1])
            directory.mkdir(parents=True, exist_ok=True)
            for name, data in self.checkpoint.items():
                (directory / name).write_bytes(data)
        else:
            raise AssertionError(args)

    def upload(self, tag, path):
        self.uploads.append(path.name)
        data = path.read_bytes()
        self.blobs[path.name] = data
        self.info["assets"].append(dict(name=path.name, size=len(data),
                                        digest="sha256:" + hashlib.sha256(data).hexdigest()))
        if self.upload_error:
            error, self.upload_error = self.upload_error, None
            raise error  # Upload succeeded remotely but the reply was lost.

    def download(self, tag, name, destination):
        self.downloads.append(name)
        (Path(destination) / name).write_bytes(self.blobs[name])


class ReleaseCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.api = FakeGitHub()
        cp.prepare(self.api, SOURCE)

    def bundle(self, source=SOURCE, arch="arm64"):
        names = cp.asset_names(source, arch)
        manifest = next(n for n in names if n.endswith("artifact-manifest.json"))
        for name in names - {manifest}:
            (self.directory / name).write_bytes(name.encode())
        payload = [dict(name=n, size=(self.directory / n).stat().st_size,
                        sha256=cp.digest(self.directory / n))
                   for n in sorted(names) if not n.endswith(("artifact-manifest.json", ".p7s"))]
        (self.directory / manifest).write_text(json.dumps(dict(
            version="3.2.999", build_provenance=source,
            signature={"status": source["mode"]}, artifacts=payload)), encoding="utf-8")
        cp.seal(self.directory, source, arch)

    def test_prepare_is_idempotent_and_does_not_overwrite_published(self):
        self.assertFalse(cp.prepare(self.api, SOURCE))
        original = copy.deepcopy(self.api.info)
        self.api.info["draft"] = False
        self.assertTrue(cp.prepare(self.api, dict(SOURCE, run_id="5678")))
        self.assertEqual(self.api.info["body"], original["body"])
        self.assertEqual(self.api.uploads, [])

    def test_unsigned_notes_explain_integrity_requirements_only_for_unsigned_mode(self):
        for mode in ("unsigned", "signed"):
            with self.subTest(mode=mode):
                api = FakeGitHub()
                cp.prepare(api, dict(SOURCE, mode=mode))
                body = api.info["body"]
                if mode == "unsigned":
                    self.assertIn("optional-signature", body)
                    self.assertIn("verified SHA-256", body)
                    self.assertIn("signature requirements are not changed", body)
                else:
                    self.assertNotIn("WARNING", body)
                self.assertTrue(api.info["draft"])

    def test_conflicting_identity_and_legacy_drafts_rejected(self):
        for field, value in (("commit", "b" * 40), ("mode", "signed"), ("run_id", "5678"),
                             ("upgrade_class", "binary_hot")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                cp.prepare(self.api, dict(SOURCE, **{field: value}))
        self.api.info["body"] = "legacy unbound draft"
        with self.assertRaisesRegex(ValueError, "no unique source binding"):
            cp.prepare(self.api, SOURCE)

    def test_annotated_tag_resolution_and_missing_tag(self):
        api = cp.GitHub(SOURCE["repository"])
        with patch.object(api, "call", side_effect=[json.dumps({"object": {"type": "tag", "sha": "b" * 40}}),
                                                   json.dumps({"object": {"type": "commit", "sha": SOURCE["commit"]}})]):
            self.assertEqual(api.tag_commit(SOURCE["tag"]), SOURCE["commit"])
        with patch.object(api, "call", return_value=None):
            self.assertIsNone(api.tag_commit(SOURCE["tag"]))

    def test_publication_rechecks_source_and_draft_state(self):
        self.api.commit = "b" * 40
        with self.assertRaisesRegex(ValueError, "no longer matches"):
            cp.verify_owner(self.api, SOURCE)
        self.api.commit = SOURCE["commit"]
        self.api.info["draft"] = False
        with self.assertRaisesRegex(ValueError, "immutable"):
            cp.verify_owner(self.api, SOURCE)

    def test_draft_can_defer_tag_creation_only_with_exact_commit_target(self):
        self.api.commit = None
        self.api.info["target_commitish"] = SOURCE["commit"]
        self.assertFalse(cp.prepare(self.api, SOURCE))
        cp.verify_owner(self.api, SOURCE)
        self.api.info["target_commitish"] = "main"
        with self.assertRaisesRegex(ValueError, "no longer matches"):
            cp.verify_owner(self.api, SOURCE)

    def test_api_auth_failure_is_not_mistaken_for_missing_release(self):
        api = cp.GitHub(SOURCE["repository"])
        error = subprocess.CompletedProcess(["gh"], 1, "", "HTTP 403: forbidden")
        with patch.object(cp.subprocess, "run", return_value=error):
            with self.assertRaisesRegex(RuntimeError, "403"):
                api.release(SOURCE["tag"])
        error.stderr = "HTTP 404: Not Found"
        with patch.object(cp.subprocess, "run", return_value=error):
            with self.assertRaisesRegex(RuntimeError, "404"):
                api.release(SOURCE["tag"])

    def test_release_lookup_resolves_draft_without_published_tag_endpoint(self):
        api = cp.GitHub(SOURCE["repository"])
        for draft in (True, False):
            info = dict(id=397548605, tag_name=SOURCE["tag"], draft=draft,
                        body=self.api.info["body"], target_commitish=SOURCE["commit"])
            calls = []

            def transport(*args, **kwargs):
                calls.append(args)
                if args[:2] == ("api", "graphql"):
                    return json.dumps({"data": {"repository": {"release": {
                        "id": info["id"], "tag_name": info["tag_name"]}}}})
                if args[1].endswith("/releases/397548605"):
                    return json.dumps(info)
                if args[1].endswith("/releases/397548605/assets?per_page=100"):
                    return json.dumps([[{"name": "first"}], [{"name": "second"}]])
                # This is the actual failed transport behavior, not a fake
                # release() implementation that assumes drafts are discoverable.
                if "/releases/tags/" in args[1]:
                    return None
                raise AssertionError(args)

            with self.subTest(draft=draft), patch.object(api, "call", side_effect=transport):
                result = api.release(SOURCE["tag"])
                self.assertEqual(result["draft"], draft)
                self.assertEqual(result["id"], 397548605)
                self.assertEqual([a["name"] for a in result["assets"]], ["first", "second"])
                self.assertFalse(any("/releases/tags/" in str(call) for call in calls))

    def test_graphql_missing_release_differs_from_permission_or_partial_error(self):
        api = cp.GitHub(SOURCE["repository"])
        with patch.object(api, "call", return_value=json.dumps({"data": {"repository": {"release": None}}})):
            self.assertIsNone(api.release(SOURCE["tag"]))
        for response in ({"data": {"repository": None}},
                         {"data": {"repository": {"release": None}}, "errors": [{"message": "denied"}]}):
            with self.subTest(response=response), patch.object(api, "call", return_value=json.dumps(response)):
                with self.assertRaisesRegex(RuntimeError, "repository access"):
                    api.release(SOURCE["tag"])

    def test_prepare_readback_retries_but_creates_only_once(self):
        info = self.api.release(SOURCE["tag"])
        with patch.object(self.api, "release", side_effect=[None, None, info]) as read:
            with patch.object(self.api, "call", wraps=self.api.call) as create, patch.object(cp.time, "sleep"):
                self.assertFalse(cp.prepare(self.api, SOURCE))
                self.assertEqual(create.call_count, 1)
                self.assertEqual(read.call_count, 3)

    def test_prepare_invisible_draft_has_bounded_actionable_failure(self):
        with patch.object(self.api, "release", return_value=None) as read:
            with patch.object(self.api, "call", wraps=self.api.call) as create, patch.object(cp.time, "sleep") as sleep:
                with self.assertRaisesRegex(RuntimeError, "not visible after 3 checks"):
                    cp.prepare(self.api, SOURCE)
                self.assertEqual(create.call_count, 1)
                self.assertEqual(read.call_count, 4)  # Initial lookup plus three readbacks.
                self.assertEqual(sleep.call_count, 2)

    def test_corruption_rejected_before_any_upload(self):
        self.bundle()
        binary = next(self.directory.glob("*FDSensor.exe"))
        binary.write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            cp.upload(self.api, self.directory, SOURCE, "arm64")
        self.assertEqual(self.api.uploads, [])

    def test_manifest_and_checkpoint_both_bound_to_run_commit_arch_mode(self):
        self.bundle()
        for field, value in (("commit", "b" * 40), ("run_id", "5678"), ("mode", "signed")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                cp.verify_checkpoint(self.directory, dict(SOURCE, **{field: value}), "arm64")
        with self.assertRaises(ValueError):
            cp.verify_checkpoint(self.directory, SOURCE, "amd64")

    def test_exact_asset_closure_required(self):
        self.bundle()
        (self.directory / "unexpected-secret.txt").write_text("not publishable", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "exact complete"):
            cp.seal(self.directory, SOURCE, "arm64")

    def test_checkpoint_manifest_and_signature_hashes_checked(self):
        signed = dict(SOURCE, mode="signed")
        self.bundle(signed)
        cp.verify_checkpoint(self.directory, signed, "arm64")
        next(self.directory.glob("*.p7s")).write_bytes(b"different signature")
        with self.assertRaisesRegex(ValueError, "Checkpoint identity or file digest"):
            cp.verify_checkpoint(self.directory, signed, "arm64")

    def test_upload_is_create_only_and_resumes_after_ambiguous_timeout(self):
        self.bundle()
        self.api.upload_error = subprocess.TimeoutExpired("gh", 300)
        with patch.object(cp.time, "sleep"):
            cp.upload(self.api, self.directory, SOURCE, "arm64")
        self.assertEqual(len(self.api.uploads), 5)
        cp.upload(self.api, self.directory, SOURCE, "arm64")
        self.assertEqual(len(self.api.uploads), 5)  # Verified, not uploaded again.

    def test_both_architecture_bundles_remain_in_draft_until_publication(self):
        original_body = self.api.info["body"]
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as output:
                self.directory = Path(output)
                self.bundle(arch=arch)
                cp.upload(self.api, self.directory, SOURCE, arch)
                self.assertTrue(self.api.info["draft"])
                self.assertEqual(self.api.info["body"], original_body)
                for name in cp.asset_names(SOURCE, arch):
                    self.assertEqual(self.api.blobs[name], (self.directory / name).read_bytes())
        self.assertEqual(set(self.api.blobs),
                         cp.asset_names(SOURCE, "amd64") | cp.asset_names(SOURCE, "arm64"))
        self.assertEqual(len(self.api.uploads), 10)

    def test_existing_same_size_different_hash_is_never_overwritten(self):
        self.bundle()
        name = sorted(cp.asset_names(SOURCE, "arm64"))[0]
        self.api.info["assets"] = [dict(name=name, size=(self.directory / name).stat().st_size,
                                       digest="sha256:" + "0" * 64)]
        with self.assertRaisesRegex(ValueError, "never overwrite"):
            cp.upload(self.api, self.directory, SOURCE, "arm64")
        self.assertEqual(self.api.uploads, [])

    def test_missing_remote_digest_requires_byte_verification(self):
        self.bundle()
        cp.upload(self.api, self.directory, SOURCE, "arm64")
        for asset in self.api.info["assets"]:
            asset.pop("digest")
        cp.upload(self.api, self.directory, SOURCE, "arm64")
        self.assertEqual(len(self.api.downloads), 5)

    def test_network_failure_has_bounded_retries(self):
        self.bundle()
        with patch.object(self.api, "release", side_effect=RuntimeError("network failure")) as call:
            with patch.object(cp.time, "sleep") as sleep, self.assertRaises(RuntimeError):
                cp.upload(self.api, self.directory, SOURCE, "arm64")
            self.assertEqual(call.call_count, 3)
            self.assertEqual(sleep.call_count, 2)

    def test_upload_to_published_release_is_refused(self):
        self.bundle()
        self.api.info["draft"] = False
        with self.assertRaisesRegex(ValueError, "immutable"):
            cp.upload(self.api, self.directory, SOURCE, "arm64")
        self.assertEqual(self.api.uploads, [])

    def test_restore_only_valid_same_run_checkpoint(self):
        self.bundle()
        self.api.checkpoint = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        self.api.artifacts = [dict(name="release-checkpoint-arm64", expired=False)]
        with tempfile.TemporaryDirectory() as output:
            self.assertTrue(cp.restore(self.api, Path(output), SOURCE, "arm64"))
        self.api.artifacts[0]["expired"] = True
        with self.assertRaisesRegex(ValueError, "expired"):
            cp.restore(self.api, self.directory, SOURCE, "arm64")

    def test_missing_checkpoint_builds_but_permission_error_does_not(self):
        self.assertFalse(cp.restore(self.api, self.directory, SOURCE, "arm64"))
        with patch.object(self.api, "call", side_effect=RuntimeError("forbidden")):
            with self.assertRaises(RuntimeError):
                cp.restore(self.api, self.directory, SOURCE, "arm64")


class ParallelGateTests(unittest.TestCase):
    def test_all_cases_execute_and_failure_propagates(self):
        seen = []

        class Fixture(unittest.TestCase):
            def test_pass(self):
                seen.append("pass")

            def test_fail(self):
                seen.append("fail")
                self.fail("expected negative control")

        output = io.StringIO()
        self.assertFalse(gate.run_parallel_cases([Fixture("test_pass"), Fixture("test_fail")], 2, output))
        self.assertCountEqual(seen, ["pass", "fail"])
        self.assertIn("2/2 executed", output.getvalue())
        self.assertIn("expected negative control", output.getvalue())
        self.assertTrue(gate.run_parallel_cases([Fixture("test_pass")], 1, io.StringIO()))

    def test_empty_selection_and_excess_parallelism_rejected(self):
        with self.assertRaises(ValueError):
            gate.run_parallel_cases([], 2, io.StringIO())
        with self.assertRaises(ValueError):
            gate.run_parallel_cases([], 8, io.StringIO())


if __name__ == "__main__":
    unittest.main()
