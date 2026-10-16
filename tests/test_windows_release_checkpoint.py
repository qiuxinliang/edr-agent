"""Behavioral release identity/retry tests; GitHub is the only mocked boundary."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
import struct
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import encrypt_p0_rules as envelope
spec = importlib.util.spec_from_file_location("checkpoint", ROOT / "scripts/windows_release_checkpoint.py")
cp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cp)
gate_spec = importlib.util.spec_from_file_location("gate", ROOT / "tests/test_windows_release_gate.py")
gate = importlib.util.module_from_spec(gate_spec)
gate_spec.loader.exec_module(gate)
SOURCE = dict(tag="win_3.2.999", commit="a" * 40, repository="owner/agent", run_id="1234",
              mode="unsigned", upgrade_class="auto")


class PrivateP0InputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        sensor = dict(kind="edr_sensor_interest_manifest", p0_artifact_rule_count=1,
                      rules_bundle_version="synthetic", p0_artifact_sha256="0" * 64)
        raw = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
        ir = dict(kind="edr_p0_rule_bundle_ir_v1", ir_schema_version=9, rule_count=1,
                  rules=[{"id": "SYNTHETIC"}], rules_bundle_version="synthetic",
                  sensor_interest_manifest_hash_mode="raw-json-v1-p0-artifact-sha256-zeroed",
                  sensor_interest_manifest_sha256=hashlib.sha256(raw(sensor)).hexdigest())
        plain = raw(ir)
        sensor["p0_artifact_sha256"] = hashlib.sha256(plain).hexdigest()
        key = envelope.hkdf_sha256(envelope.HKDF_SALT, envelope.SEED, envelope.HKDF_INFO, envelope.KEY_LEN)
        wire = envelope.aes_256_gcm_encrypt(plain, key)
        for name, data in zip(cp.P0_TEST_INPUT_FILES, (plain, wire, raw(sensor))):
            (self.directory / name).write_bytes(data)
        subprocess.run(["git", "init", "-q", str(self.directory)], check=True)
        subprocess.run(["git", "-C", str(self.directory), "add", "--", *cp.P0_TEST_INPUT_FILES], check=True)
        subprocess.run(["git", "-C", str(self.directory), "-c", "user.name=P0 fixture",
                        "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                        "commit", "-qm", "synthetic test input"], check=True)
        self.ref = subprocess.check_output(["git", "-C", str(self.directory), "rev-parse", "HEAD"], text=True).strip()

    def test_ir7_ir8_ir9_inputs_remain_bound_and_future_schema_rejects(self):
        ir_path, wire_path, sensor_path = (self.directory / name for name in cp.P0_TEST_INPUT_FILES)
        ir, sensor = json.loads(ir_path.read_bytes()), json.loads(sensor_path.read_bytes())
        raw = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
        key = envelope.hkdf_sha256(envelope.HKDF_SALT, envelope.SEED, envelope.HKDF_INFO, envelope.KEY_LEN)
        for schema in (7, 8, 9, 10):
            with self.subTest(schema=schema):
                ir["ir_schema_version"] = schema
                plain = raw(ir)
                sensor["p0_artifact_sha256"] = hashlib.sha256(plain).hexdigest()
                ir_path.write_bytes(plain)
                wire_path.write_bytes(envelope.aes_256_gcm_encrypt(plain, key))
                sensor_path.write_bytes(raw(sensor))
                subprocess.run(["git", "-C", str(self.directory), "add", "--", *cp.P0_TEST_INPUT_FILES], check=True)
                subprocess.run(["git", "-C", str(self.directory), "-c", "user.name=P0 fixture",
                                "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                                "commit", "-qm", "synthetic schema input"], check=True)
                ref = subprocess.check_output(["git", "-C", str(self.directory), "rev-parse", "HEAD"], text=True).strip()
                if schema == 10:
                    with self.assertRaises(ValueError):
                        cp.verify_p0_test_inputs(self.directory, ref)
                else:
                    self.assertRegex(cp.verify_p0_test_inputs(self.directory, ref), r"^[0-9a-f]{64}$")

    def test_exact_snapshot_produces_bound_digest_and_release_source(self):
        sha = cp.verify_p0_test_inputs(self.directory, self.ref)
        env = dict(EDR_AGENT_RELEASE_TAG=SOURCE["tag"], GITHUB_SHA=SOURCE["commit"],
                   GITHUB_REPOSITORY=SOURCE["repository"], GITHUB_RUN_ID=SOURCE["run_id"],
                   WINDOWS_RELEASE_MODE="unsigned", EDR_UPGRADE_CLASS_OVERRIDE="auto",
                   P0_TEST_INPUTS_REF=self.ref, P0_TEST_INPUTS_SHA256=sha)
        bound = cp.source(env)
        self.assertEqual(bound["p0_test_inputs"], dict(repository="qiuxinliang/EDRAI", commit=self.ref, sha256=sha))
        api = FakeGitHub()
        cp.prepare(api, bound)
        changed = copy.deepcopy(bound)
        changed["p0_test_inputs"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "another commit"):
            cp.prepare(api, changed)
        env.pop("P0_TEST_INPUTS_SHA256")
        with self.assertRaisesRegex(ValueError, "input identity"):
            cp.source(env)

    def test_verification_exports_absolute_test_directory_and_frozen_identity(self):
        output_path, env_path = self.directory / "output.txt", self.directory / "environment.txt"
        output = io.StringIO()
        with patch.dict(cp.os.environ, dict(P0_TEST_INPUTS_REF=self.ref, P0_TEST_INPUTS_SHA256="",
                                          GITHUB_OUTPUT=str(output_path), GITHUB_ENV=str(env_path))), \
                patch.object(sys, "argv", ["checkpoint", "verify-p0-inputs", "--directory", str(self.directory)]), \
                patch("sys.stdout", output):
            cp.main()
        exported = dict(line.split("=", 1) for line in env_path.read_text(encoding="utf-8").splitlines())
        self.assertEqual(Path(exported["EDR_BACKEND_CONFIG_DIR"]), self.directory.resolve())
        self.assertEqual(exported["P0_TEST_INPUTS_REF"], self.ref)
        self.assertEqual(exported["P0_TEST_INPUTS_SHA256"], cp.verify_p0_test_inputs(self.directory, self.ref))
        self.assertIn(f"sha256={exported['P0_TEST_INPUTS_SHA256']}", output_path.read_text(encoding="utf-8"))
        self.assertNotIn("SYNTHETIC", output.getvalue())

    def test_missing_file_and_moving_ref_fail(self):
        with self.assertRaisesRegex(ValueError, "fixed 40-hex"):
            cp.verify_p0_test_inputs(self.directory, "main")
        with self.assertRaisesRegex(ValueError, "frozen commit"):
            cp.verify_p0_test_inputs(self.directory, "0" * 40)
        (self.directory / cp.P0_TEST_INPUT_FILES[2]).unlink()
        with self.assertRaisesRegex(ValueError, "Missing, unsafe"):
            cp.verify_p0_test_inputs(self.directory, self.ref)

    def test_tampered_envelope_and_mismatched_plaintext_fail(self):
        path = self.directory / cp.P0_TEST_INPUT_FILES[1]
        wire = path.read_bytes()
        path.write_bytes(wire[:-1] + bytes([wire[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            cp.verify_p0_test_inputs(self.directory, self.ref)
        path.write_bytes(wire)
        (self.directory / cp.P0_TEST_INPUT_FILES[0]).write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError, "plaintext/encrypted"):
            cp.verify_p0_test_inputs(self.directory, self.ref)

    def test_manifest_mutation_and_prepare_digest_mismatch_fail(self):
        path = self.directory / cp.P0_TEST_INPUT_FILES[2]
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with self.assertRaisesRegex(ValueError, "raw binding mismatch"):
            cp.verify_p0_test_inputs(self.directory, self.ref)
        path.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "frozen prepare job"):
            cp.verify_p0_test_inputs(self.directory, self.ref, "0" * 64)

    def test_coherent_pair_mutation_still_cannot_claim_the_frozen_commit(self):
        ir_path, wire_path, sensor_path = (self.directory / name for name in cp.P0_TEST_INPUT_FILES)
        original = ir_path.read_bytes()
        changed = original + b"\n"
        ir_path.write_bytes(changed)
        key = envelope.hkdf_sha256(envelope.HKDF_SALT, envelope.SEED, envelope.HKDF_INFO, envelope.KEY_LEN)
        wire_path.write_bytes(envelope.aes_256_gcm_encrypt(changed, key))
        sensor_path.write_bytes(sensor_path.read_bytes().replace(
            hashlib.sha256(original).hexdigest().encode(), hashlib.sha256(changed).hexdigest().encode()))
        with self.assertRaisesRegex(ValueError, "committed bytes"):
            cp.verify_p0_test_inputs(self.directory, self.ref)


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
        self.deletions = []

    def tag_commit(self, tag):
        return self.commit

    def release(self, tag):
        return copy.deepcopy(self.info)

    def call(self, *args, missing=False):
        if args[:2] == ("release", "create"):
            self.info = dict(draft=True, body=args[args.index("--notes") + 1], assets=[])
            self.commit = args[args.index("--target") + 1]
        elif args[:3] == ("api", "--method", "DELETE"):
            artifact_id = int(args[3].rsplit("/", 1)[1])
            self.deletions.append(artifact_id)
            self.artifacts = [a for a in self.artifacts if a["id"] != artifact_id]
            return ""
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

    def test_cleanup_only_retires_published_run_recovery_copies(self):
        self.api.info["draft"] = False
        names = ("release-checkpoint-amd64", "release-checkpoint-arm64",
                 "release-input-amd64", "release-input-arm64", "usb-verified-final",
                 "windows-rule-validation-amd64", "windows-lifecycle-evidence-arm64")
        self.api.artifacts = [dict(id=i, name=name, expired=False,
                                  workflow_run=dict(id=1234))
                              for i, name in enumerate(names, 1)]
        self.api.artifacts.append(dict(id=8, name="release-checkpoint-amd64", expired=True,
                                       workflow_run=dict(id=1234)))
        original = copy.deepcopy(self.api.info)
        self.assertEqual(cp.cleanup_published_checkpoints(self.api, SOURCE), 5)
        self.assertEqual(self.api.deletions, [1, 2, 3, 4, 5])
        self.assertEqual([a["id"] for a in self.api.artifacts], [6, 7, 8])
        self.assertEqual(self.api.info, original)
        self.assertEqual(cp.cleanup_published_checkpoints(self.api, SOURCE), 0)

    def test_cleanup_refuses_drafts_and_foreign_release_identity(self):
        with self.assertRaisesRegex(ValueError, "published release"):
            cp.cleanup_published_checkpoints(self.api, SOURCE)
        self.api.info["draft"] = False
        for field, value in (("commit", "b" * 40), ("run_id", "5678"), ("mode", "signed")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                cp.cleanup_published_checkpoints(self.api, dict(SOURCE, **{field: value}))
        self.api.commit = "b" * 40
        with self.assertRaisesRegex(ValueError, "no longer matches"):
            cp.cleanup_published_checkpoints(self.api, SOURCE)
        self.assertEqual(self.api.deletions, [])

    def test_cleanup_validates_all_artifact_owners_before_mutating(self):
        self.api.info["draft"] = False
        valid = dict(id=1, name="release-checkpoint-amd64", workflow_run=dict(id=1234))
        for invalid in (dict(valid, id=True), dict(valid, id=-1),
                        dict(valid, id=2, workflow_run=dict(id=5678)),
                        dict(valid, id=2, workflow_run=None)):
            with self.subTest(artifact=invalid):
                self.api.artifacts = [valid, invalid]
                with self.assertRaisesRegex(ValueError, "ownership"):
                    cp.cleanup_published_checkpoints(self.api, SOURCE)
                self.assertEqual(self.api.deletions, [])

    def test_cleanup_retries_are_bounded_and_failure_is_reported(self):
        self.api.info["draft"] = False
        page = json.dumps([dict(artifacts=[dict(id=1, name="release-checkpoint-amd64",
                                               workflow_run=dict(id=1234))])])
        with patch.object(self.api, "call", side_effect=[page, RuntimeError("offline"), ""]) as call, \
                patch.object(cp.time, "sleep") as sleep:
            self.assertEqual(cp.cleanup_published_checkpoints(self.api, SOURCE), 1)
            self.assertEqual(call.call_count, 3)
            sleep.assert_called_once_with(2)
        with patch.object(self.api, "call", side_effect=[page] + [RuntimeError("forbidden")] * 3) as call, \
                patch.object(cp.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "forbidden"):
                cp.cleanup_published_checkpoints(self.api, SOURCE)
            self.assertEqual(call.call_count, 4)

    def test_cleanup_missing_delete_is_idempotent_but_forbidden_is_not(self):
        api = cp.GitHub(SOURCE["repository"])
        result = subprocess.CompletedProcess(["gh"], 1, "", "HTTP 404: Not Found")
        with patch.object(cp.subprocess, "run", return_value=result):
            self.assertIsNone(api.call("api", "--method", "DELETE", "artifact/1", missing=True))
            result.stderr = "HTTP 403: forbidden"
            with self.assertRaisesRegex(RuntimeError, "403"):
                api.call("api", "--method", "DELETE", "artifact/1", missing=True)

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

    def test_private_input_identity_remains_bound_to_manifest_and_checkpoint(self):
        bound = dict(SOURCE, p0_test_inputs=dict(repository="qiuxinliang/EDRAI", commit="b" * 40, sha256="c" * 64))
        self.bundle(bound)
        cp.verify_checkpoint(self.directory, bound, "arm64")
        for field, value in (("commit", "d" * 40), ("sha256", "e" * 64)):
            changed = copy.deepcopy(bound)
            changed["p0_test_inputs"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                cp.verify_checkpoint(self.directory, changed, "arm64")

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


class PublishedBaselineTests(unittest.TestCase):
    @staticmethod
    def release(tag, *, draft=False, prerelease=True):
        assets = []
        for arch in ("amd64", "arm64"):
            for suffix in ("exe.zip", "setup.exe", "artifact-manifest.json"):
                asset_id = len(assets) + 1
                assets.append(dict(name=f"edr-agent-{tag}-windows-{arch}-{suffix}",
                                   id=asset_id, url=f"https://api.github.com/repos/owner/agent/releases/assets/{asset_id}",
                                   size=100, digest="sha256:" + "b" * 64))
        return dict(tag_name=tag, draft=draft, prerelease=prerelease, assets=assets,
                    body="historical release provenance", target_commitish="c" * 40)

    def test_published_candidate_wins_over_failed_complete_and_incomplete_drafts(self):
        published = self.release("win_3.2.583")
        failed = self.release("win_3.2.587", draft=True, prerelease=False)
        incomplete = self.release("win_3.2.586", draft=True, prerelease=False)
        incomplete["assets"].pop()
        target = self.release("win_3.2.588", draft=True, prerelease=False)
        target["assets"] = []
        releases = [failed, target, incomplete, published]
        original = copy.deepcopy(releases)
        self.assertEqual(cp.select_baseline(releases, target["tag_name"]),
                         dict(tag="win_3.2.583", state="published", setup_rollback_supported=True))
        self.assertEqual(cp.select_baseline(releases, target["tag_name"], published["tag_name"])["tag"],
                         published["tag_name"])
        self.assertEqual(releases, original)

    def test_published_release_selection_is_numeric_and_strictly_older(self):
        releases = [self.release(tag, prerelease=False) for tag in
                    ("win_3.2.98", "win_3.2.100", "win_3.2.101", "win_3.3.1")]
        self.assertEqual(cp.select_baseline(releases, "win_3.2.101")["tag"], "win_3.2.100")
        for tag in ("win_3.2.101", "win_3.3.1"):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "strictly older"):
                cp.select_baseline(releases, "win_3.2.101", tag)

    def test_explicit_draft_and_missing_or_duplicate_releases_are_rejected(self):
        draft = self.release("win_3.2.587", draft=True)
        with self.assertRaisesRegex(ValueError, "draft"):
            cp.select_baseline([draft], "win_3.2.588", draft["tag_name"])
        for releases in ([], [draft, copy.deepcopy(draft)]):
            with self.subTest(releases=len(releases)), self.assertRaisesRegex(ValueError, "exactly one release"):
                cp.select_baseline(releases, "win_3.2.588", draft["tag_name"])
        published = self.release("win_3.2.583")
        with self.assertRaisesRegex(ValueError, "exactly one release"):
            cp.select_baseline([published, copy.deepcopy(published)], "win_3.2.588")

    def test_both_architectures_require_each_immutable_asset_once(self):
        for arch in ("amd64", "arm64"):
            for suffix in ("exe.zip", "setup.exe", "artifact-manifest.json"):
                for defect in ("missing", "duplicate"):
                    with self.subTest(arch=arch, suffix=suffix, defect=defect):
                        incomplete = self.release("win_3.2.586")
                        name = f"edr-agent-win_3.2.586-windows-{arch}-{suffix}"
                        asset = next(a for a in incomplete["assets"] if a["name"] == name)
                        if defect == "missing":
                            incomplete["assets"].remove(asset)
                        else:
                            incomplete["assets"].append(copy.deepcopy(asset))
                        with self.assertRaisesRegex(ValueError, "exactly one"):
                            cp.select_baseline([incomplete], "win_3.2.588", incomplete["tag_name"])
                        self.assertEqual(cp.select_baseline([incomplete, self.release("win_3.2.583")],
                                                            "win_3.2.588")["tag"], "win_3.2.583")

    def test_asset_metadata_failures_are_not_no_history(self):
        for field, value in (("id", None), ("id", True), ("url", ""), ("url", "http://invalid"),
                             ("size", 0), ("size", True), ("digest", "sha256:bad"), ("digest", 7)):
            with self.subTest(field=field, value=value):
                invalid = self.release("win_3.2.583")
                invalid["assets"][0][field] = value
                with self.assertRaisesRegex(ValueError, "immutable metadata"):
                    cp.select_baseline([invalid], "win_3.2.588")
                with self.assertRaisesRegex(ValueError, "immutable metadata"):
                    cp.select_baseline([invalid], "win_3.2.588", invalid["tag_name"])

    def test_historical_optional_github_digest_keeps_downstream_verification(self):
        release = self.release("win_3.2.583")
        for asset in release["assets"]:
            asset.pop("digest")
        self.assertEqual(cp.select_baseline([release], "win_3.2.588")["tag"], release["tag_name"])

    def test_known_broken_setup_boundaries_and_rollback_compatibility(self):
        for patch_version, eligible, rollback in ((303, True, False), (304, False, False),
                                                   (341, False, False), (342, True, True)):
            release = self.release(f"win_3.2.{patch_version}")
            with self.subTest(version=patch_version):
                if eligible:
                    self.assertEqual(cp.select_baseline([release], "win_3.2.588")["setup_rollback_supported"], rollback)
                else:
                    with self.assertRaisesRegex(ValueError, "known-broken Setup range"):
                        cp.select_baseline([release], "win_3.2.588", release["tag_name"])
        releases = [self.release("win_3.2.341"), self.release("win_3.2.303")]
        self.assertEqual(cp.select_baseline(releases, "win_3.2.588")["tag"], "win_3.2.303")

    def test_no_published_history_is_distinct_from_bad_release_metadata(self):
        self.assertIsNone(cp.select_baseline([], "win_3.2.588"))
        self.assertIsNone(cp.select_baseline([self.release("win_3.2.587", draft=True)], "win_3.2.588"))
        for invalid in (None, {}, [None]):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "release list"):
                cp.select_baseline(invalid, "win_3.2.588")
        for tag in ("main", "win_3.2.588-unsigned", ""):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "release tag"):
                cp.select_baseline([], tag)

    def test_paginated_github_lookup_is_readonly_and_errors_propagate(self):
        api = cp.GitHub("owner/agent")
        pages = [[self.release("win_3.2.587", draft=True)], [self.release("win_3.2.583")]]
        with patch.object(api, "call", return_value=json.dumps(pages)) as call:
            self.assertEqual(cp.select_baseline(api.releases(), "win_3.2.588")["tag"], "win_3.2.583")
        call.assert_called_once_with("api", "repos/owner/agent/releases?per_page=100", "--paginate", "--slurp")
        for response in ("not JSON", json.dumps({}), json.dumps([{}])):
            with self.subTest(response=response), patch.object(api, "call", return_value=response), self.assertRaises(ValueError):
                api.releases()
        with patch.object(api, "call", side_effect=RuntimeError("GitHub forbidden")), self.assertRaisesRegex(RuntimeError, "forbidden"):
            api.releases()

    def test_cli_requires_a_baseline_but_not_target_source_or_published_state(self):
        api = cp.GitHub("owner/agent")
        target = self.release("win_3.2.588", draft=True)
        target["assets"] = []
        args = ["checkpoint", "select-baseline", "--target-tag", target["tag_name"]]
        with patch.dict(cp.os.environ, {"GITHUB_REPOSITORY": "owner/agent"}, clear=True), \
                patch("sys.argv", args), patch.object(cp, "source", side_effect=AssertionError("target source must not be read")), \
                patch.object(cp, "GitHub", return_value=api), \
                patch.object(api, "releases", return_value=[target, self.release("win_3.2.583")]), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            cp.main()
            self.assertEqual(json.loads(output.getvalue())["tag"], "win_3.2.583")
        with patch.dict(cp.os.environ, {"GITHUB_REPOSITORY": "owner/agent"}, clear=True), \
                patch("sys.argv", args), patch.object(cp, "GitHub", return_value=api), \
                patch.object(api, "releases", return_value=[target]), \
                self.assertRaisesRegex(ValueError, "install/upgrade/rollback has no eligible published baseline"):
            cp.main()


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


class HeadlessReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def environment(self, **changes):
        value = dict(EDR_RELEASE_PACKAGE_SCOPE="headless", EDR_RELEASE_CANDIDATE="true",
                     EDR_AGENT_RELEASE_TAG=SOURCE["tag"], GITHUB_SHA=SOURCE["commit"],
                     GITHUB_REPOSITORY=SOURCE["repository"], GITHUB_RUN_ID=SOURCE["run_id"],
                     WINDOWS_RELEASE_MODE="unsigned", EDR_UPGRADE_CLASS_OVERRIDE="auto")
        value.update(changes)
        return value

    def test_scope_is_early_explicit_and_does_not_change_backend_source_schema(self):
        self.assertEqual(cp.source(self.environment()), SOURCE)
        self.assertEqual(cp.validate_scope({}), "full")
        for fields in (dict(WINDOWS_RELEASE_MODE="signed"), dict(WINDOWS_RELEASE_MODE="usb"),
                       dict(EDR_RELEASE_CANDIDATE="false"), dict(EDR_RELEASE_PACKAGE_SCOPE="unknown")):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                cp.source(self.environment(**fields))

    def test_unsupported_headless_request_fails_before_any_github_boundary(self):
        for change in (dict(EDR_RELEASE_CANDIDATE="false"),dict(WINDOWS_RELEASE_MODE="signed"),dict(WINDOWS_RELEASE_MODE="usb")):
            with self.subTest(change=change),patch.dict(os.environ,self.environment(**change),clear=True),\
                    patch.object(sys,'argv',['checkpoint','prepare']),patch.object(cp,'GitHub') as api:
                with self.assertRaisesRegex(ValueError,'requires unsigned'):
                    cp.main()
                api.assert_not_called()

    def test_owner_marker_is_bound_both_ways_and_legacy_full_shape_is_unchanged(self):
        full, headless = FakeGitHub(), FakeGitHub()
        cp.prepare(full, SOURCE)
        self.assertEqual(full.info["body"], cp.UNSIGNED + "<!-- edr-release-source:" + json.dumps(SOURCE, sort_keys=True) + " -->")
        cp.prepare(headless, SOURCE, package_scope="headless")
        self.assertEqual(cp.MARKER.findall(headless.info["body"]), cp.MARKER.findall(full.info["body"]))
        for api, scope in ((full, "headless"), (headless, "full")):
            with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, "scope"):
                cp.prepare(api, SOURCE, package_scope=scope)
        headless.info["body"] += "\n<!-- edr-release-package-scope:headless -->"
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            cp.verify_owner(headless, SOURCE, package_scope="headless")

    def bundle(self, arch="arm64", scope="headless"):
        directory = self.root / arch
        directory.mkdir()
        names = cp.asset_names(SOURCE, arch, package_scope=scope)
        manifest = next(name for name in names if name.endswith("artifact-manifest.json"))
        for name in names - {manifest}:
            (directory / name).write_bytes(name.encode())
        entries = [dict(name=name, size=(directory/name).stat().st_size, sha256=cp.digest(directory/name))
                   for name in names if name != manifest]
        (directory/manifest).write_text(json.dumps(dict(version="3.2.999", build_provenance=SOURCE,
            signature={"status":"unsigned"}, artifacts=entries)))
        cp.seal(directory, SOURCE, arch, package_scope=scope)
        return directory

    def test_headless_checkpoint_upload_missing_digest_and_remote_extra(self):
        directory = self.bundle()
        record = cp.verify_checkpoint(directory, SOURCE, "arm64", package_scope="headless")
        self.assertEqual(len(record["files"]), 3)
        self.assertEqual(record["package_scope"], "headless")
        self.assertEqual(record["source"], SOURCE)
        with self.assertRaises(ValueError):
            cp.verify_checkpoint(directory, SOURCE, "arm64")
        api = FakeGitHub()
        cp.prepare(api, SOURCE, package_scope="headless")
        cp.upload(api, directory, SOURCE, "arm64", package_scope="headless")
        for asset in api.info["assets"]:
            del asset["digest"]
        cp.upload(api, directory, SOURCE, "arm64", package_scope="headless")
        self.assertEqual(set(api.downloads), set(record["files"]))
        self.assertFalse(any("setup" in name for name in api.downloads))
        api.info["assets"].append(dict(name="forbidden-setup-ui.zip", size=1))
        with self.assertRaisesRegex(ValueError, "unexpected"):
            cp.upload(api, directory, SOURCE, "arm64", package_scope="headless")
        self.assertEqual(len(api.uploads), 3)

    def test_headless_dist_rejects_every_extra_and_cross_scope_restore(self):
        directory = self.bundle()
        for name in ("extra.txt", "standalone-setup.exe", "setup-ui.zip"):
            (directory/name).write_bytes(b"forbidden")
            with self.assertRaisesRegex(ValueError, "exact complete"):
                cp.verify_checkpoint(directory, SOURCE, "arm64", package_scope="headless")
            (directory/name).unlink()
        api = FakeGitHub()
        api.artifacts = [dict(name="release-checkpoint-arm64", expired=False)]
        api.checkpoint = {path.name:path.read_bytes() for path in directory.iterdir()}
        with self.assertRaises(ValueError):
            cp.restore(api, self.root/'restored', SOURCE, "arm64")
        full = self.bundle("amd64", "full")
        api.artifacts = [dict(name="release-checkpoint-amd64", expired=False)]
        api.checkpoint = {path.name:path.read_bytes() for path in full.iterdir()}
        with self.assertRaises(ValueError):
            cp.restore(api, self.root/'restored-headless', SOURCE, "amd64", package_scope="headless")

    def test_published_headless_reuse_requires_candidate_state_and_complete_assets(self):
        api = FakeGitHub()
        cp.prepare(api, SOURCE, package_scope="headless")
        for arch in ("amd64", "arm64"):
            cp.upload(api, self.bundle(arch), SOURCE, arch, package_scope="headless")
        api.info.update(draft=False, prerelease=True)
        self.assertTrue(cp.prepare(api, SOURCE, package_scope="headless"))
        api.info["prerelease"] = False
        with self.assertRaisesRegex(ValueError, "prerelease candidate"):
            cp.prepare(api, SOURCE, package_scope="headless")

    def test_verify_assets_is_same_authority_and_requires_both_architectures(self):
        api = FakeGitHub()
        cp.prepare(api, SOURCE, package_scope="headless")
        for arch in ("amd64", "arm64"):
            cp.upload(api, self.bundle(arch), SOURCE, arch, package_scope="headless")
        cp.verify_assets(api, SOURCE, package_scope="headless")
        api.info["assets"].pop()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            cp.verify_assets(api, SOURCE, package_scope="headless")

    @staticmethod
    def pe(machine, signed=False):
        value = bytearray(512)
        value[:2] = b"MZ"
        struct.pack_into('<I', value, 60, 128)
        value[128:132] = b"PE\0\0"
        struct.pack_into('<H', value, 132, machine)
        size, magic, start = (224, 0x10b, 96) if machine == 0x14c else (240, 0x20b, 112)
        struct.pack_into('<H', value, 148, size)
        struct.pack_into('<H', value, 152, magic)
        struct.pack_into('<I', value, 152+start-4, 16)
        if signed:
            struct.pack_into('<II', value, 152+start+32, 480, 16)
        return bytes(value)

    def stage_fixture(self, arch="arm64", baseline=False, change=None, extra_zip=None):
        tag = "win_3.2.687" if baseline else SOURCE["tag"]
        version = tag[4:]
        source = dict(SOURCE, tag=tag)
        machine = {"amd64":0x8664,"arm64":0xaa64}[arch]
        data = {"FDSensor.exe":self.pe(machine), "edr_agent_setup.exe":self.pe(0x14c),
                "FDSecurityInstallerWorker.exe":self.pe(machine), "uninstall.exe":self.pe(machine),
                "VERSION":version.encode()}
        integrity = dict(schema="edr.windows.native-package-integrity.v1", files=[
            dict(name=name, sha256=hashlib.sha256(data[name]).hexdigest()) for name in
            ("FDSecurityInstallerWorker.exe","uninstall.exe")])
        data["native-package-integrity.json"] = json.dumps(integrity).encode()
        full = dict(version=version,target_arch=arch,setup_target_arch=arch,
                    agent_binary_sha256=hashlib.sha256(data["FDSensor.exe"]).hexdigest(),
                    runtime_identity_sha256=hashlib.sha256(data["native-package-integrity.json"]).hexdigest(),
                    setup_exe_sha256=hashlib.sha256(data["edr_agent_setup.exe"]).hexdigest(),
                    setup_exe_signed=False,publisher_thumbprint="",capabilities={"signature_status":"unsigned"},
                    upgrade_protocol="edr.windows.full-installer-upgrade.v1",preserves_existing_identity=True,
                    preserves_offline_queue=True,preserves_evidence_cache=True)
        if baseline:
            full["ui_exe_sha256"] = "f"*64 # Not a claim that the old UI bytes were downloaded/verified.
        if change:
            change(data,full)
        data["full-installer-manifest.json"] = json.dumps(full).encode()
        data["package-capabilities.json"] = json.dumps(dict(signature_status="unsigned",target_arch=arch)).encode()
        downloads = self.root/'downloads';downloads.mkdir()
        prefix=f"edr-agent-{tag}-windows-{arch}-"
        archive=downloads/(prefix+'exe.zip')
        with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED) as z:
            for name,raw in data.items():z.writestr(name,raw)
            if extra_zip:z.writestr(*extra_zip)
        raw = data['FDSensor.exe']
        payload=[dict(name=archive.name,size=archive.stat().st_size,sha256=cp.digest(archive)),
                 dict(name=prefix+'FDSensor.exe',size=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                      version=version,platform='windows',arch=arch,update=dict(internal_name='FDSensor',
                          internal_version=version,runtime_identity_sha256=full['runtime_identity_sha256']))]
        manifest=downloads/(prefix+'artifact-manifest.json')
        manifest.write_text(json.dumps(dict(schema_version=1,version=version,build_provenance=source,
            signature={'status':'unsigned'},artifacts=payload)))
        assets=[]
        for i,(name,length,sha) in enumerate([(archive.name,archive.stat().st_size,cp.digest(archive)),
                (manifest.name,manifest.stat().st_size,cp.digest(manifest)),
                (prefix+'FDSensor.exe',len(raw),hashlib.sha256(raw).hexdigest())],1):
            assets.append(dict(id=i,name=name,size=length,digest='sha256:'+sha,
                url=f'https://api.github.com/repos/{SOURCE["repository"]}/releases/assets/{i}'))
        body='<!-- edr-release-source:'+json.dumps(source)+' -->'
        if not baseline:body+='\n<!-- edr-release-package-scope:headless -->'
        else:assets.append(dict(name='old-setup-ui.zip'))
        metadata=self.root/'release.json';metadata.write_text(json.dumps(dict(id=123,tag_name=tag,
            draft=not baseline,prerelease=True,target_commitish=source['commit'],body=body,assets=assets)))
        options=(dict(published_baseline=True,target_tag=SOURCE['tag']) if baseline else
                 dict(expected_source_commit=SOURCE['commit'],expected_run_id=SOURCE['run_id']))
        return downloads,self.root/'staged',metadata,tag,arch,source['commit'],SOURCE['repository'],options

    def stage(self, fixture):
        *args,options=fixture
        return cp.stage_headless(*args,**options)

    def test_stage_real_zip_and_manifest_on_both_architectures(self):
        for arch in ('amd64','arm64'):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                self.root=Path(temp)
                fixture=self.stage_fixture(arch)
                result=self.stage(fixture)
                self.assertEqual(result['target_arch'],arch)
                self.assertTrue(Path(result['setup_exe']).is_file())
                self.assertFalse(any('SetupUI' in path.name for path in Path(result['runtime_dir']).rglob('*')))
                with self.assertRaisesRegex(ValueError,'fresh destination'):
                    self.stage(fixture)

    def test_baseline_full_release_verifies_headless_subset_without_ui_bytes(self):
        result=self.stage(self.stage_fixture(baseline=True))
        self.assertEqual(result['package_scope'],'full')
        self.assertEqual(result['validation_scope'],'headless_subset')
        self.assertEqual(result['version'],'3.2.687')

    def test_stage_cli_uses_only_local_inputs_and_returns_authoritative_paths(self):
        fixture=self.stage_fixture()
        directory,destination,metadata,tag,arch,commit,repository,_=fixture
        argv=['checkpoint','stage-headless','--tag',tag,'--arch',arch,'--directory',str(directory),
              '--destination',str(destination),'--release-metadata',str(metadata),'--tag-commit',commit,
              '--expected-source-commit',commit,'--expected-run-id',SOURCE['run_id']]
        with patch.dict(os.environ,{'GITHUB_REPOSITORY':repository},clear=True),\
                patch.object(sys,'argv',argv),patch.object(cp,'GitHub') as api,patch('sys.stdout',new_callable=io.StringIO) as output:
            cp.main()
        api.assert_not_called()
        result=json.loads(output.getvalue())
        self.assertEqual(result['runtime_dir'],str(destination.resolve()))
        self.assertEqual(result['setup_exe'],str((destination/'edr_agent_setup.exe').resolve()))

    def test_unsigned_pe_gate_rejects_a_certificate_table(self):
        path=self.root/'signed.exe';path.write_bytes(self.pe(0x14c,signed=True))
        with self.assertRaisesRegex(ValueError,'certificate table'):
            cp.pe_machine(path)

    def test_native_payload_does_not_permit_native_inno_bootstrap(self):
        for arch, machine in (("amd64", 0x8664), ("arm64", 0xaa64)):
            def change(data, full):
                data["edr_agent_setup.exe"] = self.pe(machine)
                full["setup_exe_sha256"] = hashlib.sha256(data["edr_agent_setup.exe"]).hexdigest()
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                fixture = self.stage_fixture(arch, change=change)
                with self.assertRaisesRegex(ValueError, "architecture mismatch"):
                    self.stage(fixture)
                self.assertFalse(fixture[1].exists())

    def test_external_json_root_and_canonical_scalar_types_fail_with_value_error(self):
        fixture = self.stage_fixture()
        metadata = fixture[2]
        original = json.loads(metadata.read_text())
        malformed = [[], dict(original, body=[]), dict(original, target_commitish=None)]
        for field in ("tag", "commit", "repository", "run_id", "mode", "upgrade_class"):
            info = copy.deepcopy(original)
            provenance = dict(SOURCE, **{field: None})
            info["body"] = '<!-- edr-release-source:' + json.dumps(provenance) + ' -->'
            malformed.append(info)
        for info in malformed:
            with self.subTest(info=info), self.assertRaises(ValueError):
                metadata.write_text(json.dumps(info))
                self.stage(fixture)
        self.assertFalse(fixture[1].exists())

    def test_external_nested_manifest_types_fail_with_value_error(self):
        for field in ("signature", "update"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                fixture = self.stage_fixture()
                manifest_path = next(fixture[0].glob('*artifact-manifest.json'))
                manifest = json.loads(manifest_path.read_text())
                if field == "signature":
                    manifest[field] = []
                else:
                    next(entry for entry in manifest['artifacts'] if entry['name'].endswith('FDSensor.exe'))[field] = []
                manifest_path.write_text(json.dumps(manifest))
                self.refresh_download_hashes(fixture)
                with self.assertRaises(ValueError):
                    self.stage(fixture)
                self.assertFalse(fixture[1].exists())
        with tempfile.TemporaryDirectory() as temp:
            self.root = Path(temp)
            fixture = self.stage_fixture(change=lambda data, full: full.update(capabilities=[]))
            with self.assertRaisesRegex(ValueError, "manifest identity"):
                self.stage(fixture)
            self.assertFalse(fixture[1].exists())

    def test_stage_rejects_coherent_but_wrong_embedded_contracts(self):
        cases=[lambda d,m:m.update(preserves_evidence_cache=False),lambda d,m:m.update(setup_exe_sha256='0'*64),
               lambda d,m:m.update(target_arch='amd64'),lambda d,m:m.update(version='3.2.1'),
               lambda d,m:m.update(ui_exe_sha256='0'*64),lambda d,m:d.update(VERSION=b'3.2.1'),
               lambda d,m:d.update({'uninstall.exe':b'changed'}),
               lambda d,m:d.update({'edr_agent_setup.exe':self.pe(0x14c,signed=True)})]
        for change in cases:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temp:
                self.root=Path(temp)
                fixture=self.stage_fixture(change=change)
                with self.assertRaises(ValueError):self.stage(fixture)
                self.assertFalse(fixture[1].exists())

    def test_stage_rejects_path_escape_and_crc_corruption_without_publishing_stage(self):
        fixture=self.stage_fixture(extra_zip=('../escape',b'bad'))
        with self.assertRaisesRegex(ValueError,'Unsafe'):self.stage(fixture)
        self.assertFalse(fixture[1].exists())
        self.assertFalse((self.root/'escape').exists())

    @staticmethod
    def refresh_download_hashes(fixture):
        directory,_,metadata,*_=fixture
        archive=next(directory.glob('*exe.zip'))
        manifest_path=next(directory.glob('*artifact-manifest.json'))
        manifest=json.loads(manifest_path.read_text())
        for entry in manifest['artifacts']:
            if entry['name']==archive.name:
                entry.update(size=archive.stat().st_size,sha256=cp.digest(archive))
        manifest_path.write_text(json.dumps(manifest))
        info=json.loads(metadata.read_text())
        for asset in info['assets']:
            if asset.get('name') in (archive.name,manifest_path.name):
                path=directory/asset['name']
                asset.update(size=path.stat().st_size,digest='sha256:'+cp.digest(path))
        metadata.write_text(json.dumps(info))

    def test_crc_failure_cannot_publish_a_partial_stage_even_with_matching_outer_hashes(self):
        fixture=self.stage_fixture()
        archive=next(fixture[0].glob('*exe.zip'))
        with zipfile.ZipFile(archive) as z:
            entry=z.getinfo('VERSION')
        raw=bytearray(archive.read_bytes())
        offset=entry.header_offset+30+len(entry.filename.encode())+len(entry.extra)
        raw[offset]^=1
        archive.write_bytes(raw)
        self.refresh_download_hashes(fixture)
        with self.assertRaisesRegex(zipfile.BadZipFile,'CRC'):
            self.stage(fixture)
        self.assertFalse(fixture[1].exists())

    def test_stage_pins_source_run_tag_publication_and_download_scope(self):
        fixture=self.stage_fixture()
        *args,options=fixture
        for key,value in (('expected_source_commit','b'*40),('expected_run_id','999')):
            with self.subTest(key=key),self.assertRaises(ValueError):
                cp.stage_headless(*args,**dict(options,**{key:value}))
        metadata=fixture[2];original=json.loads(metadata.read_text())
        for mutate in (lambda x:x.update(tag_name='win_3.2.998'),
                       lambda x:x.update(target_commitish='b'*40),
                       lambda x:x['assets'][0].update(digest='sha256:'+'0'*64),
                       lambda x:x['assets'].append(dict(name='forbidden-setup-ui.zip'))):
            changed=copy.deepcopy(original);mutate(changed);metadata.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):self.stage(fixture)
        metadata.write_text(json.dumps(original))
        (fixture[0]/'setup-ui.zip').write_bytes(b'forbidden')
        with self.assertRaisesRegex(ValueError,'exactly'):self.stage(fixture)
        self.assertFalse(fixture[1].exists())

    def test_headless_baseline_selection_accepts_only_its_complete_metadata_subset(self):
        info=dict(tag_name='win_3.2.687',draft=False,assets=[])
        for arch in ('amd64','arm64'):
            for suffix in ('exe.zip','FDSensor.exe','artifact-manifest.json'):
                info['assets'].append(dict(id=len(info['assets'])+1,name=f'edr-agent-win_3.2.687-windows-{arch}-{suffix}',
                    size=1,url='https://api.github.com/synthetic',digest='sha256:'+'a'*64))
        selected=cp.select_baseline([info],SOURCE['tag'],package_scope='headless')
        self.assertEqual(selected['tag'],'win_3.2.687')
        self.assertTrue(selected['setup_rollback_supported'])
        with self.assertRaisesRegex(ValueError,'setup.exe'):
            cp.select_baseline([info],SOURCE['tag'])
        info['assets'].pop()
        with self.assertRaises(ValueError):
            cp.select_baseline([info],SOURCE['tag'],package_scope='headless')


if __name__ == "__main__":
    unittest.main()
