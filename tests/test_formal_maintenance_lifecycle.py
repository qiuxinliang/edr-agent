import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import stage_formal_maintenance_lifecycle as stage


def write_runtime_archive(path, members):
    with zipfile.ZipFile(path, "x") as package:
        for name, content in members:
            member = zipfile.ZipInfo(name)
            # Restore the raw name after ZipInfo's platform-dependent projection.
            member.filename = name
            member.create_system = 0
            package.writestr(member, content)


def request_fixture():
    request = {"schema": stage.REQUEST_SCHEMA}
    for label, source in stage.SOURCES.items():
        rows = []
        value = request[label] = {"assets": rows}
        names = sorted(set.union(*(stage.asset_names({"tag": source.tag, "mode": source.mode}, arch)
                                   for arch in stage.admission.ARCHES)))
        for identity, name in enumerate(names, start=1):
            rows.append(dict(id=identity, name=name, size=42,
                             digest="sha256:" + hashlib.sha256(name.encode()).hexdigest(), state="uploaded"))
        if source.mode != "unsigned":
            hashes = {row["name"]: row["digest"][7:] for row in rows}
            value["publisher_verification"] = {}
            for arch in stage.admission.ARCHES:
                prefix = stage.asset_prefix(source, arch)
                value["publisher_verification"][arch] = dict(
                    schema="edr.windows.publisher-verification.v1", verifier_source_commit=stage.VERIFIER_COMMIT,
                    version=source.tag[4:], arch=arch, thumbprint="A" * 40, subject_sha256="b" * 64,
                    subject_der_sha256="c" * 64,
                    **{key: hashes[prefix + suffix] for key, suffix in stage.SIGNED_ARTIFACT_PROOF.items()})
    return request


class MaintenanceRequestTests(unittest.TestCase):
    def test_exact_redacted_request_required_before_download_or_output(self):
        request = request_fixture()
        changed = copy.deepcopy(request)
        changed["legacy"]["assets"][0]["size"] += 1
        with patch.object(stage, "REQUEST_SHA256", stage.request_digest(request)):
            for arch in stage.admission.ARCHES:
                self.assertEqual(set(stage.validate_request(request, arch)), set(stage.SOURCES))
            with tempfile.TemporaryDirectory() as folder, patch.object(stage.admission, "api") as network:
                root = Path(folder) / "stage"
                with self.assertRaisesRegex(ValueError, "exact redacted"):
                    stage.stage_pair(changed, "amd64", root)
                network.assert_not_called()
                self.assertFalse(root.exists())

    def test_redacted_receipts_cover_both_architectures_and_exact_assets(self):
        for mutation in ("missing-arch", "raw-subject", "other-manifest"):
            with self.subTest(mutation=mutation):
                request = request_fixture()
                proofs = request["target"]["publisher_verification"]
                if mutation == "missing-arch":
                    del proofs["arm64"]
                elif mutation == "raw-subject":
                    proofs["arm64"]["subject"] = "unexpected"
                else:
                    proofs["arm64"]["manifest_sha256"] = "0" * 64
                with patch.object(stage, "REQUEST_SHA256", stage.request_digest(request)):
                    with self.assertRaises(ValueError):
                        stage.validate_request(request, "amd64")


class OfficialSourceTests(unittest.TestCase):
    def test_original_unsigned_prerelease_and_signed_drafts_have_distinct_state(self):
        request = request_fixture()
        for label, source in stage.SOURCES.items():
            with self.subTest(label=label):
                owner = dict(repository=stage.admission.PUBLIC, tag=source.tag, mode=source.mode,
                             commit=source.commit, run_id=str(source.run))
                signed = source.mode != "unsigned"
                body = "<!-- edr-release-source:" + json.dumps(owner) + " -->"
                if signed:
                    body += "\n<!-- edr-release-validation-only:true -->"
                info = dict(id=source.release_id, tag_name=source.tag, target_commitish=source.commit,
                            draft=signed, prerelease=not signed, body=body, assets=request[label]["assets"])
                assets = stage.admission.checked_assets(info["assets"])
                with patch.object(stage.admission, "api", return_value=info) as fetch:
                    self.assertEqual(stage.release_owner(source, assets), owner)
                    fetch.assert_called_once_with(stage.admission.PUBLIC, f"releases/{source.release_id}")
                    del info["prerelease"]
                    with self.assertRaisesRegex(ValueError, "ownership/state"):
                        stage.release_owner(source, assets)
                    info["prerelease"] = not signed
                    info["assets"][0]["id"] += len(info["assets"])
                    with self.assertRaisesRegex(ValueError, "asset ID, size or digest"):
                        stage.release_owner(source, assets)

    def test_signed_draft_requires_its_successful_builds_and_finalize(self):
        source = stage.SOURCES["target"]
        run = dict(id=source.run, run_attempt=source.attempt, head_sha=source.commit, status="completed",
                   conclusion="failure", path=".github/workflows/edr-agent-client-release.yml",
                   repository={"full_name": stage.admission.PUBLIC},
                   head_repository={"full_name": stage.admission.PUBLIC})
        jobs = [dict(name=name, status="completed", conclusion="success", run_attempt=source.attempt)
                for name in ("Build Windows amd64 (native)", "Build Windows arm64 (native)",
                             "Finalize USB release (one private handoff)")]
        with patch.object(stage.admission, "api", return_value=run):
            with patch.object(stage.admission, "jobs", return_value=jobs):
                stage.assert_source_run(source)
                jobs[-1]["conclusion"] = "skipped"
                with self.assertRaisesRegex(ValueError, "USB finalize"):
                    stage.assert_source_run(source)


class AdmissionStatusTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name) / "stage"
        self.request_path = self.root.parent / "request.json"
        self.status_path = self.root.parent / "admission-status.json"
        self.request = request_fixture()
        self.request_path.write_text(json.dumps(self.request), encoding="utf-8")
        identity = patch.object(stage, "REQUEST_SHA256", stage.request_digest(self.request))
        identity.start()
        self.addCleanup(identity.stop)

    def invoke(self, status_path=None):
        stage.main(["--request", str(self.request_path), "--arch", "amd64", "--root", str(self.root),
                    "--status", str(self.status_path if status_path is None else status_path)])

    def assert_status(self, code):
        report = stage.admission.read(self.status_path)
        self.assertEqual(report, {"schema": "edr.formal-maintenance-admission-status.v1", "cause_code": code})
        self.assertIs(type(report["cause_code"]), int)

    def test_release_api_failure_retains_read_cause(self):
        failed = subprocess.CompletedProcess(["gh"], 1, "", "transport error")
        with patch.object(subprocess, "run", return_value=failed), patch.object(stage.admission.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "GitHub read failed"):
                self.invoke()
        self.assert_status(1)

    def test_changed_asset_bytes_retain_asset_cause(self):
        source = stage.SOURCES["legacy"]
        owner = dict(repository=stage.admission.PUBLIC, tag=source.tag, mode=source.mode,
                     commit=source.commit, run_id=str(source.run))
        release = dict(id=source.release_id, tag_name=source.tag, target_commitish=source.commit,
                       draft=False, prerelease=True, assets=self.request["legacy"]["assets"],
                       body="<!-- edr-release-source:" + json.dumps(owner) + " -->")
        run = dict(id=source.run, run_attempt=source.attempt, head_sha=source.commit,
                   repository={"full_name": stage.admission.PUBLIC},
                   head_repository={"full_name": stage.admission.PUBLIC},
                   path=".github/workflows/edr-agent-client-release.yml", status="completed", conclusion="success")
        changed_asset = next(row for row in release["assets"] if row["name"].endswith("amd64-exe.zip"))
        api = f"repos/{stage.admission.PUBLIC}"

        def gh(args, **kwargs):
            endpoint = args[2]
            if endpoint == f"{api}/releases/assets/{changed_asset['id']}":
                kwargs["stdout"].write(b"x" * changed_asset["size"])
                return subprocess.CompletedProcess(args, 0)
            metadata = {
                f"{api}/releases/{source.release_id}": release,
                f"{api}/actions/runs/{source.run}/attempts/{source.attempt}": run,
            }
            return subprocess.CompletedProcess(args, 0, json.dumps(metadata[endpoint]))

        with patch.object(subprocess, "run", side_effect=gh):
            with self.assertRaisesRegex(ValueError, "Downloaded official asset size/digest mismatch"):
                self.invoke()
        self.assert_status(3)
        self.assertFalse((self.root / "stage.json").exists())

    def test_invalid_request_retains_request_cause_before_reads(self):
        self.request_path.write_text("{}", encoding="utf-8")
        with patch.object(subprocess, "run") as network:
            with self.assertRaisesRegex(ValueError, "exact redacted"):
                self.invoke()
            network.assert_not_called()
        self.assert_status(7)

    def test_status_path_cannot_create_a_file_inside_package_staging(self):
        with patch.object(subprocess, "run") as network:
            with self.assertRaisesRegex(ValueError, "outside the staging directory"):
                self.invoke(self.root / "legacy" / "runtime" / "status.json")
            network.assert_not_called()
        self.assertFalse(self.root.exists())


class RuntimeAdmissionTests(unittest.TestCase):
    def test_original_protocol_five_cannot_take_the_long_publisher_proof(self):
        legacy, baseline = stage.SOURCES["legacy"], stage.SOURCES["baseline"]
        with tempfile.TemporaryDirectory() as folder:
            updater = Path(folder) / "edr_agent_inplace_update.ps1"
            updater.write_text("$AgentUpdateUpdaterProtocolVersion = 5\n")
            stage.assert_original_protocol(updater, legacy)
            with self.assertRaisesRegex(ValueError, "original embedded updater protocol"):
                stage.assert_original_protocol(updater, baseline)
            updater.write_text("param(\n  [string]$TrustedPublisherSubjectDerSha256 = ''\n)\n"
                               "$AgentUpdateUpdaterProtocolVersion = 6\n")
            stage.assert_original_protocol(updater, baseline)
            with self.assertRaisesRegex(ValueError, "original embedded updater protocol"):
                stage.assert_original_protocol(updater, legacy)

    def test_full_signed_archive_uses_windows_separators_without_repacking(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / "runtime.zip"
            name = "collector\\worker.exe"
            content = b"original native bytes"
            write_runtime_archive(archive, [(name, content)])
            with zipfile.ZipFile(archive) as package:
                member, = package.infolist()
                self.assertEqual(member.orig_filename, name)
                self.assertEqual(member.filename, name.replace(os.sep, "/"))
                self.assertEqual(package.read(member), content)
            archive_sha = stage.admission.digest(archive)
            with self.assertRaisesRegex(ValueError, "Unsafe package path"):
                stage.admission.extract(archive, Path(folder) / "old")
            destination = Path(folder) / "runtime"
            stage.unpack_runtime(archive, destination)
            self.assertEqual((destination / "collector/worker.exe").read_bytes(), content)
            self.assertEqual(stage.admission.digest(archive), archive_sha)

    def test_windows_separator_does_not_admit_traversal_or_case_collisions(self):
        for names in (("collector\\..\\escape",), ("collector\\file", "COLLECTOR/File")):
            with self.subTest(names=names), tempfile.TemporaryDirectory() as folder:
                archive = Path(folder) / "runtime.zip"
                write_runtime_archive(archive, [(name, b"data") for name in names])
                destination = Path(folder) / "runtime"
                with self.assertRaises(ValueError):
                    stage.unpack_runtime(archive, destination)
                self.assertFalse(destination.exists())

    def test_publisher_reconstructed_from_verified_exact_utf8_subject(self):
        subject = "CN=" + "测" * 180
        proof = request_fixture()["baseline"]["publisher_verification"]["amd64"]
        proof["subject_sha256"] = hashlib.sha256(subject.encode("utf-8")).hexdigest()
        manifest = {"signature": dict(format="cms-detached-sha256", status="signed", authenticode_scope="headless",
                                      signer_thumbprint=proof["thumbprint"], signer_subject=subject)}
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "proof.json"
            stage.bind_publisher(manifest, proof, out)
            loaded = stage.admission.read(out)
            self.assertEqual(loaded.pop("subject"), subject)
            self.assertEqual(loaded, {key: value for key, value in proof.items() if key != "subject_sha256"})
            manifest["signature"]["signer_subject"] = subject + "X"
            with self.assertRaisesRegex(ValueError, "differs from the original backend verification"):
                stage.bind_publisher(manifest, proof, Path(folder) / "altered.json")
            self.assertFalse((Path(folder) / "altered.json").exists())


if __name__ == "__main__":
    unittest.main()
