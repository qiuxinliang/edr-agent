"""Stage the fixed 687 → 752 → 753 native Windows maintenance exercise."""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import headless_repack_lifecycle as admission
from stage_signed_publisher_lifecycle import VERIFIER_COMMIT
from windows_release_checkpoint import (MARKER, asset_names, marker_scope, marker_validation_only,
                                        prepare_lifecycle_upgrade)
from windows_usb_bundle import unpack

REQUEST_SCHEMA = "edr.formal-maintenance-validation.v1"
# Canonical JSON binds both architectures' official asset IDs, sizes, hashes
# and the redacted output of the original backend verifier.
REQUEST_SHA256 = "9d7c9056b03eccf7bba100699cd05a2ef6e6b7f00f1afb8f82430f80e37c7d52"
SHA256 = re.compile(r"[a-f0-9]{64}")
SIGNED_ARTIFACT_PROOF = {
    "manifest_sha256": "artifact-manifest.json",
    "signature_sha256": "artifact-manifest.json.p7s",
    "artifact_sha256": "FDSensor.exe",
}


@dataclass(frozen=True)
class Source:
    tag: str
    commit: str
    run: int
    attempt: int
    release_id: int
    mode: str
    updater_protocol: int


SOURCES = {
    "legacy": Source("win_3.2.687", "97064865522c6aebd050fab9675c7eb34697ece6", 38814603184, 1,
                     414318483, "unsigned", 5),
    "baseline": Source("win_3.2.752", "408f5c5f2a325d08e3eb09d6b50eac87bf6694e3", 45548404329, 3,
                       457660456, "usb", 6),
    "target": Source("win_3.2.753", "a175b978f98fce2936bda44636ab48a7d40da547", 46125713052, 2,
                     461409595, "usb", 6),
}


def request_digest(request):
    return hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def asset_prefix(source, arch):
    return f"edr-agent-{source.tag}-windows-{arch}-"


def validate_request(request, arch):
    if (not isinstance(request, dict) or set(request) != {"schema", *SOURCES}
            or request["schema"] != REQUEST_SCHEMA or request_digest(request) != REQUEST_SHA256
            or arch not in admission.ARCHES):
        raise ValueError("The exact redacted maintenance request is required")
    assets, publishers = {}, set()
    for label, source in SOURCES.items():
        value = request[label]
        signed = source.mode != "unsigned"
        if set(value) != ({"assets", "publisher_verification"} if signed else {"assets"}):
            raise ValueError("Unexpected maintenance request fields")
        assets[label] = admission.checked_assets(value["assets"])
        names = set.union(*(asset_names({"tag": source.tag, "mode": source.mode}, row)
                            for row in admission.ARCHES))
        if set(assets[label]) != names:
            raise ValueError("Maintenance request must bind the complete Full Release asset set")
        if signed:
            proofs = value["publisher_verification"]
            if set(proofs) != set(admission.ARCHES):
                raise ValueError("Backend verification for both native architectures is required")
            for proof_arch, proof in proofs.items():
                if (set(proof) != {"schema", "verifier_source_commit", "version", "arch", "thumbprint",
                                  "subject_sha256", "subject_der_sha256", *SIGNED_ARTIFACT_PROOF}
                        or proof["schema"] != "edr.windows.publisher-verification.v1"
                        or proof["verifier_source_commit"] != VERIFIER_COMMIT
                        or proof["version"] != source.tag[4:] or proof["arch"] != proof_arch
                        or not re.fullmatch(r"[A-F0-9]{40}", proof["thumbprint"])
                        or not all(SHA256.fullmatch(proof[key]) for key in ("subject_sha256", "subject_der_sha256"))):
                    raise ValueError("Maintenance requires a redacted original backend proof")
                prefix = asset_prefix(source, proof_arch)
                if any(proof[key] != assets[label][prefix + suffix]["digest"][7:]
                       for key, suffix in SIGNED_ARTIFACT_PROOF.items()):
                    raise ValueError("Backend verification and official Release hashes disagree")
                publishers.add((proof["thumbprint"], proof["subject_sha256"], proof["subject_der_sha256"]))
    if len(publishers) != 1:
        raise ValueError("All signed inputs must use the same verified publisher")
    return assets


def release_owner(source, assets):
    info = admission.api(admission.PUBLIC, f"releases/{source.release_id}")
    signed = source.mode != "unsigned"
    markers = MARKER.findall(info.get("body") or "")
    if (info.get("id") != source.release_id or info.get("tag_name") != source.tag
            or info.get("target_commitish") != source.commit or info.get("draft") is not signed
            or info.get("prerelease") is not (not signed) or marker_scope(info) != "full"
            or marker_validation_only(info) is not signed
            or len(markers) != 1):
        raise ValueError(f"{source.tag} Full Release ownership/state mismatch")
    owner = json.loads(markers[0], object_pairs_hook=admission.unique)
    expected = dict(repository=admission.PUBLIC, tag=source.tag, mode=source.mode,
                    commit=source.commit, run_id=str(source.run))
    if not isinstance(owner, dict) or any(owner.get(key) != value for key, value in expected.items()):
        raise ValueError(f"{source.tag} Release provenance mismatch")
    if admission.checked_assets(info.get("assets")) != assets:
        raise ValueError(f"{source.tag} official Release asset ID, size or digest changed")
    return owner


def assert_source_run(source):
    run = admission.api(admission.PUBLIC, f"actions/runs/{source.run}/attempts/{source.attempt}")
    if (run.get("id") != source.run or run.get("run_attempt") != source.attempt
            or run.get("head_sha") != source.commit
            or run.get("repository", {}).get("full_name") != admission.PUBLIC
            or run.get("head_repository", {}).get("full_name") != admission.PUBLIC
            or run.get("path") != ".github/workflows/edr-agent-client-release.yml"
            or run.get("status") != "completed"):
        raise ValueError(f"{source.tag} original source attempt mismatch")
    if source.mode == "unsigned":
        if run.get("conclusion") != "success":
            raise ValueError("The published legacy source attempt must have succeeded")
        return
    jobs = admission.jobs(admission.PUBLIC, source.run, source.attempt)
    # These are existing signed drafts. Their native build and sealing jobs
    # succeeded, even when the separate install/upgrade gate failed.
    job_names = [f"Build Windows {arch} (" for arch in admission.ARCHES]
    job_names.append("Finalize USB release (")
    for name in job_names:
        matches = [job for job in jobs if job.get("name", "").startswith(name)]
        if (len(matches) != 1 or matches[0].get("status") != "completed"
                or matches[0].get("conclusion") != "success"
                or matches[0].get("run_attempt") != source.attempt):
            raise ValueError(f"{source.tag} original native build or USB finalize job did not succeed")


def unpack_runtime(archive, destination):
    # The official USB signer uses Windows separators for nested ZIP members.
    # Keep the signed archive untouched and apply the existing traversal guard
    # to the same normalized paths the official unpacker will write.
    with zipfile.ZipFile(archive) as package:
        for entry in package.infolist():
            admission.safe_parts(entry.orig_filename.replace("\\", "/"))
            if (entry.flag_bits & 1 or entry.file_size > admission.MAX_FILE
                    or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                raise ValueError("Unsafe official runtime archive member")
    unpack(archive, destination)


def assert_original_protocol(path, source):
    text = path.read_text(encoding="utf-8-sig")
    protocols = re.findall(r"(?m)^\$AgentUpdateUpdaterProtocolVersion[ \t]*=[ \t]*([0-9]+)[ \t]*$", text)
    has_der_parameter = bool(re.search(r"(?m)^[ \t]*\[string\][ \t]*\$TrustedPublisherSubjectDerSha256\b", text))
    if protocols != [str(source.updater_protocol)] or has_der_parameter != (source.updater_protocol == 6):
        raise ValueError(f"{source.tag} original embedded updater protocol mismatch")


def bind_publisher(manifest, proof, destination):
    signature = manifest["signature"]
    subject = signature.get("signer_subject")
    if (not isinstance(subject, str) or not 256 < len(subject.encode("utf-8")) <= 2048
            or hashlib.sha256(subject.encode("utf-8")).hexdigest() != proof["subject_sha256"]
            or signature != dict(format="cms-detached-sha256", status="signed", authenticode_scope="headless",
                                 signer_thumbprint=proof["thumbprint"], signer_subject=subject)):
        raise ValueError("Signed Full Release publisher differs from the original backend verification")
    # Keep the canonical subject inside the disposable runner's private stage
    # directory. The public workflow input contains only its hash.
    full_proof = {key: value for key, value in proof.items() if key != "subject_sha256"}
    full_proof["subject"] = subject
    destination.write_text(json.dumps(full_proof) + "\n", encoding="utf-8")
    return full_proof


def stage_release(directory, arch, source, assets, proof):
    owner = release_owner(source, assets)
    assert_source_run(source)
    signed = source.mode != "unsigned"
    payload = directory / "target" if signed else directory
    prefix = asset_prefix(source, arch)
    suffixes = ("exe.zip", "setup.exe", "artifact-manifest.json")
    if signed:
        suffixes += ("artifact-manifest.json.p7s",)
    for suffix in suffixes:
        name = prefix + suffix
        admission.fetch(admission.PUBLIC, assets[name], payload / name)
    runtime = payload / "runtime"
    unpack_runtime(payload / (prefix + "exe.zip"), runtime)
    admission.runtime_contract(runtime, assets, source.tag, arch, signed)
    assert_original_protocol(runtime / "edr_agent_inplace_update.ps1", source)
    manifest = admission.read(payload / (prefix + "artifact-manifest.json"))
    if (manifest.get("schema_version") != 1 or manifest.get("version") != source.tag[4:]
            or manifest.get("build_provenance") != owner or "repack_provenance" in manifest):
        raise ValueError(f"{source.tag} Full artifact manifest provenance mismatch")
    expected_entries = {prefix + suffix for suffix in ("exe.zip", "setup.exe", "setup-ui.zip", "FDSensor.exe")}
    entries = manifest["artifacts"]
    if (len(entries) != len(expected_entries) or {entry["name"] for entry in entries} != expected_entries
            or any(entry["size"] != assets[entry["name"]]["size"] or
                   entry["sha256"] != assets[entry["name"]]["digest"][7:] for entry in entries)):
        raise ValueError(f"{source.tag} artifact manifest does not bind the official Full Release assets")
    if signed:
        full_proof = bind_publisher(manifest, proof, directory / "publisher-verification.json")
        # Existing Verify mode checks timestamped native Authenticode and both
        # detached CMS manifests for the declared Headless signing scope.
        verifier_input = dict(schema="edr.headless-lifecycle-input.v1", architecture=arch,
                              source={"owner": {"tag": source.tag}}, publisher_thumbprint=full_proof["thumbprint"],
                              publisher_subject=full_proof["subject"])
        (directory / "admission.json").write_text(json.dumps(verifier_input) + "\n", encoding="utf-8")
    elif (manifest["signature"].get("format") != "none" or manifest["signature"].get("status") != "unsigned"
          or manifest["signature"].get("signer_thumbprint") or manifest["signature"].get("signer_subject")
          or (runtime / "full-installer-manifest.p7s").exists()
          or admission.pe((payload / (prefix + "setup.exe")).read_bytes(), arch, installer=True)[2] != (0, 0)
          or admission.pe((runtime / "FDSensor.exe").read_bytes(), arch)[2] != (0, 0)):
        raise ValueError("The published original 687 input requires its original unsigned policy")
    if release_owner(source, assets) != owner:
        raise ValueError(f"{source.tag} Release provenance changed during admission")
    return payload


def stage_pair(request, arch, root):
    assets = validate_request(request, arch)
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=False)
    result = dict(schema="edr.formal-maintenance-stage.v1", architecture=arch,
                  cohort="687-752-753-maintenance")
    packages = {}
    for label, source in SOURCES.items():
        proof = request[label].get("publisher_verification", {}).get(arch)
        payload = stage_release(root / label, arch, source, assets[label], proof)
        prefix = asset_prefix(source, arch)
        packages[label] = payload
        result.update({
            f"{label}_version": source.tag[4:],
            f"{label}_setup_exe": str(payload / (prefix + "setup.exe")),
            f"{label}_setup_sha256": assets[label][prefix + "setup.exe"]["digest"][7:],
            f"{label}_binary_sha256": assets[label][prefix + "FDSensor.exe"]["digest"][7:],
            f"{label}_signature_status": "unsigned" if source.mode == "unsigned" else "signed",
            f"{label}_updater_protocol": source.updater_protocol,
        })
    migration = prepare_lifecycle_upgrade(packages["baseline"], packages["legacy"], root / "migration",
        SOURCES["baseline"].tag, SOURCES["legacy"].tag, arch, root / "baseline" / "publisher-verification.json")
    upgrade = prepare_lifecycle_upgrade(packages["target"], packages["baseline"], root / "upgrade",
        SOURCES["target"].tag, SOURCES["baseline"].tag, arch, root / "target" / "publisher-verification.json")
    if (migration["upgrade_class"] != "installer_required" or upgrade["upgrade_class"] != "installer_required"
            or migration["baseline_setup_sha256"] != result["legacy_setup_sha256"]
            or migration["installer_sha256"] != result["baseline_setup_sha256"]
            or upgrade["baseline_setup_sha256"] != result["baseline_setup_sha256"]
            or upgrade["installer_sha256"] != result["target_setup_sha256"]
            or migration["target_updater_sha256"] != upgrade["baseline_updater_sha256"]):
        raise ValueError("Migration and upgrade do not share the original full Setups and embedded updater")
    template = packages["legacy"] / "runtime" / "agent_windows_production.example.toml"
    if not template.is_file():
        raise ValueError("Original 687 runtime configuration template is missing")
    result.update(migration_input=str(root / "migration" / "transition.json"),
                  upgrade_input=str(root / "upgrade" / "transition.json"), legacy_config_template=str(template))
    (root / "stage.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--arch", choices=tuple(admission.ARCHES), required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    if not 0 < args.request.stat().st_size <= 32768:
        raise ValueError("Maintenance request exceeds bounded input size")
    stage_pair(admission.read(args.request), args.arch, args.root)
    print("Three pinned Full Setup inputs and both transitions verified")


if __name__ == "__main__":
    main()
