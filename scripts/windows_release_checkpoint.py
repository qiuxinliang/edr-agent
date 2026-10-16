#!/usr/bin/env python3
"""Version ownership and same-run release checkpoints; never overwrite assets.

GitHub I/O is isolated behind CLI so tests exercise the actual reconciliation
and integrity checks without publishing a release. Checkpoints are CI evidence,
not a replacement for Authenticode, CMS or endpoint update verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


CHECKPOINT = "release-checkpoint.json"
MARKER = re.compile(r"<!-- edr-release-source:(.*?) -->")
SCOPE_MARKER = re.compile(r"<!-- edr-release-package-scope:(.*?) -->")
UNSIGNED = ("WARNING: This Windows build is unsigned. Windows may show an unknown-publisher "
            "warning. Use only where the platform explicitly permits optional-signature "
            "installation/update with verified SHA-256 artifact hashes. "
            "Platform/Agent signature requirements are not changed by this release.\n")
BROKEN_SETUP_BASELINE_MIN = (3, 2, 304)
BROKEN_SETUP_BASELINE_MAX = (3, 2, 341)
P0_TEST_INPUTS_REPOSITORY = "qiuxinliang/EDRAI"
P0_TEST_INPUT_FILES = ("p0_rule_bundle_ir_v1.json", "p0_rule_bundle_ir_v1.json.enc",
                       "sensor_interest_manifest.json")


def windows_release_version(tag):
    match = re.fullmatch(r"win_(\d+)\.(\d+)\.(\d+)", tag) if isinstance(tag, str) else None
    if match is None:
        raise ValueError("Invalid Windows release tag; expected win_M.m.p")
    return tuple(int(part) for part in match.groups())


def package_scope(env=os.environ):
    value = env.get("EDR_RELEASE_PACKAGE_SCOPE", "full")
    if value not in ("full", "headless"):
        raise ValueError("Unsupported release package scope")
    return value


def validate_scope(env=os.environ):
    scope = package_scope(env)
    if scope == "headless" and (env.get("WINDOWS_RELEASE_MODE") != "unsigned" or
                               env.get("EDR_RELEASE_CANDIDATE") != "true"):
        raise ValueError("Headless scope requires unsigned mode and candidate=true")
    return scope


def marker_scope(info):
    values = SCOPE_MARKER.findall(info.get("body") or "")
    if not values:
        return "full"
    if len(values) != 1 or values[0] not in ("full", "headless"):
        raise ValueError("Release has an invalid or ambiguous package scope")
    return values[0]


def baseline_rejection(info, target_version, *, package_scope="full"):
    """A baseline has already passed publication gates, including both arches.

    Published prereleases are verified candidates in this repository. Drafts
    have not passed those gates, even when all their assets have been uploaded.
    Historical provenance belongs to that release, not the current target.
    """
    if package_scope not in ("full", "headless"):
        raise ValueError("Unsupported release package scope")
    if info.get("draft") is not False:
        return "release is a draft or has no published state"
    try:
        version = windows_release_version(info.get("tag_name"))
    except ValueError:
        return "release tag is not a supported Windows version"
    if version >= target_version:
        return "release must be strictly older than the target"
    if BROKEN_SETUP_BASELINE_MIN <= version <= BROKEN_SETUP_BASELINE_MAX:
        return "release is in the known-broken Setup range win_3.2.304..win_3.2.341"
    assets = info.get("assets")
    if not isinstance(assets, list) or any(not isinstance(asset, dict) for asset in assets):
        return "release has no valid asset metadata"
    for arch in ("amd64", "arm64"):
        prefix = f"edr-agent-{info['tag_name']}-windows-{arch}-"
        suffixes = (("exe.zip", "FDSensor.exe", "artifact-manifest.json") if package_scope == "headless"
                    else ("exe.zip", "setup.exe", "artifact-manifest.json"))
        for suffix in suffixes:
            name = prefix + suffix
            matches = [asset for asset in assets if asset.get("name") == name]
            if len(matches) != 1:
                return f"release must contain exactly one {name}"
            asset = matches[0]
            asset_digest = asset.get("digest")
            if (type(asset.get("id")) is not int or asset["id"] <= 0 or
                    not isinstance(asset.get("url"), str) or not asset["url"].startswith("https://") or
                    type(asset.get("size")) is not int or asset["size"] <= 0 or
                    (asset_digest not in (None, "") and
                     (not isinstance(asset_digest, str) or
                      not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", asset_digest)))):
                return f"release asset {name} has incomplete immutable metadata"
    return None


def select_baseline(releases, target_tag, baseline_tag="", *, package_scope="full"):
    """Return the newest eligible published baseline, or None when none exists.

    An explicit invalid baseline is an error. The target may still be a draft;
    its ownership and immutable downloads retain their separate existing gates.
    """
    target_version = windows_release_version(target_tag)
    if not isinstance(releases, list) or any(not isinstance(info, dict) for info in releases):
        raise ValueError("Invalid GitHub release list; baseline selection cannot proceed")
    if baseline_tag:
        windows_release_version(baseline_tag)
        matches = [info for info in releases if info.get("tag_name") == baseline_tag]
        if len(matches) != 1:
            raise ValueError(f"Baseline {baseline_tag} must resolve to exactly one release")
        rejection = baseline_rejection(matches[0], target_version, package_scope=package_scope)
        if rejection:
            raise ValueError(f"Baseline {baseline_tag} is not eligible: {rejection}")
        selected = matches[0]
    else:
        candidates = [info for info in releases if baseline_rejection(info, target_version, package_scope=package_scope) is None]
        if not candidates:
            for info in releases:
                try:
                    version = windows_release_version(info.get("tag_name"))
                except ValueError:
                    continue
                if info.get("draft") is False and version < target_version:
                    raise ValueError("No eligible published baseline: " + baseline_rejection(info, target_version, package_scope=package_scope))
            return None
        selected = max(candidates, key=lambda info: windows_release_version(info["tag_name"]))
        if sum(info.get("tag_name") == selected["tag_name"] for info in releases) != 1:
            raise ValueError(f"Baseline {selected['tag_name']} must resolve to exactly one release")
    return dict(tag=selected["tag_name"], state="published",
                setup_rollback_supported=windows_release_version(selected["tag_name"]) > BROKEN_SETUP_BASELINE_MAX)


def source(env=os.environ):
    validate_scope(env)
    result = {key: env[name] for key, name in (
        ("tag", "EDR_AGENT_RELEASE_TAG"), ("commit", "GITHUB_SHA"),
        ("repository", "GITHUB_REPOSITORY"), ("run_id", "GITHUB_RUN_ID"),
        ("mode", "WINDOWS_RELEASE_MODE"), ("upgrade_class", "EDR_UPGRADE_CLASS_OVERRIDE"))}
    if not re.fullmatch(r"win_\d+\.\d+\.\d+(?:-unsigned)?", result["tag"]):
        raise ValueError("Invalid release version; expected win_M.m.p")
    if not re.fullmatch(r"[0-9a-f]{40}", result["commit"]) or not result["run_id"].isdigit():
        raise ValueError("Invalid release source identity")
    if result["mode"] not in ("signed", "unsigned", "usb"):
        raise ValueError("Unsupported release mode")
    if result["mode"] == "usb" and result["upgrade_class"] == "binary_hot":
        raise ValueError("USB signing changes runtime identities; use auto or installer_required")
    ref, sha = env.get("P0_TEST_INPUTS_REF", ""), env.get("P0_TEST_INPUTS_SHA256", "")
    if ref or sha:
        if not re.fullmatch(r"[0-9a-f]{40}", ref) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError("Private P0 test input identity requires a fixed commit and verified SHA256")
        result["p0_test_inputs"] = dict(repository=P0_TEST_INPUTS_REPOSITORY, commit=ref, sha256=sha)
    return result


def verify_p0_test_inputs(directory, ref, expected_sha=""):
    """Check the private test snapshot before draft/checkpoint reuse; never print rules."""
    if not re.fullmatch(r"[0-9a-f]{40}", ref):
        raise ValueError("P0_TEST_INPUTS_REF must be a fixed 40-hex commit")
    checkout = subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=30)
    if checkout.returncode or checkout.stdout.strip() != ref:
        raise ValueError("Private P0 test input checkout does not match the frozen commit")
    data = {}
    for name in P0_TEST_INPUT_FILES:
        path = Path(directory) / name
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 4 * 1024**2:
            raise ValueError(f"Missing, unsafe or oversized private P0 test input: {name}")
        data[name] = path.read_bytes()
    import encrypt_p0_rules as envelope
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    wire, plain = data[P0_TEST_INPUT_FILES[1]], data[P0_TEST_INPUT_FILES[0]]
    if len(wire) < len(envelope.MAGIC) + envelope.NONCE_LEN + 16 or not wire.startswith(envelope.MAGIC):
        raise ValueError("Private P0 encrypted test input is not an EDR1 envelope")
    key = envelope.hkdf_sha256(envelope.HKDF_SALT, envelope.SEED, envelope.HKDF_INFO, envelope.KEY_LEN)
    try:
        decoded = AESGCM(key).decrypt(wire[4:4 + envelope.NONCE_LEN], wire[4 + envelope.NONCE_LEN:], None)
    except Exception as error:
        raise ValueError("Private P0 test input envelope authentication failed") from error
    if decoded != plain:
        raise ValueError("Private P0 plaintext/encrypted test inputs disagree")
    def unique_object(pairs):
        value = {}
        for name, item in pairs:
            if name in value:
                raise ValueError("Duplicate private P0 test input JSON field")
            value[name] = item
        return value
    ir = json.loads(plain, object_pairs_hook=unique_object)
    sensor_raw = data[P0_TEST_INPUT_FILES[2]]
    sensor = json.loads(sensor_raw, object_pairs_hook=unique_object)
    if not isinstance(ir, dict) or not isinstance(sensor, dict):
        raise ValueError("Private P0 test input JSON must contain objects")
    count = ir.get("rule_count")
    if (ir.get("kind") != "edr_p0_rule_bundle_ir_v1" or ir.get("ir_schema_version") not in (7, 8, 9) or
            type(count) is not int or count <= 0 or not isinstance(ir.get("rules"), list) or
            len(ir["rules"]) != count or sensor.get("kind") != "edr_sensor_interest_manifest" or
            sensor.get("p0_artifact_rule_count") != count or
            not ir.get("rules_bundle_version") or sensor.get("rules_bundle_version") != ir["rules_bundle_version"] or
            sensor.get("p0_artifact_sha256") != hashlib.sha256(plain).hexdigest()):
        raise ValueError("Private P0 test input IR/SensorInterest identity mismatch")
    fields = list(re.finditer(rb'"p0_artifact_sha256"\s*:\s*"([0-9a-f]{64})"', sensor_raw))
    if len(fields) != 1 or ir.get("sensor_interest_manifest_hash_mode") != "raw-json-v1-p0-artifact-sha256-zeroed":
        raise ValueError("Private P0 test input SensorInterest hash contract is invalid")
    start, end = fields[0].span(1)
    paired_sha = hashlib.sha256(sensor_raw[:start] + b"0" * 64 + sensor_raw[end:]).hexdigest()
    if paired_sha != ir.get("sensor_interest_manifest_sha256"):
        raise ValueError("Private P0 test input SensorInterest raw binding mismatch")
    for name, raw in data.items():
        committed = subprocess.run(["git", "-C", str(directory), "show", f"{ref}:{name}"],
                                   capture_output=True, timeout=30)
        if committed.returncode or committed.stdout != raw:
            raise ValueError(f"Private P0 test input differs from its committed bytes: {name}")
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in data.items()}
    sha = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if expected_sha and sha != expected_sha:
        raise ValueError("Private P0 test input digest differs from the frozen prepare job")
    return sha


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class GitHub:
    def __init__(self, repository):
        self.repository = repository

    def call(self, *args, missing=False):
        result = subprocess.run(["gh", *args], capture_output=True, text=True,
                                encoding="utf-8", timeout=300)
        if result.returncode:
            if missing and "HTTP 404" in result.stderr:
                return None
            raise RuntimeError(f"GitHub operation failed: {result.stderr.strip()[-1000:]}")
        return result.stdout

    def release(self, tag):
        # REST /releases/tags/{tag} can return 404 for an existing draft, even
        # with write access. GraphQL release(tagName:) resolves both states.
        owner, name = self.repository.split("/", 1)
        value = self.call("api", "graphql", "-f", "query=" + """
            query($owner: String!, $name: String!, $tag: String!) {
              repository(owner: $owner, name: $name) {
                release(tagName: $tag) {
                  id: databaseId tag_name: tagName
                }
              }
            }
            """, "-f", f"owner={owner}", "-f", f"name={name}", "-f", f"tag={tag}")
        response = json.loads(value)
        repository = (response.get("data") or {}).get("repository")
        if response.get("errors") or repository is None:
            raise RuntimeError("Release lookup failed; check GitHub repository access, not draft existence")
        info = repository["release"]
        if info is None:
            return None
        if info.get("tag_name") != tag or not isinstance(info.get("id"), int):
            raise RuntimeError("Release lookup returned an invalid tag/ID binding")
        # Fetch the REST representation by stable ID (including target_commitish,
        # which is not a GraphQL Release field), then paginate its assets.
        info = json.loads(self.call("api", f"repos/{self.repository}/releases/{info['id']}"))
        if info.get("tag_name") != tag:
            raise RuntimeError("Release tag changed during lookup; refusing mutation")
        # The embedded asset list can be paginated independently of the release.
        pages = self.call("api", f"repos/{self.repository}/releases/{info['id']}/assets?per_page=100",
                          "--paginate", "--slurp")
        info["assets"] = [item for page in json.loads(pages) for item in page]
        return info

    def releases(self):
        pages = json.loads(self.call("api", f"repos/{self.repository}/releases?per_page=100",
                                     "--paginate", "--slurp"))
        if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
            raise ValueError("Invalid paginated GitHub release response")
        return [info for page in pages for info in page]

    def tag_commit(self, tag):
        value = self.call("api", f"repos/{self.repository}/git/ref/tags/{tag}", missing=True)
        if value is None:
            return None
        obj = json.loads(value)["object"]
        for _ in range(8):
            if obj["type"] == "commit":
                return obj["sha"]
            if obj["type"] != "tag":
                break
            obj = json.loads(self.call("api", f"repos/{self.repository}/git/tags/{obj['sha']}"))["object"]
        raise ValueError("Release tag does not resolve to a commit")

    def download(self, tag, name, destination):
        self.call("release", "download", tag, "--repo", self.repository,
                  "--pattern", name, "--dir", str(destination))

    def upload(self, tag, path):
        self.call("release", "upload", tag, str(path), "--repo", self.repository)


def require_owner(info, expected, *, published=False, package_scope="full"):
    if info is None:
        raise ValueError("Release draft is missing; rerun the original prepare job")
    matches = MARKER.findall(info.get("body") or "")
    if len(matches) != 1:
        raise ValueError("Release has no unique source binding; use a new version, do not overwrite this draft")
    actual = json.loads(matches[0])
    if marker_scope(info) != package_scope:
        raise ValueError("Release belongs to another package scope")
    keys = set(expected) - ({"run_id"} if published else set())
    if any(actual.get(key) != expected[key] for key in keys):
        raise ValueError("Release belongs to another commit, mode or run; rerun failed jobs of the original run or use a new version")


def prepare(api, expected, *, package_scope="full"):
    asset_names(expected, "amd64", package_scope=package_scope)
    tag = expected["tag"]
    commit = api.tag_commit(tag)
    if commit is not None and commit != expected["commit"]:
        raise ValueError("Release tag does not resolve to this source commit")
    info = api.release(tag)
    if info is None:
        body = (UNSIGNED if expected["mode"] == "unsigned" else "")
        body += "<!-- edr-release-source:" + json.dumps(expected, sort_keys=True) + " -->"
        if package_scope == "headless":
            body += "\n<!-- edr-release-package-scope:headless -->"
        api.call("release", "create", tag, "--repo", api.repository, "--draft",
                 "--target", expected["commit"], "--title", f"edr-agent {tag}", "--notes", body)
        for attempt in range(3):
            info = api.release(tag)
            if info is not None:
                break
            if attempt < 2:
                time.sleep(2 ** attempt)
        if info is None:
            raise RuntimeError("Draft creation succeeded but the release is not visible after 3 checks; "
                               "check repository permissions and rerun the original prepare job")
    require_owner(info, expected, published=not info["draft"], package_scope=package_scope)
    verify_tag_target(api, info, expected)
    if package_scope == "headless":
        if not info["draft"] and info.get("prerelease") is not True:
            raise ValueError("Published Headless release must remain a prerelease candidate")
        check_headless_remote_assets(info, expected, complete=not info["draft"])
    return not info["draft"]


def verify_tag_target(api, info, expected):
    commit = api.tag_commit(expected["tag"])
    # GitHub may defer materializing a new tag until its draft is published.
    # Only an exact commit target is acceptable here, never a moving branch.
    if commit is None and info["draft"] and info.get("target_commitish") == expected["commit"]:
        return
    if commit != expected["commit"]:
        raise ValueError("Release tag no longer matches the verified source")


def verify_owner(api, expected, *, package_scope="full"):
    info = api.release(expected["tag"])
    if info is None:
        raise ValueError("Release draft is missing")
    require_owner(info, expected, package_scope=package_scope)
    if not info["draft"]:
        raise ValueError("Already published and immutable; mutation refused")
    verify_tag_target(api, info, expected)
    if package_scope == "headless":
        check_headless_remote_assets(info, expected)
    return info


def check_headless_remote_assets(info, expected, *, complete=False):
    allowed = set.union(*(asset_names(expected, arch, package_scope="headless")
                          for arch in ("amd64", "arm64")))
    names = [asset.get("name") for asset in info["assets"]]
    if (any(name not in allowed for name in names) or len(names) != len(set(names)) or
            (complete and set(names) != allowed)):
        raise ValueError("Headless release contains an unexpected, duplicated or incomplete asset set")


def asset_names(expected, arch, *, candidate=False, package_scope="full"):
    if arch not in ("amd64", "arm64"):
        raise ValueError("Invalid release architecture")
    prefix = f"edr-agent-{expected['tag']}-windows-{arch}-"
    if package_scope not in ("full", "headless") or (package_scope == "headless" and expected["mode"] != "unsigned"):
        raise ValueError("Unsupported release package scope/mode")
    suffixes = (("exe.zip", "FDSensor.exe", "artifact-manifest.json") if package_scope == "headless" else
                ("exe.zip", "setup.exe", "setup-ui.zip", "FDSensor.exe", "artifact-manifest.json"))
    names = {prefix + s for s in suffixes}
    if expected["mode"] in ("signed", "usb") and not candidate:
        names.add(prefix + "artifact-manifest.json.p7s")
    return names


def inspect_bundle(directory, expected, arch, *, candidate=False, package_scope="full"):
    directory = Path(directory)
    if candidate and expected["mode"] != "usb":
        raise ValueError("Only USB releases accept a pre-signing candidate")
    names = asset_names(expected, arch, candidate=candidate, package_scope=package_scope)
    actual = {p.name for p in directory.iterdir() if p.name != CHECKPOINT}
    if actual != names or any(not (directory / name).is_file() or (directory / name).is_symlink() for name in names):
        raise ValueError("Checkpoint must contain the exact complete architecture asset set")
    manifest_name = next(name for name in names if name.endswith("artifact-manifest.json"))
    manifest = json.loads((directory / manifest_name).read_text(encoding="utf-8-sig"))
    if manifest.get("build_provenance") != expected or manifest.get("version") != expected["tag"][4:].removesuffix("-unsigned"):
        raise ValueError("Manifest source/version mismatch")
    status = "unsigned" if candidate else ("signed" if expected["mode"] == "usb" else expected["mode"])
    if manifest.get("signature", {}).get("status") != status:
        raise ValueError("Manifest signing mode mismatch")
    files = {name: {"sha256": digest(directory / name), "size": (directory / name).stat().st_size} for name in names}
    entries = manifest.get("artifacts", [])
    payload = {name for name in names if not name.endswith(("artifact-manifest.json", ".p7s"))}
    if len(entries) != len(payload) or {e.get("name") for e in entries} != payload:
        raise ValueError("Manifest payload is incomplete or duplicated")
    for entry in entries:
        if any(entry.get(k) != files[entry["name"]][k] for k in ("sha256", "size")):
            raise ValueError(f"Manifest payload digest mismatch: {entry['name']}")
    record = {"source": expected, "arch": arch, "files": files}
    if package_scope == "headless":
        record["package_scope"] = package_scope
    return record


def seal(directory, expected, arch, *, candidate=False, package_scope="full"):
    record = inspect_bundle(directory, expected, arch, candidate=candidate, package_scope=package_scope)
    (Path(directory) / CHECKPOINT).write_text(json.dumps(record, sort_keys=True), encoding="utf-8")


def verify_checkpoint(directory, expected, arch, *, candidate=False, package_scope="full"):
    record = json.loads((Path(directory) / CHECKPOINT).read_text(encoding="utf-8"))
    if record != inspect_bundle(directory, expected, arch, candidate=candidate, package_scope=package_scope):
        raise ValueError("Checkpoint identity or file digest mismatch; refuse reuse")
    return record


def restore(api, directory, expected, arch, *, candidate=False, package_scope="full"):
    name = f"release-{'input' if candidate else 'checkpoint'}-{arch}"
    pages = api.call("api", f"repos/{api.repository}/actions/runs/{expected['run_id']}/artifacts?per_page=100",
                     "--paginate", "--slurp")
    candidates = [a for page in json.loads(pages) for a in page["artifacts"] if a["name"] == name]
    if not candidates:
        return False
    if len(candidates) != 1 or candidates[0]["expired"]:
        raise ValueError("Checkpoint expired or ambiguous; use a new release version")
    api.call("run", "download", expected["run_id"], "--repo", api.repository,
             "--name", name, "--dir", str(directory))
    verify_checkpoint(directory, expected, arch, candidate=candidate, package_scope=package_scope)
    return True


def remote_matches(api, tag, asset, local):
    if asset["size"] != local.stat().st_size:
        return False
    remote_digest = asset.get("digest")
    if remote_digest:
        return remote_digest == "sha256:" + digest(local)
    # Older GitHub assets may omit a digest. Verify bytes, never infer from size.
    with tempfile.TemporaryDirectory() as temporary:
        api.download(tag, asset["name"], temporary)
        return digest(Path(temporary) / asset["name"]) == digest(local)


def restore_usb_final(api, directory, expected):
    if expected['mode'] != 'usb':
        raise ValueError('USB final checkpoint requires USB mode')
    pages = api.call('api', f"repos/{api.repository}/actions/runs/{expected['run_id']}/artifacts?per_page=100",
                     '--paginate', '--slurp')
    matches = [a for page in json.loads(pages) for a in page['artifacts'] if a['name'] == 'usb-verified-final']
    if not matches:
        return False
    if len(matches) != 1 or matches[0]['expired']:
        raise ValueError('Signed final checkpoint expired or ambiguous; use a new version, never re-sign published assets')
    api.call('run', 'download', expected['run_id'], '--repo', api.repository,
             '--name', 'usb-verified-final', '--dir', str(directory))
    for arch in ('amd64', 'arm64'):
        verify_checkpoint(Path(directory) / arch, expected, arch)
    return True


def upload(api, directory, expected, arch, *, package_scope="full"):
    record = verify_checkpoint(directory, expected, arch, package_scope=package_scope)
    for attempt in range(3):
        try:
            info = verify_owner(api, expected, package_scope=package_scope)
            missing = []
            # Reconcile the full set before writing; detect conflicts up front.
            for name in sorted(record["files"]):
                matches = [a for a in info["assets"] if a["name"] == name]
                if matches:
                    if len(matches) != 1 or not remote_matches(api, expected["tag"], matches[0], Path(directory) / name):
                        raise ValueError(f"Existing release asset differs: {name}; never overwrite, use a new version")
                else:
                    missing.append(name)
            if not missing:
                return
            for name in missing:
                api.upload(expected["tag"], Path(directory) / name)
            # Verify the complete remote set, including after ambiguous timeouts.
            info = verify_owner(api, expected, package_scope=package_scope)
            for name in record["files"]:
                matches = [a for a in info["assets"] if a["name"] == name]
                if len(matches) != 1 or not remote_matches(api, expected["tag"], matches[0], Path(directory) / name):
                    raise RuntimeError(f"Uploaded asset not yet verified: {name}")
            return
        except (RuntimeError, subprocess.TimeoutExpired):
            if attempt == 2:
                raise
            time.sleep(2 ** (attempt + 1))


def cleanup_published_checkpoints(api, expected, *, package_scope="full"):
    """Published release assets own recovery; retire only this run's CI copies."""
    info = api.release(expected["tag"])
    require_owner(info, expected, package_scope=package_scope)
    if info.get("draft") is not False:
        raise ValueError("Checkpoint cleanup requires this run's published release")
    verify_tag_target(api, info, expected)
    pages = json.loads(api.call(
        "api", f"repos/{api.repository}/actions/runs/{expected['run_id']}/artifacts?per_page=100",
        "--paginate", "--slurp"))
    names = {"release-checkpoint-amd64", "release-checkpoint-arm64",
             "release-input-amd64", "release-input-arm64", "usb-verified-final"}
    selected = [artifact for page in pages for artifact in page["artifacts"]
                if artifact.get("name") in names and not artifact.get("expired", False)]
    # Validate the entire set before deleting; neither unrelated evidence nor
    # another run's recovery boundary may be removed.
    for artifact in selected:
        if (type(artifact.get("id")) is not int or artifact["id"] <= 0 or
                str((artifact.get("workflow_run") or {}).get("id")) != expected["run_id"]):
            raise ValueError("Checkpoint artifact has invalid run/ID ownership")
    for artifact in selected:
        for attempt in range(3):
            try:
                api.call("api", "--method", "DELETE",
                         f"repos/{api.repository}/actions/artifacts/{artifact['id']}", missing=True)
                break
            except (RuntimeError, subprocess.TimeoutExpired):
                if attempt == 2:
                    raise
                time.sleep(2 ** (attempt + 1))
    return len(selected)


def verify_assets(api, expected, *, package_scope="full"):
    info = verify_owner(api, expected, package_scope=package_scope)
    required = set.union(*(asset_names(expected, arch, package_scope=package_scope)
                           for arch in ("amd64", "arm64")))
    names = [asset["name"] for asset in info["assets"]]
    if any(names.count(name) != 1 for name in required) or (
            package_scope == "headless" and set(names) != required):
        raise ValueError("Combined release asset set is incomplete, duplicated or outside its scope")


def read_json(path, limit=4 * 1024**2):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("Missing, unsafe or oversized release JSON")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate release JSON field")
            result[key] = value
        return result
    result = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError("Release JSON must contain an object")
    return result


def pe_machine(path):
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise ValueError("Release executable is not a PE image")
        offset = int.from_bytes(header[60:64], "little")
        if not 64 <= offset <= 1024**2:
            raise ValueError("Release PE header offset is invalid")
        stream.seek(offset)
        pe = stream.read(24)
        if len(pe) != 24 or pe[:4] != b"PE\0\0":
            raise ValueError("Release executable has an invalid PE header")
        size = int.from_bytes(pe[20:22], "little")
        if not 136 <= size <= 4096:
            raise ValueError("Release PE optional header is invalid")
        optional = stream.read(size)
    if len(optional) != size:
        raise ValueError("Release PE optional header is truncated")
    magic = int.from_bytes(optional[:2], "little")
    directory = {0x10b: 96, 0x20b: 112}.get(magic)
    if directory is None or len(optional) < directory + 40:
        raise ValueError("Release executable has an invalid PE header")
    if int.from_bytes(optional[directory-4:directory], "little") < 5 or any(optional[directory+32:directory+40]):
        raise ValueError("Headless unsigned executable has a certificate table or invalid directories")
    return int.from_bytes(pe[4:6], "little")


def stage_headless(directory, destination, metadata, tag, arch, tag_commit, repository,
                   *, expected_source_commit=None, expected_run_id=None,
                   published_baseline=False, target_tag=None):
    """Validate only downloaded Headless bytes; no GitHub I/O or legacy manifest synthesis."""
    from windows_usb_bundle import unpack
    from verify_binary_hot_compatibility import runtime_identity
    directory, destination = Path(directory), Path(destination)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Headless downloads require a real directory")
    info = read_json(metadata)
    version = tag[4:]
    windows_release_version(tag)
    if arch not in ("amd64", "arm64") or not re.fullmatch(r"[0-9a-f]{40}", tag_commit):
        raise ValueError("Headless stage requires exact architecture and tag commit")
    if (info.get("tag_name") != tag or type(info.get("id")) is not int or info["id"] <= 0 or
            type(info.get("draft")) is not bool or not isinstance(info.get("body"), str)):
        raise ValueError("Release metadata tag, ID or publication state mismatch")
    matches = MARKER.findall(info.get("body") or "")
    if len(matches) != 1:
        raise ValueError("Headless release requires one canonical source marker")
    provenance = json.loads(matches[0])
    fields = ("tag", "commit", "repository", "run_id", "mode", "upgrade_class")
    if not isinstance(provenance, dict) or any(not isinstance(provenance.get(key), str) for key in fields):
        raise ValueError("Invalid canonical release source")
    environment = {name: provenance.get(key, "") for key, name in (
        ("tag", "EDR_AGENT_RELEASE_TAG"), ("commit", "GITHUB_SHA"),
        ("repository", "GITHUB_REPOSITORY"), ("run_id", "GITHUB_RUN_ID"),
        ("mode", "WINDOWS_RELEASE_MODE"), ("upgrade_class", "EDR_UPGRADE_CLASS_OVERRIDE"))}
    if "p0_test_inputs" in provenance:
        inputs = provenance["p0_test_inputs"]
        if (not isinstance(inputs, dict) or set(inputs) != {"repository", "commit", "sha256"} or
                any(not isinstance(value, str) for value in inputs.values()) or
                inputs["repository"] != P0_TEST_INPUTS_REPOSITORY):
            raise ValueError("Invalid canonical private input source")
        environment.update(P0_TEST_INPUTS_REF=inputs["commit"], P0_TEST_INPUTS_SHA256=inputs["sha256"])
    if (source(environment) != provenance or provenance["tag"] != tag or
            provenance["repository"] != repository or provenance["commit"] != tag_commit or
            provenance["mode"] != "unsigned" or provenance["upgrade_class"] not in
            ("auto", "binary_hot", "runtime_bundle", "installer_required")):
        raise ValueError("Headless canonical source/tag/repository/unsigned binding mismatch")
    target = info.get("target_commitish", "")
    if not isinstance(target, str):
        raise ValueError("Release target commit must be a string")
    if re.fullmatch(r"[0-9a-f]{40}", target) and target != tag_commit:
        raise ValueError("Release target commit no longer matches its tag")
    scope = marker_scope(info)
    if published_baseline:
        if (info["draft"] is not False or not target_tag or
                windows_release_version(tag) >= windows_release_version(target_tag)):
            raise ValueError("Baseline must be published and strictly older than target")
        if expected_source_commit or expected_run_id:
            raise ValueError("A baseline cannot borrow the current target's source identity")
    elif (scope != "headless" or expected_source_commit != tag_commit or
          str(expected_run_id) != provenance["run_id"] or
          (not info["draft"] and info.get("prerelease") is not True)):
        raise ValueError("Target must match this Headless candidate source/run")
    prefix = f"edr-agent-{tag}-windows-{arch}-"
    zip_name, manifest_name, raw_name = (prefix + suffix for suffix in
                                        ("exe.zip", "artifact-manifest.json", "FDSensor.exe"))
    if ({path.name for path in directory.iterdir()} != {zip_name, manifest_name} or
            any(path.is_symlink() or not path.is_file() for path in directory.iterdir())):
        raise ValueError("Headless downloads must contain exactly the runtime ZIP and artifact manifest")
    assets = info.get("assets")
    if not isinstance(assets, list) or any(not isinstance(asset, dict) or not isinstance(asset.get("name"), str) for asset in assets):
        raise ValueError("Invalid release asset metadata")
    if scope == "headless":
        allowed = set.union(*(asset_names(provenance, item, package_scope="headless") for item in ("amd64", "arm64")))
        if any(asset.get("name") not in allowed for asset in assets):
            raise ValueError("Headless metadata contains a forbidden extra release asset")
    selected = {}
    for name in (zip_name, manifest_name, raw_name):
        found = [asset for asset in assets if asset.get("name") == name]
        if len(found) != 1:
            raise ValueError("Missing or duplicated Headless release asset metadata: " + name)
        asset = found[0]
        if (type(asset.get("id")) is not int or asset["id"] <= 0 or
                asset.get("url") != f"https://api.github.com/repos/{repository}/releases/assets/{asset['id']}" or
                type(asset.get("size")) is not int or asset["size"] <= 0 or
                not isinstance(asset.get("digest"), str) or
                not re.fullmatch(r"sha256:[0-9a-f]{64}", asset["digest"])):
            raise ValueError("Headless asset lacks immutable ID/size/SHA256 metadata")
        selected[name] = asset
        if name != raw_name and (asset["size"] != (directory / name).stat().st_size or
                                  asset["digest"] != "sha256:" + digest(directory / name)):
            raise ValueError("Downloaded Headless asset hash/size mismatch: " + name)
    manifest = read_json(directory / manifest_name)
    if (manifest.get("build_provenance") != provenance or manifest.get("version") != version or
            manifest.get("schema_version") != 1 or
            not isinstance(manifest.get("signature"), dict) or manifest["signature"].get("status") != "unsigned"):
        raise ValueError("Headless artifact manifest source/version/unsigned mismatch")
    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or any(not isinstance(entry, dict) or not isinstance(entry.get("name"), str) for entry in entries):
        raise ValueError("Invalid Headless artifact entries")
    if scope == "headless" and (len(entries) != 2 or {entry.get("name") for entry in entries} != {zip_name, raw_name}):
        raise ValueError("Headless manifest contains an unexpected payload")
    for name in (zip_name, raw_name):
        found = [entry for entry in entries if entry.get("name") == name]
        if len(found) != 1 or any(found[0].get(field) != selected[name][field] for field in ("size",)) or found[0].get("sha256") != selected[name]["digest"][7:]:
            raise ValueError("Headless artifact entry hash/size mismatch")
    raw = next(entry for entry in entries if entry.get("name") == raw_name)
    update = raw.get("update", {})
    if (not isinstance(update, dict) or raw.get("version") != version or raw.get("platform") != "windows" or raw.get("arch") != arch or
            update.get("internal_name") != "FDSensor" or update.get("internal_version") != version or
            not isinstance(update.get("runtime_identity_sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", update.get("runtime_identity_sha256", ""))):
        raise ValueError("Headless Agent update identity mismatch")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Headless staging requires a fresh destination")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".headless-verified-", dir=destination.parent) as temporary:
        runtime = Path(temporary) / "runtime"
        # The shared unpack owner bounds paths, entries, decompression and CRC.
        unpack(directory / zip_name, runtime)
        runtime_identity(directory / zip_name)
        if any(path.name.lower() in ("fdsecuritysetupui.exe", "fdsecuritysetupui.zip", "setup-ui-manifest.json") for path in runtime.rglob("*")):
            raise ValueError("Headless runtime contains Setup UI")
        if (runtime / "VERSION").read_text(encoding="utf-8-sig").strip() != version:
            raise ValueError("Headless VERSION mismatch")
        agent, setup = runtime / "FDSensor.exe", runtime / "edr_agent_setup.exe"
        native = {"amd64": 0x8664, "arm64": 0xaa64}[arch]
        if pe_machine(agent) != native or pe_machine(setup) != 0x14c:
            raise ValueError("Headless Agent or installer architecture mismatch")
        if digest(agent) != raw["sha256"] or agent.stat().st_size != raw["size"]:
            raise ValueError("Headless Agent differs from the release artifact")
        identity_sha = digest(runtime / "native-package-integrity.json")
        if identity_sha != update["runtime_identity_sha256"]:
            raise ValueError("Headless Runtime integrity identity mismatch")
        full = read_json(runtime / "full-installer-manifest.json", 1024**2)
        if (full.get("version") != version or full.get("target_arch") != arch or full.get("setup_target_arch") != arch or
                full.get("agent_binary_sha256") != digest(agent) or full.get("runtime_identity_sha256") != identity_sha or
                full.get("setup_exe_sha256") != digest(setup) or full.get("setup_exe_signed") is not False or
                full.get("publisher_thumbprint") or full.get("upgrade_protocol") != "edr.windows.full-installer-upgrade.v1" or
                any(full.get(key) is not True for key in ("preserves_existing_identity", "preserves_offline_queue", "preserves_evidence_cache")) or
                not isinstance(full.get("capabilities"), dict) or full["capabilities"].get("signature_status") != "unsigned" or
                (runtime / "full-installer-manifest.p7s").exists()):
            raise ValueError("Embedded installer manifest identity/preservation/unsigned mismatch")
        if not published_baseline and any(key.startswith("ui_") or key in ("dotnet_runtime", "webview2_runtime") for key in full):
            raise ValueError("Headless target manifest must not invent Setup UI fields")
        capabilities = read_json(runtime / "package-capabilities.json", 1024**2)
        if capabilities.get("signature_status") != "unsigned" or capabilities.get("target_arch") != arch:
            raise ValueError("Headless package unsigned/architecture closure mismatch")
        result = dict(runtime_dir=str(destination.resolve()), setup_exe=str((destination / setup.name).resolve()),
                      version=version, target_arch=arch, source_commit=tag_commit, run_id=provenance["run_id"],
                      runtime_identity_sha256=identity_sha, agent_binary_sha256=digest(agent), setup_exe_sha256=digest(setup),
                      release_id=info["id"], package_scope=scope, validation_scope="headless_subset")
        if destination.exists():
            raise ValueError("Headless destination changed during validation")
        runtime.rename(destination)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("source", "validate-scope", "verify-assets", "stage-headless", "prepare", "verify-owner", "restore", "seal", "upload", "restore-input", "seal-input", "restore-usb-final", "select-baseline", "cleanup-published", "verify-p0-inputs"))
    parser.add_argument("--arch", choices=("amd64", "arm64"))
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--target-tag")
    parser.add_argument("--baseline-tag", default="")
    parser.add_argument("--package-scope", choices=("full", "headless"))
    parser.add_argument("--tag")
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--release-metadata", type=Path)
    parser.add_argument("--tag-commit")
    parser.add_argument("--expected-source-commit")
    parser.add_argument("--expected-run-id")
    parser.add_argument("--published-baseline", action="store_true")
    args = parser.parse_args()
    env = dict(os.environ)
    if args.package_scope:
        env["EDR_RELEASE_PACKAGE_SCOPE"] = args.package_scope
    scope = package_scope(env)
    if args.command == "validate-scope":
        print(validate_scope(env))
        return
    if args.command == "stage-headless":
        if not all((args.tag, args.arch, args.destination, args.release_metadata, args.tag_commit)):
            parser.error("stage-headless requires tag, arch, destination, release-metadata and tag-commit")
        print(json.dumps(stage_headless(args.directory, args.destination, args.release_metadata,
            args.tag, args.arch, args.tag_commit, os.environ["GITHUB_REPOSITORY"],
            expected_source_commit=args.expected_source_commit, expected_run_id=args.expected_run_id,
            published_baseline=args.published_baseline, target_tag=args.target_tag), sort_keys=True))
        return
    if args.command == "verify-p0-inputs":
        ref = os.environ.get("P0_TEST_INPUTS_REF", "")
        sha = verify_p0_test_inputs(args.directory, ref, os.environ.get("P0_TEST_INPUTS_SHA256", ""))
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"ref={ref}\nsha256={sha}\n")
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as stream:
            stream.write(f"P0_TEST_INPUTS_REF={ref}\nP0_TEST_INPUTS_SHA256={sha}\n")
            stream.write(f"EDR_BACKEND_CONFIG_DIR={args.directory.resolve()}\n")
        print("Verified private P0 test input snapshot and IR/SensorInterest binding")
        return
    if args.command == "select-baseline":
        if not args.target_tag:
            parser.error("select-baseline requires --target-tag")
        windows_release_version(args.target_tag)
        api = GitHub(os.environ["GITHUB_REPOSITORY"])
        selected = select_baseline(api.releases(), args.target_tag, args.baseline_tag, package_scope=scope)
        if selected is None:
            raise ValueError("Required install/upgrade/rollback has no eligible published baseline")
        print(json.dumps(selected, sort_keys=True))
        return
    expected = source(env)
    api = GitHub(expected["repository"])
    if args.command == "source":
        print(json.dumps(expected, sort_keys=True))
    elif args.command == "verify-owner":
        verify_owner(api, expected, package_scope=scope)
    elif args.command == "verify-assets":
        verify_assets(api, expected, package_scope=scope)
    elif args.command == "cleanup-published":
        print(f"Removed {cleanup_published_checkpoints(api, expected, package_scope=scope)} published-run CI checkpoints")
    elif args.command == "prepare":
        published = prepare(api, expected, package_scope=scope)
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"published={str(published).lower()}\n")
        print("Already published from this source; no duplicate build" if published else "Draft source identity verified")
    elif args.command in ("restore", "restore-input", "restore-usb-final"):
        restored = (restore_usb_final(api, args.directory, expected) if args.command == 'restore-usb-final'
                    else restore(api, args.directory, expected, args.arch, candidate=args.command == "restore-input", package_scope=scope))
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"restored={str(restored).lower()}\n")
        print("Verified complete checkpoint; resume upload" if restored else "No checkpoint; full build and gates required")
    elif args.command in ("seal", "seal-input"):
        seal(args.directory, expected, args.arch, candidate=args.command == "seal-input", package_scope=scope)
    else:
        upload(api, args.directory, expected, args.arch, package_scope=scope)


if __name__ == "__main__":
    main()
