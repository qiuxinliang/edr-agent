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
UNSIGNED = ("WARNING: This Windows build is unsigned. Windows may show an unknown-publisher "
            "warning. Use only where the platform explicitly permits optional-signature "
            "installation/update with verified SHA-256 artifact hashes. "
            "Platform/Agent signature requirements are not changed by this release.\n")
BROKEN_SETUP_BASELINE_MIN = (3, 2, 304)
BROKEN_SETUP_BASELINE_MAX = (3, 2, 341)


def windows_release_version(tag):
    match = re.fullmatch(r"win_(\d+)\.(\d+)\.(\d+)", tag) if isinstance(tag, str) else None
    if match is None:
        raise ValueError("Invalid Windows release tag; expected win_M.m.p")
    return tuple(int(part) for part in match.groups())


def baseline_rejection(info, target_version):
    """A baseline has already passed publication gates, including both arches.

    Published prereleases are verified candidates in this repository. Drafts
    have not passed those gates, even when all their assets have been uploaded.
    Historical provenance belongs to that release, not the current target.
    """
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
        for suffix in ("exe.zip", "setup.exe", "artifact-manifest.json"):
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


def select_baseline(releases, target_tag, baseline_tag=""):
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
        rejection = baseline_rejection(matches[0], target_version)
        if rejection:
            raise ValueError(f"Baseline {baseline_tag} is not eligible: {rejection}")
        selected = matches[0]
    else:
        candidates = [info for info in releases if baseline_rejection(info, target_version) is None]
        if not candidates:
            for info in releases:
                try:
                    version = windows_release_version(info.get("tag_name"))
                except ValueError:
                    continue
                if info.get("draft") is False and version < target_version:
                    raise ValueError("No eligible published baseline: " + baseline_rejection(info, target_version))
            return None
        selected = max(candidates, key=lambda info: windows_release_version(info["tag_name"]))
        if sum(info.get("tag_name") == selected["tag_name"] for info in releases) != 1:
            raise ValueError(f"Baseline {selected['tag_name']} must resolve to exactly one release")
    return dict(tag=selected["tag_name"], state="published",
                setup_rollback_supported=windows_release_version(selected["tag_name"]) > BROKEN_SETUP_BASELINE_MAX)


def source(env=os.environ):
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
    return result


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


def require_owner(info, expected, *, published=False):
    if info is None:
        raise ValueError("Release draft is missing; rerun the original prepare job")
    matches = MARKER.findall(info.get("body") or "")
    if len(matches) != 1:
        raise ValueError("Release has no unique source binding; use a new version, do not overwrite this draft")
    actual = json.loads(matches[0])
    keys = set(expected) - ({"run_id"} if published else set())
    if any(actual.get(key) != expected[key] for key in keys):
        raise ValueError("Release belongs to another commit, mode or run; rerun failed jobs of the original run or use a new version")


def prepare(api, expected):
    tag = expected["tag"]
    commit = api.tag_commit(tag)
    if commit is not None and commit != expected["commit"]:
        raise ValueError("Release tag does not resolve to this source commit")
    info = api.release(tag)
    if info is None:
        body = (UNSIGNED if expected["mode"] == "unsigned" else "")
        body += "<!-- edr-release-source:" + json.dumps(expected, sort_keys=True) + " -->"
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
    require_owner(info, expected, published=not info["draft"])
    verify_tag_target(api, info, expected)
    return not info["draft"]


def verify_tag_target(api, info, expected):
    commit = api.tag_commit(expected["tag"])
    # GitHub may defer materializing a new tag until its draft is published.
    # Only an exact commit target is acceptable here, never a moving branch.
    if commit is None and info["draft"] and info.get("target_commitish") == expected["commit"]:
        return
    if commit != expected["commit"]:
        raise ValueError("Release tag no longer matches the verified source")


def verify_owner(api, expected):
    info = api.release(expected["tag"])
    if info is None:
        raise ValueError("Release draft is missing")
    require_owner(info, expected)
    if not info["draft"]:
        raise ValueError("Already published and immutable; mutation refused")
    verify_tag_target(api, info, expected)
    return info


def asset_names(expected, arch, *, candidate=False):
    if arch not in ("amd64", "arm64"):
        raise ValueError("Invalid release architecture")
    prefix = f"edr-agent-{expected['tag']}-windows-{arch}-"
    names = {prefix + s for s in ("exe.zip", "setup.exe", "setup-ui.zip", "FDSensor.exe", "artifact-manifest.json")}
    if expected["mode"] in ("signed", "usb") and not candidate:
        names.add(prefix + "artifact-manifest.json.p7s")
    return names


def inspect_bundle(directory, expected, arch, *, candidate=False):
    directory = Path(directory)
    if candidate and expected["mode"] != "usb":
        raise ValueError("Only USB releases accept a pre-signing candidate")
    names = asset_names(expected, arch, candidate=candidate)
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
    return {"source": expected, "arch": arch, "files": files}


def seal(directory, expected, arch, *, candidate=False):
    record = inspect_bundle(directory, expected, arch, candidate=candidate)
    (Path(directory) / CHECKPOINT).write_text(json.dumps(record, sort_keys=True), encoding="utf-8")


def verify_checkpoint(directory, expected, arch, *, candidate=False):
    record = json.loads((Path(directory) / CHECKPOINT).read_text(encoding="utf-8"))
    if record != inspect_bundle(directory, expected, arch, candidate=candidate):
        raise ValueError("Checkpoint identity or file digest mismatch; refuse reuse")
    return record


def restore(api, directory, expected, arch, *, candidate=False):
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
    verify_checkpoint(directory, expected, arch, candidate=candidate)
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


def upload(api, directory, expected, arch):
    record = verify_checkpoint(directory, expected, arch)
    for attempt in range(3):
        try:
            info = verify_owner(api, expected)
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
            info = verify_owner(api, expected)
            for name in record["files"]:
                matches = [a for a in info["assets"] if a["name"] == name]
                if len(matches) != 1 or not remote_matches(api, expected["tag"], matches[0], Path(directory) / name):
                    raise RuntimeError(f"Uploaded asset not yet verified: {name}")
            return
        except (RuntimeError, subprocess.TimeoutExpired):
            if attempt == 2:
                raise
            time.sleep(2 ** (attempt + 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("source", "prepare", "verify-owner", "restore", "seal", "upload", "restore-input", "seal-input", "restore-usb-final", "select-baseline"))
    parser.add_argument("--arch", choices=("amd64", "arm64"))
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--target-tag")
    parser.add_argument("--baseline-tag", default="")
    args = parser.parse_args()
    if args.command == "select-baseline":
        if not args.target_tag:
            parser.error("select-baseline requires --target-tag")
        windows_release_version(args.target_tag)
        api = GitHub(os.environ["GITHUB_REPOSITORY"])
        selected = select_baseline(api.releases(), args.target_tag, args.baseline_tag)
        if selected is None:
            raise ValueError("Required install/upgrade/rollback has no eligible published baseline")
        print(json.dumps(selected, sort_keys=True))
        return
    expected = source()
    api = GitHub(expected["repository"])
    if args.command == "source":
        print(json.dumps(expected, sort_keys=True))
    elif args.command == "verify-owner":
        verify_owner(api, expected)
    elif args.command == "prepare":
        published = prepare(api, expected)
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"published={str(published).lower()}\n")
        print("Already published from this source; no duplicate build" if published else "Draft source identity verified")
    elif args.command in ("restore", "restore-input", "restore-usb-final"):
        restored = (restore_usb_final(api, args.directory, expected) if args.command == 'restore-usb-final'
                    else restore(api, args.directory, expected, args.arch, candidate=args.command == "restore-input"))
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"restored={str(restored).lower()}\n")
        print("Verified complete checkpoint; resume upload" if restored else "No checkpoint; full build and gates required")
    elif args.command in ("seal", "seal-input"):
        seal(args.directory, expected, args.arch, candidate=args.command == "seal-input")
    else:
        upload(api, args.directory, expected, args.arch)


if __name__ == "__main__":
    main()
