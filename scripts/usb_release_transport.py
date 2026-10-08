"""Private Release transport; Actions storage quota must not erase signed outputs.

Release assets carry bytes, never authority. Consumers still perform source,
payload, Authenticode and CMS verification after this transport's identity checks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

REPOSITORY = 'qiuxinliang/edr-agent-signing'
PREFIX = 'edr-private-transfer-v1\n'
SUFFIXES = ('exe.zip', 'setup.exe', 'setup-ui.zip', 'FDSensor.exe',
            'artifact-manifest.json', 'artifact-manifest.json.p7s')


def digest(path):
    sha = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(chunk)
    return sha.hexdigest()


def api(path, data=None, method=None):
    command = ['gh', 'api', f'repos/{REPOSITORY}/{path}'.rstrip('/')]
    if data is not None:
        command += ['--method', method or 'POST', '--input', '-']
    for attempt in range(3 if data is None else 1):
        try:
            result = subprocess.run(command, input=None if data is None else json.dumps(data),
                                    text=True, capture_output=True, timeout=40)
            if result.returncode == 0:
                return json.loads(result.stdout) if result.stdout.strip() else None
        except subprocess.TimeoutExpired:
            pass
        if data is None and attempt < 2:
            time.sleep(2 ** attempt)
    raise RuntimeError('Private Release API failed; check scoped Contents permission and connectivity')


def find_release(tag):
    # Draft tag endpoints can return 404 to readers: search visible exact ownership.
    matches = []
    for page in range(1, 11):
        batch = api(f'releases?per_page=100&page={page}')
        matches.extend(r for r in batch if r['tag_name'] == tag)
        if len(batch) < 100:
            break
    else:
        raise ValueError('Release discovery limit exceeded; refusing ambiguous transfer')
    if len(matches) > 1:
        raise ValueError('Duplicate private transfer Release')
    return matches[0] if matches else None


def assets(release_id):
    items = api(f'releases/{release_id}/assets?per_page=100')
    if len(items) >= 100 or len({a['name'] for a in items}) != len(items):
        raise ValueError('Unexpected private Release asset set')
    return {a['name']: a for a in items}


def check_owner(release, tag, owner):
    if (release.get('tag_name') != tag or release.get('body') != PREFIX + json.dumps(owner, sort_keys=True)
            or not release.get('prerelease')):
        raise ValueError('Private Release ownership mismatch; no overwrite permitted')


def check_asset(asset, name, size, sha256):
    if (asset.get('name') != name or asset.get('state') != 'uploaded'
            or asset.get('size') != size or asset.get('digest') != 'sha256:' + sha256
            or not re.fullmatch(r'[1-9][0-9]*', str(asset.get('id', '')))):
        raise ValueError('Private Release asset identity/size/digest mismatch: ' + name)


def asset_identity(items):
    # Downloads change counters, not the immutable asset identity.
    return {name: {k: item.get(k) for k in ('id', 'name', 'state', 'size', 'digest')}
            for name, item in items.items()}


def publish_files(tag, owner, files, prerelease=False, before_seal=None):
    """Write only an owned private transfer, retaining all local data on failure.

    prerelease=False keeps evidence draft; True seals results as a non-latest
    private prerelease so the public verifier can read with Contents:read.
    No clobber/delete, and no automatic retry of an ambiguous POST.
    """
    if not re.fullmatch(r'edr-(?:usb|evidence)-[A-Za-z0-9.-]+', tag):
        raise ValueError('Invalid private transfer tag')
    if api('')['private'] is not True:
        raise ValueError('Transfer destination must remain private')
    files = [Path(p) for p in files]
    if not files or len(files) > 32 or len({p.name for p in files}) != len(files):
        raise ValueError('Unexpected transfer file count or duplicate name')
    inventory = {}
    for path in files:
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', path.name):
            raise ValueError('Transfer accepts explicit regular files only')
        size = path.stat().st_size
        if size <= 0 or size > 1024**3:
            raise ValueError('Transfer file size outside supported range')
        inventory[path.name] = (size, digest(path))
    release = find_release(tag)
    if release is None:
        # Private finalization binds tag to its private SHA; evidence uses main.
        target = owner.get('signer', {}).get('commit', 'main')
        try:
            release = api('releases', dict(tag_name=tag, target_commitish=target,
                          name=tag, body=PREFIX + json.dumps(owner, sort_keys=True),
                          draft=True, prerelease=True, make_latest='false'))
        except RuntimeError:
            release = find_release(tag)  # reconcile one ambiguous POST, do not repeat it
            if release is None:
                raise
    check_owner(release, tag, owner)
    existing = assets(release['id'])
    if set(existing) - set(inventory):
        raise ValueError('Unexpected assets in owned transfer; refuse to mutate it')
    for path in files:
        size, sha256 = inventory[path.name]
        if path.name not in existing:
            if not release['draft']:
                raise ValueError('Published transfer is incomplete; do not mutate sealed output')
            try:
                result = subprocess.run(['gh', 'release', 'upload', tag, str(path), '--repo', REPOSITORY],
                                        capture_output=True, timeout=300)
                uploaded = result.returncode == 0
            except subprocess.TimeoutExpired:
                uploaded = False
            existing = assets(release['id'])
            if path.name not in existing:
                raise RuntimeError('Release upload did not complete; signed data retained locally: ' + path.name)
            # A timeout can have committed remotely. Accept only exact immutable bytes.
            if not uploaded:
                print('Reconciling ambiguous upload against GitHub SHA-256: ' + path.name, flush=True)
        check_asset(existing[path.name], path.name, size, sha256)
    if prerelease and release['draft']:
        if before_seal is not None:
            before_seal()
        try:
            api(f"releases/{release['id']}", dict(draft=False, prerelease=True, make_latest='false'), 'PATCH')
        except RuntimeError:
            pass  # one bounded read resolves whether the state transition committed
        release = api(f"releases/{release['id']}")
    check_owner(release, tag, owner)
    if release['draft'] == prerelease:
        raise RuntimeError('Private Release state transition not confirmed; local files retained')
    print(f"Private transfer verified: release={release['id']} assets={len(files)}", flush=True)
    return release


def expected_names(version):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('Invalid transfer version')
    return {f'edr-agent-win_{version}-windows-{arch}-{suffix}': arch
            for arch in ('amd64', 'arm64') for suffix in SUFFIXES}


def signer_identity(run, attempt, commit):
    if (not re.fullmatch(r'[1-9][0-9]*', str(run)) or not re.fullmatch(r'[1-9][0-9]*', str(attempt))
            or not re.fullmatch(r'[a-f0-9]{40}', commit)):
        raise ValueError('Invalid private signer identity')
    return dict(repository=REPOSITORY, run_id=str(run), attempt=str(attempt), commit=commit)


def result_owner(context, signer):
    return dict(schema='edr.usb-release-transfer.v1', context=context, signer=signer)


def result_tag(signer):
    return f"edr-usb-{signer['run_id']}-{signer['attempt']}"


def publish_result(directory, context, before_seal=None):
    signer = signer_identity(os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT'], os.environ['GITHUB_SHA'])
    if os.environ['GITHUB_REPOSITORY'] != REPOSITORY:
        raise ValueError('Only the private signer may return signed results')
    names = expected_names(context['version'])
    children = list(directory.glob('*/*'))
    paths = {p.name: p for p in children if p.is_file() and not p.is_symlink()}
    if len(children) != len(names) or set(paths) != set(names) or any(p.parent.name != names[n] for n, p in paths.items()):
        raise ValueError('Signed result must contain exactly both architecture bundles')
    owner = result_owner(context, signer)
    receipt = dict(owner=owner, files=[dict(name=n, size=p.stat().st_size, sha256=digest(p))
                                      for n, p in sorted(paths.items())])
    receipt_path = directory / 'usb-transfer-receipt.json'
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding='utf-8')
    return publish_files(result_tag(signer), owner, [*paths.values(), receipt_path], prerelease=True, before_seal=before_seal)


def download_asset(asset, destination):
    if (type(asset.get('size')) is not int or not 0 < asset['size'] <= 1024**3
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', str(asset.get('digest', '')))):
        raise ValueError('Invalid private asset download size/digest')
    check_asset(asset, destination.name, asset['size'], asset['digest'][7:])
    if destination.exists():
        raise ValueError('Use a fresh transfer directory')
    partial = destination.with_name(destination.name + '.partial')
    if partial.exists():
        raise ValueError('Previous partial download exists; inspect before retrying')
    with partial.open('xb') as stream:
        try:
            result = subprocess.run(['gh', 'api', f"repos/{REPOSITORY}/releases/assets/{asset['id']}",
                                     '-H', 'Accept: application/octet-stream'], stdout=stream,
                                    stderr=subprocess.PIPE, timeout=300)
        except subprocess.TimeoutExpired:
            raise RuntimeError('Private asset download timed out; no bundle accepted') from None
    if result.returncode != 0:
        raise RuntimeError('Private asset download failed; check Contents permission/connectivity')
    check_asset(asset, destination.name, partial.stat().st_size, digest(partial))
    partial.rename(destination)


def download(args, context):
    signer = signer_identity(args.signing_run, os.environ['SIGNING_ATTEMPT'], os.environ['SIGNING_COMMIT'])
    owner = result_owner(context, signer)
    tag = result_tag(signer)
    release = find_release(tag)
    if release is None:
        raise RuntimeError('Private result Release missing or Contents read permission unavailable')
    check_owner(release, tag, owner)
    if release['draft']:
        raise ValueError('Private transfer is not sealed')
    entries = assets(release['id'])
    names = expected_names(context['version'])
    if set(entries) != set(names) | {'usb-transfer-receipt.json'}:
        raise ValueError('Private response asset set differs from the dual-architecture contract')
    destination = Path(args.directory)
    destination.mkdir(parents=True, exist_ok=False)
    receipt_path = destination / 'usb-transfer-receipt.json'
    if entries[receipt_path.name]['size'] > 65536:
        raise ValueError('Unexpected transfer receipt size')
    download_asset(entries[receipt_path.name], receipt_path)
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    files = receipt.get('files', [])
    if receipt.get('owner') != owner or len(files) != len(names) or {f['name'] for f in files} != set(names):
        raise ValueError('Receipt provenance or file inventory mismatch')
    for entry in files:
        name = entry['name']
        check_asset(entries[name], name, entry['size'], entry['sha256'])
        folder = destination / names[name]
        folder.mkdir(exist_ok=True)
        download_asset(entries[name], folder / name)
    # A mutable Release cannot change during transfer without being noticed.
    if asset_identity(assets(release['id'])) != asset_identity(entries):
        raise ValueError('Private response changed during download')
    print('Private Release transport verified; independent bundle/EXE/CMS checks are still required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    from private_signing_bridge import context
    from types import SimpleNamespace
    request = SimpleNamespace(run=os.environ['SOURCE_RUN'], attempt=os.environ['SOURCE_ATTEMPT'],
                              commit=os.environ['SOURCE_COMMIT'], version=os.environ['USB_VERSION'],
                              request_id=os.environ['REQUEST_ID'])
    # Admission needs the cross-repo Actions token; upload uses only own-job token.
    own_token = os.environ['GH_TOKEN']
    def check_fresh():
        try:
            os.environ['GH_TOKEN'] = os.environ['SOURCE_READ_TOKEN']
            return context(request)
        finally:
            os.environ['GH_TOKEN'] = own_token
    verified_context = check_fresh()
    def before_seal():
        if check_fresh() != verified_context:
            raise ValueError('Signing request changed before sealing results')
    publish_result(args.directory, verified_context, before_seal=before_seal)


if __name__ == '__main__':
    main()
