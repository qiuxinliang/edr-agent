"""Carry same-run native storage QA tools through the existing private evidence owner."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import usb_release_transport as transport
from headless_repack_lifecycle import checked_assets, extract, read

PUBLIC = 'qiuxinliang/edr-agent'


def identity(architecture, environment):
    if (architecture not in ('amd64', 'arm64') or
            environment.get('GITHUB_REPOSITORY') != PUBLIC or
            environment.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'):
        raise ValueError('Storage QA transport requires this repository manual native acceptance')
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        if not re.fullmatch(r'[1-9][0-9]*', environment.get(key, '')):
            raise ValueError('Exact acceptance run and attempt required')
    if not re.fullmatch(r'[a-f0-9]{40}', environment.get('GITHUB_SHA', '')):
        raise ValueError('Exact acceptance harness commit required')
    return dict(schema='edr.storage-compat-native-transfer.v1', repository=PUBLIC,
        run_id=environment['GITHUB_RUN_ID'], attempt=environment['GITHUB_RUN_ATTEMPT'],
        commit=environment['GITHUB_SHA'], architecture=architecture)


def tag(owner):
    return f"edr-evidence-storage-tools-{owner['run_id']}-{owner['attempt']}-{owner['architecture']}"


def names(owner):
    stem = 'storage-compat-tools-' + owner['architecture']
    return stem + '.zip', stem + '.json'


def verify_bundle(repo, bundle, owner):
    spec = importlib.util.spec_from_file_location('storage_compat_native_stage', Path(__file__).with_name('stage_native.py'))
    stage_native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage_native)
    return stage_native.verify(Path(repo), Path(bundle), owner['architecture'],
        owner['commit'], owner['run_id'], owner['attempt'])


def package(repo, bundle, output, owner):
    bundle, output = Path(bundle), Path(output)
    verify_bundle(repo, bundle, owner)
    output.mkdir(parents=True, exist_ok=False)
    archive_name, receipt_name = names(owner)
    archive = output / archive_name
    manifest_sha256 = transport.digest(bundle / 'manifest.json')
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED, compresslevel=1) as target:
        for path in sorted(bundle.rglob('*')):
            if path.is_file():
                target.write(path, path.relative_to(bundle).as_posix())
    # Recheck the entire closure after packing, including source and evidence.
    verify_bundle(repo, bundle, owner)
    if manifest_sha256 != transport.digest(bundle / 'manifest.json'):
        raise ValueError('Storage tool manifest changed during packaging')
    receipt = dict(schema='edr.storage-compat-native-receipt.v1', owner=owner,
        manifest_sha256=manifest_sha256,
        archive=dict(name=archive_name, size=archive.stat().st_size, sha256=transport.digest(archive)))
    receipt_path = output / receipt_name
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    return [archive, receipt_path]


def upload(repo, bundle, output, owner):
    files = package(repo, bundle, output, owner)
    release = transport.publish_files(tag(owner), owner, files, prerelease=False)
    print('Private same-run native storage tools retained: release_id=' + str(release['id']))
    return release


def validate_release(release, owner):
    transport.check_owner(release, tag(owner), owner)
    if release.get('draft') is not True:
        raise ValueError('Native QA tools must remain a private evidence draft')


def validate_receipt(receipt, entries, owner):
    archive_name, receipt_name = names(owner)
    if set(entries) != {archive_name, receipt_name}:
        raise ValueError('Unexpected same-run storage tool asset set')
    if (receipt.get('schema') != 'edr.storage-compat-native-receipt.v1' or
            receipt.get('owner') != owner or
            not re.fullmatch(r'[a-f0-9]{64}', str(receipt.get('manifest_sha256', '')))):
        raise ValueError('Storage tool receipt ownership or manifest identity mismatch')
    artifact = receipt.get('archive', {})
    expected = entries[archive_name]
    if (artifact.get('name') != archive_name or artifact.get('size') != expected['size'] or
            'sha256:' + str(artifact.get('sha256')) != expected['digest']):
        raise ValueError('Storage tool archive differs from its official Release asset')


def download(repo, output, owner):
    if transport.api('').get('private') is not True:
        raise ValueError('Native storage tools may only use the private evidence repository')
    release = transport.find_release(tag(owner))
    if release is None:
        raise ValueError('Required same-run native tools are missing; no substitute accepted')
    validate_release(release, owner)
    entries = checked_assets(list(transport.assets(release['id']).values()))
    archive_name, receipt_name = names(owner)
    if set(entries) != {archive_name, receipt_name} or entries[receipt_name]['size'] > 65536:
        raise ValueError('Unexpected native storage tool assets or receipt size')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    receipt_path = output / receipt_name
    transport.download_asset(entries[receipt_name], receipt_path)
    receipt = read(receipt_path)
    validate_receipt(receipt, entries, owner)
    archive = output / archive_name
    transport.download_asset(entries[archive_name], archive)
    bundle = output / 'bundle'
    extract(archive, bundle)
    if transport.digest(bundle / 'manifest.json') != receipt['manifest_sha256']:
        raise ValueError('Native storage tool manifest differs from the transfer receipt')
    verify_bundle(repo, bundle, owner)
    fresh = transport.find_release(tag(owner))
    if fresh is None or fresh['id'] != release['id']:
        raise ValueError('Native tool evidence Release changed during download')
    validate_release(fresh, owner)
    if entries != checked_assets(list(transport.assets(release['id']).values())):
        raise ValueError('Native tool asset identity changed during download')
    print('Exact same-run storage tool closure verified: ' + str(bundle))
    return bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('upload', 'download'))
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--repo', type=Path, default=ROOT)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    owner = identity(args.architecture, os.environ)
    if args.mode == 'upload':
        if args.bundle is None:
            parser.error('upload requires --bundle')
        upload(args.repo, args.bundle, args.output, owner)
    else:
        download(args.repo, args.output, owner)


if __name__ == '__main__':
    main()
