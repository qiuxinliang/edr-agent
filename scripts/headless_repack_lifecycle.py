"""Read-only admission for an independently verified, no-build Headless lifecycle.

Public builds remain immutable. The private Release is only transport; its
receipt, original public source, package hashes and publisher are revalidated.
Authenticode and CMS verification is performed by the adjacent PowerShell tool.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import time
import zipfile

from usb_release_transport import digest, download_asset, asset_identity, PREFIX
from windows_usb_bundle import headless_manifest

PUBLIC = 'qiuxinliang/edr-agent'
PRIVATE = 'qiuxinliang/edr-agent-signing'
BRANCHES = {'main', 'codex/release-workflow-convergence', 'codex/ic3-p0-deployment', 'codex/rtq-process-batches',
            'codex/rtq-result-delivery-pressure'}
ARCHES = {'amd64': 0x8664, 'arm64': 0xAA64}
NATIVE = {'FDSensor.exe', 'FDSecurityInstallerWorker.exe', 'uninstall.exe',
          'collector/forensic_collector_builtin.exe'}
OPTIONAL = 'collector/forensic_collector.exe'
SUFFIXES = ('setup.exe', 'exe.zip', 'FDSensor.exe', 'artifact-manifest.json', 'artifact-manifest.json.p7s')
MAX_FILE = 512 * 1024**2


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'), object_pairs_hook=unique)


def api(repo, path, private_contents=False):
    env = dict(os.environ)
    if private_contents:
        env['GH_TOKEN'] = env.get('USB_SIGNING_RELEASE_TOKEN', '')
        if not env['GH_TOKEN']:
            raise ValueError('Private Release read requires USB_SIGNING_RELEASE_TOKEN')
    for attempt in range(3):
        try:
            result = subprocess.run(['gh', 'api', f'repos/{repo}/{path}'.rstrip('/')], env=env,
                                    capture_output=True, text=True, timeout=40)
            if result.returncode == 0:
                return json.loads(result.stdout, object_pairs_hook=unique)
        except subprocess.TimeoutExpired:
            pass
        if attempt < 2:
            time.sleep(2**attempt)
    raise RuntimeError('GitHub read failed; inspect token scope/connectivity (credentials and URLs suppressed)')


def jobs(repo, run, attempt):
    result = []
    for page in range(1, 11):
        items = api(repo, f'actions/runs/{run}/attempts/{attempt}/jobs?per_page=100&page={page}')['jobs']
        result.extend(items)
        if len(items) < 100:
            return result
    raise ValueError('Unexpected workflow job count')


def checked_assets(items):
    if not isinstance(items, list) or len(items) > 64:
        raise ValueError('Unexpected Release asset count')
    result, ids = {}, set()
    for item in items:
        name = item.get('name', '')
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name)
                or name.casefold() in {n.casefold() for n in result}
                or type(item.get('id')) is not int or item['id'] <= 0 or item['id'] in ids
                or type(item.get('size')) is not int or not 0 < item['size'] <= MAX_FILE
                or item.get('state') != 'uploaded'
                or not re.fullmatch(r'sha256:[a-f0-9]{64}', str(item.get('digest', '')))):
            raise ValueError('Official unique asset ID/size/SHA256 required')
        # Downloads legitimately change counters/timestamps. Compare only the
        # immutable API identity needed by transport, never download_count.
        result[name] = {key: item[key] for key in ('id', 'name', 'size', 'digest', 'state')}
        ids.add(item['id'])
    return result


def validate_public(release, run, run_jobs, tag, commit=None, run_id=None):
    if not re.fullmatch(r'win_[0-9]+\.[0-9]+\.[0-9]+', tag):
        raise ValueError('Invalid source tag')
    markers = re.findall(r'<!-- edr-release-source:(.*?) -->', release.get('body') or '')
    if len(markers) != 1:
        raise ValueError('Published source provenance must be unique')
    owner = json.loads(markers[0], object_pairs_hook=unique)
    if (release.get('draft') is not False or release.get('tag_name') != tag
            or release.get('target_commitish') != owner.get('commit')
            or owner.get('repository') != PUBLIC or owner.get('tag') != tag
            or owner.get('mode') != 'unsigned'
            or not re.fullmatch(r'[a-f0-9]{40}', str(owner.get('commit', '')))
            or (commit and owner['commit'] != commit) or (run_id and owner.get('run_id') != str(run_id))
            or str(run.get('id')) != owner.get('run_id') or run.get('head_sha') != owner['commit']
            or run.get('repository', {}).get('full_name') != PUBLIC
            or run.get('head_repository', {}).get('full_name') != PUBLIC
            or run.get('path') != '.github/workflows/edr-agent-client-release.yml'
            or run.get('status') != 'completed' or run.get('conclusion') != 'success'
            or not re.fullmatch(r'[1-9][0-9]*', str(run.get('run_attempt', '')))):
        raise ValueError('Published unsigned source identity/success mismatch')
    if not ((run.get('event') == 'push' and run.get('head_branch') == tag)
            or (run.get('event') == 'workflow_dispatch' and run.get('head_branch') in BRANCHES)):
        raise ValueError('Untrusted published source event/branch')
    for arch in ARCHES:
        matches = [job for job in run_jobs if job.get('name', '').startswith(f'Build Windows {arch} (')]
        if (len(matches) != 1 or matches[0].get('conclusion') != 'success'
                or matches[0].get('status') != 'completed'
                or str(matches[0].get('run_attempt')) != str(run['run_attempt'])):
            raise ValueError('Published source lacks successful native build: ' + arch)
    return owner


def public_source(tag, commit=None, run_id=None):
    release = api(PUBLIC, 'releases/tags/' + tag)
    markers = re.findall(r'<!-- edr-release-source:(.*?) -->', release.get('body') or '')
    if len(markers) != 1:
        raise ValueError('Missing unique published source provenance')
    owner = json.loads(markers[0], object_pairs_hook=unique)
    source_run = owner.get('run_id', '')
    if not re.fullmatch(r'[1-9][0-9]*', str(source_run)):
        raise ValueError('Invalid published source run')
    run = api(PUBLIC, 'actions/runs/' + source_run)
    owner = validate_public(release, run, jobs(PUBLIC, source_run, run['run_attempt']), tag, commit, run_id)
    obj = api(PUBLIC, 'git/ref/tags/' + tag)['object']
    for _ in range(4):
        if obj.get('type') != 'tag':
            break
        obj = api(PUBLIC, 'git/tags/' + obj['sha'])['object']
    if obj.get('type') != 'commit' or obj.get('sha') != owner['commit']:
        raise ValueError('Published tag moved away from its original source')
    assets = checked_assets(api(PUBLIC, f"releases/{release['id']}/assets?per_page=100"))
    return dict(release_id=release['id'], owner=owner, attempt=str(run['run_attempt']), assets=assets)


def validate_transfer(release, run, args, source, signing_jobs=None):
    if not (release.get('body') or '').startswith(PREFIX):
        raise ValueError('Unknown private transfer ownership format')
    owner = json.loads(release['body'][len(PREFIX):], object_pairs_hook=unique)
    executor = owner.get('executor', {})
    expected_source = dict(source['owner'])
    expected_source['attempt'] = source['attempt']
    if (owner.get('schema') != 'edr.published-headless-repack-transfer.v1'
            or owner.get('scope') != 'headless' or owner.get('version') != args.source_tag[4:]
            or owner.get('source') != expected_source or owner.get('signer') != executor
            or executor != dict(repository=PRIVATE, run_id=str(args.private_run),
                                attempt=str(args.private_attempt), commit=args.private_commit)
            or release.get('id') != int(args.private_release_id)
            or release.get('tag_name') != f'edr-usb-headless-repack-{args.private_run}-{args.private_attempt}'
            or release.get('draft') is not False or release.get('prerelease') is not True
            or release.get('target_commitish') != args.private_commit
            or run.get('repository', {}).get('full_name') != PRIVATE
            or run.get('head_repository', {}).get('full_name') != PRIVATE
            or str(run.get('id')) != str(args.private_run)
            or not re.fullmatch(r'[1-9][0-9]*', str(run.get('run_attempt', '')))
            or int(run['run_attempt']) < int(args.private_attempt)
            or run.get('head_sha') != args.private_commit or run.get('event') != 'workflow_dispatch'
            or run.get('head_branch') != 'main'
            or run.get('path') != '.github/workflows/published-headless-repack.yml'
            or run.get('status') != 'completed' or run.get('conclusion') != 'success'):
        raise ValueError('Private repack source/executor/scope/success mismatch')
    if 'baseline_tag' in owner:
        if owner['baseline_tag'] != args.baseline_tag:
            raise ValueError('Acceptance baseline differs from pinned signing selection')
        matches = [j for j in (signing_jobs or []) if j.get('name') == 'Sign and repackage Headless']
        if (len(matches) != 1 or matches[0].get('status') != 'completed'
                or matches[0].get('conclusion') != 'success'
                or str(matches[0].get('run_attempt')) != str(args.private_attempt)):
            raise ValueError('Reused signing attempt lacks its successful exact signing job')
    elif str(run['run_attempt']) != str(args.private_attempt):
        raise ValueError('Legacy repack requires its exact successful attempt')
    return owner


def validate_result(receipt, owner, assets, version, thumbprint):
    expected = {f'edr-agent-win_{version}-windows-{arch}-{suffix}' for arch in ARCHES for suffix in SUFFIXES}
    if set(assets) != expected | {'result.json'}:
        raise ValueError('Private Release must contain exactly ten Headless payloads plus result.json')
    if (receipt.get('schema') != 'edr.published-headless-repack-result.v1'
            or receipt.get('status') != 'succeeded' or receipt.get('installable') is not True
            or receipt.get('version') != version or receipt.get('scope') != 'headless'
            or receipt.get('publisher_thumbprint') != thumbprint
            or any(receipt.get(k) != owner.get(k) for k in ('source', 'executor', 'previous_signature_test'))
            or not re.fullmatch(r'[a-f0-9]{64}', str(receipt.get('admission_sha256', '')))):
        raise ValueError('Installable Headless result identity/status mismatch')
    provenance = receipt.get('repack_provenance')
    if not isinstance(provenance, dict) or dict(provenance, schema=owner['schema'], signer=owner['executor']) != owner:
        raise ValueError('Repack provenance differs from transfer owner')
    files = receipt.get('files')
    if not isinstance(files, list) or len(files) != 10 or {f.get('name') for f in files} != expected:
        raise ValueError('Incomplete or duplicate result file inventory')
    for file in files:
        asset = assets[file['name']]
        if (file.get('arch') not in ARCHES or f"-windows-{file['arch']}-" not in file['name']
                or file.get('size') != asset['size'] or 'sha256:' + str(file.get('sha256')) != asset['digest']):
            raise ValueError('Result file differs from official Release asset')


def safe_parts(name):
    if not isinstance(name, str) or not name or '\\' in name or name.startswith('/'):
        raise ValueError('Unsafe package path')
    parts = name.rstrip('/').split('/')
    for part in parts:
        if (not part or part in ('.', '..') or part.endswith((' ', '.'))
                or re.search(r'[:<>"|?*\x00-\x1f\x7f]', part)
                or re.fullmatch(r'(?i)(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(?:\..*)?', part)):
            raise ValueError('Unsafe package path')
    return parts


def extract(archive, destination):
    if destination.exists():
        raise ValueError('Runtime extraction requires a fresh destination')
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if not 0 < len(members) <= 10000:
            raise ValueError('ZIP member count outside bounds')
        seen, files, total = set(), set(), 0
        for member in members:
            parts = safe_parts(member.orig_filename)
            key, mode = '/'.join(parts).casefold(), member.external_attr >> 16
            if (key in seen or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or member.flag_bits & 1 or member.file_size > MAX_FILE
                    or any('/'.join(parts[:i]).casefold() in files for i in range(1, len(parts)))):
                raise ValueError('Unsafe or duplicate ZIP member')
            seen.add(key)
            if not member.is_dir():
                if any(old.startswith(key + '/') for old in seen):
                    raise ValueError('ZIP file/directory collision')
                files.add(key)
            total += member.file_size
            if total > 2 * 1024**3:
                raise ValueError('ZIP decompression size outside bounds')
        destination.mkdir(parents=True)
        for member in members:
            path = destination.joinpath(*safe_parts(member.orig_filename))
            if member.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with source.open(member) as src, path.open('xb') as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)


def pe(data, arch, installer=False):
    if len(data) < 256 or data[:2] != b'MZ':
        raise ValueError('Invalid PE header')
    offset = struct.unpack_from('<I', data, 60)[0]
    if offset < 64 or offset + 24 > len(data) or data[offset:offset + 4] != b'PE\0\0':
        raise ValueError('Invalid PE signature')
    machine, sections = struct.unpack_from('<HH', data, offset + 4)
    optional, optional_size = offset + 24, struct.unpack_from('<H', data, offset + 20)[0]
    if machine != (0x14C if installer else ARCHES[arch]) or not 1 <= sections <= 96 or optional_size < 136:
        raise ValueError('PE machine/sections mismatch')
    if optional + optional_size + sections * 40 > len(data):
        raise ValueError('Truncated PE sections')
    magic = struct.unpack_from('<H', data, optional)[0]
    if magic != (0x10B if installer else 0x20B):
        raise ValueError('PE optional-header architecture mismatch')
    directory = 96 if installer else 112
    count = struct.unpack_from('<I', data, optional + directory - 4)[0]
    if count < 5 or directory + count * 8 > optional_size:
        raise ValueError('Invalid PE directory range')
    headers = struct.unpack_from('<I', data, optional + 60)[0]
    if not optional + optional_size + sections * 40 <= headers <= len(data):
        raise ValueError('Invalid PE header bounds')
    ranges = []
    for index in range(sections):
        size, pointer = struct.unpack_from('<II', data, optional + optional_size + index * 40 + 16)
        if size:
            if pointer < headers or pointer + size > len(data) or any(pointer < end and start < pointer + size for start, end in ranges):
                raise ValueError('Invalid PE section bounds/overlap')
            ranges.append((pointer, pointer + size))
    security = optional + directory + 32
    certificate = struct.unpack_from('<II', data, security)
    return optional + 64, security, certificate, max([headers] + [end for _, end in ranges])


def same_payload(original, signed, arch):
    before, after = original.read_bytes(), signed.read_bytes()
    checksum, directory, old_cert, _ = pe(before, arch)
    check2, dir2, (start, size), content_end = pe(after, arch)
    if (old_cert != (0, 0) or (checksum, directory) != (check2, dir2)
            or start != (len(before) + 7) // 8 * 8 or size < 8 or start + size != len(after)
            or start < content_end or after[len(before):start] != b'\0' * (start - len(before))):
        raise ValueError('Signature is not an aligned append-only PE certificate')
    position = start
    while position < len(after):
        if position + 8 > len(after):
            raise ValueError('Truncated WIN_CERTIFICATE')
        length, revision, kind = struct.unpack_from('<IHH', after, position)
        padded = (length + 7) // 8 * 8
        if length <= 8 or revision != 0x200 or kind != 2 or position + padded > len(after) or after[position + length:position + padded] != b'\0' * (padded - length):
            raise ValueError('Invalid WIN_CERTIFICATE')
        position += padded
    a, b = bytearray(before), bytearray(after[:len(before)])
    for start, size in ((checksum, 4), (directory, 8)):
        a[start:start + size] = b'\0' * size
        b[start:start + size] = b'\0' * size
    if a != b:
        raise ValueError('Signed executable payload changed')


def inventory(directory):
    return {p.relative_to(directory).as_posix(): digest(p) for p in directory.rglob('*') if p.is_file()}


def runtime_contract(directory, assets, tag, arch, signed):
    version, prefix = tag[4:], f'edr-agent-{tag}-windows-{arch}-'
    caps = read(directory / 'package-capabilities.json')
    if ((directory / 'VERSION').read_text(encoding='utf-8-sig').strip() != version
            or caps.get('signature_status') != ('signed' if signed else 'unsigned')):
        raise ValueError('Runtime version/signature closure mismatch')
    if (directory / 'ARCH').exists():
        target_arch = (directory / 'ARCH').read_text(encoding='utf-8-sig').strip()
    else:
        target_arch = caps.get('target_arch', caps.get('arch'))
    if target_arch != arch:
        raise ValueError('Runtime architecture mismatch')
    integrity = read(directory / 'native-package-integrity.json')
    entries = integrity.get('files', [])
    if (integrity.get('schema') != 'edr.windows.native-package-integrity.v1' or not entries
            or len({e.get('name', '').casefold() for e in entries}) != len(entries)):
        raise ValueError('Invalid native integrity inventory')
    for entry in entries:
        path = directory.joinpath(*safe_parts(entry['name']))
        if not path.is_file() or path.is_symlink() or digest(path) != entry.get('sha256'):
            raise ValueError('Runtime native component integrity failure')
    if not NATIVE - {'FDSensor.exe'} <= {e['name'] for e in entries}:
        raise ValueError('Missing native lifecycle integrity coverage')
    names = sorted(NATIVE | ({OPTIONAL} if (directory / OPTIONAL).exists() else set()))
    for name in names:
        pe((directory / name).read_bytes(), arch)
    pe((directory / 'edr_agent_setup.exe').read_bytes(), arch, installer=True)
    for local, suffix in (('FDSensor.exe', 'FDSensor.exe'), ('edr_agent_setup.exe', 'setup.exe')):
        path, asset = directory / local, assets[prefix + suffix]
        if path.stat().st_size != asset['size'] or 'sha256:' + digest(path) != asset['digest']:
            raise ValueError('Runtime/standalone Headless asset mismatch')
    full = read(directory / 'full-installer-manifest.json')
    if (full.get('version') != version or full.get('target_arch') != arch or full.get('setup_target_arch') != arch
            or full.get('setup_exe_sha256') != digest(directory / 'edr_agent_setup.exe')
            or full.get('agent_binary_sha256') != digest(directory / 'FDSensor.exe')
            or full.get('runtime_identity_sha256') != digest(directory / 'native-package-integrity.json')
            or full.get('capabilities') != caps or full.get('setup_exe_signed') is not signed):
        raise ValueError('Headless installer manifest closure mismatch')
    return names


def compare_runtime(original, target, arch, thumbprint):
    left, right = inventory(original), inventory(target)
    native = NATIVE | ({OPTIONAL} if OPTIONAL in left else set())
    changed = native | {'edr_agent_setup.exe', 'full-installer-manifest.json', 'native-package-integrity.json', 'package-capabilities.json'}
    if set(right) != set(left) | {'full-installer-manifest.p7s'} or any(left[n] != right[n] for n in left if n not in changed):
        raise ValueError('Repack changed immutable runtime contents')
    for name in native:
        same_payload(original / name, target / name, arch)
    caps = read(original / 'package-capabilities.json')
    caps['signature_status'] = 'signed'
    if read(target / 'package-capabilities.json') != caps:
        raise ValueError('Repack changed unrelated package capabilities')
    integrity = read(original / 'native-package-integrity.json')
    for entry in integrity['files']:
        entry['sha256'] = digest(target.joinpath(*safe_parts(entry['name'])))
    if read(target / 'native-package-integrity.json') != integrity:
        raise ValueError('Repack changed native integrity contract')
    before, after = read(original / 'full-installer-manifest.json'), read(target / 'full-installer-manifest.json')
    if not isinstance(after.get('generated_at_utc'), str) or after != headless_manifest(target, before, thumbprint, after.get('generated_at_utc')):
        raise ValueError('Repack changed installer recovery/publisher contract')


def compare_artifact_manifest(original, target, directory, receipt, assets, version, arch, thumbprint, subject):
    expected = copy.deepcopy(read(original))
    expected['signature'] = dict(format='cms-detached-sha256', status='signed', authenticode_scope='headless', signer_thumbprint=thumbprint, signer_subject=subject)
    expected['repack_provenance'] = receipt['repack_provenance']
    prefix = f'edr-agent-win_{version}-windows-{arch}-'
    names = {prefix + suffix for suffix in ('exe.zip', 'setup.exe', 'FDSensor.exe')}
    expected['artifacts'] = [entry for entry in expected['artifacts'] if entry['name'] in names]
    for entry in expected['artifacts']:
        item = assets[entry['name']]
        entry['size'], entry['sha256'] = item['size'], item['digest'][7:]
        if entry['name'] == prefix + 'FDSensor.exe':
            entry['update']['upgrade_class'] = 'installer_required'
            entry['update']['runtime_identity_sha256'] = digest(directory / 'native-package-integrity.json')
    if read(target) != expected:
        raise ValueError('Repack changed unrelated artifact/update metadata')


def manifest_contract(path, assets, source, version, arch, receipt=None, thumbprint=None, subject=None):
    value = read(path)
    if value.get('version') != version or value.get('build_provenance') != source['owner']:
        raise ValueError('Artifact manifest changed original build provenance')
    entries = value.get('artifacts', [])
    if len({e.get('name') for e in entries}) != len(entries):
        raise ValueError('Duplicate artifact manifest entry')
    prefix = f'edr-agent-win_{version}-windows-{arch}-'
    expected = {prefix + s for s in ('exe.zip', 'setup.exe', 'FDSensor.exe')}
    if receipt:
        if ({e.get('name') for e in entries} != expected or value.get('repack_provenance') != receipt['repack_provenance']
                or value.get('signature') != dict(format='cms-detached-sha256', status='signed', authenticode_scope='headless', signer_thumbprint=thumbprint, signer_subject=subject)):
            raise ValueError('Artifact Headless signature/provenance contract mismatch')
    elif value.get('signature', {}).get('status') != 'unsigned':
        raise ValueError('Original manifest is not unsigned')
    for name in expected:
        match = [e for e in entries if e.get('name') == name]
        if len(match) != 1 or match[0].get('size') != assets[name]['size'] or 'sha256:' + str(match[0].get('sha256')) != assets[name]['digest']:
            raise ValueError('Artifact manifest does not bind official asset bytes')


def fetch(repo, asset, destination):
    # Transport helper uses a fixed private repository; public download uses the
    # same bounded gh binary-output pattern without signed URL logging.
    destination.parent.mkdir(parents=True, exist_ok=True)
    if repo == PRIVATE:
        previous = os.environ.get('GH_TOKEN')
        try:
            os.environ['GH_TOKEN'] = os.environ['USB_SIGNING_RELEASE_TOKEN']
            download_asset(asset, destination)
        finally:
            if previous is None:
                os.environ.pop('GH_TOKEN', None)
            else:
                os.environ['GH_TOKEN'] = previous
        return
    partial = destination.with_name(destination.name + '.partial')
    if destination.exists() or partial.exists():
        raise ValueError('Download destination already exists')
    for attempt in range(2):
        try:
            with partial.open('xb') as output:
                result = subprocess.run(['gh', 'api', f"repos/{repo}/releases/assets/{asset['id']}", '-H', 'Accept: application/octet-stream'], stdout=output, stderr=subprocess.PIPE, timeout=300)
            if result.returncode == 0:
                if partial.stat().st_size != asset['size'] or 'sha256:' + digest(partial) != asset['digest']:
                    raise ValueError('Downloaded official asset size/digest mismatch')
                partial.rename(destination)
                return
        except subprocess.TimeoutExpired:
            pass
        finally:
            if partial.exists():
                partial.unlink()
        if attempt == 0:
            time.sleep(2)
    raise RuntimeError('Official asset download failed within bounded retries')


def stage(args):
    for tag in (args.source_tag, args.baseline_tag):
        if not re.fullmatch(r'win_[0-9]+\.[0-9]+\.[0-9]+', tag):
            raise ValueError('Invalid source/baseline tag')
    for field in ('source_run', 'private_release_id', 'private_run', 'private_attempt'):
        if not re.fullmatch(r'[1-9][0-9]*', str(getattr(args, field))):
            raise ValueError('Invalid run/attempt/Release identity')
    for value in (args.source_commit, args.private_commit):
        if not re.fullmatch(r'[a-f0-9]{40}', value):
            raise ValueError('Invalid immutable commit')
    if not re.fullmatch(r'[0-9A-F]{40}', args.thumbprint) or not args.subject:
        raise ValueError('Explicit publisher thumbprint/subject required')
    root = Path(args.root).resolve()
    if root.exists():
        raise ValueError('Use a fresh lifecycle input directory')
    if api(PRIVATE, '', True).get('private') is not True:
        raise ValueError('Signing transfer repository must remain private')
    source = public_source(args.source_tag, args.source_commit, args.source_run)
    baseline = public_source(args.baseline_tag)
    if tuple(map(int, args.baseline_tag[4:].split('.'))) >= tuple(map(int, args.source_tag[4:].split('.'))):
        raise ValueError('Baseline must be genuinely older than target')
    release = api(PRIVATE, f'releases/{args.private_release_id}', True)
    private_run = api(PRIVATE, f'actions/runs/{args.private_run}')
    # Automatic dispatch can start this consumer just before the private
    # transfer job exits. Wait only for that exact run; never accept in-progress.
    for _ in range(12):
        if private_run.get('status') == 'completed': break
        if private_run.get('head_sha') != args.private_commit:
            raise ValueError('Private executor changed while waiting for completion')
        time.sleep(5)
        private_run = api(PRIVATE, f'actions/runs/{args.private_run}')
    signing_jobs = jobs(PRIVATE, args.private_run, args.private_attempt)
    owner = validate_transfer(release, private_run, args, source, signing_jobs)
    assets = checked_assets(api(PRIVATE, f'releases/{args.private_release_id}/assets?per_page=100', True))
    root.mkdir(parents=True)
    fetch(PRIVATE, assets['result.json'], root / 'result.json')
    receipt = read(root / 'result.json')
    validate_result(receipt, owner, assets, args.source_tag[4:], args.thumbprint)
    for label, repo, state, tag in (('original', PUBLIC, source, args.source_tag), ('baseline', PUBLIC, baseline, args.baseline_tag), ('target', PRIVATE, dict(assets=assets), args.source_tag)):
        prefix = f'edr-agent-{tag}-windows-{args.arch}-'
        for suffix in ('exe.zip', 'setup.exe', 'artifact-manifest.json') + (('artifact-manifest.json.p7s',) if label == 'target' else ()):
            name = prefix + suffix
            fetch(repo, state['assets'][name], root / label / name)
        extract(root / label / (prefix + 'exe.zip'), root / label / 'runtime')
        runtime_contract(root / label / 'runtime', state['assets'], tag, args.arch, label == 'target')
        manifest_contract(root / label / (prefix + 'artifact-manifest.json'), state['assets'], baseline if label == 'baseline' else source, tag[4:], args.arch,
                          receipt if label == 'target' else None, args.thumbprint, args.subject)
    compare_runtime(root / 'original/runtime', root / 'target/runtime', args.arch, args.thumbprint)
    manifest_name = f'edr-agent-{args.source_tag}-windows-{args.arch}-artifact-manifest.json'
    compare_artifact_manifest(root / 'original' / manifest_name, root / 'target' / manifest_name,
                             root / 'target/runtime', receipt, assets, args.source_tag[4:],
                             args.arch, args.thumbprint, args.subject)
    # Re-read mutable Release metadata after download; no stale partial result can
    # satisfy acceptance. Never writes source or destination Release metadata.
    if public_source(args.source_tag, args.source_commit, args.source_run) != source or public_source(args.baseline_tag) != baseline:
        raise ValueError('Published source changed during admission')
    latest_assets = checked_assets(api(PRIVATE, f'releases/{args.private_release_id}/assets?per_page=100', True))
    if asset_identity(latest_assets) != asset_identity(assets) or validate_transfer(api(PRIVATE, f'releases/{args.private_release_id}', True), api(PRIVATE, f'actions/runs/{args.private_run}'), args, source, jobs(PRIVATE, args.private_run, args.private_attempt)) != owner:
        raise ValueError('Private transfer changed during admission')
    evidence = dict(schema='edr.headless-lifecycle-input.v1', source=source, baseline=baseline,
                    transfer=owner, private_release_id=args.private_release_id,
                    assets=asset_identity(assets), architecture=args.arch,
                    publisher_thumbprint=args.thumbprint, publisher_subject=args.subject)
    (root / 'admission.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print('Headless source, official asset digests, package contents and immutable Agent payload verified')


def installed(args):
    root, actual = Path(args.root).resolve(), Path(args.install_dir)
    admission = read(root / 'admission.json')
    labels = {'install-target-fresh': 'target', 'upgrade-target': 'target',
              'install-baseline': 'baseline', 'repair-baseline': 'baseline', 'rollback-baseline': 'baseline'}
    if (args.stage not in labels or admission.get('schema') != 'edr.headless-lifecycle-input.v1'
            or admission.get('architecture') != args.arch):
        raise ValueError('Unknown installed runtime checkpoint/admission')
    label = labels[args.stage]
    source = admission['baseline'] if label == 'baseline' else admission['source']
    expected_version = source['owner']['tag'][4:]
    if args.expected_version != expected_version:
        raise ValueError('Installed runtime checkpoint version differs from admitted package')
    expected = root / label / 'runtime'
    names = sorted(NATIVE | ({OPTIONAL} if (expected / OPTIONAL).exists() else set()))
    evidence = Path(args.evidence_dir)
    evidence.mkdir(parents=True, exist_ok=True)
    receipt = dict(schema='edr.headless-installed-native.v1', status='failed', stage=args.stage,
                   architecture=args.arch, version=expected_version, package=label,
                   source=source['owner'], install_dir=str(actual), files=[], error=None)
    try:
        for directory in (actual, *actual.parents):
            info = directory.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise ValueError('Installed runtime root/parent is a link or reparse point')
        if (actual / 'VERSION').read_text(encoding='utf-8-sig').strip() != expected_version:
            raise ValueError('Actual installed VERSION differs from admitted package')
        for name in names:
            reference, path = expected.joinpath(*safe_parts(name)), actual.joinpath(*safe_parts(name))
            record = dict(name=name, expected_sha256=digest(reference), expected_size=reference.stat().st_size,
                          actual_sha256=None, actual_size=None, status='failed')
            receipt['files'].append(record)
            for component in (path, *path.parents):
                if component == actual:
                    break
                info = component.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError('Installed native path is a link/reparse point: ' + name)
            if not path.is_file():
                raise ValueError('Installed native component missing: ' + name)
            record.update(actual_size=path.stat().st_size, actual_sha256=digest(path))
            if record['actual_size'] != record['expected_size'] or record['actual_sha256'] != record['expected_sha256']:
                raise ValueError('Installed native bytes differ from admitted runtime: ' + name)
            pe(path.read_bytes(), args.arch)
            record['status'] = 'succeeded'
        receipt['status'] = 'succeeded'
    except Exception as error:
        receipt['error'] = str(error)
        raise
    finally:
        (evidence / (args.stage + '.installed-native.json')).write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(f"Installed native closure verified: stage={args.stage} architecture={args.arch} files={len(names)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    stage_parser = commands.add_parser('stage')
    for name in ('source-tag', 'source-commit', 'source-run', 'private-release-id', 'private-run', 'private-attempt', 'private-commit', 'thumbprint', 'subject', 'baseline-tag', 'root'):
        stage_parser.add_argument('--' + name, required=True)
    stage_parser.add_argument('--arch', required=True, choices=ARCHES)
    installed_parser = commands.add_parser('installed')
    for name in ('root', 'install-dir', 'evidence-dir', 'stage', 'expected-version'):
        installed_parser.add_argument('--' + name, required=True)
    installed_parser.add_argument('--arch', required=True, choices=ARCHES)
    args = parser.parse_args()
    (stage if args.command == 'stage' else installed)(args)


if __name__ == '__main__':
    main()
