"""USB packaging boundary: untrusted ZIPs are data, never executable build scripts."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import zipfile

import windows_release_checkpoint as cp

NATIVE = {'FDSensor.exe', 'FDSecurityInstallerWorker.exe', 'uninstall.exe',
          'collector/forensic_collector_builtin.exe', 'collector/forensic_collector.exe'}


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def child(root, name):
    name = name.replace('\\', '/')
    parts = PurePosixPath(name).parts
    if (not parts or name.startswith('/') or any(p in ('.', '..') or p.endswith((' ', '.'))
            or re.search(r'[:\x00-\x1f]', p) or re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', p)
            for p in parts)):
        raise ValueError('Unsafe archive/manifest path')
    path = root.joinpath(*parts)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Path escapes packaging directory')
    return path


def unpack(archive, destination):
    # Bound decompression before writing; no partial extraction for malformed input.
    with zipfile.ZipFile(archive) as z:
        seen, total = set(), 0
        for info in z.infolist():
            path = child(destination, info.filename)
            key = str(path).casefold()
            mode = info.external_attr >> 16
            if key in seen or stat.S_ISLNK(mode):
                raise ValueError('Duplicate or symlink archive entry')
            seen.add(key)
            total += info.file_size
            if total > 2 * 1024**3 or len(seen) > 10000:
                raise ValueError('Archive exceeds release packaging limits')
        for info in z.infolist():
            path = child(destination, info.filename)
            if info.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, path.open('xb') as dst:
                    shutil.copyfileobj(src, dst)


def inventory(root):
    return {p.relative_to(root).as_posix(): cp.digest(p) for p in root.rglob('*') if p.is_file()}


def headless_manifest(runtime, original, thumbprint, generated_at):
    """Existing protocol-5 consumers need a signed installer, not a GUI shell."""
    return dict(
        name='FDSecurity Headless Installer', version=original['version'],
        target_arch=original['target_arch'], setup_target_arch=original['setup_target_arch'],
        setup_exe='FDSecuritySetup.exe', setup_exe_sha256=cp.digest(runtime / 'edr_agent_setup.exe'),
        setup_exe_signed=True, agent_binary_sha256=cp.digest(runtime / 'FDSensor.exe'),
        runtime_identity_sha256=cp.digest(runtime / 'native-package-integrity.json'),
        publisher_thumbprint=thumbprint, capabilities=read(runtime / 'package-capabilities.json'),
        upgrade_protocol=original['upgrade_protocol'],
        preserves_existing_identity=original['preserves_existing_identity'],
        preserves_offline_queue=original['preserves_offline_queue'],
        preserves_evidence_cache=original['preserves_evidence_cache'],
        generated_at_utc=generated_at)


def stage(assets, destination, expected, arch, candidate):
    (cp.verify_checkpoint if candidate else cp.inspect_bundle)(assets, expected, arch, candidate=candidate)
    if destination.exists():
        raise ValueError('Use a fresh staging directory; previous attempts are not trusted')
    destination.mkdir(parents=True)
    shutil.copytree(assets, destination / 'assets')
    prefix = f'edr-agent-{expected["tag"]}-windows-{arch}-'
    unpack(assets / (prefix + 'exe.zip'), destination / 'runtime')
    unpack(assets / (prefix + 'setup-ui.zip'), destination / 'ui')
    runtime, ui = destination / 'runtime', destination / 'ui'
    if (runtime / 'VERSION').read_text().strip() != expected['tag'][4:]:
        raise ValueError('Runtime version mismatch')
    identities = [(runtime / 'FDSensor.exe', assets / (prefix + 'FDSensor.exe')),
                  (runtime / 'edr_agent_setup.exe', assets / (prefix + 'setup.exe'))]
    if candidate:
        identities.extend(((ui / 'FDSecuritySetup.exe', assets / (prefix + 'setup.exe')),
                           (ui / 'setup-ui-manifest.json', runtime / 'full-installer-manifest.json')))
    for left, right in identities:
        if cp.digest(left) != cp.digest(right):
            raise ValueError('Installer/runtime/raw asset identity mismatch')
    integrity = read(runtime / 'native-package-integrity.json')
    if integrity.get('schema') != 'edr.windows.native-package-integrity.v1':
        raise ValueError('Unknown runtime integrity schema')
    entries = integrity['files']
    if len({e['name'].casefold() for e in entries}) != len(entries):
        raise ValueError('Duplicate runtime integrity entry')
    for entry in entries:
        if cp.digest(child(runtime, entry['name'])) != entry['sha256']:
            raise ValueError('Runtime component hash mismatch')
    runtime_status = 'unsigned' if candidate else 'signed'
    for root, manifest_name, setup_name, status in (
            (ui, 'setup-ui-manifest.json', 'FDSecuritySetup.exe', 'unsigned'),
            (runtime, 'full-installer-manifest.json', 'edr_agent_setup.exe', runtime_status)):
        manifest = read(root / manifest_name)
        hashes = {'setup_exe_sha256': root / setup_name,
                  'agent_binary_sha256': runtime / 'FDSensor.exe',
                  'runtime_identity_sha256': runtime / 'native-package-integrity.json'}
        if root == ui:
            hashes['ui_exe_sha256'] = ui / 'FDSecuritySetupUI.exe'
            if manifest.get('ui_exe_signed') is not False:
                raise ValueError('Setup UI executable must remain unsigned')
        for key, path in hashes.items():
            if manifest.get(key) != cp.digest(path):
                raise ValueError('Installer manifest hash mismatch: ' + key)
        if (manifest['version'] != expected['tag'][4:] or manifest['target_arch'] != arch
                or manifest['setup_target_arch'] != arch or manifest['capabilities']['signature_status'] != status
                or manifest.get('setup_exe_signed') is not (status == 'signed')):
            raise ValueError('Installer version/architecture/signature closure mismatch')
    if read(runtime / 'package-capabilities.json')['signature_status'] != runtime_status:
        raise ValueError('Runtime signature closure mismatch')
    if not candidate:
        release = read(assets / (prefix + 'artifact-manifest.json'))
        if release['signature'].get('authenticode_scope') != 'headless':
            raise ValueError('Final USB release must explicitly declare Headless signing scope')


def compare(original, signed, thumbprint, subject):
    for root, allowed, additions in (
        ('runtime', NATIVE | {'native-package-integrity.json', 'package-capabilities.json',
                             'edr_agent_setup.exe', 'full-installer-manifest.json'}, {'full-installer-manifest.p7s'}),
        ('ui', {'FDSecuritySetup.exe', 'setup-ui-manifest.json'}, {'setup-ui-manifest.p7s'})):
        before, after = inventory(original / root), inventory(signed / root)
        if set(after) != set(before) | additions:
            raise ValueError('Signed package file set changed: ' + root)
        if any(before[n] != after[n] for n in before if n not in allowed):
            raise ValueError('Signing changed an immutable package component: ' + root)
    for name in ('package-capabilities.json', 'native-package-integrity.json'):
        before, after = read(original / 'runtime' / name), read(signed / 'runtime' / name)
        if name == 'package-capabilities.json':
            before['signature_status'] = 'signed'
        else:
            for entry in before['files']:
                entry['sha256'] = cp.digest(child(signed / 'runtime', entry['name']))
        if before != after:
            raise ValueError('Runtime metadata changed outside signing contract')
    before, after = read(original / 'ui/setup-ui-manifest.json'), read(signed / 'ui/setup-ui-manifest.json')
    for key in ('setup_exe_sha256', 'agent_binary_sha256', 'runtime_identity_sha256', 'generated_at_utc'):
        before[key] = after[key]  # Hashes were independently checked by stage().
    before.update(publisher_thumbprint=thumbprint)
    if before != after:
        raise ValueError('Installer contract changed outside signing fields')
    full = read(signed / 'runtime/full-installer-manifest.json')
    if full != headless_manifest(signed / 'runtime', read(original / 'ui/setup-ui-manifest.json'),
                                 thumbprint, full.get('generated_at_utc')):
        raise ValueError('Headless installer contract changed outside signing fields')
    before = read(next((original / 'assets').glob('*artifact-manifest.json')))
    after = read(next((signed / 'assets').glob('*artifact-manifest.json')))
    before['signature'] = dict(format='cms-detached-sha256', status='signed', authenticode_scope='headless',
                               signer_thumbprint=thumbprint, signer_subject=subject)
    for entry in before['artifacts']:
        p = signed / 'assets' / entry['name']
        entry.update(sha256=cp.digest(p), size=p.stat().st_size)
        if 'update' in entry:
            entry['update'].update(upgrade_class='installer_required',
                                  runtime_identity_sha256=cp.digest(signed / 'runtime/native-package-integrity.json'))
    if before != after:
        raise ValueError('Release contract/source changed outside signing fields')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('stage-input', 'verify'))
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    p.add_argument('--signed', type=Path)
    p.add_argument('--thumbprint', default='')
    p.add_argument('--subject', default='')
    args = p.parse_args()
    expected = cp.source()
    if expected['mode'] != 'usb':
        raise ValueError('USB finalization requires an explicit USB release')
    stage(args.input, args.output / 'original', expected, args.arch, True)
    if args.mode == 'verify':
        if not re.fullmatch('[A-F0-9]{40}', args.thumbprint) or not args.subject:
            raise ValueError('Pinned publisher thumbprint/subject required')
        stage(args.signed, args.output / 'signed', expected, args.arch, False)
        compare(args.output / 'original', args.output / 'signed', args.thumbprint, args.subject)
    print('USB bundle data contract verified: ' + args.arch)


if __name__ == '__main__':
    main()
