"""Bind two explicitly admitted signed candidates to the existing native lifecycle.

The input receipts come from the real backend verifier, not from the candidate
binary. This is a disposable-runner acceptance entry, never a production rollout.
"""
import argparse
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import headless_repack_lifecycle as admission
from windows_release_checkpoint import prepare_lifecycle_upgrade

VERIFIER_COMMIT = 'c59eda045e3e2b9c882d462b74533e2c4b6c45da'


def validate_request(request, arch):
    if (not isinstance(request, dict) or
            request.get('schema') != 'edr.signed-publisher-validation.v1' or
            request.get('legacy_tag') != 'win_3.2.723' or arch not in admission.ARCHES or
            not re.fullmatch(r'[a-f0-9]{40}', str(request.get('source_commit', '')))):
        raise ValueError('Explicit signed publisher validation identity is required')
    versions = []
    certificates = []
    for label in ('baseline', 'target'):
        value = request.get(label)
        if not isinstance(value, dict) or not re.fullmatch(r'win_[0-9]+\.[0-9]+\.[0-9]+', str(value.get('tag', ''))):
            raise ValueError('Both signed candidate versions must be explicit')
        versions.append(tuple(map(int, value['tag'][4:].split('.'))))
        for key in ('source_release_id', 'source_run', 'private_release_id', 'private_run', 'private_attempt'):
            if not re.fullmatch(r'[1-9][0-9]*', str(value.get(key, ''))):
                raise ValueError('Exact source and signing run/attempt/Release IDs are required')
        if not re.fullmatch(r'[a-f0-9]{40}', str(value.get('private_commit', ''))):
            raise ValueError('Exact signing executor commit is required')
        proofs = value.get('publisher_verification')
        if not isinstance(proofs, dict) or set(proofs) != set(admission.ARCHES):
            raise ValueError('Real backend publisher verification is required for both architectures')
        for proof_arch, proof in proofs.items():
            if (not isinstance(proof, dict) or
                    proof.get('schema') != 'edr.windows.publisher-verification.v1' or
                    proof.get('verifier_source_commit') != VERIFIER_COMMIT or
                    proof.get('version') != value['tag'][4:] or proof.get('arch') != proof_arch or
                    not re.fullmatch(r'[A-F0-9]{40}', str(proof.get('thumbprint', ''))) or
                    not isinstance(proof.get('subject'), str) or not 256 < len(proof['subject'].encode('utf-8')) <= 2048):
                raise ValueError('Publisher proof must bind the actual long-name failure and verifier')
            for key in ('manifest_sha256', 'signature_sha256', 'artifact_sha256', 'subject_der_sha256'):
                if not re.fullmatch(r'[a-f0-9]{64}', str(proof.get(key, ''))):
                    raise ValueError('Publisher proof requires exact SHA-256 identities')
            certificates.append((proof['thumbprint'], proof['subject'], proof['subject_der_sha256']))
    if not (versions[0] > (3, 2, 723) and versions[1] > versions[0]):
        raise ValueError('Acceptance requires a genuinely newer signed upgrade after legacy migration')
    if len(set(certificates)) != 1:
        raise ValueError('Both architectures and versions must use the same verified publisher')
    return request


def stage_pair(request, arch, root):
    request = validate_request(request, arch)
    root = Path(root).resolve()
    if root.exists():
        raise ValueError('Signed acceptance requires a fresh input directory')
    root.mkdir(parents=True)
    for label in ('baseline', 'target'):
        value = request[label]
        proof = value['publisher_verification'][arch]
        admission.stage(SimpleNamespace(source_tag=value['tag'], source_commit=request['source_commit'],
            source_run=str(value['source_run']), source_release_id=str(value['source_release_id']),
            private_release_id=str(value['private_release_id']), private_run=str(value['private_run']),
            private_attempt=str(value['private_attempt']), private_commit=value['private_commit'],
            thumbprint=proof['thumbprint'], subject=proof['subject'], baseline_tag=request['legacy_tag'],
            root=str(root / label), arch=arch, validation_draft=True))
        (root / label / 'publisher-verification.json').write_text(json.dumps(proof, indent=2) + '\n', encoding='utf-8')
    base, target = root / 'baseline', root / 'target'
    migration = prepare_lifecycle_upgrade(base / 'target', base / 'baseline', root / 'migration',
        request['baseline']['tag'], request['legacy_tag'], arch, base / 'publisher-verification.json')
    upgrade = prepare_lifecycle_upgrade(target / 'target', base / 'target', root / 'upgrade',
        request['target']['tag'], request['baseline']['tag'], arch, target / 'publisher-verification.json')
    if migration['target_updater_sha256'] != upgrade['baseline_updater_sha256']:
        raise ValueError('Migration and real upgrade do not share the original installed updater')
    result = dict(schema='edr.signed-publisher-stage.v1', architecture=arch,
        source_commit=request['source_commit'], verifier_source_commit=VERIFIER_COMMIT,
        legacy_version=request['legacy_tag'][4:], baseline_version=request['baseline']['tag'][4:],
        target_version=request['target']['tag'][4:],
        legacy_setup_exe=str(base / 'baseline/runtime/edr_agent_setup.exe'),
        baseline_setup_exe=migration['installer_path'], target_setup_exe=upgrade['installer_path'],
        migration_input=str(root / 'migration' / 'transition.json'),
        upgrade_input=str(root / 'upgrade' / 'transition.json'),
        legacy_config_template=str(base / 'baseline/runtime/agent_windows_production.example.toml'))
    (root / 'request.json').write_text(json.dumps(request, indent=2) + '\n', encoding='utf-8')
    (root / 'stage.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    if not 0 < args.request.stat().st_size <= 32768:
        raise ValueError('Signed acceptance request exceeds its bounded input size')
    request = json.loads(args.request.read_text(encoding='utf-8-sig'), object_pairs_hook=admission.unique)
    print(json.dumps(stage_pair(request, args.arch, args.root), sort_keys=True))


if __name__ == '__main__':
    main()
