"""Fixed, disposable ARM task qualification; never published-baseline eligibility."""
import argparse
import json
import os
from pathlib import Path

import headless_repack_lifecycle as io_owner
import windows_release_checkpoint as checkpoint
import windows_usb_bundle as normal_bundle

SCHEMA = 'edr.exact-installed-742-to-747.v1'
SOURCE_COMMIT = 'b307daa7a4e60a141d344fcb10bded19d97b436d'
TARGET_COMMIT = '388d69438781d93cd36871354439585feb1ebc07'
UPDATER_SHA = 'cae170855648559201c20b62d2d72d1bf2f030b61f5fda8ba27aa7534bd7a183'
PACKAGED_UPDATER_SHA = '88912072d0e842bb07c1ee730b91233f39e0e8dad57e403990c702bda58edc2a'
LAUNCHER_SHA = '656d349640d5403af0881bb5db7a4811074450cb93b6602c1322f03edfafd8c3'
THUMBPRINT = '01BB4E940A8E9CD5C09DEE81F17B5FB016750C3F'
DER_SHA = 'fb7a1b9fa95054b69d11e982bc77c6bb78f778b7e85943b3d1b198923d172a8a'
COHORT = 'installed742-to747'
# Exact existing official metadata, not caller-selectable release eligibility.
ASSETS = {'source': [{'digest': 'sha256:32b77e511853047a87f43c75d7c739f8f3be467fc57374cf2cce5fc65efa73be',
             'id': 722889728,
             'name': 'edr-agent-win_3.2.742-windows-arm64-artifact-manifest.json',
             'size': 6324},
            {'digest': 'sha256:3ec9d6a9bf4ce1c3f1762847f7e6c70b15f202596f9acdabf9862a102779f519',
             'id': 722889858,
             'name': 'edr-agent-win_3.2.742-windows-arm64-artifact-manifest.json.p7s',
             'size': 4573},
            {'digest': 'sha256:35068437d8fc507a7146dc603cea15d900d388a4edfc3c829a3aaae3c76eede7',
             'id': 722890064,
             'name': 'edr-agent-win_3.2.742-windows-arm64-exe.zip',
             'size': 14164070},
            {'digest': 'sha256:e6ea9736829d0c0be5284c570f198ec888bcaad1845a074ea8838ebf6b326dbe',
             'id': 722890317,
             'name': 'edr-agent-win_3.2.742-windows-arm64-FDSensor.exe',
             'size': 3410480},
            {'digest': 'sha256:6122591c151953e0416ca70815f4c437e62425cd1f5f48676087b25e32783c92',
             'id': 722890505,
             'name': 'edr-agent-win_3.2.742-windows-arm64-setup.exe',
             'size': 7343080},
            {'digest': 'sha256:5a7139a160a1fa8b354b8d9efb3b6bf5f9674de2c252320b7c55700e6dd5bb48',
             'id': 722890825,
             'name': 'result.json',
             'size': 5388}],
 'target': [{'digest': 'sha256:9495c0d399327a259aa9ac94c472443d3b899f6388f5222f386b7c8f8d298fbb',
             'id': 761637551,
             'name': 'edr-agent-win_3.2.747-windows-amd64-artifact-manifest.json',
             'size': 4701},
            {'digest': 'sha256:b75728f8e37e74f5b5d9fb7ea1729f7b5f8a066f8f0be038a1a995c078cf3f4d',
             'id': 761637808,
             'name': 'edr-agent-win_3.2.747-windows-amd64-artifact-manifest.json.p7s',
             'size': 4573},
            {'digest': 'sha256:a5f8c919d996301fa762d081fc5ceb30d23585ab754ae387efa13dccd05f1e67',
             'id': 761638047,
             'name': 'edr-agent-win_3.2.747-windows-amd64-exe.zip',
             'size': 13438603},
            {'digest': 'sha256:7ed86f96465a0098a6c73d1e4a6fa5253650061bfeb874c886d85ff64c8c7358',
             'id': 761638434,
             'name': 'edr-agent-win_3.2.747-windows-amd64-FDSensor.exe',
             'size': 3534896},
            {'digest': 'sha256:48a7db992987eff642684e22f8478b89e5c0dd65d0d671786fe465580b0d8d4c',
             'id': 761638680,
             'name': 'edr-agent-win_3.2.747-windows-amd64-setup-ui.zip',
             'size': 76981493},
            {'digest': 'sha256:fb677054112b86b4aa428f09577ce37ec44ad8252f75473b69c32bf2affba88c',
             'id': 761639469,
             'name': 'edr-agent-win_3.2.747-windows-amd64-setup.exe',
             'size': 7036536},
            {'digest': 'sha256:b499e6a0d595e8273e14eba632ca6bb0c05015ccbc69ca71ffd549ee9f4339d7',
             'id': 761639784,
             'name': 'edr-agent-win_3.2.747-windows-arm64-artifact-manifest.json',
             'size': 4716},
            {'digest': 'sha256:b565294b9574fdb2597f3fdf1c8322602d96c4553954900bdff6c498b8bf88ae',
             'id': 761640053,
             'name': 'edr-agent-win_3.2.747-windows-arm64-artifact-manifest.json.p7s',
             'size': 4573},
            {'digest': 'sha256:4f7552ea8e4ab869d93cf125240c85070c6406e2b1b9733f50a5aeab853b3c81',
             'id': 761640338,
             'name': 'edr-agent-win_3.2.747-windows-arm64-exe.zip',
             'size': 14134986},
            {'digest': 'sha256:c1ea2133d925ff688dd6f15419ecd5dd2065525466e78b8a44c51212a6464fd0',
             'id': 761640743,
             'name': 'edr-agent-win_3.2.747-windows-arm64-FDSensor.exe',
             'size': 3420208},
            {'digest': 'sha256:ba410ab39d6a83e9efbd7a4d016b061eaf707a1f11d13f1ec7a7682fa735c58c',
             'id': 761641065,
             'name': 'edr-agent-win_3.2.747-windows-arm64-setup-ui.zip',
             'size': 72980062},
            {'digest': 'sha256:94584a2fef75b65d2cd8574da399f58d4587aa6edf32f13477919c23ce1b5959',
             'id': 761641973,
             'name': 'edr-agent-win_3.2.747-windows-arm64-setup.exe',
             'size': 7332008},
            {'digest': 'sha256:304fde48663629d0f721a86631619dc7fa2d07d7554fe21d1b5882004f44d2ca',
             'id': 761642277,
             'name': 'usb-transfer-receipt.json',
             'size': 2873}]}
OWNERS = {'source': {'baseline_tag': 'win_3.2.723',
            'executor': {'attempt': '2',
                         'commit': '451122c8cdb268de00aab367e1347f63456253ec',
                         'repository': 'qiuxinliang/edr-agent-signing',
                         'run_id': '42446128878'},
            'schema': 'edr.published-headless-repack-transfer.v1',
            'scope': 'headless',
            'signer': {'attempt': '2',
                       'commit': '451122c8cdb268de00aab367e1347f63456253ec',
                       'repository': 'qiuxinliang/edr-agent-signing',
                       'run_id': '42446128878'},
            'source': {'attempt': '1',
                       'commit': 'b307daa7a4e60a141d344fcb10bded19d97b436d',
                       'mode': 'unsigned',
                       'p0_test_inputs': {'commit': '1190a89c39c0fcf675626afe040ed11b93670f09',
                                          'repository': 'qiuxinliang/EDRAI',
                                          'sha256': 'dbcdf97bd9adc64912deae6f42142adb1c1d74221e7cd02084596857055d996d'},
                       'repository': 'qiuxinliang/edr-agent',
                       'run_id': '42383797957',
                       'tag': 'win_3.2.742',
                       'upgrade_class': 'installer_required'},
            'version': '3.2.742'},
 'target': {'context': {'executor': {'attempt': '13',
                                     'commit': '388d69438781d93cd36871354439585feb1ebc07',
                                     'repository': 'qiuxinliang/edr-agent',
                                     'run_id': '44045971480'},
                        'inputs': [{'digest': 'sha256:dcb2081961778766a9fa523ff962d13bf161240beed4b5ff198b2a2bd3f65f9f',
                                    'id': '14312986737',
                                    'name': 'release-input-amd64',
                                    'size_in_bytes': 103562761},
                                   {'digest': 'sha256:22214133a03a061f7f1f3f487719789796997640cc4e0c0db2d0a3bbca12af2e',
                                    'id': '14313043719',
                                    'name': 'release-input-arm64',
                                    'size_in_bytes': 100120711}],
                        'request_id': 'd3528c3f4e3441a6863367819a4f5087',
                        'scope': 'headless',
                        'source': {'attempt': '13',
                                   'commit': '388d69438781d93cd36871354439585feb1ebc07',
                                   'repository': 'qiuxinliang/edr-agent',
                                   'run_id': '44045971480'},
                        'version': '3.2.747'},
            'schema': 'edr.usb-release-transfer.v1',
            'signer': {'attempt': '1',
                       'commit': '71bdff6a7ee830c6ed0607b778d7d20c644ce805',
                       'repository': 'qiuxinliang/edr-agent-signing',
                       'run_id': '44226648826'}}}
RELEASES = {'source': (438033469, 'edr-usb-headless-repack-42446128878-2'),
            'target': (449468760, 'edr-usb-44226648826-1')}


def validate_request(request):
    if not isinstance(request, dict) or set(request) != {'schema', 'source_publisher_proof', 'target_publisher_proof'} or request['schema'] != SCHEMA:
        raise ValueError('Exact installed742-to747 request schema/fields required')
    for label, version in (('source', '3.2.742'), ('target', '3.2.747')):
        proof = request[label + '_publisher_proof']
        checkpoint.publisher_verification_map(json.dumps({'arm64': proof}), 'win_' + version, 'arm64')
        expected = {a['name']: a for a in ASSETS[label]}
        prefix = 'edr-agent-win_' + version + '-windows-arm64-'
        for field, suffix in (('manifest_sha256', 'artifact-manifest.json'),
                              ('signature_sha256', 'artifact-manifest.json.p7s'), ('artifact_sha256', 'FDSensor.exe')):
            if proof[field] != expected[prefix + suffix]['digest'][7:]:
                raise ValueError('Proof differs from fixed official ' + label + ' asset: ' + field)
        if proof.get('thumbprint') != THUMBPRINT or proof.get('subject_der_sha256') != DER_SHA or not isinstance(proof.get('subject'), str) or not 0 < len(proof['subject'].encode()) <= 2048:
            raise ValueError('Exact publisher identity required')
    return request


def validate_routing(raw, environment):
    if not raw:
        return None
    if (len(raw.encode('utf-8')) > 32768 or environment.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or environment.get('LIFECYCLE_PACKAGE_SCOPE') != 'full'
            or environment.get('LIFECYCLE_ARCHITECTURE') != 'arm64'
            or environment.get('LIFECYCLE_TARGET_TAG') != 'win_3.2.747'
            or environment.get('LIFECYCLE_BASELINE_TAG') != 'win_3.2.742'
            or environment.get('CACHE_RECOVERY_SUBSET') == 'true'
            or environment.get('PUBLISHER_VALIDATION_REQUEST') or environment.get('PUBLISHER_VERIFICATION_JSON')):
        raise ValueError('Exact installed transition requires its isolated manual full ARM742-to747 route')
    return validate_request(json.loads(raw, object_pairs_hook=io_owner.unique))


def validate_release(label, release):
    release_id, tag = RELEASES[label]
    if release.get('id') != release_id or release.get('tag_name') != tag or release.get('draft') is not False or release.get('prerelease') is not True:
        raise ValueError('Fixed sealed private release identity required')
    body = release.get('body', '')
    if not body.startswith('edr-private-transfer-v1\n') or json.loads(body.split('\n', 1)[1], object_pairs_hook=io_owner.unique) != OWNERS[label]:
        raise ValueError('Historical product/signer transport identity changed')
    actual = io_owner.checked_assets(release.get('assets'))
    expected = {a['name']: a for a in ASSETS[label]}
    if set(actual) != set(expected):
        raise ValueError('Official asset set changed')
    for name, item in expected.items():
        if any(actual[name].get(key) != item[key] for key in ('id', 'name', 'size', 'digest')):
            raise ValueError('Official asset identity changed: ' + name)
    return actual


def check_manifest(label, directory, assets, proof):
    version = '3.2.742' if label == 'source' else '3.2.747'
    prefix = 'edr-agent-win_' + version + '-windows-arm64-'
    path = directory / (prefix + 'artifact-manifest.json')
    manifest = io_owner.read(path)
    signature = manifest.get('signature', {})
    if (manifest.get('version') != version or signature.get('status') != 'signed'
            or signature.get('format') != 'cms-detached-sha256'
            or signature.get('signer_thumbprint') != THUMBPRINT or signature.get('signer_subject') != proof['subject']):
        raise ValueError('Signed manifest publisher/version changed')
    provenance = manifest.get('build_provenance', {})
    if provenance.get('commit') != (SOURCE_COMMIT if label == 'source' else TARGET_COMMIT) or provenance.get('run_id') != ('42383797957' if label == 'source' else '44045971480'):
        raise ValueError('Product provenance changed')
    if provenance.get('repository')!=io_owner.PUBLIC or provenance.get('tag')!='win_'+version or provenance.get('mode')!=('unsigned' if label=='source' else 'usb'):
        raise ValueError('Product repository/tag/mode changed')
    for field, suffix in (('manifest_sha256', 'artifact-manifest.json'), ('signature_sha256', 'artifact-manifest.json.p7s')):
        if io_owner.digest(directory / (prefix + suffix)) != proof[field]:
            raise ValueError('Downloaded proof input changed')
    listed=manifest.get('artifacts', [])
    if not isinstance(listed,list) or any(not isinstance(a,dict) or not isinstance(a.get('name'),str) for a in listed):
        raise ValueError('Signed manifest artifact list invalid')
    entries = {a['name']: a for a in listed}
    if len(entries)!=len(listed):raise ValueError('Duplicate signed manifest artifact')
    for suffix in ('FDSensor.exe', 'exe.zip', 'setup.exe'):
        name = prefix + suffix
        if name not in entries or any(entries[name].get(key) != value for key, value in (('size', assets[name]['size']), ('sha256', assets[name]['digest'][7:]))):
            raise ValueError('Signed manifest artifact binding changed')
    return manifest


def stage(request, root):
    validate_request(request)
    root = Path(root).resolve()
    if root.exists():
        raise ValueError('Fresh exact acceptance input root required')
    # Prove both credentials can read these exact private Contents before creating inputs.
    releases = {label: io_owner.api(io_owner.PRIVATE, 'releases/' + str(RELEASES[label][0]), private_contents=True) for label in RELEASES}
    inventories = {label: validate_release(label, release) for label, release in releases.items()}
    root.mkdir(parents=True)
    for label, version in (('source', '3.2.742'), ('target', '3.2.747')):
        directory = root / label
        directory.mkdir()
        prefix = 'edr-agent-win_' + version + '-windows-arm64-'
        for suffix in ('artifact-manifest.json', 'artifact-manifest.json.p7s', 'FDSensor.exe', 'exe.zip', 'setup.exe'):
            io_owner.fetch(io_owner.PRIVATE, inventories[label][prefix + suffix], directory / (prefix + suffix))
        proof = request[label + '_publisher_proof']
        check_manifest(label, directory, inventories[label], proof)
        runtime = directory / 'runtime'
        if label=='source':
            io_owner.extract(directory / (prefix + 'exe.zip'), runtime)
        else:
            normal_bundle.unpack(directory / (prefix + 'exe.zip'), runtime)
        io_owner.runtime_contract(runtime, inventories[label], 'win_' + version, 'arm64', True)
        (directory / 'publisher-verification.json').write_text(json.dumps(proof, ensure_ascii=False), encoding='utf-8')
    source, target = root / 'source', root / 'target'
    if io_owner.digest(source / 'runtime/edr_agent_inplace_update.ps1') != PACKAGED_UPDATER_SHA:
        raise ValueError('Official source runtime updater changed')
    result = dict(schema='edr.exact-installed-742-to-747.inputs.v1', architecture='arm64', runtime_mode='scheduled_task',
        source_version='3.2.742', target_version='3.2.747', source_setup_exe=str(source / 'edr-agent-win_3.2.742-windows-arm64-setup.exe'),
        target_setup_exe=str(target / 'edr-agent-win_3.2.747-windows-arm64-setup.exe'), source_runtime_directory=str(source / 'runtime'),
        source_installed_agent_sha256=request['source_publisher_proof']['artifact_sha256'], source_installed_updater_sha256=UPDATER_SHA,
        source_installed_launcher_sha256=LAUNCHER_SHA, source_publisher_proof=str(source/'publisher-verification.json'),
        target_publisher_proof=str(target/'publisher-verification.json'),
        upgrade_input=None, upgrade_input_sha256=None, storage_tools_input=None, storage_tools_input_sha256=None,
        first_hop_inputs_staged=False, qualification_only=True, full_gate=False, full_gate_passed=False, deployment_authorized=False,
        old_full_setup_rollback_supported=False,
        official_source_runtime_sha256=inventories['source']['edr-agent-win_3.2.742-windows-arm64-exe.zip']['digest'][7:],
        storage_cohort=COHORT, storage_source_commits={'legacy': SOURCE_COMMIT, 'candidate': TARGET_COMMIT},
        identities={'products': {'source': SOURCE_COMMIT, 'target': TARGET_COMMIT}, 'historical_signers': {k: OWNERS[k].get('signer') for k in OWNERS},
                    'harness': {k: os.environ.get(k, '') for k in ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')}})
    binding_paths={
        'source_setup':result['source_setup_exe'], 'target_setup':result['target_setup_exe'],
        'source_manifest':str(source/'edr-agent-win_3.2.742-windows-arm64-artifact-manifest.json'),
        'source_cms':str(source/'edr-agent-win_3.2.742-windows-arm64-artifact-manifest.json.p7s'),
        'source_proof':str(source/'publisher-verification.json'),
        'target_manifest':str(target/'edr-agent-win_3.2.747-windows-arm64-artifact-manifest.json'),
        'target_cms':str(target/'edr-agent-win_3.2.747-windows-arm64-artifact-manifest.json.p7s'),
        'target_proof':str(target/'publisher-verification.json'),
        'source_runtime_archive':str(source/'edr-agent-win_3.2.742-windows-arm64-exe.zip')}
    result['file_bindings']=[dict(role=role,path=path,bytes=Path(path).stat().st_size,sha256=io_owner.digest(path)) for role,path in binding_paths.items()]
    result['runtime_file_bindings']={label:[dict(relative_path=file.relative_to(root/label/'runtime').as_posix(),
        bytes=file.stat().st_size,sha256=io_owner.digest(file)) for file in sorted((root/label/'runtime').rglob('*')) if file.is_file()] for label in ('source','target')}
    (root / 'lifecycle-inputs.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('validate', 'stage'))
    parser.add_argument('--request', type=Path)
    parser.add_argument('--root', type=Path)
    args = parser.parse_args()
    raw = args.request.read_text(encoding='utf-8-sig') if args.request else os.environ.get('EXACT_INSTALLED_TRANSITION_REQUEST', '')
    if len(raw.encode('utf-8')) > 32768:
        raise ValueError('Exact request exceeds 32 KiB')
    request = validate_request(json.loads(raw, object_pairs_hook=io_owner.unique))
    if args.mode == 'validate':
        print('Fixed exact installed742-to747 request accepted; no installation performed')
        return
    if not args.root:
        parser.error('stage requires --root')
    stage(request, args.root)
    path=Path(args.root).resolve()/'lifecycle-inputs.json'
    print(json.dumps(dict(input_path=str(path),input_sha256=io_owner.digest(path),qualification_only=True,full_gate=False,deployment_authorized=False)))


if __name__ == '__main__':
    main()
