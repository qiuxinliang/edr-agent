"""Fixed, disposable ARM task qualification; never published-baseline eligibility."""
import argparse
import hashlib
import re
import stat
import zipfile
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
    late = environment.get('EXACT742_LATE_HEALTH_RECOVERY', '')
    maintenance = environment.get('EXACT742_SETUP_MAINTENANCE_RECOVERY', '')
    if (late not in ('', 'false', 'true') or maintenance not in ('', 'false', 'true')
            or ((late == 'true' or maintenance == 'true') and not raw)):
        raise ValueError('Exact case requires the explicit exact installed transition request and boolean case flags')
    if late == 'true' and maintenance == 'true':
        raise ValueError('Late-health and direct Setup maintenance/recovery are mutually exclusive cases')
    if (late == 'true' or maintenance == 'true') and (environment.get('INSTALLER_TIMEOUT_RECOVERY') == 'true' or environment.get('NATIVE_REPEAT_COUNT', '1') != '1'):
        raise ValueError('Exact recovery is one case and cannot mix generic timeout or repeat modes')
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



INSTALL_DIR = r'C:\Program Files\FDSecurity'
INTEGRITY_SHA = '5399c68ef8860199c2efccc4ece6b8e489b01cd7e6f89cfe582df3332e4f37f9'
FIRST_HOP_SCHEMA = 'edr.exact742-to747.first-hop.v1'
BINDING_ROLES = {'source_setup', 'target_setup', 'source_manifest', 'source_cms', 'source_proof',
                 'target_manifest', 'target_cms', 'target_proof', 'source_runtime_archive'}


def pinned_file(path, expected, limit=32 * 1024 * 1024):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400
            or not 0 < info.st_size <= limit or not re.fullmatch('[a-f0-9]{64}', str(expected))
            or io_owner.digest(path) != expected):
        raise ValueError('Exact first-hop file identity changed: ' + path.name)
    return path


def qualification_consumer(receipt, environment):
    """Only this clean hosted job's successful actual Setup receipt is eligible."""
    identities = {'harness_commit': 'GITHUB_SHA', 'run_id': 'GITHUB_RUN_ID',
                  'run_attempt': 'GITHUB_RUN_ATTEMPT', 'job': 'GITHUB_JOB'}
    for field, variable in identities.items():
        value = environment.get(variable, '')
        pattern = '[a-f0-9]{40}' if field == 'harness_commit' else ('[1-9][0-9]*' if field in ('run_id', 'run_attempt') else '[A-Za-z0-9_-]+')
        if not re.fullmatch(pattern, value) or receipt.get(field) != value:
            raise ValueError('Qualification is not from this fresh harness job: ' + field)
    if (environment.get('GITHUB_ACTIONS') != 'true' or environment.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or environment.get('RUNNER_ARCH') != 'ARM64' or receipt.get('runner_environment') != 'github-hosted'
            or receipt.get('architecture') != 'arm64' or receipt.get('target_version') != '3.2.747'
            or receipt.get('schema') != 'edr.exact-installed742.qualification-result.v1'
            or receipt.get('complete') is not True or receipt.get('qualification_only') is not True
            or any(receipt.get(k) is not False for k in ('full_gate', 'full_gate_passed', 'deployment_authorized'))
            or receipt.get('source_version') != '3.2.742'):
        raise ValueError('First-hop requires actual hosted ARM qualification, never full-gate admission')
    source_assets = {a['name']: a for a in ASSETS['source']}
    agent = source_assets['edr-agent-win_3.2.742-windows-arm64-FDSensor.exe']['digest'][7:]
    expected = dict(install_dir=INSTALL_DIR, runtime_mode='scheduled_task', agent_sha256=agent,
                    updater_sha256=UPDATER_SHA, launcher_sha256=LAUNCHER_SHA, native_integrity_sha256=INTEGRITY_SHA)
    if receipt.get('consumer_identity') != expected or receipt.get('source_setup_sha256') != source_assets['edr-agent-win_3.2.742-windows-arm64-setup.exe']['digest'][7:]:
        raise ValueError('Actual signed Setup consumer identity mismatch')
    if receipt.get('setup_output') != {k: expected[k] for k in ('updater_sha256', 'launcher_sha256', 'native_integrity_sha256')}:
        raise ValueError('Qualification actual Setup output changed')
    if not re.fullmatch('[a-f0-9]{64}', str(receipt.get('config_sha256', ''))):
        raise ValueError('Qualification synthetic config digest missing')
    task, uninstall = receipt.get('task_owner', {}), receipt.get('uninstall', {})
    if (task.get('mode') != 'scheduled_task' or task.get('name') != 'FDSecurityAgent' or task.get('path') != '\\'
            or not task.get('xml') or not task.get('sddl') or uninstall.get('version') != '3.2.742'
            or uninstall.get('location', '').rstrip('\\') != INSTALL_DIR):
        raise ValueError('Qualification source task or uninstall prestate missing')
    return expected



def assert_updater_equivalence(packaged, actual):
    if (hashlib.sha256(packaged).hexdigest() != PACKAGED_UPDATER_SHA
            or hashlib.sha256(actual).hexdigest() != UPDATER_SHA
            or packaged.replace(b'\r\n', b'\n') != actual):
        raise ValueError('Installed CAE is not the exact packaged updater CRLF-to-LF equivalent')

def prepare_first_hop(input_path, input_sha256, receipt_path, receipt_sha256, destination, environment=None):
    """Test-only adapter: original packaged baseline889 stays distinct from installed CAE."""
    environment = os.environ if environment is None else environment
    input_path = pinned_file(input_path, input_sha256, 1024 * 1024)
    receipt_path = pinned_file(receipt_path, receipt_sha256, 1024 * 1024)
    staged, receipt = io_owner.read(input_path), io_owner.read(receipt_path)
    consumer = qualification_consumer(receipt, environment)
    if (staged.get('schema') != 'edr.exact-installed-742-to-747.inputs.v1'
            or staged.get('source_version') != '3.2.742' or staged.get('target_version') != '3.2.747'
            or staged.get('architecture') != 'arm64' or staged.get('runtime_mode') != 'scheduled_task'
            or staged.get('first_hop_inputs_staged') is not False or staged.get('upgrade_input') is not None
            or staged.get('storage_tools_input') is not None):
        raise ValueError('First-hop requires unchanged qualification-only staging')
    root = input_path.parent
    bindings = staged.get('file_bindings', [])
    if len(bindings) != len(BINDING_ROLES) or {b['role'] for b in bindings} != BINDING_ROLES:
        raise ValueError('Exact first-hop requires nine unique staged roles')
    role_paths = {}
    for label, version in (('source', '3.2.742'), ('target', '3.2.747')):
        prefix = 'edr-agent-win_' + version + '-windows-arm64-'
        role_paths.update({label + '_setup': root / label / (prefix + 'setup.exe'),
                          label + '_manifest': root / label / (prefix + 'artifact-manifest.json'),
                          label + '_cms': root / label / (prefix + 'artifact-manifest.json.p7s'),
                          label + '_proof': root / label / 'publisher-verification.json'})
    role_paths['source_runtime_archive'] = root / 'source/edr-agent-win_3.2.742-windows-arm64-exe.zip'
    for field, role in [('source_setup_exe', 'source_setup'), ('target_setup_exe', 'target_setup'),
                        ('source_publisher_proof', 'source_proof'), ('target_publisher_proof', 'target_proof')]:
        if Path(staged.get(field, '')).resolve() != role_paths[role].resolve():
            raise ValueError('Qualification role path changed: ' + field)
    for binding in bindings:
        if Path(binding['path']).resolve() != role_paths[binding['role']].resolve():
            raise ValueError('Staged role does not identify its exact release member')
        file = pinned_file(binding['path'], binding['sha256'])
        if file.stat().st_size != binding['bytes']:
            raise ValueError('Staged input length changed')
    request = {'schema': SCHEMA, **{label + '_publisher_proof': io_owner.read(staged[label + '_publisher_proof']) for label in ('source', 'target')}}
    validate_request(request)
    for label in ('source', 'target'):
        inventory = {a['name']: a for a in ASSETS[label]}
        directory = root / label
        check_manifest(label, directory, inventory, request[label + '_publisher_proof'])
        archive = directory / ('edr-agent-win_' + ('3.2.742' if label == 'source' else '3.2.747') + '-windows-arm64-exe.zip')
        pinned_file(archive, inventory[archive.name]['digest'][7:])
    installed = Path(INSTALL_DIR)
    for name, expected in [('FDSensor.exe', consumer['agent_sha256']), ('edr_agent_inplace_update.ps1', UPDATER_SHA),
                           ('FDSensorTaskLaunch.ps1', LAUNCHER_SHA), ('native-package-integrity.json', INTEGRITY_SHA),
                           ('agent.toml', receipt['config_sha256'])]:
        pinned_file(installed / name, expected)
    baseline = root / 'source/edr-agent-win_3.2.742-windows-arm64-exe.zip'
    with zipfile.ZipFile(baseline) as archive:
        packaged = archive.read('edr_agent_inplace_update.ps1')
    actual = (installed / 'edr_agent_inplace_update.ps1').read_bytes()
    assert_updater_equivalence(packaged, actual)
    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError('Fresh first-hop output directory required')
    transition = checkpoint.prepare_lifecycle_upgrade(root / 'target', root / 'source', destination,
        'win_3.2.747', 'win_3.2.742', 'arm64', Path(staged['target_publisher_proof']))
    if (transition['baseline_updater_sha256'] != PACKAGED_UPDATER_SHA or transition['upgrade_class'] != 'installer_required'
            or transition['binary_sha256'] != request['target_publisher_proof']['artifact_sha256']):
        raise ValueError('Standard target release binding differs from exact first-hop')
    transition_path = destination / 'transition.json'
    result = dict(schema=FIRST_HOP_SCHEMA, source_consumer_receipt_path=str(receipt_path.resolve()),
        source_consumer_receipt_sha256=receipt_sha256, qualification_input_path=str(input_path.resolve()),
        qualification_input_sha256=input_sha256, target_release_binding_path=str(transition_path),
        target_release_binding_sha256=io_owner.digest(transition_path), packaged_source_runtime_sha256=io_owner.digest(baseline),
        packaged_source_updater_sha256=PACKAGED_UPDATER_SHA, source_updater_path=str(installed / 'edr_agent_inplace_update.ps1'),
        install_dir=INSTALL_DIR, architecture='arm64', runtime_mode='scheduled_task',
        harness={key: receipt[key] for key in ('harness_commit', 'run_id', 'run_attempt', 'job')},
        expected_recovery=dict(version=receipt['source_version'], agent_sha256=consumer['agent_sha256'], updater_sha256=consumer['updater_sha256'],
            launcher_sha256=consumer['launcher_sha256'], native_integrity_sha256=consumer['native_integrity_sha256'],
            config_sha256=receipt['config_sha256'], task_owner=receipt['task_owner'], uninstall=receipt['uninstall']),
        target_agent_sha256=transition['binary_sha256'], full_gate=False, deployment_authorized=False,
        old_full_setup_rollback_supported=False)
    path = destination / 'first-hop-input.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('validate', 'stage', 'first-hop'))
    parser.add_argument('--request', type=Path)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--input-sha256')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--receipt-sha256')
    args = parser.parse_args()
    if args.mode == 'first-hop':
        if not all((args.input, args.input_sha256, args.receipt, args.receipt_sha256, args.root)):
            parser.error('first-hop requires pinned --input, --receipt and fresh --root')
        path = prepare_first_hop(args.input, args.input_sha256, args.receipt, args.receipt_sha256, args.root)
        print(json.dumps(dict(input_path=str(path), input_sha256=io_owner.digest(path), full_gate=False, deployment_authorized=False)))
        return
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
