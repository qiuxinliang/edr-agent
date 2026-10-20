"""CI-only dependency closure adapter; does not build, execute or release Agent.

The pinned existing native-tool owner supplies PE/import/OS-allowlist checks.
This file is a private executable DRAFT, not Windows-validated.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import time


FAILURE_CODES = frozenset((
    'pinned_import_owner_mismatch', 'seed_manifest_sha_mismatch',
    'same_source_passed_seed_tool_required', 'compiled_agent_identity_mismatch',
    'compiled_agent_architecture_mismatch', 'dependency_stage_deadline',
    'dependency_file_count_cap', 'dependency_architecture_mismatch',
    'dependency_total_cap', 'dependency_source_changed',
    'dependency_copy_readback_mismatch',
    'dependency_not_in_pinned_compiler_roots', 'ambiguous_dependency_bytes',
    'runtime_inventory_mismatch',
))
OWNER_FAILURE_CODES = {
    'Symlink/reparse path is not permitted': 'owner_reparse_refused',
    'Required directory is missing': 'owner_directory_missing',
    'Required regular file is missing': 'owner_regular_file_missing',
    'File exceeds the bounded diagnostic artifact size': 'owner_file_cap',
    'Invalid PE DOS header': 'owner_pe_dos_header',
    'Invalid PE header offset': 'owner_pe_offset',
    'Invalid PE signature': 'owner_pe_signature',
    'Expected a complete PE32+ optional header': 'owner_pe_optional_header',
    'Unrecognised dumpbin dependency output': 'owner_dumpbin_shape',
    'dumpbin reported a dependency diagnostic': 'owner_dumpbin_diagnostic',
    'Invalid dependency name or unexpected dumpbin import section': 'owner_import_shape',
    'dumpbin produced no recognised imports': 'owner_imports_empty',
    'Native tool staging deadline expired': 'owner_stage_deadline',
    'dumpbin dependency inspection failed': 'owner_dumpbin_failed',
    'Invalid or ambiguous dependency filename': 'owner_dll_name_ambiguous',
    'Staged artifact contains missing or extra files': 'owner_inventory_mismatch',
    'Invalid staged artifact path': 'owner_artifact_path',
    'Staged artifact hash/size mismatch': 'owner_artifact_hash_or_size',
    'Staged PE architecture mismatch': 'owner_artifact_machine',
}


def failure_projection(error):
    """No exception text, paths, arguments or traceback in the public result."""
    cause = 'unknown'
    if isinstance(error, ValueError) and len(error.args) == 1 and type(error.args[0]) is str:
        value = error.args[0]
        if value in FAILURE_CODES:
            cause = value
        else:
            cause = OWNER_FAILURE_CODES.get(value, 'unknown')
    kind = type(error).__module__ + '.' + type(error).__qualname__
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,255}', kind, re.ASCII):
        kind = 'unknown'
    return {'schema': 'edr.ci-owned-failure.v1', 'origin': 'python_stage',
            'exception_type': kind, 'hresult': None, 'cause_code': cause}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--owner', required=True)
    p.add_argument('--owner-sha256', required=True)
    p.add_argument('--agent', required=True)
    p.add_argument('--agent-sha256', required=True)
    p.add_argument('--dumpbin', required=True)
    p.add_argument('--dll-root', action='append', required=True)
    p.add_argument('--destination', required=True)
    p.add_argument('--receipt', required=True)
    p.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
    p.add_argument('--native-manifest', required=True)
    p.add_argument('--native-manifest-sha256', required=True)
    p.add_argument('--source', required=True)
    p.add_argument('--run-id', required=True)
    p.add_argument('--run-attempt', required=True)
    a = p.parse_args()
    owner = Path(a.owner)
    if hashlib.sha256(owner.read_bytes()).hexdigest() != a.owner_sha256:
        raise ValueError('pinned_import_owner_mismatch')
    spec = importlib.util.spec_from_file_location('ci_native_import_owner', owner)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # definitions only: its __main__ is not run.
    native = module.real_path(a.native_manifest)
    if hashlib.sha256(native.read_bytes()).hexdigest() != a.native_manifest_sha256:
        raise ValueError('seed_manifest_sha_mismatch')
    metadata = json.loads(native.read_text(encoding='utf-8'))
    if (metadata['schema'] != 'edr.retention-native-tools.v1'
            or metadata['source_sha'] != a.source or metadata['arch'] != a.arch
            or metadata['run_id'] != a.run_id
            or metadata['run_attempt'] != a.run_attempt
            or metadata['provenance']['stager']['sha256'] != a.owner_sha256
            or metadata['prior_contract_status'] != 'passed'
            or metadata['native_contracts_passed_before_staging'] is not True):
        raise ValueError('same_source_passed_seed_tool_required')
    module.verify_stage(native.parent, metadata)
    agent = module.real_path(a.agent)
    dumpbin = module.real_path(a.dumpbin)
    if agent.name != 'FDSensor.exe' or module.digest(agent) != a.agent_sha256:
        raise ValueError('compiled_agent_identity_mismatch')
    expected_machine = module.MACHINES[a.arch]
    if module.pe_machine(agent) != expected_machine:
        raise ValueError('compiled_agent_architecture_mismatch')
    destination = Path(a.destination)
    module.real_path(destination.parent, directory=True)
    destination.mkdir()  # exclusive: never reuse a runtime directory.
    indexes = [module.dll_index(module.real_path(x, directory=True)) for x in a.dll_root]
    indexes.insert(0, module.dll_index(agent.parent))
    deadline = time.monotonic() + 50
    pending, done, rows, total = [agent], set(), [], 0
    while pending:
        if time.monotonic() >= deadline:
            raise ValueError('dependency_stage_deadline')
        source = pending.pop(0)
        name = source.name.lower()
        if name in done:
            continue
        if len(done) >= module.MAX_FILES:
            raise ValueError('dependency_file_count_cap')
        if module.pe_machine(source) != expected_machine:
            raise ValueError('dependency_architecture_mismatch')
        before = source.stat()
        digest = module.digest(source)
        total += before.st_size
        if total > module.MAX_TOTAL:
            raise ValueError('dependency_total_cap')
        imports = module.imports(source, dumpbin, deadline)
        target = destination / ('FDSensor.exe' if source == agent else name)
        with source.open('rb') as src, target.open('xb') as dst:
            # Existing owner caps each source at 64MiB; no unbounded body read.
            shutil.copyfileobj(src, dst, length=1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        after = source.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (
                after.st_size, after.st_mtime_ns, after.st_ino):
            raise ValueError('dependency_source_changed')
        if module.digest(source) != digest or module.digest(target) != digest:
            raise ValueError('dependency_copy_readback_mismatch')
        rows.append({'name': target.name, 'bytes': before.st_size,
                     'sha256': digest, 'imports': imports})
        done.add(name)
        for dependency in imports:
            if dependency in module.OS_DLLS:
                continue
            candidates = [i[dependency] for i in indexes if dependency in i]
            if not candidates:
                raise ValueError('dependency_not_in_pinned_compiler_roots')
            digests = {module.digest(x) for x in candidates}
            if len(digests) != 1:
                raise ValueError('ambiguous_dependency_bytes')
            if dependency not in done:
                pending.append(candidates[0])
    if {x.name for x in destination.iterdir()} != {x['name'] for x in rows}:
        raise ValueError('runtime_inventory_mismatch')
    value = {'schema': 'edr.ci-unshipped-agent-closure.v1', 'arch': a.arch,
             'agent_sha256': a.agent_sha256, 'import_owner_sha256': a.owner_sha256,
             'files': rows, 'total_bytes': total, 'product_executed': False,
             'release_or_installer_stage': False}
    with Path(a.receipt).open('x', encoding='utf-8', newline='\n') as f:
        json.dump(value, f, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps(failure_projection(error), sort_keys=True), flush=True)
        raise SystemExit(1)
