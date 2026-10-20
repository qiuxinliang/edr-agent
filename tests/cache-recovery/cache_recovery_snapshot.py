"""Exact synthetic owner read-only snapshot. No migration, model or transport."""
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time

TENANT = 'synthetic-floor-tenant'
ENDPOINT = 'synthetic-floor-endpoint'
SOURCE = 'parent-soak-0'
GUARDS = (
    'retention_active_clock_v1_insert', 'retention_active_clock_v1_update',
    'retention_active_clock_v1_delete', 'alert_context_floor_v1_insert',
    'alert_context_floor_v1_update', 'alert_context_floor_v1_eligible',
    'alert_context_floor_v1_delete',
)


def need(ok, cause):
    if not ok:
        raise ValueError(cause)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False).encode()).hexdigest()


def bounded_json(path):
    before=path.stat()
    need(path.is_file() and not path.is_symlink() and before.st_size <= 16384, 'snapshot_metadata_bound')
    with path.open('rb') as stream:
        raw=stream.read(before.st_size+1)
    after=path.stat()
    need(len(raw)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns), 'snapshot_metadata_changed')
    return json.loads(raw)


DEFAULT_DB_READ_CAP = 64 * 1024 * 1024
CONFIG_READ_CAP = 131072
# Matches src/config/config.c's accepted integer range, with zero explicitly
# rejected for this QA input rather than borrowing the cache's default.
MAX_CONFIG_BUDGET_MB = 0x7fffffff


class SnapshotInputError(ValueError):
    def __init__(self, role, kind, details, cap):
        super().__init__('snapshot_' + role + '_' + kind)
        self.diagnostic = dict(role=role, type=kind,
            is_regular=stat.S_ISREG(details.st_mode) if details is not None else None,
            is_symlink=(stat.S_ISLNK(details.st_mode) or bool(getattr(details, 'st_file_attributes', 0) & 1024)) if details is not None else None,
            bytes=details.st_size if details is not None else None, cap=cap)


def snapshot_input(role, path, cap):
    try:
        details = path.lstat()
    except OSError:
        raise SnapshotInputError(role, 'unavailable', None, cap) from None
    if stat.S_ISLNK(details.st_mode) or getattr(details, 'st_file_attributes', 0) & 1024:
        raise SnapshotInputError(role, 'symlink', details, cap)
    if not stat.S_ISREG(details.st_mode):
        raise SnapshotInputError(role, 'not_regular', details, cap)
    if details.st_size < 0 or details.st_size > cap:
        raise SnapshotInputError(role, 'size', details, cap)
    return details


def config_db_read_cap(config=None, config_sha256=None, db_path=None):
    if config is None and config_sha256 is None:
        return DEFAULT_DB_READ_CAP
    if config is None or config_sha256 is None:
        raise SnapshotInputError('config', 'parameters', None, CONFIG_READ_CAP)
    details = snapshot_input('config', config, CONFIG_READ_CAP)
    for item in config.parents:
        try:
            parent = item.lstat()
        except OSError:
            raise SnapshotInputError('config', 'unavailable', None, CONFIG_READ_CAP) from None
        if stat.S_ISLNK(parent.st_mode) or getattr(parent, 'st_file_attributes', 0) & 1024:
            raise SnapshotInputError('config', 'symlink', parent, CONFIG_READ_CAP)
    if not isinstance(config_sha256, str) or not re.fullmatch('[0-9a-f]{64}', config_sha256):
        raise SnapshotInputError('config', 'sha', details, CONFIG_READ_CAP)
    try:
        with config.open('rb') as stream:
            first = os.fstat(stream.fileno())
            body = stream.read(CONFIG_READ_CAP + 1)
            last = os.fstat(stream.fileno())
        after = snapshot_input('config', config, CONFIG_READ_CAP)
    except OSError:
        raise SnapshotInputError('config', 'unavailable', None, CONFIG_READ_CAP) from None
    # Compare each API with itself: Windows stat/fstat creation-time semantics
    # differ. SHA binds the exact bytes, without borrowing those timestamps.
    snap = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns)
    if (len(body) != details.st_size or len(body) != first.st_size or
            snap(details) != snap(after) or snap(first) != snap(last) or
            not stat.S_ISREG(first.st_mode)):
        raise SnapshotInputError('config', 'changed', after, CONFIG_READ_CAP)
    if hashlib.sha256(body).hexdigest() != config_sha256:
        raise SnapshotInputError('config', 'sha', after, CONFIG_READ_CAP)
    try:
        import tomllib
    except ImportError:
        raise SnapshotInputError('config', 'stdlib_tomllib_required', after, CONFIG_READ_CAP) from None
    try:
        value = tomllib.loads(body.decode('utf-8-sig'))
    except (UnicodeError, tomllib.TOMLDecodeError):
        raise SnapshotInputError('config', 'toml', after, CONFIG_READ_CAP) from None
    offline = value.get('offline')
    budget = offline.get('evidence_cache_max_size_mb') if type(offline) is dict else None
    if type(budget) is not int:
        raise SnapshotInputError('config', 'budget_type', after, CONFIG_READ_CAP)
    if not 1 <= budget <= MAX_CONFIG_BUDGET_MB:
        raise SnapshotInputError('config', 'budget_range', after, CONFIG_READ_CAP)
    configured_path = offline.get('evidence_cache_path')
    if (type(configured_path) is not str or not configured_path or
            not Path(configured_path).is_absolute() or db_path is None or
            os.path.normcase(os.path.abspath(configured_path)) != os.path.normcase(os.path.abspath(db_path))):
        raise SnapshotInputError('config', 'db_path', after, CONFIG_READ_CAP)
    return budget * 1024 * 1024


def inspect(path, expected=None, db_read_cap=DEFAULT_DB_READ_CAP):
    """Caller owns the disposable fixture path. All SQL is one short ro snapshot."""
    deadline = time.monotonic() + 8
    snapshot_input('db', path, db_read_cap)
    db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=.2)
    db.row_factory = sqlite3.Row
    db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        rows = db.execute('''SELECT candidate_id, endpoint_id, tenant_id, pid, ppid,
          event_time_ns, process_start_key, process_creation_filetime_100ns,
          subject_command_fact_id,parent_command_fact_id,alert_context_protect_until_active_ms
          FROM p0_candidates WHERE endpoint_id=? AND tenant_id=? AND pid=99102
          AND process_start_key='99102' LIMIT 2''', (ENDPOINT, TENANT)).fetchall()
        need(len(rows) == 1, 'exact_synthetic_child_required')
        child = dict(rows[0]); candidate = child['candidate_id']
        rows = db.execute('''SELECT r.artifact_id,r.fact_id,r.candidate_id_json,
          r.created_ns,r.upload_status,r.minio_key,f.manifest_template_json
          FROM context_reference_projection r JOIN context_facts f ON f.fact_id=r.fact_id
          WHERE r.artifact_id=? AND r.candidate_id=? AND f.endpoint_id=? AND f.tenant_id=?
          LIMIT 2''', (candidate+':alert_parent_context', candidate, ENDPOINT, TENANT)).fetchall()
        need(len(rows) == 1, 'exact_parent_fact_required')
        ref = dict(rows[0]); need(len(ref['manifest_template_json'].encode()) <= 65536, 'fact_bound')
        fact = json.loads(ref.pop('manifest_template_json'))
        need(fact['source_event_id'] == SOURCE and fact['parent_pid_state'] == 1 and
             fact['child']['pid'] == 99102 and fact['child']['process_start_key'] == '99102' and
             fact['child']['process_creation_filetime_100ns'] == child['process_creation_filetime_100ns'] and
             int(fact['event_time_ns']) == child['event_time_ns'], 'source_child_binding')
        parent = fact['parent']
        need(parent['pid'] == 99101 and child['ppid'] == 99101 and
             parent['process_start_key'] == '99101' and parent['name'] == 'pressure-parent.exe' and
             parent['path'] == 'C:/synthetic/pressure-parent.exe' and parent['path_quality'] == 'complete' and
             int(parent['process_creation_filetime_100ns']) == int(child['process_creation_filetime_100ns']) - 10000000 and
             parent['command_fact_ref'] == child['parent_command_fact_id'] and fact['candidate_id'] is None and
             json.loads(ref['candidate_id_json']) == candidate, 'parent_binding')
        commands = []
        for key, pid, start, birth, body in (
                ('subject_command_fact_id', 99102, '99102', child['process_creation_filetime_100ns'],
                 'floor-child.exe --synthetic'),
                ('parent_command_fact_id', 99101, '99101', parent['process_creation_filetime_100ns'],
                 'pressure-parent.exe --synthetic-retained')):
            rows = db.execute('''SELECT artifact_id,sha256,manifest_json,command_retention_policy,
              command_owner_pid,command_owner_start_key,command_owner_creation,upload_status,minio_key
              FROM artifacts WHERE artifact_id=? AND endpoint_id=? AND tenant_id=?
              AND artifact_type='process_command_line' LIMIT 2''',
                              (child[key], ENDPOINT, TENANT)).fetchall()
            need(len(rows) == 1, 'command_owner_required')
            command = dict(rows[0]); need(len(command['manifest_json'].encode()) <= 65536, 'command_bound')
            payload = json.loads(command.pop('manifest_json'))
            need(command['command_retention_policy'] == 1 and command['command_owner_pid'] == pid and
                 command['command_owner_start_key'] == start and command['command_owner_creation'] == birth and
                 command['upload_status'] == 'embedded' and not command['minio_key'] and
                 payload['reference'] == child[key] and payload['command_line'] == body and
                 command['sha256'] == hashlib.sha256(body.encode()).hexdigest(), 'command_generation_or_body')
            commands.append([command, payload])
        rows = db.execute('''SELECT artifact_id,sha256,manifest_json,created_ns,upload_status,minio_key
          FROM artifacts WHERE artifact_id=? AND candidate_id=? AND endpoint_id=? AND tenant_id=?
          AND artifact_type='p0_context_bundle' LIMIT 2''',
                          (candidate+':p0_context_bundle:candidate', candidate, ENDPOINT, TENANT)).fetchall()
        need(len(rows) == 1, 'bundle_owner_required')
        bundle = dict(rows[0]); need(len(bundle['manifest_json'].encode()) <= 65536, 'bundle_bound')
        bundle['manifest_json'] = json.loads(bundle['manifest_json'])
        clock = db.execute("""SELECT value FROM metrics WHERE minute_unix=0 AND endpoint_id=''
          AND metric_name='local_retention_v1_active_ms' AND typeof(value)='integer' AND value>=0""").fetchall()
        need(len(clock) == 1, 'active_clock_required')
        active = clock[0][0]; floor = child['alert_context_protect_until_active_ms']
        need(type(floor) is int and floor > active >= 0, 'owner_floor_not_live')
        placeholders = ','.join('?' for unused in GUARDS)
        guards = db.execute('SELECT name,sql FROM sqlite_master WHERE type=\'trigger\' AND name IN ('+
                            placeholders+') ORDER BY name', GUARDS).fetchall()
        need(len(guards) == len(GUARDS), 'floor_guards_missing')
        result = dict(schema='edr.ci-cache-recovery-snapshot.v1', source_is_synthetic=True,
                      source_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(), child_pid=99102,
                      child_start_key='99102', child_birth=child['process_creation_filetime_100ns'],
                      parent_pid=99101, parent_start_key='99101',
                      parent_birth=parent['process_creation_filetime_100ns'],
                      owner_sha256=digest([child, ref, fact, bundle, commands]),
                      guards_sha256=digest([list(row) for row in guards]),
                      floor_ms=floor, active_ms=active, command_facts=2,
                      readonly=True, cache_library_opened=False)
        if expected:
            for key in ('source_sha256', 'child_pid', 'child_start_key', 'child_birth', 'parent_pid',
                        'parent_start_key', 'parent_birth', 'owner_sha256', 'guards_sha256', 'floor_ms'):
                need(result[key] == expected[key], 'preservation_mismatch_'+key)
            need(result['active_ms'] >= expected['active_ms'], 'active_clock_regressed')
        need(time.monotonic() < deadline, 'snapshot_deadline')
        db.rollback()
        return result
    finally:
        db.close()



def validate_native_tools(manifest_path, manifest_sha, owner_path, owner_sha, arch, source, run_id):
    """Read-only consumer of the existing packager; no dumpbin, build or download."""
    def pinned(path, expected, cap):
        for item in (path, *path.parents):
            info = item.lstat()
            need(not item.is_symlink() and not getattr(info, 'st_file_attributes', 0) & 1024,
                 'native_tool_reparse')
        before = path.stat()
        need(path.is_file() and 0 < before.st_size <= cap and re.fullmatch('[0-9a-f]{64}', expected),
             'native_tool_input_bound')
        with path.open('rb') as stream:
            raw = stream.read(before.st_size + 1)
        after = path.stat()
        need(len(raw) == before.st_size and
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and
             hashlib.sha256(raw).hexdigest() == expected, 'native_tool_input_pin')
        return raw
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'native_manifest_duplicate_key')
            result[key] = value
        return result
    need(arch in ('amd64', 'arm64') and re.fullmatch('[0-9a-f]{40}', source) and
         re.fullmatch('[1-9][0-9]*', run_id), 'native_manifest_binding')
    owner_raw = pinned(owner_path, owner_sha, 65536)
    manifest_raw = pinned(manifest_path, manifest_sha, 131072)
    # Import the original existing owner from its caller-frozen same-source path.
    spec = importlib.util.spec_from_file_location('recovery_native_stage_owner', owner_path)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    need(pinned(owner_path, owner_sha, 65536) == owner_raw, 'native_owner_changed')
    manifest = json.loads(manifest_raw, object_pairs_hook=pairs,
                          parse_constant=lambda unused: (_ for _ in ()).throw(ValueError('native_manifest_constant')))
    need(manifest.get('schema') == 'edr.retention-native-tools.v1' and
         manifest.get('source_sha') == source and manifest.get('arch') == arch and
         manifest.get('run_id') == run_id and manifest.get('run_attempt') == '1' and
         manifest.get('prior_contract_status') == 'passed' and
         manifest.get('native_contracts_passed_before_staging') is True and
         manifest.get('purpose') == 'private_isolated_storage_diagnostics' and
         manifest.get('product_payload') is False and 'allowed_diagnostic_argv' not in manifest,
         'same_source_passed_native_manifest')
    files = manifest.get('files')
    need(type(files) is list and 1 <= len(files) <= owner.MAX_FILES, 'native_manifest_file_count')
    names = set(); total = 0
    for item in files:
        need(type(item) is dict, 'native_manifest_file_shape')
        name = item.get('name')
        need(type(name) is str and name not in names and
             (name == owner.TOOL or owner.DLL_NAME.fullmatch(name)) and name not in owner.OS_DLLS,
             'native_manifest_unique_name')
        need(type(item.get('bytes')) is int and 0 < item['bytes'] <= owner.MAX_FILE and
             type(item.get('machine')) is int and item['machine'] == owner.MACHINES[arch] and
             type(item.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', item['sha256']),
             'native_manifest_file_identity')
        deps = item.get('imports')
        need(type(deps) is list and 1 <= len(deps) <= 128 and
             all(type(dep) is str and owner.DLL_NAME.fullmatch(dep) for dep in deps) and
             deps == sorted(set(deps)), 'native_manifest_import_shape')
        names.add(name); total += item['bytes']
    need(owner.TOOL in names and total <= owner.MAX_TOTAL, 'native_manifest_tool_or_total')
    by_name = {item['name']: item for item in files}; seen = set(); todo = [owner.TOOL]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for dep in by_name[name]['imports']:
            need(dep in owner.OS_DLLS or dep in names, 'native_manifest_dependency_missing')
            if dep in names:
                todo.append(dep)
    need(seen == names, 'native_manifest_unreachable_extra')
    # Original owner enforces no extras, regular paths, bytes/SHA and real PE32+ machine.
    need(manifest_path.name == 'manifest.json', 'native_manifest_filename')
    owner.verify_stage(manifest_path.parent, manifest)
    need(pinned(manifest_path, manifest_sha, 131072) == manifest_raw, 'native_manifest_changed')
    return dict(schema='edr.ci-native-tools-validation.v1', files=len(files), bytes=total,
                manifest_sha256=manifest_sha, validation_owner_sha256=owner_sha,
                actual_pe_hash_size_and_manifest_dependency_closure=True,
                independent_import_table_rescan=False, external_io=False)


def validate_tools_main():
    p = argparse.ArgumentParser(description='Read-only existing native-tool owner verification')
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--manifest-sha256', required=True)
    p.add_argument('--validation-owner', type=Path, required=True)
    p.add_argument('--validation-owner-sha256', required=True)
    p.add_argument('--arch', required=True)
    p.add_argument('--source', required=True)
    p.add_argument('--run-id', required=True)
    args = p.parse_args(sys.argv[2:])
    need(os.name == 'nt' and os.environ.get('GITHUB_ACTIONS') == 'true' and
         os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'disposable_ci_only')
    print(json.dumps(validate_native_tools(args.manifest, args.manifest_sha256,
          args.validation_owner, args.validation_owner_sha256, args.arch, args.source, args.run_id)))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--expected', type=Path)
    p.add_argument('--config', type=Path)
    p.add_argument('--config-sha256')
    args = p.parse_args()
    need(os.name == 'nt' and os.environ.get('GITHUB_ACTIONS') == 'true' and
         os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'disposable_ci_only')
    db_read_cap = config_db_read_cap(args.config, args.config_sha256, args.db)
    root = Path(os.environ['RUNNER_TEMP']).resolve()
    for item in (args.db, *args.db.parents):
        try:
            details = item.lstat()
        except OSError:
            raise SnapshotInputError('db', 'unavailable', None, db_read_cap) from None
        if stat.S_ISLNK(details.st_mode) or getattr(details, 'st_file_attributes', 0) & 1024:
            raise SnapshotInputError('db', 'symlink', details, db_read_cap)
    path = args.db.resolve()
    relative = path.relative_to(root)
    need(len(relative.parts) == 3 and re.fullmatch(r'edr-cache-recovery-[0-9a-f]{32}', relative.parts[0]) and
         relative.parts[1:] == ('evidence', 'cache.db'), 'exact_synthetic_db_path')
    expected = bounded_json(args.expected) if args.expected else None
    result = inspect(path, expected, db_read_cap)
    with args.output.open('x', encoding='utf-8') as f:
        json.dump(result, f, indent=2); f.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':
    if sys.argv[1:2] == ['--verify-native-tools']:
        validate_tools_main()
    else:
        try:
            main()
        except SnapshotInputError as error:
            print('snapshot_input_guard ' + json.dumps(error.diagnostic, separators=(',', ':')), file=sys.stderr)
            raise SystemExit(1) from None
