"""Pure temporary synthetic SQL checks; not Windows/updater/cache-library proof."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('snapshot', Path(__file__).with_name('cache_recovery_snapshot.py'))
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


class Snapshot(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name).resolve() / 'cache.db'
        self.db = sqlite3.connect(self.path)
        self.db.executescript('''
          CREATE TABLE p0_candidates(candidate_id,endpoint_id,tenant_id,pid,ppid,event_time_ns,
            process_start_key,process_creation_filetime_100ns,subject_command_fact_id,
            parent_command_fact_id,alert_context_protect_until_active_ms);
          CREATE TABLE context_facts(fact_id,endpoint_id,tenant_id,manifest_template_json);
          CREATE TABLE context_reference_projection(artifact_id,candidate_id,fact_id,
            candidate_id_json,created_ns,upload_status,minio_key);
          CREATE TABLE artifacts(artifact_id,endpoint_id,tenant_id,candidate_id,artifact_type,
            sha256,manifest_json,created_ns,upload_status,minio_key,command_retention_policy,
            command_owner_pid,command_owner_start_key,command_owner_creation);
          CREATE TABLE metrics(minute_unix,endpoint_id,metric_name,value);
        ''')
        self.db.execute('INSERT INTO p0_candidates VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                        ('candidate',M.ENDPOINT,M.TENANT,99102,99101,100,'99102','134000000010000000','child-command','parent-command',3600020))
        fact = dict(schema='edr.local-alert-parent-context.v1',candidate_id=None,
                    source_event_id=M.SOURCE,event_time_ns='100',parent_pid_state=1,
                    child=dict(pid=99102,process_start_key='99102',process_creation_filetime_100ns='134000000010000000'),
                    parent=dict(pid=99101,process_start_key='99101',process_creation_filetime_100ns='134000000000000000',
                                name='pressure-parent.exe',path='C:/synthetic/pressure-parent.exe',path_quality='complete',command_fact_ref='parent-command'))
        self.db.execute('INSERT INTO context_facts VALUES(?,?,?,?)',('fact',M.ENDPOINT,M.TENANT,json.dumps(fact)))
        self.db.execute('INSERT INTO context_reference_projection VALUES(?,?,?,?,?,?,?)',
                        ('candidate:alert_parent_context','candidate','fact','"candidate"',1,'local_manifest',''))
        for key,pid,birth,body in [('child-command',99102,'134000000010000000','floor-child.exe --synthetic'),
                                    ('parent-command',99101,'134000000000000000','pressure-parent.exe --synthetic-retained')]:
            self.db.execute('INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                            (key,M.ENDPOINT,M.TENANT,'','process_command_line',M.hashlib.sha256(body.encode()).hexdigest(),json.dumps(dict(reference=key,command_line=body)),1,'embedded','',1,pid,str(pid),birth))
        self.db.execute('INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                        ('candidate:p0_context_bundle:candidate',M.ENDPOINT,M.TENANT,'candidate','p0_context_bundle','',json.dumps(dict(public_synthetic=True)),1,'local_manifest','',0,0,'',''))
        self.db.execute('INSERT INTO metrics VALUES(?,?,?,?)',(0,'','local_retention_v1_active_ms',20))
        # These no-op trigger bodies test name/hash preservation only. Production
        # guard behavior is neither substituted nor certified by these unit tests.
        for name in M.GUARDS:
            self.db.execute('CREATE TRIGGER '+name+' BEFORE DELETE ON p0_candidates BEGIN SELECT 1; END')
        self.db.commit()

    def tearDown(self):
        self.db.close(); self.temp.cleanup()

    def test_roundtrip_hash_and_no_body_output(self):
        before=M.inspect(self.path);after=M.inspect(self.path,before)
        self.assertEqual(before,after)
        encoded=json.dumps(after)
        self.assertNotIn('pressure-parent.exe',encoded)
        self.assertNotIn('--synthetic-retained',encoded)

    def test_command_generation_conflict(self):
        self.db.execute("UPDATE artifacts SET command_owner_creation='different' WHERE artifact_id='parent-command'");self.db.commit()
        with self.assertRaisesRegex(ValueError,'command_generation_or_body'):M.inspect(self.path)

    def test_zero_floor_refused(self):
        self.db.execute('UPDATE p0_candidates SET alert_context_protect_until_active_ms=0');self.db.commit()
        with self.assertRaisesRegex(ValueError,'owner_floor_not_live'):M.inspect(self.path)

    def test_missing_guard_refused(self):
        self.db.execute('DROP TRIGGER alert_context_floor_v1_delete');self.db.commit()
        with self.assertRaisesRegex(ValueError,'floor_guards_missing'):M.inspect(self.path)

    def test_owner_hash_mismatch(self):
        expected=M.inspect(self.path);expected['owner_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'preservation_mismatch_owner_sha256'):M.inspect(self.path,expected)

    def test_clock_regression_refused(self):
        expected=M.inspect(self.path);expected['active_ms']=21
        with self.assertRaisesRegex(ValueError,'active_clock_regressed'):M.inspect(self.path,expected)

    def test_wrong_source_refused(self):
        row=json.loads(self.db.execute('SELECT manifest_template_json FROM context_facts').fetchone()[0]);row['source_event_id']='another-source'
        self.db.execute('UPDATE context_facts SET manifest_template_json=?',(json.dumps(row),));self.db.commit()
        with self.assertRaisesRegex(ValueError,'source_child_binding'):M.inspect(self.path)


    def config(self, budget='512', extra='', body=None, db_path=None):
        path = self.path.parent / 'fixture config.toml'
        if body is None:
            body = ('[offline]\nevidence_cache_max_size_mb=' + budget + '\n' +
                    'evidence_cache_path=' + json.dumps(str(db_path or self.path)) + '\n' + extra)
        path.write_text(body, encoding='utf-8')
        return path, M.hashlib.sha256(path.read_bytes()).hexdigest()

    def config_error(self, kind, path, sha):
        with self.assertRaises(M.SnapshotInputError) as caught:
            M.config_db_read_cap(path, sha, self.path)
        error = caught.exception
        self.assertEqual(error.diagnostic['role'], 'config')
        self.assertEqual(error.diagnostic['type'], kind)
        self.assertEqual(set(error.diagnostic), {'role','type','is_regular','is_symlink','bytes','cap'})
        self.assertNotIn(str(path), str(error))
        return error.diagnostic

    def test_config_runtime_stdlib_tomllib_available_before_product(self):
        path, sha = self.config()
        self.assertEqual(M.config_db_read_cap(path, sha, self.path), 512 * 1024 * 1024)

    def test_config_missing_stdlib_is_actionable_not_a_fallback(self):
        path, sha = self.config()
        with mock.patch.dict('sys.modules', {'tomllib': None}):
            self.config_error('stdlib_tomllib_required', path, sha)
        self.assertEqual(M.config_db_read_cap(), M.DEFAULT_DB_READ_CAP)

    def test_config_seed_default_stays_64mib(self):
        self.assertEqual(M.config_db_read_cap(), 64 * 1024 * 1024)
        self.assertEqual(M.inspect(self.path), M.inspect(self.path))

    def test_config_real_sqlite_over64_with512_keeps_owner_and_main_db_bytes(self):
        owner = M.inspect(self.path)
        self.db.execute('CREATE TABLE unrelated_payload(body BLOB)')
        self.db.execute('INSERT INTO unrelated_payload VALUES(zeroblob(?))', (65 * 1024 * 1024,))
        self.db.commit()
        self.assertGreater(self.path.stat().st_size, 64 * 1024 * 1024)
        path, sha = self.config()
        limit = M.config_db_read_cap(path, sha, self.path)
        before_hash = M.hashlib.sha256(self.path.read_bytes()).hexdigest()
        before_mtime = self.path.stat().st_mtime_ns
        self.assertEqual(M.inspect(self.path, owner, limit), owner)
        self.assertEqual(M.hashlib.sha256(self.path.read_bytes()).hexdigest(), before_hash)
        self.assertEqual(self.path.stat().st_mtime_ns, before_mtime)
        with self.assertRaises(M.SnapshotInputError) as default:
            M.inspect(self.path)
        self.assertEqual(default.exception.diagnostic['type'], 'size')
        self.assertEqual(default.exception.diagnostic['cap'], 64 * 1024 * 1024)
        low, low_sha = self.config(budget='1')
        with self.assertRaises(M.SnapshotInputError) as refused:
            M.inspect(self.path, owner, M.config_db_read_cap(low, low_sha, self.path))
        self.assertEqual(refused.exception.diagnostic['cap'], 1024 * 1024)
        self.assertEqual(M.hashlib.sha256(self.path.read_bytes()).hexdigest(), before_hash)
        print(json.dumps(dict(schema='edr.ci-snapshot-config-cap.synthetic.v1',
            db_bytes=self.path.stat().st_size, configured_main_db_read_cap=limit,
            seed_main_db_read_cap=M.DEFAULT_DB_READ_CAP, owner_sha256=owner['owner_sha256'],
            main_db_sha256=before_hash, main_db_bytes_and_mtime_unchanged=True,
            selected_owner_projection_unchanged=True, wal_shm_zero_writes_asserted=False), separators=(',', ':')))

    def test_config_sha_mismatch_and_shape_refused(self):
        path, sha = self.config()
        for wrong in ('0' * 64, 'UNBOUND', '', 'F' * 64):
            with self.subTest(wrong=wrong): self.config_error('sha', path, wrong)

    def test_config_parameters_are_paired(self):
        path, sha = self.config()
        self.config_error('parameters', path, None)
        self.config_error('parameters', None, sha)

    def test_config_budget_strict_integer_and_key_required(self):
        for value in ('true','false','512.0','"512"','[512]','{value=512}'):
            with self.subTest(value=value):
                path, sha = self.config(budget=value)
                self.config_error('budget_type', path, sha)
        for body in ('', '[offline]\nevidence_cache_path="/public/cache.db"\n', '[offline]\nevidence_cache_max_size_mb=512\n[offline.evidence_cache_path]\nvalue="x"\n'):
            path, sha = self.config(body=body)
            self.config_error('budget_type' if 'evidence_cache_max_size_mb' not in body else 'db_path', path, sha)

    def test_config_budget_matches_c_config_positive_range(self):
        for value in ('0','-1','2147483648','4294967296'):
            with self.subTest(value=value):
                path, sha = self.config(budget=value)
                self.config_error('budget_range', path, sha)
        path, sha = self.config(budget='2147483647')
        self.assertEqual(M.config_db_read_cap(path, sha, self.path), 2147483647 * 1024 * 1024)

    def test_config_toml_parse_and_duplicate_key_refused(self):
        for body in ('[offline', '[offline]\nevidence_cache_max_size_mb=512\nevidence_cache_max_size_mb=1\n'):
            path, sha = self.config(body=body)
            self.config_error('toml', path, sha)

    def test_config_must_bind_exact_db_path(self):
        for other in (self.path.with_name('other.db'), Path('relative.db')):
            path, sha = self.config(db_path=other)
            self.config_error('db_path', path, sha)

    def test_config_nonregular_and_symlink_refused(self):
        path, sha = self.config()
        self.config_error('not_regular', self.path.parent, sha)
        link = self.path.parent / 'config-link.toml'
        link.symlink_to(path)
        self.config_error('symlink', link, sha)
        parent = self.path.parent / 'linked-parent'
        parent.symlink_to(self.path.parent, target_is_directory=True)
        self.config_error('symlink', parent / path.name, sha)

    def test_config_changed_during_read_refused(self):
        path, sha = self.config()
        before = path.stat()
        changed = SimpleNamespace(st_dev=before.st_dev, st_ino=before.st_ino,
            st_size=before.st_size, st_mtime_ns=before.st_mtime_ns + 1,
            st_mode=before.st_mode)
        with mock.patch.object(M.os, 'fstat', side_effect=[before, changed]):
            self.config_error('changed', path, sha)

    def test_config_size_cap_and_stable_input_hash(self):
        path, sha = self.config(body='#' + 'x' * 131072)
        d = self.config_error('size', path, sha)
        self.assertEqual(d['bytes'], 131073)
        self.assertEqual(d['cap'], 131072)

    def test_db_nonregular_symlink_and_finite_guard_fields(self):
        for path, kind in ((self.path.parent, 'not_regular'), (self.path.with_name('missing.db'), 'unavailable')):
            with self.assertRaises(M.SnapshotInputError) as caught: M.inspect(path)
            self.assertEqual(caught.exception.diagnostic['type'], kind)
        link = self.path.with_name('cache-link.db');link.symlink_to(self.path)
        with self.assertRaises(M.SnapshotInputError) as caught: M.inspect(link)
        self.assertEqual(caught.exception.diagnostic['type'], 'symlink')
        self.assertTrue(caught.exception.diagnostic['is_symlink'])
        self.assertNotIn(str(link), json.dumps(caught.exception.diagnostic))


class NativeTools(unittest.TestCase):
    """Synthetic PE headers/files exercise the actual imported owner, never execute EXEs."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.owner = Path(os.environ.get('EDR_RECOVERY_NATIVE_STAGE_OWNER', str(Path(__file__).resolve().parents[2]/'scripts/stage_retention_native_tools.py')))
        self.owner_sha = M.hashlib.sha256(self.owner.read_bytes()).hexdigest()
        pe = bytearray(64+24+112);pe[:2] = b'MZ';struct.pack_into('<I', pe, 60, 64)
        pe[64:68] = b'PE\0\0';struct.pack_into('<H', pe, 68, 0xaa64)
        struct.pack_into('<H', pe, 84, 112);pe[88:90] = b'\x0b\x02'
        self.body = bytes(pe)
        self.tool = self.root/'test_local_evidence_cache_candidate.exe'
        self.tool.write_bytes(self.body)
        self.manifest = dict(schema='edr.retention-native-tools.v1', source_sha='1'*40,
          arch='arm64', run_id='123', run_attempt='1', prior_contract_status='passed',
          native_contracts_passed_before_staging=True, purpose='private_isolated_storage_diagnostics',
          product_payload=False, files=[dict(name=self.tool.name, bytes=len(self.body),
          sha256=M.hashlib.sha256(self.body).hexdigest(), machine=0xaa64, imports=['kernel32.dll'])])
        self.path = self.root/'manifest.json'

    def tearDown(self):
        self.temp.cleanup()

    def validate(self):
        self.path.write_text(json.dumps(self.manifest))
        return M.validate_native_tools(self.path, M.hashlib.sha256(self.path.read_bytes()).hexdigest(),
          self.owner, self.owner_sha, 'arm64', '1'*40, '123')

    def test_real_owner_pe_hash_size_success_without_execution(self):
        result = self.validate()
        self.assertEqual(result['files'], 1)
        self.assertTrue(result['actual_pe_hash_size_and_manifest_dependency_closure'])
        self.assertFalse(result['independent_import_table_rescan'])

    def test_empty_files_refused(self):
        self.manifest['files'] = []
        with self.assertRaisesRegex(ValueError, 'native_manifest_file_count'): self.validate()

    def test_duplicate_tool_refused(self):
        self.manifest['files'] *= 2
        with self.assertRaisesRegex(ValueError, 'native_manifest_unique_name'): self.validate()

    def test_missing_tool_refused(self):
        self.manifest['files'][0]['name'] = 'sqlite3.dll'
        with self.assertRaisesRegex(ValueError, 'native_manifest_tool_or_total'): self.validate()

    def test_wrong_schema_refused(self):
        self.manifest['schema'] = 'other'
        with self.assertRaisesRegex(ValueError, 'same_source_passed_native_manifest'): self.validate()

    def test_failed_gate_refused(self):
        self.manifest['prior_contract_status'] = 'failed'
        self.manifest['native_contracts_passed_before_staging'] = False
        with self.assertRaisesRegex(ValueError, 'same_source_passed_native_manifest'): self.validate()

    def test_missing_dependency_refused(self):
        self.manifest['files'][0]['imports'].append('unknown.dll')
        with self.assertRaisesRegex(ValueError, 'native_manifest_dependency_missing'): self.validate()

    def test_unreachable_listed_dll_refused(self):
        item = dict(self.manifest['files'][0]);item['name'] = 'sqlite3.dll'
        self.manifest['files'].append(item)
        with self.assertRaisesRegex(ValueError, 'native_manifest_unreachable_extra'): self.validate()

    def test_unlisted_file_refused(self):
        (self.root/'extra.dll').write_bytes(self.body)
        with self.assertRaisesRegex(ValueError, 'missing or extra files'): self.validate()

    def test_actual_wrong_pe_machine_refused_even_if_manifest_matches(self):
        body = bytearray(self.body);struct.pack_into('<H', body, 68, 0x8664)
        self.tool.write_bytes(body);self.manifest['files'][0]['sha256'] = M.hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(ValueError, 'PE architecture mismatch'): self.validate()

    def test_actual_hash_mismatch_refused(self):
        self.tool.write_bytes(self.body+b'x')
        with self.assertRaisesRegex(ValueError, 'hash/size mismatch'): self.validate()

    def test_path_component_refused(self):
        self.manifest['files'][0]['name'] = '../test_local_evidence_cache_candidate.exe'
        with self.assertRaisesRegex(ValueError, 'native_manifest_unique_name'): self.validate()

    def test_symlink_refused(self):
        self.tool.unlink();other=self.root/'other';other.write_bytes(self.body);self.tool.symlink_to(other)
        # Exact artifact-set validation rejects the extra target before path validation.
        with self.assertRaises(ValueError): self.validate()

    def test_unbound_owner_hash_refused(self):
        self.owner_sha='0'*64
        with self.assertRaisesRegex(ValueError, 'native_tool_input_pin'): self.validate()


if __name__=='__main__':
    unittest.main(verbosity=2)
