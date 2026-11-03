"""Bundle-boundary regressions; fabricated PE headers do not claim native execution."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
import stage_native
from prepare import PINS


class TestConfigurationTests(unittest.TestCase):
    TEXT=('CMAKE_BUILD_TYPE:STRING=StorageCompat\n'
          'CMAKE_MAP_IMPORTED_CONFIG_STORAGECOMPAT:UNINITIALIZED=Release;\n'
          'CMAKE_MSVC_RUNTIME_LIBRARY:STRING=MultiThreadedDLL\n')

    def test_explicit_nonproduction_with_release_dependencies(self):
        result=stage_native.test_configuration(self.TEXT)
        self.assertEqual(result['CMAKE_BUILD_TYPE'],'StorageCompat')
        self.assertEqual(result['CMAKE_MAP_IMPORTED_CONFIG_STORAGECOMPAT'],'Release;')
        self.assertEqual(result['CMAKE_MSVC_RUNTIME_LIBRARY'],'MultiThreadedDLL')

    def test_reject_production_release_configuration(self):
        with self.assertRaisesRegex(ValueError,'CMAKE_BUILD_TYPE'):
            stage_native.test_configuration(self.TEXT.replace('=StorageCompat','=Release'))

    def test_reject_missing_release_mapping(self):
        with self.assertRaisesRegex(ValueError,'CMAKE_MAP_IMPORTED_CONFIG_STORAGECOMPAT'):
            stage_native.test_configuration('\n'.join(x for x in self.TEXT.splitlines() if 'MAP_IMPORTED' not in x))

    def test_reject_debug_mapping(self):
        with self.assertRaisesRegex(ValueError,'CMAKE_MAP_IMPORTED_CONFIG_STORAGECOMPAT'):
            stage_native.test_configuration(self.TEXT.replace('=Release','=Debug'))

    def test_reject_mapping_without_generic_import(self):
        with self.assertRaisesRegex(ValueError,'CMAKE_MAP_IMPORTED_CONFIG_STORAGECOMPAT'):
            stage_native.test_configuration(self.TEXT.replace('=Release;','=Release'))

    def test_reject_debug_or_static_crt(self):
        for runtime in ('MultiThreadedDebugDLL','MultiThreaded','MultiThreadedDebug'):
            with self.subTest(runtime=runtime),self.assertRaisesRegex(ValueError,'CMAKE_MSVC_RUNTIME_LIBRARY'):
                stage_native.test_configuration(self.TEXT.replace('=MultiThreadedDLL','='+runtime))

    def test_reject_duplicate_setting(self):
        with self.assertRaisesRegex(ValueError,'CMAKE_BUILD_TYPE'):
            stage_native.test_configuration(self.TEXT+'CMAKE_BUILD_TYPE:UNINITIALIZED=StorageCompat\n')


class BundleBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        self.repo=Path(__file__).resolve().parents[2];self.sha='d'*40
        self.manifest={'schema':'edr.windows.storage-compat-bundle.v1','architecture':'amd64',
            'harness_commit':self.sha,'run_id':'123','run_attempt':'1','source_commits':dict(PINS),
            'test_configuration':dict(stage_native.TEST_CONFIGURATION),
            'native_cross_version_passed':True,'product_payload':False,'roles':{},'files':[]}
        pe=bytearray(512);pe[:2]=b'MZ';struct.pack_into('<I',pe,60,128);pe[128:132]=b'PE\0\0'
        struct.pack_into('<H',pe,132,0x8664);struct.pack_into('<H',pe,148,240);pe[152:154]=b'\x0b\x02'
        for role in PINS:
            (self.root/role).mkdir();entry={'source_commit':PINS[role]}
            for kind in ('cache','queue'):
                relative=role+'/storage_compat_'+kind+'.exe';path=self.root/relative;path.write_bytes(pe)
                sha=hashlib.sha256(pe).hexdigest();entry[kind+'_path']=relative;entry[kind+'_sha256']=sha
                self.manifest['files'].append({'path':relative,'bytes':len(pe),'sha256':sha,'machine':0x8664,'imports':['kernel32.dll']})
            self.manifest['roles'][role]=entry

    def tearDown(self):self.temp.cleanup()

    def verify(self):
        (self.root/'manifest.json').write_text(json.dumps(self.manifest))
        return stage_native.verify(self.repo,self.root,'amd64',self.sha,'123','1')

    def test_exact_closed_bundle(self):self.assertEqual(self.verify()['source_commits'],PINS)

    def test_file_mutation(self):
        with (self.root/self.manifest['files'][0]['path']).open('ab') as f:f.write(b'x')
        with self.assertRaisesRegex(ValueError,'bundle_file_size'):self.verify()

    def test_wrong_native_architecture(self):
        self.manifest['architecture']='arm64'
        with self.assertRaisesRegex(ValueError,'bundle_architecture_schema'):self.verify()

    def test_wrong_source_commit(self):
        self.manifest['source_commits']['legacy']='a'*40
        with self.assertRaisesRegex(ValueError,'bundle_source_scope'):self.verify()

    def test_missing_dependency(self):
        self.manifest['files'][0]['imports'].append('missing-runtime.dll')
        with self.assertRaisesRegex(ValueError,'bundle_dependency_closure'):self.verify()

    def test_undeclared_extra_file(self):
        (self.root/'legacy/unexpected.dll').write_bytes(b'not admitted')
        with self.assertRaisesRegex(ValueError,'bundle_extra_or_missing_file'):self.verify()

    def test_duplicate_path(self):
        self.manifest['files'].append(dict(self.manifest['files'][0]))
        with self.assertRaisesRegex(ValueError,'bundle_path'):self.verify()

    def test_path_traversal(self):
        self.manifest['files'][0]['path']='legacy/../outside.exe'
        with self.assertRaisesRegex(ValueError,'bundle_path'):self.verify()

    def test_empty_dependency_parse(self):
        self.manifest['files'][0]['imports']=[]
        with self.assertRaisesRegex(ValueError,'bundle_imports'):self.verify()

    def test_role_executable_not_swappable(self):
        self.manifest['roles']['legacy']['cache_path']='candidate/storage_compat_cache.exe'
        with self.assertRaisesRegex(ValueError,'role_tool_binding'):self.verify()

    def test_missing_native_result(self):
        self.manifest['native_cross_version_passed']=False
        with self.assertRaisesRegex(ValueError,'bundle_source_scope'):self.verify()

    def test_other_run_not_accepted(self):
        self.manifest['run_attempt']='2'
        with self.assertRaisesRegex(ValueError,'bundle_owner_identity'):self.verify()

    def test_bundle_wrong_test_configuration(self):
        self.manifest['test_configuration']['CMAKE_MSVC_RUNTIME_LIBRARY']='MultiThreadedDebugDLL'
        with self.assertRaisesRegex(ValueError,'bundle_test_configuration'):self.verify()


if __name__=='__main__':unittest.main()
