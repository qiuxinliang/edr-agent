"""Guard the diagnostic input boundary without compilers, network or UTM."""
from pathlib import Path
import importlib.util
import shutil
import struct
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('preflight_diag_build',HERE/'build.py')
build=importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)

class FrozenProbeInputs(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='preflight-build-contract-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.source=self.root/'source'
        for name in build.PINS:
            p=self.source/name;p.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(HERE.parents[1]/name,p)

    def output(self,name):
        p=self.root/name;p.mkdir();return p

    def test_same_frozen_input_accepts_windows_checkout_without_mutation(self):
        baseline=build.generate(self.source,self.output('lf'))
        for name in build.PINS:
            p=self.source/name
            p.write_bytes(p.read_bytes().replace(b'\n',b'\r\n'))
        before={name:(self.source/name).read_bytes() for name in build.PINS}
        windows=build.generate(self.source,self.output('crlf'))
        self.assertEqual(baseline['traced_sha256'],windows['traced_sha256'])
        self.assertTrue(all(v['only_checkout_crlf_normalized'] for v in windows['source_bindings'].values()))
        self.assertEqual(before,{name:(self.source/name).read_bytes() for name in build.PINS})

    def test_different_storage_input_rejects_before_generating_probe(self):
        p=self.source/next(iter(build.PINS))
        p.write_bytes(p.read_bytes()+b'\n/* not the frozen source */\n')
        output=self.output('changed')
        with self.assertRaisesRegex(RuntimeError,'frozen source digest mismatch'):
            build.generate(self.source,output)
        self.assertEqual(list(output.iterdir()),[])

    def test_pe_architecture_is_read_from_actual_dll_bytes(self):
        p=self.root/'sqlite3.dll'
        raw=bytearray(134);raw[:2]=b'MZ';struct.pack_into('<I',raw,0x3c,128)
        raw[128:132]=b'PE\0\0';struct.pack_into('<H',raw,132,0x8664)
        p.write_bytes(raw);self.assertEqual(build.pe_machine(p),0x8664)
        struct.pack_into('<H',raw,132,0xaa64)
        p.write_bytes(raw);self.assertEqual(build.pe_machine(p),0xaa64)
        p.write_bytes(b'not a PE')
        with self.assertRaisesRegex(RuntimeError,'not PE'):
            build.pe_machine(p)

if __name__=='__main__':unittest.main()
