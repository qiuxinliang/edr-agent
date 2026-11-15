#!/usr/bin/env python3
"""Build only the frozen read-only preflight pair; never build/install an Agent."""
from pathlib import Path
import argparse
import ast
import difflib
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
PINS = {
    'src/storage/evidence_cache_migration.c': 'fc136adc3b4d543c8ca37434ba96966ebedc31561d27cd4ede0ec34be20384ac',
    'src/storage/evidence_context_store.c': '70583e452e8ad1d1f3a024afb8960b9f7bfafbc6971d2276824f9332d7ece6c4',
}
REFERENCE_COMMIT = '984b955a64f5513377c465426faf45f9a0e9bf72'

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def invoke(args, cwd, name, timeout=40):
    p = subprocess.run([str(v) for v in args], cwd=cwd, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    (cwd/(name+'.stdout')).write_bytes(p.stdout)
    (cwd/(name+'.stderr')).write_bytes(p.stderr)
    if p.returncode:
        raise RuntimeError(name+' failed; inspect retained build stdout/stderr')
    return p.stdout

def generate(source, output):
    source_bindings = {}
    for name, pin in PINS.items():
        raw = (source/name).read_bytes()
        canonical = raw.replace(b'\r\n', b'\n')
        if hashlib.sha256(canonical).hexdigest() != pin:
            raise RuntimeError('frozen source digest mismatch: '+name)
        source_bindings[name] = {'checkout_sha256':hashlib.sha256(raw).hexdigest(),
            'canonical_lf_sha256':pin,'only_checkout_crlf_normalized':raw!=canonical}
    # Emit only exact source SQL literals. Dynamic identifiers stay redacted.
    literals = set()
    token = r'"(?:\\.|[^"\\])*"'
    space = r'(?:\s|/\*.*?\*/|//[^\n]*\n)*'
    for name in PINS:
        text = (source/name).read_text()
        for match in re.finditer(token+'(?:'+space+token+')*', text, re.S):
            value = ''.join(ast.literal_eval(x.group()) for x in re.finditer(token,
                re.sub(r'/\*.*?\*/|//[^\n]*\n', '', match.group(), flags=re.S)))
            if value.startswith(('PRAGMA ', 'SELECT ', 'CREATE ', 'SAVEPOINT ', 'ROLLBACK',
                                 'RELEASE ', 'BEGIN', 'DROP ', 'DELETE ', 'INSERT ', 'UPDATE ')):
                literals.add(value)
    (output/'static_sql.h').write_text('static const char *const diag_static_sql[] = {\n'+
        ''.join('  '+json.dumps(s)+',\n' for s in sorted(literals))+'};\n')
    original = (source/'src/storage/evidence_cache_migration.c').read_text()
    start = original.index('int edr_local_evidence_cache_startup_preflight(')
    end = original.index('\nint edr_local_evidence_cache_migrate(', start)
    body = original[start:end]
    replacements = [
        ('  if (!path || !path[0]) return -1;', '  DIAG_MARK("path_validation");\n  if (!path || !path[0]) return -1;'),
        ('  uint64_t length = file_bytes(path);', '  DIAG_MARK("file_stat");\n  uint64_t length = file_bytes(path);'),
        ('  if (sqlite3_open_v2(path,', '  DIAG_MARK("readonly_open");\n  if (sqlite3_open_v2(path,'),
        ('  if (sqlite3_exec(db,"PRAGMA query_only=ON;BEGIN;",', '  DIAG_MARK("snapshot_begin");\n  if (sqlite3_exec(db,"PRAGMA query_only=ON;BEGIN;",'),
        ('  if (edr_context_store_check_format(&store,db)', '  DIAG_MARK("format_check");\n  if (edr_context_store_check_format(&store,db)'),
        ('  if (scalar(db,"PRAGMA page_count",', '  DIAG_MARK("page_metrics");\n  if (scalar(db,"PRAGMA page_count",'),
        ('  if (edr_context_store_retirement_schema_pages(&store,', '  DIAG_MARK("retirement_schema_pages");\n  if (edr_context_store_retirement_schema_pages(&store,'),
        ('  if (scalar(db,"SELECT COUNT(*) FROM sqlite_master WHERE type=\'table\' AND name=\'metrics\'",', '  DIAG_MARK("metrics_inventory");\n  if (scalar(db,"SELECT COUNT(*) FROM sqlite_master WHERE type=\'table\' AND name=\'metrics\'",'),
        ('  if (metrics && scalar(db,', '  DIAG_MARK("retention_clock_presence");\n  if (metrics && scalar(db,'),
        ('  if (clock && (scalar(db,', '  DIAG_MARK("retention_clock_validity");\n  if (clock && (scalar(db,'),
        ('  if (scalar(db,"SELECT COUNT(*) FROM sqlite_master WHERE type=\'trigger\'', '  DIAG_MARK("guard_inventory");\n  if (scalar(db,"SELECT COUNT(*) FROM sqlite_master WHERE type=\'trigger\''),
        ('  if (schema_pages>available)', '  DIAG_MARK("capacity_decision");\n  if (schema_pages>available)'),
        ('  if (interrupted(&deadline)) result=-1;', '  if (interrupted(&deadline)) { DIAG_MARK("deadline"); result=-1; }'),
        ('  if (db) sqlite3_close(db);', '  diag_complete(result,db);\n  if (db) sqlite3_close(db);'),
    ]
    for old, new in replacements:
        if body.count(old) != 1:
            raise RuntimeError('instrumentation binding changed')
        body = body.replace(old, new)
    traced = original[:start]+body+original[end:]
    patch = ''.join(difflib.unified_diff(original.splitlines(True), traced.splitlines(True),
        fromfile='src/storage/evidence_cache_migration.c', tofile='temporary/evidence_cache_migration.traced.c', n=0))
    if patch != (HERE/'instrumentation.patch').read_text():
        raise RuntimeError('instrumentation patch mismatch')
    (output/'frozen-migration.c').write_text(original)
    (output/'frozen-context.c').write_text((source/'src/storage/evidence_context_store.c').read_text())
    (output/'evidence_cache_migration.traced.c').write_text(traced)
    for name in ('probe.c', 'trace_runtime.h'):
        shutil.copyfile(HERE/name, output/name)
    return {'reference_commit':REFERENCE_COMMIT, 'production_storage_sha256':PINS,
            'source_bindings':source_bindings,
            'traced_sha256':sha(output/'evidence_cache_migration.traced.c'),
            'instrumentation_patch_sha256':sha(HERE/'instrumentation.patch')}

def pe_machine(path):
    with path.open('rb') as f:
        if f.read(2) != b'MZ': raise RuntimeError('SQLite runtime is not PE')
        f.seek(0x3c); offset = struct.unpack('<I', f.read(4))[0]
        f.seek(offset)
        if f.read(4) != b'PE\0\0': raise RuntimeError('SQLite runtime PE signature invalid')
        return struct.unpack('<H', f.read(2))[0]

def windows_build(source, output, dll):
    for tool in ('cl', 'dumpbin', 'lib'):
        if not shutil.which(tool): raise RuntimeError('MSVC x64 developer environment required: '+tool)
    if dll.name.lower() != 'sqlite3.dll' or pe_machine(dll) != 0x8664:
        raise RuntimeError('original baseline x64 sqlite3.dll required')
    sdk = Path(os.environ.get('WindowsSdkDir', ''))/'Include'/os.environ.get('WindowsSDKVersion', '').rstrip('\\/')/'um/winsqlite/winsqlite3.h'
    if not sdk.is_file(): raise RuntimeError('Windows SDK winsqlite3.h unavailable')
    # Header only. Imports below explicitly name the original baseline sqlite3.dll.
    (output/'sqlite3.h').write_text('#include <winsqlite/winsqlite3.h>\n')
    exports = invoke(['dumpbin', '/nologo', '/exports', dll], output, 'sqlite-exports')
    names = re.findall(rb'^\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(sqlite3_[A-Za-z0-9_]+)\s*$', exports, re.M)
    if len(names) < 100 or len(set(names)) != len(names):
        raise RuntimeError('SQLite export inventory unavailable or ambiguous')
    (output/'sqlite3.def').write_text('LIBRARY sqlite3.dll\nEXPORTS\n'+''.join('  '+v.decode('ascii')+'\n' for v in sorted(names)))
    invoke(['lib', '/nologo', '/machine:x64', '/def:sqlite3.def', '/out:sqlite3.lib'], output, 'sqlite-import-library')
    shutil.copyfile(dll, output/'sqlite3.dll')
    closure = {'sqlite3.dll':sha(dll)}
    for name in ('vcruntime140.dll', 'vcruntime140_1.dll'):
        p=dll.parent/name
        if p.is_file(): shutil.copyfile(p,output/name);closure[name]=sha(p)
    for mode in ('original','trace'):
        command = ['cl', '/nologo', '/Bv', '/std:c11', '/O2', '/MT', '/Gy', '/Gw',
                   '/D_CRT_SECURE_NO_WARNINGS', '/DEDR_HAVE_SQLITE=1']
        command += ['/I'+str(p) for p in (source/'include', source/'src/storage', source/'third_party/cjson', output)]
        if mode=='trace': command += ['/DDIAG_TRACE=1']
        command += [output/'probe.c', source/'third_party/cjson/cJSON.c',
                    '/Fe:'+str(output/('preflight-'+mode+'.exe')), '/link', '/OPT:REF',
                    str(output/'sqlite3.lib'), 'advapi32.lib']
        invoke(command, output, mode+'-build')
        invoke(['dumpbin', '/nologo', '/dependents', output/('preflight-'+mode+'.exe')], output, mode+'-imports')
        imports=(output/(mode+'-imports.stdout')).read_text(errors='replace').lower()
        if 'sqlite3.dll' not in imports or 'winsqlite3.dll' in imports:
            raise RuntimeError('probe imports wrong SQLite runtime')
        raw=invoke([output/('preflight-'+mode+'.exe'), output/'missing-build-smoke.db', '128'], output, mode+'-smoke',6)
        parsed=json.loads(raw)
        if len(raw)>=8192 or parsed['result'] != 0: raise RuntimeError('probe build smoke failed')
    return {'platform':'Windows AMD64 MSVC', 'runtime_dll_sha256':closure,
            'sqlite_header':str(sdk), 'sqlite_header_sha256':sha(sdk),
            'compiler':str(Path(shutil.which('cl')).resolve()),
            'compiler_sha256':sha(shutil.which('cl')), 'compiler_banner_file':'original-build.stderr',
            'runtime_imports':'sqlite3.dll; system winsqlite3.dll forbidden',
            'sqlite_version':parsed['sqlite_version']}

def host_build(source,output):
    cc=shutil.which('cc')
    if not cc: raise RuntimeError('host C compiler unavailable')
    for mode in ('original','trace'):
        cmd=[cc,'-std=c11','-D_POSIX_C_SOURCE=200809L','-DEDR_HAVE_SQLITE=1','-O2','-Wall','-Wextra',
             '-Wno-unused-function','-Wno-unused-parameter','-ffunction-sections','-fdata-sections']
        cmd += ['-I'+str(p) for p in (source/'include',source/'src/storage',source/'third_party/cjson',output)]
        if mode=='trace':cmd+=['-DDIAG_TRACE=1']
        cmd += [str(output/'probe.c'),str(source/'third_party/cjson/cJSON.c'),'-lsqlite3','-lm']
        cmd += ['-Wl,-dead_strip'] if sys.platform=='darwin' else ['-Wl,--gc-sections']
        cmd += ['-o',str(output/('preflight-'+mode))]
        invoke(cmd,output,mode+'-build')
    return {'platform':'host-only '+sys.platform,'runtime':'host system -lsqlite3; not Windows validation',
            'compiler':cc}

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source','--baseline-source',dest='source',type=Path,default=HERE.parents[1])
    dll=p.add_mutually_exclusive_group()
    dll.add_argument('--sqlite-dll',type=Path)
    dll.add_argument('--baseline-runtime',type=Path)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();source=a.source.resolve();output=a.output.resolve()
    output.mkdir(mode=0o700)
    if list(output.iterdir()): raise RuntimeError('fresh empty output directory required')
    bound=generate(source,output)
    if os.name=='nt':
        runtime=a.sqlite_dll
        if a.baseline_runtime:
            found=[v for v in a.baseline_runtime.resolve().rglob('sqlite3.dll') if v.is_file()]
            if len(found)!=1:raise RuntimeError('baseline runtime must contain exactly one sqlite3.dll')
            runtime=found[0]
        if runtime is None:raise RuntimeError('Windows requires verified original --sqlite-dll or --baseline-runtime')
        details=windows_build(source,output,runtime.resolve())
    else:
        if a.sqlite_dll or a.baseline_runtime:raise RuntimeError('Windows runtime cannot be validated on this host')
        details=host_build(source,output)
    bound.update(details)
    bound['budget']={'busy_timeout_ms':200,'progress_ops':1000,'deadline_ms':2000,'caller_timeout_s':6,'max_stdout_bytes':8192}
    bound['files']={v.name:{'sha256':sha(v),'bytes':v.stat().st_size} for v in sorted(output.iterdir()) if v.is_file()}
    (output/'build-manifest.json').write_text(json.dumps(bound,indent=2)+'\n')
    print(json.dumps({'output':str(output),'platform':bound['platform'],'manifest':str(output/'build-manifest.json')}))

if __name__=='__main__':main()
