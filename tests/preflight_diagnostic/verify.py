#!/usr/bin/env python3
"""Twelve bounded synthetic cases; never open the original failed CI database."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
import time

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--probe-root',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
D=a.probe_root.resolve()
ROOT=a.output.resolve()
ROOT.mkdir(mode=0o700)
assert not list(ROOT.iterdir()),'fresh empty synthetic result directory required'
SUFFIX='.exe' if os.name=='nt' else ''
manifest=json.loads((D/'build-manifest.json').read_text())
assert manifest['budget']=={'busy_timeout_ms':200,'progress_ops':1000,'deadline_ms':2000,'caller_timeout_s':6,'max_stdout_bytes':8192}
for mode in ('original','trace'):
 pin=manifest['files']['preflight-'+mode+SUFFIX]
 f=D/('preflight-'+mode+SUFFIX)
 assert hashlib.sha256(f.read_bytes()).hexdigest()==pin['sha256']
records=[]
started=time.monotonic()

def digest(path):
    if not path.exists(): return None
    return {'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

def snapshot(path):
    return {'main':digest(path),'wal':digest(Path(str(path)+'-wal'))}

def exercise(name,path,expected,budget=128,kind=None,phase=None,code=None):
    outputs={}
    original=snapshot(path)
    for mode in ('original','trace'):
        assert time.monotonic()-started<144,'synthetic suite 150-second deadline'
        process=subprocess.run([str(D/('preflight-'+mode+SUFFIX)),str(path),str(budget)],capture_output=True,timeout=6)
        (ROOT/(name+'-'+mode+'.stdout')).write_bytes(process.stdout)
        (ROOT/(name+'-'+mode+'.stderr')).write_bytes(process.stderr)
        assert process.returncode==0 and not process.stderr,(name,mode,process.returncode)
        assert len(process.stdout)<8192,(name,'output_limit')
        out=json.loads(process.stdout)
        assert out['result']==expected,(name,mode,out)
        assert snapshot(path)==original,(name,mode,'main_or_wal_changed')
        (ROOT/(name+'-'+mode+'.json')).write_bytes(process.stdout)
        outputs[mode]=out
    traced=outputs['trace']
    assert outputs['original']['result']==traced['result']
    if original['main'] and original['main']['bytes']:
        assert traced['readonly_open_flags']==1 and traced['busy_timeout_ms']==200 and traced['progress_ops']==1000
    failure=traced['first_failure']
    if expected==0: assert failure is None,(name,failure)
    if kind: assert failure['kind']==kind,(name,failure)
    if phase: assert failure['phase']==phase,(name,failure)
    if code is not None: assert failure['sqlite_primary_code']==code,(name,failure)
    records.append({'case':name,'expected_result':expected,'original_result':outputs['original']['result'],
        'trace_result':traced['result'],'main_wal_unchanged_after_each':True,'snapshot':original,
        'original_elapsed_ms':outputs['original']['elapsed_ms'],'trace_elapsed_ms':traced['elapsed_ms'],
        'trace':traced})

def database(name):
    path=ROOT/(name+'.db')
    db=sqlite3.connect(path)
    db.execute('CREATE TABLE metrics(minute_unix INTEGER,endpoint_id TEXT,metric_name TEXT,value INTEGER)')
    db.commit()
    return path,db

exercise('missing',ROOT/'missing.db',0)
path,db=database('available');db.close()
exercise('available',path,0)

path,db=database('unsupported');db.execute('PRAGMA user_version=99');db.close()
exercise('unsupported',path,-1,kind='logical_rejection',phase='format_check',code=0)

path,db=database('fence_empty')
db.executescript('CREATE TABLE context_retirement_progress(candidate_id TEXT,phase INTEGER);'
                 'CREATE TABLE p0_candidates(candidate_id TEXT,retention_policy_version INTEGER,local_retention_state TEXT);'
                 'PRAGMA user_version=3;')
db.close()
exercise('fence_empty',path,-1,kind='logical_rejection',phase='format_check')

path=ROOT/'corrupt.db';path.write_bytes(b'public-synthetic-invalid-sqlite\n')
exercise('corrupt',path,-1,kind='sqlite_api_error',phase='format_check',code=26)

path,db=database('schema_mismatch')
db.execute('CREATE TABLE context_retirement_progress(unexpected TEXT)');db.close()
exercise('schema_mismatch',path,-1,kind='logical_rejection',phase='retirement_schema_pages')

path,db=database('bad_clock')
db.execute("INSERT INTO metrics VALUES(0,'','local_retention_v1_active_ms','invalid')");db.commit();db.close()
exercise('bad_clock',path,-1,kind='logical_rejection',phase='retention_clock_validity')

path,db=database('duplicate_clock')
db.executemany("INSERT INTO metrics VALUES(0,'','local_retention_v1_active_ms',?)",[(1,),(2,)])
db.commit();db.close()
exercise('duplicate_clock',path,-1,kind='logical_rejection',phase='retention_clock_validity')

path,db=database('capacity')
db.executescript('CREATE TABLE padding(payload BLOB);INSERT INTO padding VALUES(zeroblob(1100000));')
db.close()
exercise('capacity',path,1,budget=1,kind='capacity_rejection',phase='capacity_decision')

path,db=database('locked')
db.execute('BEGIN EXCLUSIVE')
try:
    exercise('exclusive_lock',path,-1,kind='sqlite_api_error',phase='format_check',code=5)
finally:
    db.rollback();db.close()

path,db=database('wal')
try:
    assert db.execute('PRAGMA journal_mode=WAL').fetchone()[0]=='wal'
    db.execute('PRAGMA wal_autocheckpoint=0')
    db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    db.execute("INSERT INTO metrics VALUES(0,'','local_retention_v1_active_ms',1)");db.commit()
    assert Path(str(path)+'-wal').stat().st_size>0
    exercise('existing_wal_available',path,0)
    db.execute("UPDATE metrics SET value='invalid'");db.commit()
    exercise('existing_wal_bad_clock',path,-1,kind='logical_rejection',phase='retention_clock_validity')
finally:
    db.close()

report={'scope':'synthetic '+('Windows native' if os.name=='nt' else 'host '+os.sys.platform)+' only; same input to original and trace; no product changes',
        'cases':records,'passed':len(records),'all_main_wal_unchanged_after_each':True,
        'unverified':(['Windows native execution'] if os.name!='nt' else [])+['original AMD64 CI failing database (not retained)',
                      'original CI first failing SQL','2-second interruption path (lock/busy tested instead)'],
        'build_manifest':str(D/'build-manifest.json'),'instrumentation':'tests/preflight_diagnostic/instrumentation.patch'}
report_path=ROOT/'verification.json';report_path.write_text(json.dumps(report,indent=2)+'\n')

print(json.dumps({'passed':len(records),'main_wal_unchanged':True,'report':str(report_path)}))
