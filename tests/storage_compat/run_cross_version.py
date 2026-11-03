"""Run immutable old/new storage consumers in fresh processes on isolated copies."""
import argparse, hashlib, json, platform, sqlite3, subprocess, time
from pathlib import Path
from prepare import PINS

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--legacy-bin',type=Path,required=True)
    p.add_argument('--candidate-bin',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    deadline=time.monotonic()+120
    epoch=str(int(time.time()));tenant='synthetic-storage-tenant';endpoint='synthetic-storage-endpoint'
    receipts=[];negatives=[];identities={};native_machines=set()
    suffix='.exe' if platform.system()=='Windows' else ''
    tools={role:{kind:folder/('storage_compat_'+kind+suffix) for kind in ('cache','queue')}
           for role,folder in [('legacy',a.legacy_bin),('candidate',a.candidate_bin)]}
    for role,pair in tools.items():
        identities[role]={kind:{'path':str(exe.resolve()),'sha256':sha(exe)} for kind,exe in pair.items()}

    def invoke(role,kind,action,db,generation,label,expect_failure=False,epoch_arg=epoch,
               tenant_arg=tenant,endpoint_arg=endpoint,expected_failure=None):
        exe=tools[role][kind]
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('cross-version acceptance deadline')
        policy=['16','24','72'] if kind=='cache' else ['16','72','72']
        result=subprocess.run([str(exe),action,str(db),epoch_arg,str(generation),tenant_arg,endpoint_arg,*policy],
                              capture_output=True,text=True,encoding='utf-8',timeout=min(30,remaining))
        (a.output/(label+'.stdout.json')).write_text(result.stdout,encoding='utf-8')
        (a.output/(label+'.stderr.txt')).write_text(result.stderr,encoding='utf-8')
        if expect_failure:
            if result.returncode==0 or result.stdout.strip():
                raise ValueError('negative produced success: '+label)
            if expected_failure and (result.returncode!=2 or
                    result.stderr.strip()!='storage_compat phase='+action+' cause='+expected_failure):
                raise ValueError('identity was not rejected at its original owner boundary: '+label)
            negatives.append({'case':label,'exit_code':result.returncode,'success_receipt':False})
            return
        if result.returncode:
            raise ValueError(label+' failed: '+result.stderr[-500:])
        receipt=json.loads(result.stdout)
        if receipt['source_commit']!=PINS[role] or receipt['action']!=action or receipt['owner']!=('evidence_cache' if kind=='cache' else 'queue'):
            raise ValueError('receipt owner/source mismatch')
        if receipt['tenant_id']!=tenant_arg or receipt['endpoint_id']!=endpoint_arg or receipt['epoch']!=int(epoch_arg):
            raise ValueError('receipt input identity changed')
        if receipt['network'] or receipt['direct_sql_writes'] or receipt['sensor_capture']:
            raise ValueError('unexpected scope claim')
        if platform.system()=='Windows':
            if receipt.get('native_windows') is not True or receipt.get('process_machine')!=0 or receipt.get('native_machine') not in (0x8664,0xaa64):
                raise ValueError('native process identity is missing or emulated')
            native_machines.add(receipt['native_machine'])
            if len(native_machines)!=1:raise ValueError('mixed native architectures')
        elif receipt.get('native_windows') is not False:
            raise ValueError('host cannot claim Windows execution')
        records=receipt['records']
        if len(records)!=(generation*2 if action=='read' else 2):
            raise ValueError('missing records')
        receipts.append({'label':label,'file':label+'.stdout.json','sha256':sha(a.output/(label+'.stdout.json'))})
        return records

    def clone(source,name):
        dest=a.output/name;dest.mkdir()
        # Real SQLite backup reads the complete committed snapshot, including WAL.
        # No fabricated rows, schema statements or immutable=1 WAL bypass.
        target=dest/source.name;snapshot_deadline=min(deadline,time.monotonic()+15)
        def progress(status,remaining,total):
            if time.monotonic()>snapshot_deadline:raise TimeoutError('snapshot deadline')
        with sqlite3.connect(source.resolve().as_uri()+'?mode=ro',uri=True,timeout=2) as read:
            with sqlite3.connect(target,timeout=2) as write:
                read.backup(write,pages=128,progress=progress,sleep=.01)
        return target

    def comparable(records):
        return sorted(records,key=lambda x:json.dumps(x,sort_keys=True))

    for kind in ('cache','queue'):
        original=a.output/(kind+'-legacy.db')
        old=invoke('legacy',kind,'create',original,1,kind+'-legacy-write')
        for role in ('legacy','candidate'):
            db=clone(original,kind+'-'+role+'-reads-old')
            actual=invoke(role,kind,'read',db,1,kind+'-'+role+'-read-old')
            if comparable(actual)!=comparable(old):raise ValueError('old data readback changed')
        upgraded=clone(original,kind+'-candidate-write')
        new=invoke('candidate',kind,'append',upgraded,2,kind+'-candidate-append')
        for role in ('candidate','legacy'):
            db=clone(upgraded,kind+'-'+role+'-reads-new')
            actual=invoke(role,kind,'read',db,2,kind+'-'+role+'-read-new')
            if comparable(actual)!=comparable(old+new):raise ValueError('candidate/rollback readback changed')
        duplicate=clone(original,kind+'-negative-duplicate')
        invoke('legacy',kind,'seed',duplicate,1,kind+'-duplicate-seed',True)
        wrong=clone(original,kind+'-negative-missing')
        invoke('candidate',kind,'read',wrong,2,kind+'-missing-generation',True)
        wrong_epoch=clone(original,kind+'-negative-expired')
        invoke('candidate',kind,'read',wrong_epoch,1,kind+'-expired-epoch',True,epoch_arg='1700000000')
        absent=a.output/(kind+'-absent.db')
        invoke('candidate',kind,'read',absent,1,kind+'-missing-database',True)
        corrupt=a.output/(kind+'-corrupt.db');corrupt.write_bytes(b'not a sqlite database\n')
        invoke('candidate',kind,'read',corrupt,1,kind+'-corrupt-database',True)
    # Actual old/new record and protobuf owners retain at most 47 endpoint and
    # 63 tenant bytes. The installed test's former 51-byte endpoint must fail
    # before SQLite opens, not overflow a record or fail later in RTQ parsing.
    boundary_receipts=[];boundary_negatives=[]
    bounded_tenant='synthetic-storage-tenant-'.ljust(63,'t')
    bounded_endpoint='synthetic-storage-endpoint-'.ljust(47,'e')
    for role in ('legacy','candidate'):
        for kind in ('cache','queue'):
            label=kind+'-'+role+'-identity-max'
            original=a.output/(label+'.db')
            written=invoke(role,kind,'create',original,1,label+'-write',
                           tenant_arg=bounded_tenant,endpoint_arg=bounded_endpoint)
            copy=clone(original,label+'-read-copy')
            actual=invoke(role,kind,'read',copy,1,label+'-read',
                          tenant_arg=bounded_tenant,endpoint_arg=bounded_endpoint)
            if comparable(actual)!=comparable(written):raise ValueError('boundary identity readback changed')
            boundary_receipts.extend([label+'-write',label+'-read'])
            for field,length in (('endpoint',48),('endpoint',51),('tenant',64)):
                negative=kind+'-'+role+'-'+field+'-'+str(length)
                database=a.output/(negative+'.db')
                invoke(role,kind,'create',database,1,negative,True,
                       tenant_arg=('t'*length if field=='tenant' else bounded_tenant),
                       endpoint_arg=('e'*length if field=='endpoint' else bounded_endpoint),
                       expected_failure='fixture_'+field+'_identity')
                if list(a.output.glob(database.name+'*')):
                    raise ValueError('rejected identity created database state: '+negative)
                boundary_negatives.append(negative)
    summary={'schema':'edr.test.storage-cross-version.v1','passed':True,'platform':platform.system(),
             'machine':platform.machine(),'source_commits':PINS,'tools':identities,'epoch':int(epoch),
             'native_windows':platform.system()=='Windows','installed_agent_lifecycle':False,
             'native_machine':next(iter(native_machines)) if native_machines else None,
             'input_origin':'synthetic_records_via_original_storage_owner_api',
             'production_storage_and_codec':True,'production_rule_engine':False,
             'queue_reader_delivery_clock_advance_s':301,'network':False,
             'main_matrix':{'reads':8,'write_phases':4,'negative_cases':10},
             'identity_boundaries':{'endpoint_max_bytes':47,'tenant_max_bytes':63,
                                    'reads':4,'write_phases':4,'receipt_labels':boundary_receipts,
                                    'negative_cases':boundary_negatives,'rejection_before_database_open':True},
             'receipts':receipts,'negatives':negatives}
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'passed':True,'platform':platform.system(),'reads':8,'write_phases':4,
                      'boundary_reads':4,'boundary_write_phases':4,
                      'negatives':len(negatives),'summary':str(a.output/'summary.json')}))

if __name__=='__main__':main()
