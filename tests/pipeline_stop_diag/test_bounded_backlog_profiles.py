"""Host-only contracts; parent/worker JSON and process APIs are explicit fakes."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HOME = Path(__file__).resolve().parent
SOURCE = HOME / 'run_bounded_backlog_profiles.py'
spec = importlib.util.spec_from_file_location('backlog_consumer', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def worker_rows(n=128, profile='ready'):
    input_sha = 'a' * 64
    offered = dict(kind='pipeline_diag_backlog_input', slots=n, bus_capacity_slots=n,
        slot_size_bytes=128, bus_payload_array_bytes=128*n,
        cache_budget_mb=512, queue_budget_mb=512, mixed_type_count_each=n//4,
        input_sha256=input_sha, all_input_dispositions_verified=False)
    cost = dict(kind='pipeline_diag_backlog_cost', slots=n, elapsed_ns=100000,
        vfs_read_bytes=10, vfs_write_bytes=20, vfs_syncs=2,
        thread_cpu_known=True, thread_kernel_100ns=1, thread_user_100ns=2,
        thread_cpu_before_error=0, thread_cpu_after_error=0,
        cpu_counter_regressed=False, scope='same_thread_preprocess_main')
    drain = dict(kind='pipeline_diag_drain_end', slots=n, completed_slots=n,
        input_sha256=input_sha, real_ir_ready=profile=='ready', real_sqlite=True,
        necessary_source_owners_seeded=1, necessary_source_bytes_unchanged=True,
        actions_observed=0, process_evidence_worker_windows_thread_started=True,
        network_transport_initialized=False, source_ack_inferred=False,
        ave_initialized=False, all_input_dispositions_verified=False,
        win_actor_branch_compiled=True, stop_set_before_worker=True, loop_returned=True,
        timings_inclusive=True, elapsed_ns=100000,
        vfs_read_bytes=12, vfs_write_bytes=20, vfs_syncs=2)
    state = dict(kind='pipeline_diag_backlog_source_state', slots=n,
        source_only_retry_pending=0, source_only_backpressure_failed_delta=0,
        source_only_retry_capacity_exhausted_delta=0, source_only_loss_detected=0,
        source_only_terminal_unhealthy=int(profile=='missing'),
        source_only_unhealthy_families=0, deferred_storage_failures=0,
        deferred_retry_degraded=0, necessary_source_owners_seeded=1,
        necessary_source_bytes_unchanged=True, all_input_dispositions_verified=False,
        required_owner_unresolved=False)
    stages = [dict(kind='pipeline_diag_stage', stage=i, calls=1, inclusive_total_ns=100, max_ns=50) for i in range(1,40)]
    return [offered, cost, drain] + stages + [state,
        dict(kind='pipeline_diag_evidence_stop', shutdown_timeouts=0,
             terminal_unhealthy=0, slots_used=0),
        dict(kind='pipeline_diag_worker_complete', cleanup_returned=True)]


def get(rows, kind):
    return next(row for row in rows if row['kind']==kind)


def write_profile(case, n, exit_code=0):
    parents = []
    for profile in ('ready','missing'):
        home = case / ('pipeline-stop-'+str(n)+'-'+profile)
        home.mkdir()
        rows = worker_rows(n, profile)
        output = b''.join((json.dumps(row)+'\n').encode() for row in rows)
        (home/'worker.stdout.log').write_bytes(output)
        (home/'worker.stderr.log').write_bytes(b'')
        parents.append(dict(schema='edr.private.pipeline-parent.v1',
            cause='worker_complete', profile=profile, accepted=exit_code==0,
            child_exit_known=True, job_natural_zero=True, cleanup_verified=True,
            termination_attempted=False, parent_deadline_exceeded=False,
            child_exit_code=exit_code, child_pid=200, child_birth_filetime=1000000,
            elapsed_ms=10, fixture_sampled_peak_bytes=100000,
            fixture_final_sample_bytes=100000, fixture_samples=1, last_error_diagnostic_only=0,
            stdout_bytes=len(output),stderr_bytes=0))
    return b''.join((json.dumps(row)+'\n').encode() for row in parents)


class FakeClock:
    def __init__(self, value=0): self.value=value
    def __call__(self): return self.value


class FakeParent:
    def __init__(self, factory, args, cwd, stdout, stderr):
        n=int(args[1].removeprefix('--backlog'))
        self.factory=factory; self.pid=100+n; self.code=None;self.waits=0
        self.exit=factory.exits[len(factory.calls)] if len(factory.calls)<len(factory.exits) else 0
        self.duration=factory.durations[len(factory.calls)] if len(factory.calls)<len(factory.durations) else 1
        self.timeout=factory.timeout
        assert (cwd/'intent.json').is_file(), 'intent before process'
        factory.calls.append(n)
        stdout.write(write_profile(cwd,n,self.exit));stderr.write(b'')
    def wait(self, timeout):
        self.waits+=1
        if self.timeout and self.waits==1:
            self.factory.clock.value+=timeout
            raise subprocess.TimeoutExpired('public-fake-parent',timeout)
        self.factory.clock.value+=self.duration
        self.code=self.exit
        return self.code
    def poll(self): return self.code
    def kill(self): self.factory.kills+=1; self.exit=90


class Factory:
    def __init__(self,clock,exits=(),durations=(),timeout=False):
        self.clock=clock;self.exits=exits;self.durations=durations
        self.timeout=timeout;self.calls=[];self.kills=0
    def __call__(self,*args,**kwargs): return FakeParent(self,*args,**kwargs)


class ConsumerContracts(unittest.TestCase):
    def test_all_six_profile_combinations(self):
        for n in m.SLOTS:
            for profile in ('ready','missing'):
                with self.subTest(n=n,profile=profile):
                    self.assertEqual(m.validate_worker(worker_rows(n,profile),n,profile)['slots'],n)

    def test_missing_and_duplicate_new_kind(self):
        for kind in ('pipeline_diag_backlog_input','pipeline_diag_backlog_cost','pipeline_diag_backlog_source_state'):
            for duplicate in (False,True):
                rows=worker_rows();item=get(rows,kind)
                rows.append(copy.deepcopy(item)) if duplicate else rows.remove(item)
                with self.subTest(kind=kind,duplicate=duplicate), self.assertRaises(m.ContractError):
                    m.validate_worker(rows,128,'ready')

    def test_bad_input_fields(self):
        changes={'slots':True,'bus_capacity_slots':1024,'slot_size_bytes':0,
            'bus_payload_array_bytes':16385,'cache_budget_mb':8,'queue_budget_mb':8,
            'mixed_type_count_each':31,'input_sha256':'F'*64,'all_input_dispositions_verified':True}
        for key,value in changes.items():
            rows=worker_rows();get(rows,'pipeline_diag_backlog_input')[key]=value
            with self.subTest(key=key),self.assertRaises(m.ContractError):m.validate_worker(rows,128,'ready')

    def test_extra_fields_rejected(self):
        for kind in ('pipeline_diag_backlog_input','pipeline_diag_backlog_cost','pipeline_diag_backlog_source_state'):
            rows=worker_rows();get(rows,kind)['private_text']='never-export'
            with self.subTest(kind=kind),self.assertRaises(m.ContractError):m.validate_worker(rows,128,'ready')

    def test_known_cpu_shape_and_errors(self):
        changes={'thread_kernel_100ns':None,'thread_user_100ns':True,
            'thread_cpu_before_error':5,'thread_cpu_after_error':5,
            'cpu_counter_regressed':True,'scope':'other','elapsed_ns':100001,
            'vfs_read_bytes':13,'vfs_write_bytes':21,'vfs_syncs':3}
        for key,value in changes.items():
            rows=worker_rows();get(rows,'pipeline_diag_backlog_cost')[key]=value
            with self.subTest(key=key),self.assertRaises(m.ContractError):m.validate_worker(rows,128,'ready')

    def test_unknown_cpu_is_nullable_not_zero(self):
        rows=worker_rows();cost=get(rows,'pipeline_diag_backlog_cost')
        cost.update(thread_cpu_known=False,thread_kernel_100ns=None,thread_user_100ns=None,
                    thread_cpu_before_error=5)
        self.assertIsNone(m.validate_worker(rows,128,'ready')['extra']['cost']['thread_user_100ns'])
        cost['thread_user_100ns']=0
        with self.assertRaises(m.ContractError):m.validate_worker(rows,128,'ready')

    def test_regressed_unknown_cpu_kept_unknown(self):
        rows=worker_rows();get(rows,'pipeline_diag_backlog_cost').update(
            thread_cpu_known=False,thread_kernel_100ns=None,thread_user_100ns=None,cpu_counter_regressed=True)
        self.assertFalse(m.validate_worker(rows,128,'ready')['extra']['cost']['thread_cpu_known'])

    def test_unresolved_owner_rejected(self):
        for key,value in {'required_owner_unresolved':True,'source_only_retry_pending':1,
            'source_only_retry_capacity_exhausted_delta':1,'source_only_loss_detected':1,
            'deferred_retry_degraded':1,'necessary_source_bytes_unchanged':False,
            'necessary_source_owners_seeded':2,'all_input_dispositions_verified':True}.items():
            rows=worker_rows();get(rows,'pipeline_diag_backlog_source_state')[key]=value
            with self.subTest(key=key),self.assertRaises(m.ContractError):m.validate_worker(rows,128,'ready')

    def test_missing_ir_unhealthy_not_itself_loss(self):
        rows=worker_rows(128,'missing');state=get(rows,'pipeline_diag_backlog_source_state')
        state.update(source_only_terminal_unhealthy=1,source_only_unhealthy_families=255,
                     source_only_backpressure_failed_delta=3,deferred_storage_failures=2)
        self.assertTrue(m.validate_worker(rows,128,'missing')['extra']['source_state']['source_only_terminal_unhealthy'])

    def test_default_relevant_requirements_not_weakened(self):
        for key,value in {'completed_slots':127,'real_ir_ready':False,'real_sqlite':False,
            'necessary_source_owners_seeded':0,'actions_observed':1,
            'process_evidence_worker_windows_thread_started':False,
            'network_transport_initialized':True,'source_ack_inferred':True}.items():
            rows=worker_rows();get(rows,'pipeline_diag_drain_end')[key]=value
            with self.subTest(key=key),self.assertRaises(m.ContractError):m.validate_worker(rows,128,'ready')

    def test_stage_inventory_and_windows_calls(self):
        for change in ('missing','duplicate','wrong_order','windows_branch_zero'):
            rows=worker_rows();stage=get(rows,'pipeline_diag_stage')
            if change=='missing':rows.remove(stage)
            elif change=='duplicate':rows.append(copy.deepcopy(stage))
            elif change=='wrong_order':stage['stage']=2
            else:next(row for row in rows if row.get('stage')==7)['calls']=0
            with self.subTest(change=change),self.assertRaises(m.ContractError):m.validate_worker(rows,128,'ready')

    def test_strict_json_rejects_duplicate_nan_utf8(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'\xff'):
            with self.subTest(raw=raw),self.assertRaises(Exception):m.parse(raw)

    def test_noncontract_error_message_not_exported(self):
        self.assertEqual(m.failure_code(OSError('private-path-token')), 'unexpected_OSError')

    def test_collect_real_public_files_and_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            case=Path(tmp);(case/'parent.stdout.log').write_bytes(write_profile(case,128))
            (case/'parent.stderr.log').write_bytes(b'');result={}
            m.collect_profile(case,128,0,result)
            self.assertEqual(len(result['streams']),6)
            self.assertEqual(len(result['workers']),2)
            self.assertEqual(result['streams']['parent.stdout.log']['sha256'],
                m.sha((case/'parent.stdout.log').read_bytes()))

    def test_nonzero_parent_retains_all_available_stream_pins(self):
        with tempfile.TemporaryDirectory() as tmp:
            case=Path(tmp);(case/'parent.stdout.log').write_bytes(write_profile(case,128,91))
            (case/'parent.stderr.log').write_bytes(b'');result={}
            with self.assertRaises(m.ContractError):m.collect_profile(case,128,91,result)
            self.assertEqual(len(result['streams']),6)

    def test_file_cap_still_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'public.log';p.write_bytes(b'x'*(m.LOG_CAP+1))
            with self.assertRaises(m.ContractError):m.take(p)

    def test_three_profiles_exact_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock=FakeClock();factory=Factory(clock)
            result=m.run_profiles(Path(tmp)/'case',Path('public-fake.exe'),{},factory,clock)
            self.assertTrue(result['accepted']);self.assertEqual(factory.calls,list(m.SLOTS))
            self.assertEqual(result['not_started'],[]);self.assertEqual(factory.kills,0)

    def test_first_failure_stops_later_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock=FakeClock();factory=Factory(clock,exits=[91])
            result=m.run_profiles(Path(tmp)/'case',Path('public-fake.exe'),{},factory,clock)
            self.assertFalse(result['accepted']);self.assertEqual(factory.calls,[128])
            self.assertEqual([row['slots'] for row in result['not_started']],[1024,8192])

    def test_no_partial_next_budget_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock=FakeClock();factory=Factory(clock,durations=[88,88])
            result=m.run_profiles(Path(tmp)/'case',Path('public-fake.exe'),{},factory,clock)
            self.assertFalse(result['accepted']);self.assertEqual(factory.calls,[128,1024])
            self.assertEqual(result['not_started'],[dict(slots=8192,reason='not_started_budget')])

    def test_initial_insufficient_budget_launches_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock=FakeClock(200);factory=Factory(clock)
            result=m.run_profiles(Path(tmp)/'case',Path('public-fake.exe'),{},factory,clock,started=0)
            self.assertFalse(result['accepted']);self.assertEqual(factory.calls,[])
            self.assertEqual(len(result['not_started']),3)

    def test_timeout_never_promoted_and_single_owned_kill(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock=FakeClock();factory=Factory(clock,timeout=True)
            result=m.run_profiles(Path(tmp)/'case',Path('public-fake.exe'),{},factory,clock)
            self.assertFalse(result['accepted']);self.assertEqual(factory.calls,[128])
            self.assertEqual(factory.kills,1)
            one=json.loads((Path(tmp)/'case/backlog-128/receipt.json').read_bytes())
            self.assertTrue(one['outer_kill_requested']);self.assertFalse(one['accepted'])
            self.assertNotIn('streams',one)

    def test_cleanup_unknown_does_not_read_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            case=Path(tmp);raw=write_profile(case,128)
            rows=[json.loads(line) for line in raw.splitlines()]
            rows[0]['cleanup_verified']=False
            (case/'parent.stdout.log').write_bytes(b''.join((json.dumps(row)+'\n').encode() for row in rows))
            (case/'parent.stderr.log').write_bytes(b'')
            # An oversized worker file would otherwise be read/rejected.
            (case/'pipeline-stop-128-ready/worker.stdout.log').write_bytes(b'x'*(m.LOG_CAP+1))
            result={}
            with self.assertRaisesRegex(m.ContractError,'parent_worker_quiescence_unknown'):
                m.collect_profile(case,128,0,result)
            self.assertEqual(set(result['streams']),{'parent.stdout.log','parent.stderr.log'})
            self.assertEqual(result['parent_rows'],rows)
            self.assertNotIn('workers',result)

    def test_terminated_child_keeps_closed_parent_failure_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            case=Path(tmp);raw=write_profile(case,8192)
            rows=[json.loads(line) for line in raw.splitlines()]
            rows[1].update(cause='worker_deadline',accepted=False,
                           termination_attempted=True,job_natural_zero=False,
                           child_exit_code=90,elapsed_ms=85000)
            (case/'parent.stdout.log').write_bytes(b''.join(
                (json.dumps(row)+'\n').encode() for row in rows))
            (case/'parent.stderr.log').write_bytes(b'')
            # Failure metadata remains useful without reading either worker.
            for profile in ('ready','missing'):
                (case/f'pipeline-stop-8192-{profile}/worker.stdout.log').unlink()
            result={}
            with self.assertRaisesRegex(m.ContractError,'parent_worker_quiescence_unknown'):
                m.collect_profile(case,8192,90,result)
            self.assertEqual(result['parent_rows'],rows)
            self.assertEqual(set(result['streams']),{'parent.stdout.log','parent.stderr.log'})
            self.assertNotIn('workers',result)

    def test_invalid_parent_fields_are_not_preserved(self):
        for field,value in [('child_exit_known','true'),('child_pid',-1),
                            ('private_text','not a closed field')]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as tmp:
                case=Path(tmp);rows=[json.loads(line) for line in write_profile(case,128).splitlines()]
                rows[0][field]=value
                (case/'parent.stdout.log').write_bytes(b''.join(
                    (json.dumps(row)+'\n').encode() for row in rows))
                (case/'parent.stderr.log').write_bytes(b'')
                result={}
                with self.assertRaises(m.ContractError):
                    m.collect_profile(case,128,0,result)
                self.assertNotIn('parent_rows',result)
                self.assertNotIn('workers',result)

    def test_proof_copy_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp)/'repo';case=Path(tmp)/'case';case.mkdir()
            paths=['contract-build/tests/pipeline-stop-generated/SOURCE-TRANSFORM-v2.json',
                   'contract-build/tests/pipeline-stop-source-closure-Release.txt']
            for path in paths:
                p=repo/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'public-proof\r\n')
            result=m.copy_proofs(repo,case)
            self.assertEqual(set(result),{'source-transform-v2.json','source-closure-Release.txt'})
            self.assertTrue(all((case/name).read_bytes()==b'public-proof\r\n' for name in result))

    def test_producer_pins_allow_only_two_exact_newline_variants(self):
        root=HOME
        for name,pins in m.PRODUCER_PINS.items():
            raw=(root/Path(name).name).read_bytes()
            self.assertIn(m.sha(raw),pins)
            self.assertIn(m.sha(raw.replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')),pins)
            self.assertNotIn(m.sha(raw+b' '),pins)

    def test_reusing_case_refused_before_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            case=Path(tmp)/'case';case.mkdir();clock=FakeClock();factory=Factory(clock)
            with self.assertRaises(FileExistsError):m.run_profiles(case,Path('public-fake.exe'),{},factory,clock)
            self.assertEqual(factory.calls,[])


if __name__=='__main__':
    unittest.main(verbosity=2)
