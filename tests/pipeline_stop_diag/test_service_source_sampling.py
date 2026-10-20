"""Local source reversal and pure C/WinAPI-seam contracts; not native SCM proof."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

SHIM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <errno.h>
#define _WIN32 1
typedef uint32_t DWORD;
typedef void *HANDLE;
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED UINT32_MAX
static atomic_uint s_worker_phase;
static uint64_t now_ns;
static DWORD last_error, tid = 7u;
static unsigned mode, waits;
DWORD GetLastError(void) { return last_error; }
void SetLastError(DWORD value) { last_error = value; }
static DWORD GetCurrentThreadId(void) { last_error = 888u; errno = 777; return tid; }
static uint64_t edr_monotonic_ns(void) { last_error = 999u; return now_ns; }
static DWORD WaitForSingleObject(HANDLE handle, DWORD ms) {
  (void)handle; assert(ms > 0u && ms <= 10u); ++waits;
  if (mode == 0u) { now_ns += ms * UINT64_C(1000000); return WAIT_OBJECT_0; }
  if (mode == 2u) { now_ns = UINT64_C(61000000000); last_error = 5u; return WAIT_FAILED; }
  if (mode == 3u) { assert(waits == 1u); now_ns = UINT64_C(61000000000); return WAIT_TIMEOUT; }
  if (mode == 4u) return WAIT_TIMEOUT; /* Deliberately frozen clock. */
  if (mode == 5u && waits > 1u) return WAIT_OBJECT_0;
  if (mode == 6u) { assert(waits == 1u); now_ns = UINT64_C(61000000000); return WAIT_OBJECT_0; }
  if (mode == 7u) { assert(waits == 1u); now_ns = UINT64_C(60000000000); return WAIT_OBJECT_0; }
  now_ns += ms * UINT64_C(1000000); return WAIT_TIMEOUT;
}
#include "service_substage_frontier.inc"
unsigned probe_current_site(void) { return atomic_load(&s_worker_callsite); }
unsigned probe_is_worker(void) { return tid == 7u; }
typedef int EdrBehaviorRecord;
void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *record);
void probe_nested_envelopes(void);
void probe_wal_callback(void);
static int evaluated;
static int original_call(void) { ++evaluated; SetLastError(42u); errno = 19; return 17; }
static void reset(unsigned chosen) {
  mode = chosen; waits = 0u; now_ns = 0u; SetLastError(73u); errno = 23;
  atomic_store(&s_worker_phase, 3u); atomic_store(&s_worker_callsite, 79u);
}
static void verify(const PreprocessJoinSamples *s) {
  unsigned phases = 0u, sites = 0u;
  assert(s->samples <= 6001u && s->capped <= 1u);
  if (s->capped) assert(s->samples == 6001u);
  for (unsigned i = 0u; i < 13u; ++i) { assert(s->phase_hits[i] <= 6001u); phases += s->phase_hits[i]; }
  for (unsigned i = 0u; i < 138u; ++i) { assert(s->callsite_hits[i] <= 6001u); sites += s->callsite_hits[i]; }
  assert(phases == s->samples && sites == s->samples);
}
int main(void) {
  uint64_t first, nested, disabled; DWORD error, result; PreprocessJoinSamples samples;
  SetLastError(31u); errno = 17; preprocess_substage_worker_enter();
  assert(GetLastError() == 31u && errno == 17);
  first = preprocess_substage_enter(4u, 2u);
  nested = preprocess_substage_enter(8u, 79u);
  assert(atomic_load(&s_worker_callsite) == 79u);
  preprocess_substage_leave(nested);
  assert(atomic_load(&s_worker_substage) == 4u && atomic_load(&s_worker_callsite) == 2u);
  tid = 8u; SetLastError(32u); errno = 18;
  disabled = preprocess_substage_enter(6u, 1u); assert(disabled == UINT64_MAX);
  preprocess_substage_leave(first); preprocess_substage_clear(); preprocess_substage_worker_exit();
  assert(atomic_load(&s_worker_substage) == 4u && atomic_load(&s_worker_callsite) == 2u);
  assert(atomic_load(&s_worker_probe_thread_id) == 7u && GetLastError() == 32u && errno == 18);
  tid = 7u; preprocess_substage_leave(first);
  assert(atomic_load(&s_worker_callsite) == 0u);
  result = (DWORD)PREPROCESS_SUBSTAGE_INT(8u, 79u, first, original_call());
  assert(result == 17u && evaluated == 1 && GetLastError() == 42u && errno == 19);
  PREPROCESS_SUBSTAGE_VOID(8u, 79u, first, (void)original_call());
  assert(evaluated == 2 && atomic_load(&s_worker_callsite) == 0u && GetLastError() == 42u && errno == 19);
  /* The envelope and three typed wrappers below execute in another real TU.
   * Its algorithm body is an explicit synthetic seam, not SQLite acceptance. */
  first = preprocess_substage_enter(8u, 54u);
  edr_local_evidence_cache_record_behavior(NULL);
  assert(atomic_load(&s_worker_callsite) == 54u);
  { int normal = 0, early = 1;
    edr_local_evidence_cache_record_behavior(&normal);
    assert(atomic_load(&s_worker_callsite) == 54u && GetLastError() == 64u && errno == 24);
    edr_local_evidence_cache_record_behavior(&early);
    assert(atomic_load(&s_worker_callsite) == 54u);
    probe_nested_envelopes();
    assert(atomic_load(&s_worker_callsite) == 54u);
    probe_wal_callback();
    assert(atomic_load(&s_worker_callsite) == 54u);
    tid = 8u; SetLastError(51u); errno = 21;
    edr_local_evidence_cache_record_behavior(&normal);
    assert(atomic_load(&s_worker_callsite) == 54u && GetLastError() == 64u && errno == 24);
    probe_nested_envelopes();
    assert(atomic_load(&s_worker_callsite) == 54u);
    probe_wal_callback();
    assert(atomic_load(&s_worker_callsite) == 54u);
    tid = 7u;
  }
  preprocess_substage_leave(first);
  first = preprocess_substage_enter(8u, 45u);
  { int early = 1; edr_local_evidence_cache_record_behavior(&early); }
  assert(atomic_load(&s_worker_callsite) == 45u);
  preprocess_substage_leave(first);
  assert(atomic_load(&s_worker_callsite) == 0u);
  reset(0u); result = preprocess_join_sampled_wait(NULL, &error, &samples); verify(&samples);
  assert(result == WAIT_OBJECT_0 && error == 0u && waits == 1u && samples.samples == 0u && GetLastError() == 73u && errno == 23);
  reset(1u); result = preprocess_join_sampled_wait(NULL, &error, &samples); verify(&samples);
  assert(result == WAIT_TIMEOUT && error == 0u && waits == 6000u && samples.samples == 5999u && samples.capped == 0u && now_ns == UINT64_C(60000000000));
  reset(2u); result = preprocess_join_sampled_wait(NULL, &error, &samples); verify(&samples);
  assert(result == WAIT_FAILED && error == 5u && waits == 1u && samples.samples == 0u && GetLastError() == 5u);
  reset(3u); result = preprocess_join_sampled_wait(NULL, &error, &samples); verify(&samples);
  assert(result == WAIT_TIMEOUT && waits == 1u && samples.samples == 0u); /* No late zero-query, new wait or sample. */
  reset(6u); result = preprocess_join_sampled_wait(NULL, &error, &samples); verify(&samples);
  assert(result == WAIT_TIMEOUT && error == 0u && waits == 1u && samples.samples == 0u && GetLastError() == 73u);
  reset(7u); result = preprocess_join_sampled_wait(NULL, &error, &samples); verify(&samples);
  assert(result == WAIT_TIMEOUT && waits == 1u && samples.samples == 0u); /* Equality is outside the observation window. */
  reset(5u); atomic_store(&s_worker_phase, 99u); atomic_store(&s_worker_callsite, 200u);
  result = preprocess_join_sampled_wait(NULL, &error, &samples); verify(&samples);
  assert(result == WAIT_OBJECT_0 && waits == 2u && samples.samples == 1u && samples.phase_hits[0] == 1u && samples.callsite_hits[0] == 1u);
  reset(5u); atomic_store(&s_worker_phase, 3u); atomic_store(&s_worker_callsite, 134u);
  result = preprocess_join_sampled_wait(NULL, &error, &samples); verify(&samples);
  assert(result == WAIT_OBJECT_0 && samples.samples == 1u && samples.callsite_hits[134] == 1u);
  reset(5u); atomic_store(&s_worker_phase, 3u); atomic_store(&s_worker_callsite, 137u);
  result = preprocess_join_sampled_wait(NULL, &error, &samples); verify(&samples);
  assert(result == WAIT_OBJECT_0 && samples.samples == 1u && samples.callsite_hits[137] == 1u);
  reset(4u); result = preprocess_join_sampled_wait(NULL, &error, &samples); verify(&samples);
  assert(result == WAIT_TIMEOUT && waits == 6001u && samples.samples == 6001u && samples.capped == 1u);
  SetLastError(44u); errno = 29; preprocess_join_samples_print(&samples);
  assert(GetLastError() == 44u && errno == 29);
  preprocess_substage_worker_exit();
  assert(atomic_load(&s_worker_probe_thread_id) == 0u && preprocess_substage_enter(1u, 1u) == UINT64_MAX);
  return 0;
}
'''

CACHE_SHIM_PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
typedef int EdrBehaviorRecord;
typedef struct { int unused; } PreparedContextArtifacts;
#if defined(_WIN32)
#include <windows.h>
#else
extern uint32_t GetLastError(void);
extern void SetLastError(uint32_t error);
#endif
extern unsigned probe_current_site(void);
extern unsigned probe_is_worker(void);
static unsigned called;
static void check(unsigned site);
#if defined(EDR_HAVE_SQLITE)
typedef int sqlite3;
#define SQLITE_OK 0
#define SQLITE_CHECKPOINT_PASSIVE 0
static uint64_t s_evidence_wal_page_size = 4096u;
static unsigned wal_physical_calls, wal_checkpoint_calls, wal_error_calls;
static int wal_physical_result = 1, wal_checkpoint_result;
static int sqlite_physical_write_allow(uint64_t bytes) {
  check(136u); assert(bytes > 0u); ++wal_physical_calls;
  SetLastError(71u); errno=31; return wal_physical_result;
}
static int sqlite3_wal_checkpoint_v2(sqlite3 *db, const char *name, int mode,
                                     int *log, int *checkpointed) {
  (void)db; assert(name && !strcmp(name,"main") && mode == SQLITE_CHECKPOINT_PASSIVE);
  assert(!log && !checkpointed); check(137u); ++wal_checkpoint_calls;
  SetLastError(72u); errno=32; return wal_checkpoint_result;
}
static void set_error(const char *text) {
  assert(text && !strcmp(text,"automatic evidence checkpoint deferred; committed WAL retained"));
  check(135u); ++wal_error_calls; SetLastError(74u); errno=34;
}
static unsigned transaction_calls[7];
static int transaction_int(unsigned site, int result) {
  assert(site >= 128u && site <= 134u); check(site); ++transaction_calls[site-128u];
  SetLastError(68u); errno=28; return result;
}
static void transaction_void(unsigned site) {
  assert(site == 133u); check(site); ++transaction_calls[site-128u];
  SetLastError(68u); errno=28;
}
#endif

static void check(unsigned site) { assert(probe_current_site() == (probe_is_worker() ? site : 54u)); }
static int original_int(void) { check(82u); ++called; SetLastError(62u); errno=22; return -17; }
static uint32_t original_u32(void) { check(85u); ++called; SetLastError(63u); errno=23; return UINT32_C(0xf0000000); }
static void original_void(void) { check(81u); ++called; SetLastError(64u); errno=24; }
'''

# Only algorithm bodies are seams. The signatures, wrapper bytes and bridge
# below are extracted from the real generated manifest, not reimplemented.
NESTED_SHIM_BODIES = {
    'sqlite_size_budget_allow': r'''
  check(126u); ++nested_calls[1]; SetLastError(66u); errno=26;
  return nested_mode ? -29 : 7;
}
''',
    'sqlite_prepare_context_artifacts': r'''
  (void)candidate_ids; (void)candidate_count; (void)prepared;
  check(125u); ++nested_calls[0];
  if (!r) { SetLastError(65u); errno=25; return -17; }
  int result = sqlite_size_budget_allow(); check(125u);
  assert(GetLastError() == 66u && errno == 26);
  return result == 7 ? 0 : -31;
}
''',
    'sqlite_record_context_artifacts': r'''
  check(127u); ++nested_calls[2];
  if (!r) { SetLastError(67u); errno=27; return -37; }
  uint64_t transaction_previous[7];
  for (unsigned site = 128u; site <= 134u; ++site) {
    if (site == 133u) SERVICE_TRANSACTION_VOID(133u, transaction_previous[5], transaction_void(133u));
    else assert(SERVICE_TRANSACTION_INT(site, transaction_previous[site-128u], transaction_int(site, -17)) == -17);
    check(127u); assert(GetLastError() == 68u && errno == 28);
  }
  int result = sqlite_prepare_context_artifacts(r, candidate_ids, 1u,
                                              (PreparedContextArtifacts *)prepared);
  check(127u); assert(GetLastError() == 66u && errno == 26);
  return result == 0 ? 3 : -41;
}
''',
}
NESTED_SHIM_TEST = r'''
void probe_wal_callback(void) {
#if defined(EDR_HAVE_SQLITE)
  wal_physical_calls=wal_checkpoint_calls=wal_error_calls=0u;
  wal_physical_result=1; wal_checkpoint_result=SQLITE_OK;
  SetLastError(81u); errno=41;
  assert(sqlite_guarded_autocheckpoint(NULL,NULL,"main",999) == SQLITE_OK);
  assert(wal_physical_calls == 0u && wal_checkpoint_calls == 0u && wal_error_calls == 0u);
  assert(GetLastError() == 81u && errno == 41); check(54u);
  const uint64_t outer=preprocess_substage_enter(8u,134u);
  assert(sqlite_guarded_autocheckpoint(NULL,NULL,"main",1000) == SQLITE_OK);
  assert(wal_physical_calls == 1u && wal_checkpoint_calls == 1u && wal_error_calls == 0u);
  assert(GetLastError() == 72u && errno == 32); check(134u);
  wal_physical_result=0;
  assert(sqlite_guarded_autocheckpoint(NULL,NULL,"main",1001) == SQLITE_OK);
  assert(wal_physical_calls == 2u && wal_checkpoint_calls == 1u && wal_error_calls == 0u);
  assert(GetLastError() == 71u && errno == 31); check(134u);
  wal_physical_result=1; wal_checkpoint_result=10;
  assert(sqlite_guarded_autocheckpoint(NULL,NULL,"main",1002) == SQLITE_OK);
  assert(wal_physical_calls == 3u && wal_checkpoint_calls == 2u && wal_error_calls == 1u);
  assert(GetLastError() == 74u && errno == 34); check(134u);
  preprocess_substage_leave(outer); check(54u);
#endif
}
void probe_nested_envelopes(void) {
#if defined(EDR_HAVE_SQLITE)
  char ids[1][160] = {{0}}; int record = 0; PreparedContextArtifacts prepared = {0};
  nested_mode = 0; memset(nested_calls, 0, sizeof(nested_calls)); memset(transaction_calls, 0, sizeof(transaction_calls));
  assert(sqlite_record_context_artifacts(&record, ids, &prepared) == 3);
  assert(nested_calls[0] == 1u && nested_calls[1] == 1u && nested_calls[2] == 1u);
  assert(GetLastError() == 66u && errno == 26); check(54u);
  assert(sqlite_prepare_context_artifacts(NULL, ids, 1u, &prepared) == -17);
  assert(GetLastError() == 65u && errno == 25); check(54u);
  nested_mode = 1;
  assert(sqlite_size_budget_allow() == -29);
  assert(GetLastError() == 66u && errno == 26); check(54u);
  assert(sqlite_prepare_context_artifacts(&record, ids, 1u, &prepared) == -31);
  assert(GetLastError() == 66u && errno == 26); check(54u);
  assert(sqlite_record_context_artifacts(NULL, ids, &prepared) == -37);
  assert(GetLastError() == 67u && errno == 27); check(54u);
  assert(sqlite_record_context_artifacts(&record, ids, &prepared) == -41);
  assert(GetLastError() == 66u && errno == 26); check(54u);
  assert(nested_calls[0] == 4u && nested_calls[1] == 4u && nested_calls[2] == 3u);
  for(unsigned i=0u;i<7u;++i) assert(transaction_calls[i] == 2u);
#endif
}
'''
CACHE_SHIM_BODY = r'''
static void service_diag_record_behavior_impl(const EdrBehaviorRecord *r) {
  uint64_t previous[3];
  if (!r) return;
  check(80u);
  if (*r) return;
  assert(SERVICE_CACHE_INT(82u, previous[0], original_int()) == -17);
  assert(GetLastError() == 62u && errno == 22); check(80u);
  assert(SERVICE_CACHE_U32(85u, previous[1], original_u32()) == UINT32_C(0xf0000000));
  assert(GetLastError() == 63u && errno == 23); check(80u);
  SERVICE_CACHE_VOID(81u, previous[2], original_void());
  assert(GetLastError() == 64u && errno == 24); check(80u);
  assert(called == (probe_is_worker() ? 3u : 6u));
}
'''


class ServiceSampling(unittest.TestCase):
    def generate(self, output, source_root=ROOT):
        done = subprocess.run([sys.executable, '-B', str(HERE / 'generate_service_source.py'), str(source_root), str(output)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        receipt = json.loads(done.stdout)
        self.assertEqual((receipt['source_count'], receipt['cache_call_transforms'], receipt['cache_nested_envelopes'], receipt['max_assigned_id'], receipt['callsite_bins']), (2, 44, 3, 137, 138))
        self.assertEqual(receipt['cache_transaction_calls'], 27)
        self.assertEqual((receipt['cache_wal_envelopes'],receipt['cache_wal_calls']),(1,2))
        return [json.loads((output / name).read_bytes()) for name in ('SERVICE-SOURCE-TRANSFORM-v2.json', 'SERVICE-CACHE-SOURCE-TRANSFORM-v2.json')]

    def test_raw_reversal_lf_crlf_and_fixed_callsite_map(self):
        paths = ['src/preprocess/preprocess_pipeline.c', 'src/storage/local_evidence_cache.c']
        originals = [(ROOT / path).read_bytes().replace(b'\r\n', b'\n') for path in paths]
        inventories = []
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            for label, endings in [('lf', (False, False)), ('crlf', (True, True)), ('mixed-owners', (False, True))]:
                source_root, output = work / label, work / (label + '-generated')
                inputs = [raw.replace(b'\n', b'\r\n') if crlf else raw for raw, crlf in zip(originals, endings)]
                for relative, raw in zip(paths, inputs):
                    path = source_root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
                proofs = self.generate(output, source_root)
                pipeline, cache = proofs
                self.assertEqual([c['callsite_id'] for c in pipeline['changes']], list(range(1, 80)))
                self.assertEqual([c['callsite_id'] for c in cache['changes']], list(range(81, 125)))
                self.assertEqual(pipeline['namespace'], cache['namespace'])
                self.assertEqual(pipeline['namespace']['cache_envelope'], 80)
                self.assertEqual(pipeline['namespace']['unassigned_range'], [])
                self.assertEqual(pipeline['namespace']['cache_nested_range'], [125, 127])
                self.assertEqual(pipeline['namespace']['cache_transaction_range'], [128, 134])
                self.assertEqual(pipeline['namespace']['cache_wal_envelope'],135)
                self.assertEqual(pipeline['namespace']['cache_wal_range'],[136,137])
                self.assertEqual([(c['callsite_id'],c['kind']) for c in cache['wal_changes']],[(136,'INT'),(137,'INT')])
                self.assertEqual(pipeline['namespace']['sampling_version'], 4)
                self.assertEqual({site:sum(c['callsite_id']==site for c in cache['transaction_changes']) for site in range(128,135)}, {128:1,129:11,130:10,131:1,132:1,133:2,134:1})
                self.assertEqual([(c['callsite_id'], c['name']) for c in cache['nested_envelopes']], [
                    (125, 'sqlite_prepare_context_artifacts'), (126, 'sqlite_size_budget_allow'),
                    (127, 'sqlite_record_context_artifacts')])
                self.assertEqual(len(pipeline['local_previous_arrays']), 18)
                self.assertEqual({c['old'].split('(')[0] for c in cache['changes'] if c['kind'] == 'U32'}, {'context_window_matches', 'context_before_count'})
                self.assertNotIn('record_time_ns', {c['old'].split('(')[0] for c in cache['changes']})
                case_inventory = []
                for proof, raw, output_name in zip(proofs, inputs, ['pipeline.service.instrumented.c', 'cache.service.instrumented.c']):
                    self.assertTrue(proof['inverse_raw_exact'])
                    self.assertEqual(proof['source_sha256'], hashlib.sha256(raw).hexdigest())
                    self.assertEqual(proof['reversed_sha256'], hashlib.sha256(raw).hexdigest())
                    generated_raw = (output / output_name).read_bytes()
                    self.assertEqual(proof['generated_sha256'], hashlib.sha256(generated_raw).hexdigest())
                    text = raw.decode('utf-8')
                    for call in proof['changes']:
                        self.assertEqual(text[call['start']:call['end']], call['old'])
                    generated = generated_raw.decode('utf-8')
                    delta = proof['positive_cache_proof']
                    self.assertTrue(delta['proof_delta_inverse_raw_exact'])
                    for key in (('remove_bridge','remove_call') if proof is pipeline else ('remove_append',)):
                        self.assertEqual(generated.count(delta[key]), 1)
                        generated = generated.replace(delta[key], '', 1)
                    self.assertEqual(hashlib.sha256(generated.encode()).hexdigest(), delta['pre_proof_generated_sha256'])
                    reversal = proof['raw_reversal']
                    if proof is pipeline:
                        remove = ('remove_timeout_log', 'remove_observer_before', 'remove_observer_after', 'remove_wrapper', 'remove_header', 'remove_worker_entry', 'remove_worker_exit')
                        replacements = [('rename_header_from', 'rename_header_to'), ('wait_generated', 'wait_original'), ('error_generated', 'error_original')]
                        declarations = reversal['remove_local_declarations']
                    else:
                        remove = ('remove_wrapper', 'remove_nested_bridge')
                        replacements = [('generated_header', 'original_header')]
                        declarations = [reversal['remove_local_declaration'], reversal['remove_transaction_declaration'], reversal['remove_wal_declaration']]
                        for call in reversed(proof['wal_changes']):
                            self.assertEqual(text[call['start']:call['end']],call['old'])
                            self.assertEqual(generated.count(call['new']),1)
                            generated=generated.replace(call['new'],call['old'],1)
                        wal=proof['wal_envelope']
                        self.assertEqual(text[wal['start']:wal['header_end']],wal['original_header'])
                        self.assertEqual(generated.count(wal['wrapper']),1)
                        generated=generated.replace(wal['wrapper'],'',1).replace(wal['generated_header'],wal['original_header'],1)
                        for call in reversed(proof['transaction_changes']):
                            self.assertEqual(text[call['start']:call['end']], call['old'])
                            self.assertEqual(generated.count(call['new']), 1)
                            generated = generated.replace(call['new'], call['old'], 1)
                        for envelope in reversal['nested_envelopes']:
                            self.assertEqual(text[envelope['start']:envelope['header_end']], envelope['original_header'])
                            self.assertEqual(text[envelope['end']-1], '}')
                            # The wrapper is inserted in the same original SQLite
                            # conditional branch; no wrapper appears after its endif.
                            self.assertLess(envelope['end'], text.index('\n#endif', text.index('static int sqlite_record_budgeted_context_artifacts')))
                            self.assertEqual(generated.count(envelope['wrapper']), 1)
                            generated = generated.replace(envelope['wrapper'], '', 1)
                            self.assertEqual(generated.count(envelope['generated_header']), 1)
                            generated = generated.replace(envelope['generated_header'], envelope['original_header'], 1)
                    for key in remove:
                        self.assertEqual(generated.count(reversal[key]), 1, key)
                        generated = generated.replace(reversal[key], '', 1)
                    for start, end in replacements:
                        self.assertEqual(generated.count(reversal[start]), 1, start)
                        generated = generated.replace(reversal[start], reversal[end], 1)
                    for declaration in declarations:
                        self.assertGreaterEqual(generated.count(declaration), 1)
                        generated = generated.replace(declaration, '', 1)
                    for call in reversed(proof['changes']):
                        self.assertEqual(generated.count(call['new']), 1)
                        generated = generated.replace(call['new'], call['old'], 1)
                    self.assertEqual(generated.encode('utf-8'), raw)
                    case_inventory.append([(c['callsite_id'], c['owner'], c['line'], c['old'].replace('\r\n', '\n')) for c in proof['changes'] + proof.get('transaction_changes',[]) + proof.get('wal_changes',[])])
                inventories.append(case_inventory)
            self.assertEqual(inventories[0], inventories[1])
            self.assertEqual(inventories[0], inventories[2])

    def cache_shim(self, cache):
        reversal = cache['raw_reversal']
        bridge = reversal['generated_header'].removesuffix('static void service_diag_record_behavior_impl(const EdrBehaviorRecord *r) {')
        nested = ['#if defined(EDR_HAVE_SQLITE)\n', reversal['remove_nested_bridge'],
                  'static unsigned nested_calls[3];\nstatic int nested_mode;\n']
        # Use the actual generated WAL algorithm body. Only its two external
        # effects, set_error and Windows APIs are explicitly stubbed above.
        wal = cache['wal_envelope']
        text = Path(cache['source']).read_bytes().decode('utf-8')
        body = text[wal['header_end']:wal['end']]
        for call in sorted(cache['wal_changes'], key=lambda c:c['start'], reverse=True):
            start,end = call['start']-wal['header_end'],call['end']-wal['header_end']
            self.assertEqual(body[start:end],call['old'])
            body = body[:start]+call['new']+body[end:]
        body = reversal['remove_wal_declaration']+body
        nested += [wal['generated_header'],body,wal['wrapper']]
        for envelope in sorted(cache['nested_envelopes'], key=lambda c: c['start']):
            nested += [envelope['generated_header'], NESTED_SHIM_BODIES[envelope['name']], envelope['wrapper']]
        nested += ['#endif\n', NESTED_SHIM_TEST]
        return CACHE_SHIM_PREFIX + '\n'.join(nested) + bridge + CACHE_SHIM_BODY + reversal['remove_wrapper']

    def test_real_c_helpers_with_explicit_winapi_seams(self):
        clang = shutil.which('clang')
        if not clang:
            self.skipTest('local C compiler unavailable; no Windows claim')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, cache_source, binary = root / 'test.c', root / 'cache.c', root / 'test'
            source.write_text(SHIM)
            _, cache = self.generate(root / 'generated')
            cache_source.write_text(self.cache_shim(cache))
            built = subprocess.run([clang, '-std=c11', '-DEDR_HAVE_SQLITE=1', '-Wall', '-Wextra', '-Werror', '-I', str(HERE), str(source), str(cache_source), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            self.assertEqual(ran.stdout, '')
            match = re.fullmatch(r'\[preprocess\] worker join samples version=4 interval_ms=10 samples=(\d+) capped=([01]) phase_hits=([0-9,]+) callsite_hits=([0-9,]+)\n', ran.stderr)
            self.assertIsNotNone(match, ran.stderr)
            self.assertLess(len(ran.stderr.encode()), 4096)
            count, capped = map(int, match.group(1, 2))
            phases, sites = ([int(x) for x in match.group(i).split(',')] for i in (3, 4))
            self.assertEqual((len(phases), len(sites)), (13, 138))
            self.assertEqual((count, capped), (6001, 1))
            self.assertEqual(sum(phases), count)
            self.assertEqual(sum(sites), count)
            print(ran.stderr, end='')
            # The same generated helper wrappers must disappear with SQLite's
            # original branch; the non-SQL cache envelope still links and runs.
            built = subprocess.run([clang, '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(HERE), str(source), str(cache_source), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stderr)

    def test_single_positive_cache_probe_with_explicit_api_and_getter_seams(self):
        clang = shutil.which('clang')
        if not clang:
            self.skipTest('local C compiler unavailable; no real-cache or Windows claim')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pipeline, cache = self.generate(root / 'generated')
            template = (HERE / 'service_substage_frontier.inc').read_text()
            begin = template.index('static int preprocess_substage_is_worker(void) {')
            end = template.index('\n}\n', begin) + 2
            gate = template[begin:end]
            (root / 'positive.inc').write_text(cache['positive_cache_proof']['remove_append'])
            source = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include "edr/local_evidence_cache.h"
#include "edr/sha256.h"
#define _WIN32 1
typedef uint32_t DWORD;
static DWORD error_value = 73u, thread_id = 8u;
static unsigned getter_calls;
static atomic_uint s_worker_probe_thread_id;
static DWORD GetLastError(void) { return error_value; }
static void SetLastError(DWORD value) { error_value = value; }
static DWORD GetCurrentThreadId(void) { errno = 300; error_value = 301u; return thread_id; }
static DWORD GetCurrentProcessId(void) { errno = 400; error_value = 401u; return 1234u; }
void edr_local_evidence_cache_get_status(EdrEvidenceCacheStatus *out) {
  ++getter_calls; memset(out, 0, sizeof(*out));
  out->db_open = 1; out->storage_format = 1u;
  out->context_facts_written = 8u; out->context_refs_written = 16u;
  out->records_written = 3u; out->retention_clock_valid = 1u;
  strcpy(out->path, "C:\\PublicFixture\\cache.db");
  errno = 600; error_value = 601u;
}
@GATE@
#include "positive.inc"
static void normal_worker_tail(void) {
@CALL@}
int main(void) {
  atomic_store(&s_worker_probe_thread_id, 7u);
  errno = 23; SetLastError(73u);
  normal_worker_tail();
  assert(getter_calls == 0u && errno == 23 && GetLastError() == 73u);
  thread_id = 7u; normal_worker_tail();
  assert(getter_calls == 1u && errno == 23 && GetLastError() == 73u);
  return 0;
}
'''.replace('@GATE@', gate).replace('@CALL@', pipeline['positive_cache_proof']['remove_call'])
            path, binary = root / 'positive.c', root / 'positive'
            path.write_text(source)
            built = subprocess.run([clang, '-std=c11', '-Wall', '-Wextra', '-Werror',
                                    '-I', str(ROOT / 'include'), '-I', str(root),
                                    str(path), str(ROOT / 'src/command/sha256.c'),
                                    '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            self.assertEqual(ran.stdout, '')
            rows = ran.stderr.splitlines()
            self.assertEqual(len(rows), 1)
            prefix = '[preprocess] worker cache proof '
            self.assertTrue(rows[0].startswith(prefix))
            self.assertLess(len(ran.stderr.encode()), 1024)
            value = json.loads(rows[0][len(prefix):])
            self.assertEqual(set(value), {'schema','version','pid','tid','status_getter_calls',
                'db_open','storage_format','path_hash_valid','cache_path_sha256',
                'context_facts_written','context_refs_written','candidate_records_written',
                'retention_clock_valid','pipeline_source_sha256','cache_source_sha256'})
            self.assertEqual(value['schema'], 'edr.test.service-cache-positive-proof.v1')
            self.assertEqual((value['version'], value['pid'], value['tid'], value['status_getter_calls']), (1,1234,7,1))
            self.assertEqual((value['db_open'],value['storage_format'],value['path_hash_valid'],value['retention_clock_valid']), (1,1,1,1))
            self.assertEqual((value['context_facts_written'],value['context_refs_written'],value['candidate_records_written']), (8,16,3))
            self.assertEqual(value['cache_path_sha256'], hashlib.sha256(b'C:\\PublicFixture\\cache.db').hexdigest())
            self.assertEqual(value['pipeline_source_sha256'], pipeline['source_sha256'])
            self.assertEqual(value['cache_source_sha256'], cache['source_sha256'])
            self.assertNotIn('PublicFixture', ran.stderr)

    def test_existing_mingw_headers_syntax_only(self):
        compiler = shutil.which('x86_64-w64-mingw32-gcc')
        if not compiler:
            self.skipTest('existing MinGW unavailable; no native/MSVC SDK claim')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'syntax.c'
            path.write_text('#include <windows.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <stdatomic.h>\nstatic atomic_uint s_worker_phase;\nstatic uint64_t edr_monotonic_ns(void){return 1;}\n#include "service_substage_frontier.inc"\nint main(void){PreprocessJoinSamples s;DWORD e;preprocess_substage_worker_enter();uint64_t p=preprocess_substage_enter(8,79);preprocess_substage_int_leave(p,0);preprocess_substage_clear();preprocess_join_sampled_wait(0,&e,&s);preprocess_join_samples_print(&s);preprocess_substage_worker_exit();return 0;}\n')
            ran = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsyntax-only', '-I', str(HERE), str(path)], capture_output=True, text=True)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            _, cache = self.generate(Path(temporary) / 'generated')
            cache_path = Path(temporary) / 'cache.c'
            cache_path.write_text(self.cache_shim(cache))
            for definitions in ([], ['-DEDR_HAVE_SQLITE=1']):
                ran = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsyntax-only', *definitions, str(cache_path)], capture_output=True, text=True)
                self.assertEqual(ran.returncode, 0, ran.stderr)


if __name__ == '__main__':
    unittest.main()
