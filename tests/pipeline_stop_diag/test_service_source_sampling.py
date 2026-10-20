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
  for (unsigned i = 0u; i < 128u; ++i) { assert(s->callsite_hits[i] <= 6001u); sites += s->callsite_hits[i]; }
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
    tid = 8u; SetLastError(51u); errno = 21;
    edr_local_evidence_cache_record_behavior(&normal);
    assert(atomic_load(&s_worker_callsite) == 54u && GetLastError() == 64u && errno == 24);
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
typedef int EdrBehaviorRecord;
extern uint32_t GetLastError(void);
extern void SetLastError(uint32_t error);
extern unsigned probe_current_site(void);
extern unsigned probe_is_worker(void);
static unsigned called;
static void check(unsigned site) { assert(probe_current_site() == (probe_is_worker() ? site : 54u)); }
static int original_int(void) { check(82u); ++called; SetLastError(62u); errno=22; return -17; }
static uint32_t original_u32(void) { check(85u); ++called; SetLastError(63u); errno=23; return UINT32_C(0xf0000000); }
static void original_void(void) { check(81u); ++called; SetLastError(64u); errno=24; }
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
        self.assertEqual((receipt['source_count'], receipt['cache_call_transforms'], receipt['max_assigned_id'], receipt['callsite_bins']), (2, 44, 124, 128))
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
                self.assertEqual(pipeline['namespace']['unassigned_range'], [125, 127])
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
                    reversal = proof['raw_reversal']
                    if proof is pipeline:
                        remove = ('remove_timeout_log', 'remove_observer_before', 'remove_observer_after', 'remove_wrapper', 'remove_header', 'remove_worker_entry', 'remove_worker_exit')
                        replacements = [('rename_header_from', 'rename_header_to'), ('wait_generated', 'wait_original'), ('error_generated', 'error_original')]
                        declarations = reversal['remove_local_declarations']
                    else:
                        remove = ('remove_wrapper',)
                        replacements = [('generated_header', 'original_header')]
                        declarations = [reversal['remove_local_declaration']]
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
                    case_inventory.append([(c['callsite_id'], c['owner'], c['line'], c['old'].replace('\r\n', '\n')) for c in proof['changes']])
                inventories.append(case_inventory)
            self.assertEqual(inventories[0], inventories[1])
            self.assertEqual(inventories[0], inventories[2])

    def test_real_c_helpers_with_explicit_winapi_seams(self):
        clang = shutil.which('clang')
        if not clang:
            self.skipTest('local C compiler unavailable; no Windows claim')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, cache_source, binary = root / 'test.c', root / 'cache.c', root / 'test'
            source.write_text(SHIM)
            _, cache = self.generate(root / 'generated')
            reversal = cache['raw_reversal']
            bridge = reversal['generated_header'].removesuffix('static void service_diag_record_behavior_impl(const EdrBehaviorRecord *r) {')
            cache_source.write_text(CACHE_SHIM_PREFIX + bridge + CACHE_SHIM_BODY + reversal['remove_wrapper'])
            built = subprocess.run([clang, '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(HERE), str(source), str(cache_source), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            self.assertEqual(ran.stdout, '')
            match = re.fullmatch(r'\[preprocess\] worker join samples version=2 interval_ms=10 samples=(\d+) capped=([01]) phase_hits=([0-9,]+) callsite_hits=([0-9,]+)\n', ran.stderr)
            self.assertIsNotNone(match, ran.stderr)
            self.assertLess(len(ran.stderr.encode()), 4096)
            count, capped = map(int, match.group(1, 2))
            phases, sites = ([int(x) for x in match.group(i).split(',')] for i in (3, 4))
            self.assertEqual((len(phases), len(sites)), (13, 128))
            self.assertEqual((count, capped), (6001, 1))
            self.assertEqual(sum(phases), count)
            self.assertEqual(sum(sites), count)
            print(ran.stderr, end='')

    def test_existing_mingw_headers_syntax_only(self):
        compiler = shutil.which('x86_64-w64-mingw32-gcc')
        if not compiler:
            self.skipTest('existing MinGW unavailable; no native/MSVC SDK claim')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'syntax.c'
            path.write_text('#include <windows.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <stdatomic.h>\nstatic atomic_uint s_worker_phase;\nstatic uint64_t edr_monotonic_ns(void){return 1;}\n#include "service_substage_frontier.inc"\nint main(void){PreprocessJoinSamples s;DWORD e;preprocess_substage_worker_enter();uint64_t p=preprocess_substage_enter(8,79);preprocess_substage_int_leave(p,0);preprocess_substage_clear();preprocess_join_sampled_wait(0,&e,&s);preprocess_join_samples_print(&s);preprocess_substage_worker_exit();return 0;}\n')
            ran = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsyntax-only', '-I', str(HERE), str(path)], capture_output=True, text=True)
            self.assertEqual(ran.returncode, 0, ran.stderr)


if __name__ == '__main__':
    unittest.main()
