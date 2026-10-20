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
static DWORD GetLastError(void) { return last_error; }
static void SetLastError(DWORD value) { last_error = value; }
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
  for (unsigned i = 0u; i < 80u; ++i) { assert(s->callsite_hits[i] <= 6001u); sites += s->callsite_hits[i]; }
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
  reset(5u); atomic_store(&s_worker_phase, 99u); atomic_store(&s_worker_callsite, 99u);
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


class ServiceSampling(unittest.TestCase):
    def test_raw_reversal_lf_crlf_and_fixed_callsite_map(self):
        original = (ROOT / 'src/preprocess/preprocess_pipeline.c').read_bytes()
        lf = original.replace(b'\r\n', b'\n')
        inventories = []
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            for label, raw in [('lf', lf), ('crlf', lf.replace(b'\n', b'\r\n'))]:
                source_root, output = work / label, work / (label + '-generated')
                path = source_root / 'src/preprocess/preprocess_pipeline.c'
                path.parent.mkdir(parents=True)
                path.write_bytes(raw)
                done = subprocess.run([sys.executable, '-B', str(HERE / 'generate_service_source.py'), str(source_root), str(output)], capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stderr)
                proof = json.loads((output / 'SERVICE-SOURCE-TRANSFORM-v1.json').read_bytes())
                self.assertTrue(proof['inverse_raw_exact'])
                self.assertEqual(proof['source_sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(proof['reversed_sha256'], hashlib.sha256(raw).hexdigest())
                calls = proof['changes']
                self.assertEqual([call['callsite_id'] for call in calls], list(range(1, 80)))
                self.assertEqual(len(proof['local_previous_arrays']), 18)
                text = raw.decode('utf-8')
                for call in calls:
                    self.assertEqual(text[call['start']:call['end']], call['old'])
                generated = (output / 'pipeline.service.instrumented.c').read_bytes().decode('utf-8')
                reversal = proof['raw_reversal']
                for key in ('remove_timeout_log', 'remove_observer_before', 'remove_observer_after', 'remove_wrapper', 'remove_header', 'remove_worker_entry', 'remove_worker_exit'):
                    self.assertEqual(generated.count(reversal[key]), 1, key)
                    generated = generated.replace(reversal[key], '', 1)
                for start, end in [('rename_header_from', 'rename_header_to'), ('wait_generated', 'wait_original'), ('error_generated', 'error_original')]:
                    self.assertEqual(generated.count(reversal[start]), 1, start)
                    generated = generated.replace(reversal[start], reversal[end], 1)
                for declaration in reversal['remove_local_declarations']:
                    generated = generated.replace(declaration, '', 1)
                for call in reversed(calls):
                    self.assertEqual(generated.count(call['new']), 1)
                    generated = generated.replace(call['new'], call['old'], 1)
                self.assertEqual(generated.encode('utf-8'), raw)
                inventories.append([(call['callsite_id'], call['owner'], call['line'], call['old'].replace('\r\n', '\n')) for call in calls])
            self.assertEqual(inventories[0], inventories[1])

    def test_real_c_helpers_with_explicit_winapi_seams(self):
        clang = shutil.which('clang')
        if not clang:
            self.skipTest('local C compiler unavailable; no Windows claim')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, binary = root / 'test.c', root / 'test'
            source.write_text(SHIM)
            built = subprocess.run([clang, '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(HERE), str(source), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            self.assertEqual(ran.stdout, '')
            match = re.fullmatch(r'\[preprocess\] worker join samples version=1 interval_ms=10 samples=(\d+) capped=([01]) phase_hits=([0-9,]+) callsite_hits=([0-9,]+)\n', ran.stderr)
            self.assertIsNotNone(match, ran.stderr)
            self.assertLess(len(ran.stderr.encode()), 4096)
            count, capped = map(int, match.group(1, 2))
            phases, sites = ([int(x) for x in match.group(i).split(',')] for i in (3, 4))
            self.assertEqual((len(phases), len(sites)), (13, 80))
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
