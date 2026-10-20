/* Diagnostic target only. The preprocess thread alone publishes frontiers;
 * GetCurrentThreadId is used only for that writer gate, preserving LastError
 * and errno. No event clock, allocation, lock, thread or per-event output.
 * The existing stop caller samples independent relaxed loads, not a stack. */
#include <errno.h>
typedef enum {
  PREPROCESS_SUBSTAGE_UNKNOWN = 0,
  PREPROCESS_SUBSTAGE_DECODE = 1,
  PREPROCESS_SUBSTAGE_GENERATION = 2,
  PREPROCESS_SUBSTAGE_TOKEN = 3,
  PREPROCESS_SUBSTAGE_CACHE = 4,
  PREPROCESS_SUBSTAGE_EVIDENCE = 5,
  PREPROCESS_SUBSTAGE_P0 = 6,
  PREPROCESS_SUBSTAGE_CORRELATION = 7,
  PREPROCESS_SUBSTAGE_RECORD = 8
} PreprocessWorkerSubstage;
static atomic_uint s_worker_substage;
static atomic_uint s_worker_callsite;
#ifdef _WIN32
static atomic_uint s_worker_probe_thread_id;
static int preprocess_substage_is_worker(void) {
  const int saved_errno = errno;
  const DWORD saved_error = GetLastError();
  const DWORD current = GetCurrentThreadId();
  const unsigned owner = atomic_load_explicit(&s_worker_probe_thread_id, memory_order_relaxed);
  SetLastError(saved_error); errno = saved_errno;
  return owner != 0u && current == owner;
}
static void preprocess_substage_worker_enter(void) {
  const int saved_errno = errno;
  const DWORD saved_error = GetLastError();
  atomic_store_explicit(&s_worker_probe_thread_id, GetCurrentThreadId(), memory_order_relaxed);
  atomic_store_explicit(&s_worker_substage, 0u, memory_order_relaxed);
  atomic_store_explicit(&s_worker_callsite, 0u, memory_order_relaxed);
  SetLastError(saved_error); errno = saved_errno;
}
#else
static int preprocess_substage_is_worker(void) { return 0; }
#endif
static void preprocess_substage_clear(void) {
  if (!preprocess_substage_is_worker()) return;
  atomic_store_explicit(&s_worker_substage, 0u, memory_order_relaxed);
  atomic_store_explicit(&s_worker_callsite, 0u, memory_order_relaxed);
}
#ifdef _WIN32
static void preprocess_substage_worker_exit(void) {
  if (!preprocess_substage_is_worker()) return;
  preprocess_substage_clear();
  atomic_store_explicit(&s_worker_probe_thread_id, 0u, memory_order_relaxed);
}
#endif
uint64_t preprocess_substage_enter(unsigned substage, unsigned callsite) {
  uint64_t previous;
  if (!preprocess_substage_is_worker()) return UINT64_MAX;
  previous = ((uint64_t)atomic_load_explicit(&s_worker_substage, memory_order_relaxed) << 32) |
      atomic_load_explicit(&s_worker_callsite, memory_order_relaxed);
  atomic_store_explicit(&s_worker_substage, substage, memory_order_relaxed);
  atomic_store_explicit(&s_worker_callsite, callsite, memory_order_relaxed);
  return previous;
}
void preprocess_substage_leave(uint64_t previous) {
  if (previous == UINT64_MAX || !preprocess_substage_is_worker()) return;
  atomic_store_explicit(&s_worker_substage, (unsigned)(previous >> 32), memory_order_relaxed);
  atomic_store_explicit(&s_worker_callsite, (unsigned)previous, memory_order_relaxed);
}
static int preprocess_substage_int_leave(uint64_t previous, int result) {
  preprocess_substage_leave(previous);
  return result;
}
#define PREPROCESS_SUBSTAGE_VOID(stage, site, previous, call) \
  ((previous) = preprocess_substage_enter(stage, site), (call), preprocess_substage_leave(previous))
#define PREPROCESS_SUBSTAGE_INT(stage, site, previous, call) \
  ((previous) = preprocess_substage_enter(stage, site), preprocess_substage_int_leave((previous), (call)))

#ifdef _WIN32
#define PREPROCESS_JOIN_SAMPLE_CAP 6001u
#define PREPROCESS_JOIN_PHASE_BINS 13u
#define PREPROCESS_JOIN_CALLSITE_BINS 128u
typedef struct {
  unsigned samples, capped;
  unsigned phase_hits[PREPROCESS_JOIN_PHASE_BINS];
  unsigned callsite_hits[PREPROCESS_JOIN_CALLSITE_BINS];
} PreprocessJoinSamples;
static DWORD preprocess_join_sampled_wait(HANDLE thread, DWORD *wait_error,
                                          PreprocessJoinSamples *samples) {
  const int saved_errno = errno;
  const DWORD saved_error = GetLastError();
  const uint64_t deadline = edr_monotonic_ns() + UINT64_C(60000000000);
  DWORD result = WAIT_TIMEOUT;
  *wait_error = 0u;
  memset(samples, 0, sizeof(*samples));
  while (samples->samples < PREPROCESS_JOIN_SAMPLE_CAP) {
    const uint64_t now = edr_monotonic_ns();
    uint64_t milliseconds;
    unsigned phase, site;
    if (now >= deadline) break;
    milliseconds = (deadline - now + UINT64_C(999999)) / UINT64_C(1000000);
    if (milliseconds > 10u) milliseconds = 10u;
    result = WaitForSingleObject(thread, (DWORD)milliseconds);
    if (result == WAIT_FAILED) { *wait_error = GetLastError(); break; }
    if (edr_monotonic_ns() >= deadline) { result = WAIT_TIMEOUT; break; }
    if (result != WAIT_TIMEOUT) break;
    phase = atomic_load_explicit(&s_worker_phase, memory_order_relaxed);
    site = atomic_load_explicit(&s_worker_callsite, memory_order_relaxed);
    samples->phase_hits[phase < PREPROCESS_JOIN_PHASE_BINS ? phase : 0u]++;
    samples->callsite_hits[site < PREPROCESS_JOIN_CALLSITE_BINS ? site : 0u]++;
    samples->samples++;
    if (samples->samples == PREPROCESS_JOIN_SAMPLE_CAP) samples->capped = 1u;
  }
  /* Observer deadline: late scheduling can conservatively reject an earlier exit.
   * No final zero-wait and no frontier sample at or after the deadline. */
  SetLastError(result == WAIT_FAILED ? *wait_error : saved_error);
  errno = saved_errno;
  return result;
}
static void preprocess_join_samples_print(const PreprocessJoinSamples *samples) {
  char line[4096];
  size_t used;
  int n, saved_errno = errno;
  DWORD saved_error = GetLastError();
  n = snprintf(line, sizeof(line), "[preprocess] worker join samples version=2 interval_ms=10 samples=%u capped=%u phase_hits=",
               samples->samples, samples->capped);
  if (n < 0 || (size_t)n >= sizeof(line)) goto done;
  used = (size_t)n;
  for (unsigned i = 0u; i < PREPROCESS_JOIN_PHASE_BINS; ++i) {
    n = snprintf(line + used, sizeof(line) - used, "%s%u", i ? "," : "", samples->phase_hits[i]);
    if (n < 0 || (size_t)n >= sizeof(line) - used) goto done;
    used += (size_t)n;
  }
  n = snprintf(line + used, sizeof(line) - used, " callsite_hits=");
  if (n < 0 || (size_t)n >= sizeof(line) - used) goto done;
  used += (size_t)n;
  for (unsigned i = 0u; i < PREPROCESS_JOIN_CALLSITE_BINS; ++i) {
    n = snprintf(line + used, sizeof(line) - used, "%s%u", i ? "," : "", samples->callsite_hits[i]);
    if (n < 0 || (size_t)n >= sizeof(line) - used) goto done;
    used += (size_t)n;
  }
  if (used + 1u >= sizeof(line)) goto done;
  line[used++] = '\n'; line[used] = '\0';
  fputs(line, stderr); fflush(stderr);
done:
  SetLastError(saved_error); errno = saved_errno;
}
#endif
