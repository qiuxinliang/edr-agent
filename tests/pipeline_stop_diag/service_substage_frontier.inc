
/* Numeric diagnostic frontier only. The preprocess worker is the sole writer;
 * the stop observer performs independent relaxed reads, never a stack snapshot.
 * No clock, allocation, lock, OS query or per-event output belongs here. */
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

static unsigned preprocess_substage_enter(unsigned substage) {
  return atomic_exchange_explicit(&s_worker_substage, substage, memory_order_relaxed);
}
static void preprocess_substage_leave(unsigned previous) {
  atomic_store_explicit(&s_worker_substage, previous, memory_order_relaxed);
}
static int preprocess_substage_int_leave(unsigned previous, int result) {
  preprocess_substage_leave(previous);
  return result;
}
#define PREPROCESS_SUBSTAGE_VOID(stage, previous, call) \
  ((previous) = preprocess_substage_enter(stage), (call), preprocess_substage_leave(previous))
#define PREPROCESS_SUBSTAGE_INT(stage, previous, call) \
  ((previous) = preprocess_substage_enter(stage), preprocess_substage_int_leave((previous), (call)))
