#include "core/storage_space_preflight.h"
#ifdef _WIN32
/* Config loading has no socket listener in this CLI client. */
void edr_win_listen_apply_config(const EdrConfig *cfg) { (void)cfg; }
#ifdef EDR_COMMAND_STATE_INVENTORY_TEST
/* Only this test executable can observe a real failed lock or control time.
 * The production Agent has no test environment or event handling. */
static HANDLE test_observed, test_sleeping, test_resume;
static unsigned test_attempts, test_conflicts, test_sleeps;
static int test_deadline, test_attempt_cap;
static ULONGLONG test_ticks;

static HANDLE test_open_event(const char *prefix, const char *suffix) {
  char name[160];
  int n = snprintf(name, sizeof(name), "%s-%s", prefix, suffix);
  if (n < 0 || (size_t)n >= sizeof(name)) abort();
  HANDLE event = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, name);
  if (!event) abort();
  return event;
}

static void test_inventory_initialize(void) {
  const char *mode = getenv("EDR_PREFLIGHT_TEST_MODE");
  if (!mode) return;
  if (strcmp(mode, "observe") && strcmp(mode, "deadline") && strcmp(mode, "attempt_cap")) abort();
  const char *prefix = getenv("EDR_PREFLIGHT_TEST_EVENT_PREFIX");
  if (!prefix || strncmp(prefix, "Local\\EDRInventory-", 19) || strlen(prefix) > 96u) abort();
  test_deadline = !strcmp(mode, "deadline");
  test_attempt_cap = !strcmp(mode, "attempt_cap");
  test_observed = test_open_event(prefix, "observed");
  test_sleeping = test_open_event(prefix, "sleeping");
  test_resume = test_open_event(prefix, "resume");
}

ULONGLONG edr_command_state_inventory_test_now(void) {
  return test_deadline || test_attempt_cap ? test_ticks : GetTickCount64();
}

void edr_command_state_inventory_test_sleep(DWORD ms) {
  if (test_observed) test_sleeps++;
  if (test_attempt_cap) return;
  if (!test_deadline) { Sleep(ms); return; }
  if (test_sleeps != 1u || ms == 0u || ms > 25u) abort();
  test_ticks += 1000u;
  if (!SetEvent(test_sleeping) || WaitForSingleObject(test_resume, 5000u) != WAIT_OBJECT_0) abort();
}

void edr_command_state_inventory_test_observe(DWORD error) {
  if (!test_observed) return;
  test_attempts++;
  if (error == ERROR_LOCK_VIOLATION) {
    test_conflicts++;
    if (!SetEvent(test_observed)) abort();
  }
}

static int test_inventory_finish(int rc) {
  if (!test_observed) return rc;
  fprintf(stderr, "inventory_test attempts=%u conflicts=%u sleeps=%u mode=%s\n",
          test_attempts, test_conflicts, test_sleeps,
          test_deadline ? "deadline" : (test_attempt_cap ? "attempt_cap" : "observe"));
  if (!CloseHandle(test_observed) || !CloseHandle(test_sleeping) || !CloseHandle(test_resume)) abort();
  if (test_deadline && (test_attempts != 1u || test_conflicts != 1u || test_sleeps != 1u)) return 90;
  if (test_attempt_cap && (test_attempts != 41u || test_conflicts != 41u || test_sleeps != 40u)) return 90;
  return rc;
}
#endif
#endif
/* Query-copy storage is unrelated to preflight. Any accidental write is a
 * hard failure; the production command owner parser/lock are linked below. */
int edr_local_evidence_cache_record_command_result(const char *a, const char *b,
    const char *c, int d, int e, const char *f, const char *g) {
  (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g;
  abort();
}
int main(int argc, char **argv) {
  if (argc < 2 || strcmp(argv[1], "--storage-space-preflight")) return 2;
#if defined(_WIN32) && defined(EDR_COMMAND_STATE_INVENTORY_TEST)
  test_inventory_initialize();
  return test_inventory_finish(edr_storage_space_preflight_main(argc, argv));
#else
  return edr_storage_space_preflight_main(argc, argv);
#endif
}
