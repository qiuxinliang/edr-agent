/* Isolate storage in encoder/admission unit tests. The real SQLite resolver
 * is exercised by test_command_fact_transport, not replaced in that test. */
#include "edr/local_evidence_cache.h"
#include <stdlib.h>
#include <string.h>

static const char *s_test_subject_fact;
static int s_test_resolve_calls;
static int s_test_fail_after = -1;
void edr_test_set_stub_command_fact(const char *subject) {
  s_test_subject_fact = subject;
}
void edr_test_set_stub_command_fact_fail_after(int successful_calls) {
  s_test_fail_after = successful_calls;
  s_test_resolve_calls = 0;
}
int edr_test_stub_command_fact_resolve_count(void) {
  return s_test_resolve_calls;
}
void edr_local_evidence_cache_resolve_commands(const EdrBehaviorRecord *record,
                                               char **subject, char **parent) {
  (void)record;
  ++s_test_resolve_calls;
  *subject = NULL;
  if (s_test_subject_fact &&
      (s_test_fail_after < 0 || s_test_resolve_calls <= s_test_fail_after)) {
    size_t length = strlen(s_test_subject_fact) + 1u;
    *subject = malloc(length);
    if (*subject) memcpy(*subject, s_test_subject_fact, length);
  }
  *parent = NULL;
}
