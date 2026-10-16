/* Isolate storage in encoder/admission unit tests. The real SQLite resolver
 * is exercised by test_command_fact_transport, not replaced in that test. */
#include "edr/local_evidence_cache.h"
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>

static const char *s_test_subject_fact;
static int s_test_resolve_calls;
static int s_test_fail_after = -1;
static atomic_int s_test_alert_context_calls;
static atomic_int s_test_alert_context_outcome;
void edr_test_set_stub_alert_context_outcome(int outcome) {
  atomic_store(&s_test_alert_context_calls, 0);
  atomic_store(&s_test_alert_context_outcome, outcome);
}
int edr_test_stub_alert_context_count(void) {
  return atomic_load(&s_test_alert_context_calls);
}
int edr_local_evidence_cache_record_alert_context(const EdrBehaviorRecord *record,
                                                  const EdrCommandFacts *facts) {
  (void)record; (void)facts;
  atomic_fetch_add(&s_test_alert_context_calls, 1);
  return atomic_load(&s_test_alert_context_outcome);
}
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
