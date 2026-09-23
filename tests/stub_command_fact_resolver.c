/* Isolate storage in encoder/admission unit tests. The real SQLite resolver
 * is exercised by test_command_fact_transport, not replaced in that test. */
#include "edr/local_evidence_cache.h"
void edr_local_evidence_cache_resolve_commands(const EdrBehaviorRecord *record,
                                               char **subject, char **parent) {
  (void)record;
  *subject = NULL;
  *parent = NULL;
}
