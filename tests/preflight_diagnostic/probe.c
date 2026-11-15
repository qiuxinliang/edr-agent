/* Standalone test only. Never link into Agent or installer. */
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "evidence_context_store.h"
#ifdef DIAG_TRACE
#include "trace_runtime.h"
#endif
#include "frozen-context.c"
#ifdef DIAG_TRACE
static int diag_format(EdrContextStore *s, sqlite3 *db) {
  int rc=edr_context_store_check_format(s,db);
  if (rc) diag_capture("logical_rejection","edr_context_store_check_format",rc,db,NULL);
  return rc;
}
static int diag_schema(EdrContextStore *s, uint64_t pages, uint64_t size, uint64_t *required) {
  int rc=edr_context_store_retirement_schema_pages(s,pages,size,required);
  if (rc) diag_capture("logical_rejection","edr_context_store_retirement_schema_pages",rc,s->db,NULL);
  return rc;
}
#define edr_context_store_check_format diag_format
#define edr_context_store_retirement_schema_pages diag_schema
#include "evidence_cache_migration.traced.c"
#undef edr_context_store_check_format
#undef edr_context_store_retirement_schema_pages
#undef sqlite3_open_v2
#undef sqlite3_open
#undef sqlite3_prepare_v2
#undef sqlite3_step
#undef sqlite3_exec
#undef sqlite3_busy_timeout
#undef sqlite3_progress_handler
#else
#include "frozen-migration.c"
#endif

int main(int argc, char **argv) {
  if (argc != 3) return 64;
  char *end=NULL;
  unsigned long budget=strtoul(argv[2],&end,10);
  if (!argv[2][0] || !end || *end || budget>UINT32_MAX) return 64;
  uint64_t start=migration_clock_ms();
  int rc=edr_local_evidence_cache_startup_preflight(argv[1],(uint32_t)budget);
  uint64_t elapsed=migration_clock_ms()-start;
#ifdef DIAG_TRACE
  if (rc && !diag_first.kind) diag_capture("logical_rejection","preflight",rc,NULL,NULL);
  diag_print(rc,elapsed);
#else
  printf("{\"result\":%d,\"elapsed_ms\":%llu,\"sqlite_version\":\"%s\"}\n",rc,(unsigned long long)elapsed,sqlite3_libversion());
#endif
  return 0;
}
