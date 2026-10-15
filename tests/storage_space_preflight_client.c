#include "core/storage_space_preflight.h"
#ifdef _WIN32
/* Config loading has no socket listener in this CLI client. */
void edr_win_listen_apply_config(const EdrConfig *cfg) { (void)cfg; }
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
  return edr_storage_space_preflight_main(argc, argv);
}
