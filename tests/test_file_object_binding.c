#include "edr/file_object_binding.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void edr_test_file_object_binding_contract(void);

static void test_unrelated_eviction(size_t count, uint64_t close_at) {
  EdrFileObjectBinding *entries = calloc(count, sizeof(*entries));
  EdrFileObjectHistory history = {0};
  assert(entries);
  edr_file_object_binding_close(entries, count, &history, 11, close_at);
  edr_file_object_binding_open(entries, count, &history, 22, 200, "C:\\Fixture\\target.txt");
  for (size_t i = 2; i < count; ++i)
    edr_file_object_binding_open(entries, count, &history, 100 + i, 500 + i,
                                "C:\\Fixture\\other.txt");
  assert(edr_file_object_binding_resolve(entries, count, &history, 22, 10000));
  edr_file_object_binding_open(entries, count, &history, 99999, 9000, "C:\\Fixture\\new.txt");
  assert(entries[1].object == 22 && entries[1].opened_at == 200 && !entries[1].closed_at);
  /* Eviction affected object11, not the still-open resident object22. */
  assert(edr_file_object_binding_resolve(entries, count, &history, 22, 10000));
  /* A delayed boundary must still retire that resident, even below the
   * admission watermark left by unrelated traffic. */
  edr_file_object_binding_close(entries, count, &history, 22, 300);
  assert(!edr_file_object_binding_resolve(entries, count, &history, 22, 10000));
  free(entries);
}

static void test_new_generation_does_not_evict_its_own_boundary(void) {
  EdrFileObjectBinding entries[2] = {{0}};
  EdrFileObjectHistory history = {0};
  edr_file_object_binding_open(entries, 2, &history, 11, 100, "old");
  edr_file_object_binding_open(entries, 2, &history, 22, 200, "other");
  assert(history.next == 0 && entries[0].object == 11);
  edr_file_object_binding_open(entries, 2, &history, 11, 300, "new");
  const char *path = edr_file_object_binding_resolve(entries, 2, &history, 11, 350);
  assert(path && strcmp(path, "new") == 0);
  assert(history.discarded_through == 100 && history.discarded_through < 300);
  /* Delayed old metadata cannot replace the accepted new generation. */
  edr_file_object_binding_open(entries, 2, &history, 11, 100, "old");
  path = edr_file_object_binding_resolve(entries, 2, &history, 11, 350);
  assert(path && strcmp(path, "new") == 0);
  assert(!edr_file_object_binding_resolve(entries, 2, &history, 11, 150));
}

static void test_scoped_history_and_diagnostics(void) {
  EdrFileObjectBinding entries[4] = {{0}};
  EdrFileObjectHistory history = {0};
  EdrFileObjectResolution detail;
  edr_file_object_binding_close(entries, 4, &history, 11, 400);
  edr_file_object_binding_open(entries, 4, &history, 22, 200, "target");
  edr_file_object_binding_open(entries, 4, &history, 33, 500, "other");
  edr_file_object_binding_open(entries, 4, &history, 44, 600, "other");
  edr_file_object_binding_open(entries, 4, &history, 55, 700, "other");
  assert(history.evictions == 1 && history.last_evicted_object == 11);
  assert(history.last_evicted_at == 400 && history.discarded_through == 400);
  /* Duplicate resident Create does not revoke its already proven path. */
  edr_file_object_binding_open(entries, 4, &history, 22, 200, "target");
  assert(edr_file_object_binding_resolve_detail(entries, 4, &history, 22, 800, &detail));
  assert(detail.status == EDR_FILE_OBJECT_RESOLVED && detail.opened_at == 200);
  /* A delayed NEW generation below the floor cannot leave the older path live. */
  edr_file_object_binding_open(entries, 4, &history, 22, 300, "reuse");
  assert(!edr_file_object_binding_resolve_detail(entries, 4, &history, 22, 800, &detail));
  assert(detail.status == EDR_FILE_OBJECT_HISTORY_DISCARDED);
  edr_file_object_binding_open(entries, 4, &history, 22, 200, "target");
  assert(!edr_file_object_binding_resolve(entries, 4, &history, 22, 800));

  edr_file_object_binding_open(entries, 4, &history, 22, 900, "fresh");
  edr_file_object_binding_close(entries, 4, &history, 22, 300);
  assert(edr_file_object_binding_resolve(entries, 4, &history, 22, 950));
  /* Unknown identity is still global, and a duplicate cannot undo it. */
  edr_file_object_binding_unknown_boundary(entries, 4, &history, 1000);
  edr_file_object_binding_open(entries, 4, &history, 22, 900, "fresh");
  assert(!edr_file_object_binding_resolve_detail(entries, 4, &history, 22, 1100, &detail));
  assert(detail.status == EDR_FILE_OBJECT_UNKNOWN_BOUNDARY);
  assert(strcmp(edr_file_object_resolution_name(detail.status), "unidentified_boundary") == 0);
  edr_file_object_binding_open(entries, 4, &history, 22, 1200, "new_epoch_fact");
  assert(edr_file_object_binding_resolve(entries, 4, &history, 22, 1250));
  edr_file_object_binding_close(entries, 4, &history, 22, 1300);
  assert(!edr_file_object_binding_resolve_detail(entries, 4, &history, 22, 1300, &detail));
  assert(detail.status == EDR_FILE_OBJECT_CLOSED && detail.closed_at == 1300);
  assert(!edr_file_object_binding_resolve_detail(entries, 4, &history, 999, 1300, &detail));
  assert(detail.status == EDR_FILE_OBJECT_MISSING && !detail.opened_at);
}

/* Compare pressure against the same observed history without eviction. A
 * bounded cache may withhold evidence, but must never invent a usable path
 * or resurrect another lifetime. Exhaust all 720 arrival orders at 2/4 slots. */
static void check_arrival_order(const unsigned *order, size_t capacity) {
  EdrFileObjectBinding bounded[4] = {{0}}, retained[16] = {{0}};
  EdrFileObjectHistory small = {0}, full = {0};
  static const uint64_t objects[] = {11,11,11,11,22,22};
  static const uint64_t times[] = {100,200,300,400,150,350};
  static const char *const paths[] = {"A",NULL,"B",NULL,"C",NULL};
  for (size_t step = 0; step < 6; ++step) {
    unsigned e = order[step];
    if (paths[e]) {
      edr_file_object_binding_open(bounded, capacity, &small, objects[e], times[e], paths[e]);
      edr_file_object_binding_open(retained, 16, &full, objects[e], times[e], paths[e]);
    } else {
      edr_file_object_binding_close(bounded, capacity, &small, objects[e], times[e]);
      edr_file_object_binding_close(retained, 16, &full, objects[e], times[e]);
    }
    for (uint64_t object = 11; object <= 22; object += 11)
      for (uint64_t at = 100; at <= 450; at += 25) {
        const char *actual = edr_file_object_binding_resolve(bounded, capacity, &small, object, at);
        const char *expected = edr_file_object_binding_resolve(retained, 16, &full, object, at);
        if (actual) assert(expected && strcmp(actual, expected) == 0);
      }
  }
}

static void permute_arrivals(unsigned *order, size_t depth) {
  if (depth == 6) {
    check_arrival_order(order, 2); check_arrival_order(order, 4);
    return;
  }
  for (unsigned e = 0; e < 6; ++e) {
    size_t i;
    for (i = 0; i < depth && order[i] != e; ++i) {}
    if (i != depth) continue;
    order[depth] = e;
    permute_arrivals(order, depth + 1);
  }
}

void edr_test_file_object_binding_contract(void) {
  test_new_generation_does_not_evict_its_own_boundary();
  test_unrelated_eviction(4, 150);
  test_unrelated_eviction(4, 400);
  test_unrelated_eviction(4096, 150);
  test_unrelated_eviction(4096, 400);
  test_scoped_history_and_diagnostics();
  unsigned order[6];
  permute_arrivals(order, 0);
  EdrFileObjectBinding entries[32] = {{0}};
  EdrFileObjectHistory history = {0};
  const size_t count = sizeof(entries) / sizeof(entries[0]);
  const uint64_t object = 0xffff848901f66ea0ULL;
  const char *path = "C:\\Fixture\\existing.txt";
  /* Captured Windows sequence: existing-file Create -> Write -> Cleanup,
   * without NameCreate. Decode can happen after Cleanup. */
  edr_file_object_binding_open(entries, count, &history, object, 100, path);
  edr_file_object_binding_close(entries, count, &history, object, 200);
  assert(strcmp(edr_file_object_binding_resolve(entries, count, &history, object, 150), path) == 0);
  assert(!edr_file_object_binding_resolve(entries, count, &history, object, 200));
  assert(!edr_file_object_binding_resolve(entries, count, &history, object, 99));
  assert(!edr_file_object_binding_resolve(entries, count, &history, 0, 150));
  assert(!edr_file_object_binding_resolve(entries, count, &history, object + 1, 150));
  /* The same lifetime contract applies to Read. No NameCreate is needed
   * when the actual Read's FileObject has an independently observed Create.
   * Neither an absent binding nor a conflicting live FileKey may be guessed. */
  int read_conflict = 0;
  const char *read_path = edr_file_object_binding_resolve(entries, count, &history, object, 150);
  assert(edr_file_mutation_binding_select(NULL, read_path, 0, 0, &read_conflict) == read_path);
  assert(!read_conflict);
  assert(!edr_file_mutation_binding_select("C:\\Wrong.txt", read_path, 0, 0, &read_conflict));
  assert(read_conflict);
  assert(!edr_file_mutation_binding_select(NULL,
      edr_file_object_binding_resolve(entries, count, &history, object, 200),
      0, 0, &read_conflict));
  edr_file_object_binding_open(entries, count, &history, object, 300, "C:\\Fixture\\new.txt");
  assert(strcmp(edr_file_object_binding_resolve(entries, count, &history, object, 150), path) == 0);
  assert(strstr(edr_file_object_binding_resolve(entries, count, &history, object, 350), "new.txt"));
  edr_file_object_binding_close(entries, count, &history, object, 400);
  assert(!edr_file_object_binding_resolve(entries, count, &history, object, 450));
  /* Duplicate Close must not close a later reuse. */
  edr_file_object_binding_close(entries, count, &history, object, 200);
  assert(strstr(edr_file_object_binding_resolve(entries, count, &history, object, 350), "new.txt"));
  memset(entries, 0, sizeof(entries)); memset(&history, 0, sizeof(history));
  assert(!edr_file_object_binding_resolve(entries, count, &history, object, 150));
  edr_file_object_binding_close(entries, count, &history, object, 200);
  edr_file_object_binding_open(entries, count, &history, object, 100, path);
  assert(edr_file_object_binding_resolve(entries, count, &history, object, 150));
  assert(!edr_file_object_binding_resolve(entries, count, &history, object, 201));
  /* Close before a reused object's Create must retain its time, even with
   * an older, already-closed generation in the cache. */
  edr_file_object_binding_close(entries, count, &history, object, 400);
  edr_file_object_binding_open(entries, count, &history, object, 300, path);
  assert(edr_file_object_binding_resolve(entries, count, &history, object, 350));
  assert(!edr_file_object_binding_resolve(entries, count, &history, object, 400));
  edr_file_object_binding_open(entries, count, &history, object, 300, "C:\\Other.txt");
  edr_file_object_binding_open(entries, count, &history, object, 300, path);
  assert(!edr_file_object_binding_resolve(entries, count, &history, object, 350));
  edr_file_object_binding_open(entries, count, &history, object, 500, NULL);
  assert(!edr_file_object_binding_resolve(entries, count, &history, object, 550));
  char long_path[EDR_FILE_OBJECT_PATH_CAP + 1];
  memset(long_path, 'x', sizeof(long_path)); long_path[sizeof(long_path) - 1] = 0;
  edr_file_object_binding_open(entries, count, &history, object, 600, long_path);
  assert(!edr_file_object_binding_resolve(entries, count, &history, object, 650));

  /* Cache pressure must not lose a Close then accept its delayed Create. */
  memset(entries, 0, sizeof(entries)); memset(&history, 0, sizeof(history));
  edr_file_object_binding_close(entries, 2, &history, object, 400);
  edr_file_object_binding_open(entries, 2, &history, object + 1, 500, path);
  edr_file_object_binding_open(entries, 2, &history, object + 2, 600, path);
  assert(history.discarded_through == 400);
  edr_file_object_binding_open(entries, 2, &history, object, 300, path);
  assert(!edr_file_object_binding_resolve(entries, 2, &history, object, 450));
  assert(edr_file_object_binding_resolve(entries, 2, &history, object + 2, 650));
  /* A retained, closed NameCreate must not shadow a fresh FileObject/Create
   * on a subsequent write pass. No fallback is allowed for live conflicts. */
  memset(entries, 0, sizeof(entries)); memset(&history, 0, sizeof(history));
  edr_file_object_binding_open(entries, count, &history, object, 100, path);
  edr_file_object_binding_close(entries, count, &history, object, 200);
  edr_file_object_binding_open(entries, count, &history, object, 300, path);
  const char *current = edr_file_object_binding_resolve(entries, count, &history, object, 350);
  int conflict = 0;
  assert(edr_file_mutation_binding_select(NULL, current, 1, 1, &conflict) == current);
  assert(!conflict);
  assert(!edr_file_mutation_binding_select(NULL, current, 1, 0, &conflict));
  assert(!edr_file_mutation_binding_select("C:\\Other.txt", current, 0, 0, &conflict));
  assert(conflict);
  assert(edr_file_mutation_binding_select("c:\\fixture\\existing.txt", current, 0, 0, &conflict));
  assert(!conflict);
  edr_file_object_binding_close(entries, count, &history, object, 400);
  current = edr_file_object_binding_resolve(entries, count, &history, object, 450);
  assert(!edr_file_mutation_binding_select(NULL, current, 1, 1, &conflict));
  /* Evicting a reused generation must not revive an older open generation. */
  memset(entries, 0, sizeof(entries)); memset(&history, 0, sizeof(history));
  edr_file_object_binding_open(entries, 2, &history, object, 100, path);
  edr_file_object_binding_open(entries, 2, &history, object, 300, "C:\\Other.txt");
  history.next = 1;
  edr_file_object_binding_open(entries, 2, &history, object + 1, 500, path);
  assert(!edr_file_object_binding_resolve(entries, 2, &history, object, 450));
}

#ifndef EDR_FILE_OBJECT_BINDING_NO_MAIN
int main(void) {
  edr_test_file_object_binding_contract();
  puts("FileObject binding: existing files, close, reuse, reordering, conflicts and eviction passed");
  return 0;
}
#endif
