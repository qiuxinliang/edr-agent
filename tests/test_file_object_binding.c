#include "edr/file_object_binding.h"
#include <assert.h>
#include <stdio.h>

void edr_test_file_object_binding_contract(void);

void edr_test_file_object_binding_contract(void) {
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
