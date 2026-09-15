/* Exercises the real bundler using synthetic data only, on Windows and POSIX. */
#define main forensic_collector_main
#include "../tools/forensic_collector/main.c"
#undef main

#include <assert.h>

int main(void) {
  char base[MAXPATH];
#ifdef _WIN32
  char temp[MAXPATH];
  assert(GetTempPathA(sizeof(temp), temp));
  char leaf[64];
  snprintf(leaf, sizeof(leaf), "forensic regression %lu", (unsigned long)GetCurrentProcessId());
  assert(join_path_exact(base, sizeof(base), temp, leaf) == 0);
#else
  snprintf(base, sizeof(base), "/tmp/forensic regression %lu", (unsigned long)getpid());
#endif
  assert(make_dir(base) == 0);
  assert(copy_text_exact(g_output_dir, sizeof(g_output_dir), base) == 0);
  assert(edr_forensic_storage_ready(base));
  assert(!edr_forensic_storage_ready("/__edr_missing_volume__/missing"));
  char old[MAXPATH];
  assert(join_path_exact(old, sizeof(old), base, "old_archive.tar.gz") == 0);
  FILE *f = fopen(old, "wb"); assert(f); fputs("old synthetic artifact", f); fclose(f);
  for (unsigned run = 0; run < 8; ++run) {
    g_file_count = 0; g_collected_bytes = 0; g_limit_exceeded = 0;
    assert(write_str_file("manifest.json", "{\"synthetic\":true}\n") == 0);
    assert(write_str_file("evidence.txt", "synthetic evidence\n") == 0);
    char name[64]; snprintf(name, sizeof(name), "bundle_%u.tar.gz", run);
    assert(join_path_exact(g_out_file, sizeof(g_out_file), base, name) == 0);
    assert(make_bundle() == 0);
    char cmd[MAXPATH + 40];
    snprintf(cmd, sizeof(cmd), "tar -tzf \"%s\"", g_out_file);
#ifdef _WIN32
    FILE *list = _popen(cmd, "r");
#else
    FILE *list = popen(cmd, "r");
#endif
    assert(list);
    char line[512]; unsigned entries = 0;
    while (fgets(line, sizeof(line), list)) {
      assert(strstr(line, "manifest.json") || strstr(line, "evidence.txt"));
      assert(!strstr(line, ".tar.gz"));
      entries++;
    }
#ifdef _WIN32
    assert(_pclose(list) == 0);
#else
    assert(pclose(list) == 0);
#endif
    assert(entries == 2);
    f = fopen(g_out_file, "rb"); assert(f);
    assert(fseek(f, 0, SEEK_END) == 0); assert(ftell(f) < 4096); fclose(f);
    assert(make_bundle() != 0); /* existing evidence must not be overwritten */
  }
  f = tmpfile(); assert(f);
  g_collected_bytes = MAX_COLLECTION_BYTES - 3u;
  assert(write_evidence(f, "abc", 3) == 0);
  assert(write_evidence(f, "d", 1) != 0);
  assert(g_limit_exceeded && g_collected_bytes == MAX_COLLECTION_BYTES);
  fclose(f);
  for (unsigned run = 0; run < 8; ++run) {
    char name[64], path[MAXPATH]; snprintf(name, sizeof(name), "bundle_%u.tar.gz", run);
    assert(join_path_exact(path, sizeof(path), base, name) == 0); assert(remove(path) == 0);
  }
  const char *names[] = {"manifest.json", "evidence.txt", "old_archive.tar.gz"};
  for (unsigned i = 0; i < 3; ++i) {
    char path[MAXPATH]; assert(join_path_exact(path, sizeof(path), base, names[i]) == 0);
    assert(remove(path) == 0);
  }
#ifdef _WIN32
  assert(_rmdir(base) == 0);
#else
  assert(rmdir(base) == 0);
#endif
  puts("PASS: eight bounded archives, no history/self inclusion, no overwrite, aggregate budget");
  return 0;
}
