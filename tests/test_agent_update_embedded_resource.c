#include "edr/windows_resource_ids.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static void require_true(int value, const char *message) {
  if (!value) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
  }
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  require_true(root && root[0], "EDR_SOURCE_DIR is configured");
  char path[4096];
  int written = snprintf(path, sizeof(path), "%s/scripts/edr_agent_inplace_update.ps1", root);
  require_true(written > 0 && (size_t)written < sizeof(path), "source updater path fits");
  FILE *source = fopen(path, "rb");
  require_true(source != NULL, "source updater opens");
  require_true(fseek(source, 0, SEEK_END) == 0, "source updater size seek succeeds");
  long source_size = ftell(source);
  require_true(source_size > 0 && fseek(source, 0, SEEK_SET) == 0, "source updater is non-empty");
  unsigned char *source_bytes = (unsigned char *)malloc((size_t)source_size);
  require_true(source_bytes != NULL, "source updater buffer allocates");
  require_true(fread(source_bytes, 1u, (size_t)source_size, source) == (size_t)source_size,
               "source updater reads completely");
  fclose(source);

  HMODULE module = GetModuleHandleA(NULL);
  HRSRC resource = FindResourceA(module, MAKEINTRESOURCEA(IDR_EDR_AGENT_UPDATE_SCRIPT), RT_RCDATA);
  require_true(resource != NULL, "test executable contains updater RCDATA");
  DWORD resource_size = SizeofResource(module, resource);
  HGLOBAL loaded = LoadResource(module, resource);
  const void *resource_bytes = loaded ? LockResource(loaded) : NULL;
  require_true(resource_bytes != NULL && resource_size == (DWORD)source_size,
               "embedded updater size matches release source");
  require_true(memcmp(resource_bytes, source_bytes, (size_t)source_size) == 0,
               "embedded updater bytes match release source");
  free(source_bytes);
  puts("ok");
  return 0;
}
