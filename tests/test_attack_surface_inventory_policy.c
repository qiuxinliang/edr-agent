#include "edr/attack_surface_inventory.h"
#include "cJSON.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  EdrConfig cfg;
  EdrAsurfInventorySummary summary;
  memset(&cfg, 0, sizeof(cfg));
  memset(&summary, 0, sizeof(summary));

  FILE *fp = tmpfile();
  assert(fp != NULL);
  fputc('{', fp);
  edr_asurf_inventory_write_json(fp, &cfg, 0, &summary);
  fputc('}', fp);
  assert(fflush(fp) == 0);
  assert(fseek(fp, 0, SEEK_END) == 0);
  long length = ftell(fp);
  assert(length > 2);
  rewind(fp);
  char *body = (char *)calloc((size_t)length + 1u, 1u);
  assert(body != NULL);
  assert(fread(body, 1u, (size_t)length, fp) == (size_t)length);
  fclose(fp);

  cJSON *root = cJSON_Parse(body);
  assert(root != NULL);
  const char *keys[] = {"services", "scheduledTasks", "startupItems", "localAccounts", "localGroups",
                        "shares", "browserExtensions", "installedSoftware"};
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
    cJSON *bucket = cJSON_GetObjectItemCaseSensitive(root, keys[i]);
    cJSON *items = bucket ? cJSON_GetObjectItemCaseSensitive(bucket, "items") : NULL;
    assert(cJSON_IsArray(items));
    assert(cJSON_GetArraySize(items) == 0);
  }
  assert(summary.service_count == 0);
  assert(summary.browser_extension_count == 0);
  assert(summary.installed_software_count == 0);
  cJSON_Delete(root);
  free(body);
  return 0;
}
