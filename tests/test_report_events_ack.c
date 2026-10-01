#include "edr/report_events_ack.h"
#include "cJSON.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int accepted(const char *text) {
  return edr_report_events_acknowledged(text, "test-endpoint", "test-batch",
                                       (const uint8_t *)"0123456789ab", 12,
                                       (const uint8_t *)"payload", 7);
}
static void change_and_reject(const char *fixture, const char *object, const char *key, cJSON *value) {
  cJSON *root = cJSON_Parse(fixture), *parent = root;
  char *text;
  assert(root);
  if (strcmp(object, "root")) parent = cJSON_GetObjectItemCaseSensitive(root, "data");
  if (!strcmp(object, "ack")) parent = cJSON_GetObjectItemCaseSensitive(parent, "ack");
  assert(cJSON_ReplaceItemInObjectCaseSensitive(parent, key, value));
  text = cJSON_PrintUnformatted(root); assert(text);
  assert(!accepted(text)); free(text); cJSON_Delete(root);
}
int main(int argc, char **argv) {
  char fixture[2048]; size_t n;
  FILE *in;
  assert(argc == 2);
  in = fopen(argv[1], "rb"); assert(in);
  n = fread(fixture, 1, sizeof(fixture)-1, in); assert(!ferror(in)); fclose(in); fixture[n] = 0;
  assert(accepted(fixture));
  assert(!accepted(""));
  assert(!accepted("{}"));
  assert(!accepted("{\"code\":\"OK\",\"data\":{\"accepted\":true}}"));
  change_and_reject(fixture, "root", "code", cJSON_CreateString("BUSINESS_REJECTED"));
  change_and_reject(fixture, "data", "accepted", cJSON_CreateFalse());
  change_and_reject(fixture, "ack", "state", cJSON_CreateString("memory"));
  change_and_reject(fixture, "ack", "state", cJSON_CreateString("partial"));
  change_and_reject(fixture, "ack", "version", cJSON_CreateNumber(2));
  change_and_reject(fixture, "ack", "endpoint_id", cJSON_CreateString("different-endpoint"));
  change_and_reject(fixture, "ack", "batch_id", cJSON_CreateString("different-batch"));
  change_and_reject(fixture, "ack", "payload_sha256", cJSON_CreateString("wrong-hash"));
  {
    cJSON *root = cJSON_Parse(fixture), *data = cJSON_GetObjectItemCaseSensitive(root, "data");
    cJSON *ack = cJSON_GetObjectItemCaseSensitive(data, "ack");
    char *text;
    cJSON_ReplaceItemInObjectCaseSensitive(ack, "state", cJSON_CreateString("processed"));
    text = cJSON_PrintUnformatted(root); assert(text && accepted(text)); free(text);
    cJSON_AddNumberToObject(data, "invalid_frames", 1);
    text = cJSON_PrintUnformatted(root); assert(text && !accepted(text)); free(text);
    cJSON_Delete(root);
  }
  puts("report-events receipt contract ok");
  return 0;
}
