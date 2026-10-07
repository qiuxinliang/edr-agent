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
  {
    cJSON *root=cJSON_Parse(fixture), *data=cJSON_GetObjectItemCaseSensitive(root,"data");
    cJSON *hold=cJSON_DetachItemFromObjectCaseSensitive(data,"ack");
    cJSON_AddItemToObject(data,"hold",hold);
    cJSON_ReplaceItemInObjectCaseSensitive(root,"code",cJSON_CreateString("EVIDENCE_PROJECTION_POLICY_HELD"));
    cJSON_ReplaceItemInObjectCaseSensitive(data,"accepted",cJSON_CreateFalse());
    cJSON_ReplaceItemInObjectCaseSensitive(hold,"state",cJSON_CreateString("policy_held"));
    cJSON_AddStringToObject(hold,"tenant_id","test-tenant");
    char *text=cJSON_PrintUnformatted(root); assert(text && !accepted(text));
    assert(edr_report_events_policy_held(text,"test-tenant","test-endpoint","test-batch",
      (const uint8_t *)"0123456789ab",12,(const uint8_t *)"payload",7));
    assert(!edr_report_events_policy_held(text,"other","test-endpoint","test-batch",
      (const uint8_t *)"0123456789ab",12,(const uint8_t *)"payload",7));
    assert(!edr_report_events_policy_held(text,"test-tenant","test-endpoint","different",
      (const uint8_t *)"0123456789ab",12,(const uint8_t *)"payload",7));
    assert(!edr_report_events_policy_held(text,"test-tenant","test-endpoint","test-batch",
      (const uint8_t *)"0123456789ab",12,(const uint8_t *)"payloae",7));
    free(text);
    const char *fields[]={"tenant_id","endpoint_id","batch_id","payload_sha256","version","state"};
    for (size_t i=0;i<sizeof(fields)/sizeof(fields[0]);i++) {
      cJSON *old=cJSON_DetachItemFromObjectCaseSensitive(hold,fields[i]); assert(old);
      text=cJSON_PrintUnformatted(root); assert(text);
      assert(!edr_report_events_policy_held(text,"test-tenant","test-endpoint","test-batch",
        (const uint8_t *)"0123456789ab",12,(const uint8_t *)"payload",7));
      free(text); cJSON_AddItemToObject(hold,fields[i],old);
    }
    cJSON_AddObjectToObject(data,"ack"); text=cJSON_PrintUnformatted(root); assert(text);
    assert(!edr_report_events_policy_held(text,"test-tenant","test-endpoint","test-batch",
      (const uint8_t *)"0123456789ab",12,(const uint8_t *)"payload",7));
    free(text);cJSON_Delete(root);
  }
  puts("report-events receipt contract ok");
  return 0;
}
