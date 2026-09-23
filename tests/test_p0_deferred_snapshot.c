#include "edr/p0_deferred_snapshot.h"
#include "edr/storage_queue.h"
#include "cJSON.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  EdrBehaviorRecord original = {0}, restored;
  EdrP0RuleIrBinding binding = {0}, decoded;
  char *json = NULL, rule[64]; size_t length;
  /* Populate every field through the production descriptor manifest, including
   * strings at their actual boundaries and generation IDs above JSON 2^53. */
#define TEXT(n) memset(original.n,'a',sizeof(original.n)-1u);
#define UNSIGNED(n) original.n=127u;
#define SIGNED(n) original.n=1;
#define FLOAT(n) original.n=7.8125f;
#define MITRE(n) for(size_t i=0;i<EDR_BR_MAX_MITRE;++i) snprintf(original.n[i],sizeof(original.n[i]),"T%04u",(unsigned)i);
#include "../src/preprocess/p0_deferred_fields.inc"
#undef TEXT
#undef UNSIGNED
#undef SIGNED
#undef FLOAT
#undef MITRE
  original.process_start_key=UINT64_MAX;
  original.process_creation_filetime_100ns=UINT64_C(134337835418663457);
  original.event_time_ns=INT64_C(1789309942708556400);
  original.file_key=UINT64_MAX-1u;
  original.syscall_result=INT64_MIN;
  strcpy(original.parent_name,"父进程.exe");
  strcpy(original.cmdline,"powershell.exe -File \"C:\\用户\\context.ps1\"\nsecond line");
  strcpy(binding.rules_bundle_version,"r283");
  memset(binding.artifact_sha256,'a',64u);
  assert(edr_p0_deferred_snapshot_encode(&original,&binding,"R-TEST",&json,&length));
  assert(edr_p0_deferred_snapshot_decode(json,length,&restored,&decoded,rule,sizeof(rule)));
#define TEXT(n) assert(!strcmp(original.n,restored.n));
#define UNSIGNED(n) assert(original.n==restored.n);
#define SIGNED(n) assert(original.n==restored.n);
#define FLOAT(n) assert(original.n==restored.n);
#define MITRE(n) for(size_t i=0;i<EDR_BR_MAX_MITRE;++i) assert(!strcmp(original.n[i],restored.n[i]));
#include "../src/preprocess/p0_deferred_fields.inc"
#undef TEXT
#undef UNSIGNED
#undef SIGNED
#undef FLOAT
#undef MITRE
  assert(!strcmp(rule,"R-TEST") && !strcmp(decoded.artifact_sha256,binding.artifact_sha256));
  /* Truncation, unsupported schemas, numeric overflow and duplicate/missing
   * fields must fail explicitly, never restore a partial valid-looking record. */
  assert(!edr_p0_deferred_snapshot_decode(json,length-1u,&restored,&decoded,rule,sizeof(rule)));
  cJSON *root=cJSON_Parse(json); assert(root);
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(root,"schema"),4);
  char *bad=cJSON_PrintUnformatted(root); assert(bad);
  assert(!edr_p0_deferred_snapshot_decode(bad,strlen(bad),&restored,&decoded,rule,sizeof(rule)));
  free(bad);
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(root,"schema"),3);
  cJSON *record=cJSON_GetObjectItemCaseSensitive(root,"record");
  assert(cJSON_ReplaceItemInObjectCaseSensitive(record,"pid",cJSON_CreateString("4294967296")));
  bad=cJSON_PrintUnformatted(root); assert(bad);
  assert(!edr_p0_deferred_snapshot_decode(bad,strlen(bad),&restored,&decoded,rule,sizeof(rule)));
  free(bad); cJSON_Delete(root);
  /* Existing schema-2 rows preserve syscall outcomes after upgrade. */
  root=cJSON_Parse(json); assert(root);
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(root,"schema"),2);
  cJSON_DeleteItemFromObjectCaseSensitive(root,"command_facts");
  record=cJSON_GetObjectItemCaseSensitive(root,"record");
  cJSON_DeleteItemFromObjectCaseSensitive(record,"parent_process_start_key");
  cJSON_DeleteItemFromObjectCaseSensitive(record,"parent_process_creation_filetime_100ns");
  bad=cJSON_PrintUnformatted(root); assert(bad);
  assert(edr_p0_deferred_snapshot_decode(bad,strlen(bad),&restored,&decoded,rule,sizeof(rule)));
  assert(restored.syscall_result==INT64_MIN && restored.syscall_result_known==original.syscall_result_known);
  assert(!restored.parent_process_start_key && !restored.parent_process_creation_filetime_100ns);
  free(bad); cJSON_Delete(root);
  /* Existing schema-1 durable rows survive upgrade with outcome unknown. */
  root=cJSON_Parse(json); assert(root);
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(root,"schema"),1);
  cJSON_DeleteItemFromObjectCaseSensitive(root,"command_facts");
  record=cJSON_GetObjectItemCaseSensitive(root,"record");
  cJSON_DeleteItemFromObjectCaseSensitive(record,"parent_process_start_key");
  cJSON_DeleteItemFromObjectCaseSensitive(record,"parent_process_creation_filetime_100ns");
  const char *syscall_fields[] = {"syscall_name", "syscall_sensor", "syscall_result",
    "syscall_target_pid", "syscall_result_known", "syscall_success", "syscall_success_known"};
  for (size_t i=0;i<sizeof(syscall_fields)/sizeof(syscall_fields[0]);++i)
    cJSON_DeleteItemFromObjectCaseSensitive(record,syscall_fields[i]);
  bad=cJSON_PrintUnformatted(root); assert(bad);
  assert(edr_p0_deferred_snapshot_decode(bad,strlen(bad),&restored,&decoded,rule,sizeof(rule)));
  assert(restored.process_start_key==UINT64_MAX && restored.syscall_name[0]==0);
  assert(!restored.syscall_result_known && !restored.syscall_success_known);
  char *legacy=NULL; size_t legacy_length=0;
  assert(edr_p0_deferred_snapshot_encode(&restored,&decoded,rule,&legacy,&legacy_length));
  assert(legacy_length==strlen(bad) && strcmp(legacy,bad)==0);
  free(legacy);
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(root,"schema"),2);
  free(bad); bad=cJSON_PrintUnformatted(root); assert(bad);
  assert(!edr_p0_deferred_snapshot_decode(bad,strlen(bad),&restored,&decoded,rule,sizeof(rule)));
  free(bad); cJSON_Delete(root); free(json);
  /* Worst-case JSON escaping of every bounded source string must fit the
   * storage contract, not just a short typical process command line. */
#define TEXT(n) memset(original.n,1,sizeof(original.n)-1u); original.n[sizeof(original.n)-1u]=0;
#define UNSIGNED(n)
#define SIGNED(n)
#define FLOAT(n)
#define MITRE(n)
#include "../src/preprocess/p0_deferred_fields.inc"
#undef TEXT
#undef UNSIGNED
#undef SIGNED
#undef FLOAT
#undef MITRE
  assert(edr_p0_deferred_snapshot_encode(&original,&binding,"R-TEST",&json,&length));
  printf("maximum escaped snapshot: %zu bytes; storage limit: %u bytes\n",length,
      (unsigned)EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_PAYLOAD_BYTES);
  assert(length<=EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_PAYLOAD_BYTES);
  free(json);
  memset(original.cmdline,'x',sizeof(original.cmdline));
  assert(!edr_p0_deferred_snapshot_encode(&original,&binding,"R-TEST",&json,&length));
  assert(json==NULL && length==0u);
  puts("p0 deferred snapshot: all fields/lossless generations/invalid input OK");
  return 0;
}
