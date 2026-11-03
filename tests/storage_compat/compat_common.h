#ifndef COMPAT_COMMON_H
#define COMPAT_COMMON_H
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#ifndef COMPAT_SOURCE_COMMIT
#error immutable source identity required
#endif
static const char *compat_stage;
static void compat_need(int ok, const char *cause) {
  if (!ok) { fprintf(stderr,"storage_compat phase=%s cause=%s\n",compat_stage?compat_stage:"args",cause); exit(2); }
}
static int64_t compat_epoch;
static unsigned compat_generations;
static uint32_t compat_max_mb,compat_retention,compat_selected;
static const char *compat_tenant,*compat_endpoint;
#ifdef _WIN32
static USHORT compat_process_machine,compat_native_machine;
#endif
static int compat_identity(const char *s,size_t capacity) {
  size_t n=strlen(s);if(!n||n>=capacity)return 0;
  for(size_t i=0;i<n;i++)if(!((s[i]>='a'&&s[i]<='z')||(s[i]>='A'&&s[i]<='Z')||(s[i]>='0'&&s[i]<='9')||s[i]=='-'||s[i]=='_'))return 0;
  return 1;
}
static uint32_t compat_positive(const char *value) {
  char *end=NULL;errno=0;unsigned long n=strtoul(value,&end,10);
  compat_need(value[0]>='0'&&value[0]<='9'&&!errno&&end&&!*end&&n>0&&n<=INT_MAX,"storage_policy_positive_integer");return (uint32_t)n;
}
static void compat_args(int argc,char **argv) {
  compat_need(argc==10,"usage_action_database_epoch_generations_tenant_endpoint_budget_retention_selected");
  compat_stage=argv[1];
  compat_need(!strcmp(argv[1],"create") || !strcmp(argv[1],"seed") || !strcmp(argv[1],"append") || !strcmp(argv[1],"read"),"action");
  char *end=NULL; errno=0; compat_epoch=strtoll(argv[3],&end,10);
  compat_need(!errno && end && !*end && compat_epoch>0 && llabs((long long)time(NULL)-compat_epoch)<3600,"fresh_epoch");
  compat_need(!strcmp(argv[4],"1") || !strcmp(argv[4],"2"),"generations");
  compat_generations=(unsigned)atoi(argv[4]);
  compat_tenant=argv[5];compat_endpoint=argv[6];
  /* Both the original record and wire owners must retain the whole identity.
   * Reject before opening a DB or copying into either fixed-size field. */
  compat_need(compat_identity(compat_tenant,sizeof(((EdrBehaviorRecord *)0)->tenant_id))&&
              compat_identity(compat_tenant,sizeof(((edr_v1_BehaviorEvent *)0)->tenant_id)),"fixture_tenant_identity");
  compat_need(compat_identity(compat_endpoint,sizeof(((EdrBehaviorRecord *)0)->endpoint_id))&&
              compat_identity(compat_endpoint,sizeof(((edr_v1_BehaviorEvent *)0)->endpoint_id)),"fixture_endpoint_identity");
  compat_max_mb=compat_positive(argv[7]);compat_retention=compat_positive(argv[8]);compat_selected=compat_positive(argv[9]);
  compat_need(compat_selected>=compat_retention,"selected_retention_must_cover_recent");
  const char *blocked[]={"EDR_QUEUE_MAX_DB_MB","EDR_QUEUE_RETENTION_HOURS","EDR_QUEUE_MAX_RETRIES","EDR_QUEUE_DRAIN_MAX_ROWS","EDR_QUEUE_CIRCUIT_BACKOFF_MS","EDR_EVIDENCE_CONTEXT_WINDOW_S"};
  for(size_t i=0;i<sizeof(blocked)/sizeof(blocked[0]);i++){const char *v=getenv(blocked[i]);compat_need(!v||!*v,"storage_environment_override_not_allowed");}
#ifdef _WIN32
  compat_need(IsWow64Process2(GetCurrentProcess(),&compat_process_machine,&compat_native_machine)!=0,"native_process_machine");
  compat_need(compat_process_machine==IMAGE_FILE_MACHINE_UNKNOWN&&(compat_native_machine==IMAGE_FILE_MACHINE_ARM64||compat_native_machine==IMAGE_FILE_MACHINE_AMD64),"native_execution_required");
#endif
#ifdef _WIN32
  WIN32_FILE_ATTRIBUTE_DATA data;SetLastError(ERROR_SUCCESS);int exists=GetFileAttributesExA(argv[2],GetFileExInfoStandard,&data)!=0;
  DWORD path_error=GetLastError();
  if(!strcmp(argv[1],"create"))compat_need(!exists&&(path_error==ERROR_FILE_NOT_FOUND||path_error==ERROR_PATH_NOT_FOUND)&&compat_generations==1u,"create_requires_new_database");
  else compat_need(exists&&!(data.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))&&(data.nFileSizeHigh||data.nFileSizeLow),"existing_regular_database_required");
#else
  struct stat st;errno=0;int exists=lstat(argv[2],&st)==0;
  if (!strcmp(argv[1],"create")) compat_need(!exists && errno==ENOENT && compat_generations==1u,"create_requires_new_database");
  else compat_need(exists && S_ISREG(st.st_mode) && st.st_size>0,"existing_regular_database_required");
#endif
  if (!strcmp(argv[1],"append")) compat_need(compat_generations==2u,"append_requires_second_generation");
  if (!strcmp(argv[1],"seed")) compat_need(compat_generations==1u,"seed_requires_first_generation");
}
static void compat_sha(const void *p,size_t n,char out[65]) { compat_need(edr_sha256_hex(p,n,out)==0,"sha256"); }
static const char *compat_string(cJSON *o,const char *key) {
  cJSON *v=cJSON_GetObjectItemCaseSensitive(o,key);compat_need(cJSON_IsString(v),key);return v->valuestring;
}
static void compat_equal(cJSON *row,const char *key,const char *want) {compat_need(!strcmp(compat_string(row,key),want),key);}
static cJSON *compat_receipt(const char *kind,cJSON *records) {
  cJSON *r=cJSON_CreateObject();compat_need(r!=NULL,"receipt_alloc");
  cJSON_AddStringToObject(r,"schema","edr.test.storage-compat.v1");
  cJSON_AddStringToObject(r,"owner",kind);cJSON_AddStringToObject(r,"action",compat_stage);
  cJSON_AddStringToObject(r,"source_commit",COMPAT_SOURCE_COMMIT);
#ifdef _WIN32
  cJSON_AddStringToObject(r,"platform","Windows");cJSON_AddNumberToObject(r,"process_machine",compat_process_machine);
  cJSON_AddNumberToObject(r,"native_machine",compat_native_machine);cJSON_AddBoolToObject(r,"native_windows",1);
#else
  cJSON_AddStringToObject(r,"platform","host_posix");cJSON_AddBoolToObject(r,"native_windows",0);
#endif
  cJSON_AddStringToObject(r,"input_origin","synthetic_records_via_original_storage_owner_api");
  cJSON_AddBoolToObject(r,"direct_sql_writes",0);cJSON_AddBoolToObject(r,"network",0);
  cJSON_AddBoolToObject(r,"sensor_capture",0);cJSON_AddNumberToObject(r,"epoch",(double)compat_epoch);
  cJSON_AddStringToObject(r,"tenant_id",compat_tenant);cJSON_AddStringToObject(r,"endpoint_id",compat_endpoint);
  cJSON *policy=cJSON_CreateObject();cJSON_AddNumberToObject(policy,"max_mb",compat_max_mb);
  cJSON_AddNumberToObject(policy,"retention_hours",compat_retention);cJSON_AddNumberToObject(policy,"selected_retention_hours",compat_selected);
  cJSON_AddItemToObject(r,"storage_policy",policy);
  cJSON_AddItemToObject(r,"records",records);return r;
}
static void compat_print(cJSON *r) {char *s=cJSON_PrintUnformatted(r);compat_need(s!=NULL,"receipt_json");puts(s);free(s);cJSON_Delete(r);}
#endif
