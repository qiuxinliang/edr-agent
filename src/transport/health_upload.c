#include "edr/health_upload.h"
#include <string.h>
#include <stdlib.h>

void edr_health_upload_reset(EdrHealthUpload *s) {
 if (!s) return;
 cJSON_Delete(s->base); s->base = NULL; s->revision[0] = 0; s->full_at_ns = 0;
}

static int same_identity(const cJSON *a, const cJSON *b) {
 const char *keys[] = {"endpoint_id", "agent_version", "policy_version"};
 for (size_t i=0; i<3; i++) {
  const cJSON *x=cJSON_GetObjectItemCaseSensitive(a,keys[i]);
  const cJSON *y=cJSON_GetObjectItemCaseSensitive(b,keys[i]);
  if (!x || !y || !cJSON_Compare(x,y,1)) return 0;
 }
 return 1;
}

/* cJSON stores numbers as doubles. Preserve raw full JSON for values outside
 * the exact integer range; never round future health counters to save bytes. */
static int unsafe_number(const cJSON *v) {
 if (cJSON_IsNumber(v) && (v->valuedouble >= 9007199254740992.0 ||
                           v->valuedouble <= -9007199254740992.0)) return 1;
 const cJSON *child;
 cJSON_ArrayForEach(child,v) { if (unsafe_number(child)) return 1; }
 return 0;
}
static int exact_block_equal(const cJSON *a, const cJSON *b) {
 char *left=cJSON_PrintUnformatted(a), *right=cJSON_PrintUnformatted(b);
 int same=left && right && strcmp(left,right)==0;
 cJSON_free(left); cJSON_free(right); return same;
}

static cJSON *make_delta(const EdrHealthUpload *s, const cJSON *full) {
 cJSON *out=cJSON_Duplicate(full,1);
 cJSON *changes=cJSON_CreateObject(), *update=cJSON_CreateObject(), *removed=cJSON_CreateArray();
 if (!out || !changes || !update || !removed) goto fail;
 const cJSON *before=cJSON_GetObjectItemCaseSensitive(s->base,"engine_health");
 const cJSON *after=cJSON_GetObjectItemCaseSensitive(full,"engine_health");
 const cJSON *item;
 cJSON_ArrayForEach(item,after) {
  const cJSON *old=cJSON_GetObjectItemCaseSensitive(before,item->string);
  if (!old || !exact_block_equal(old,item)) {
   cJSON *copy=cJSON_Duplicate(item,1);
   if (!copy || !cJSON_AddItemToObject(changes,item->string,copy)) { cJSON_Delete(copy); goto fail; }
  }
 }
 cJSON_ArrayForEach(item,before) {
  if (!cJSON_GetObjectItemCaseSensitive(after,item->string)) {
   cJSON *key=cJSON_CreateString(item->string);
   if (!key || !cJSON_AddItemToArray(removed,key)) { cJSON_Delete(key); goto fail; }
  }
 }
 if (!cJSON_AddNumberToObject(update,"version",1) || !cJSON_AddStringToObject(update,"base",s->revision)) goto fail;
 if (!cJSON_AddItemToObject(update,"removed",removed)) goto fail;
 removed=NULL;
 if (!cJSON_ReplaceItemInObjectCaseSensitive(out,"engine_health",changes)) goto fail;
 changes=NULL;
 if (!cJSON_AddItemToObject(out,"engine_health_update",update)) goto fail;
 return out;
fail:
 cJSON_Delete(out); cJSON_Delete(changes); cJSON_Delete(update); cJSON_Delete(removed); return NULL;
}

int edr_health_upload(EdrHealthUpload *s, const char *body, uint64_t now_ns,
                      EdrHealthSend send, void *ctx) {
 if (!s || !body || !send) return -1;
 cJSON *full=cJSON_Parse(body), *delta=NULL, *response=NULL;
 char *full_wire=NULL, *delta_wire=NULL;
 int rc=-1, is_delta=0;
 char reply[2048]={0};
 cJSON *health=cJSON_GetObjectItemCaseSensitive(full,"engine_health");
 if (!cJSON_IsObject(full) || !cJSON_IsObject(health) ||
     cJSON_GetObjectItemCaseSensitive(full,"engine_health_update") ||
     cJSON_GetObjectItemCaseSensitive(health,"_health_transport")) goto done;
 if (unsafe_number(full)) {
  edr_health_upload_reset(s);
  s->full_bytes += strlen(body); s->attempt_bytes += strlen(body);
  rc=send(body,reply,sizeof(reply),ctx);
  if (rc==0) s->full_count++;
  goto done;
 }
 cJSON *stats=cJSON_AddObjectToObject(health,"health_upload");
 if (!stats || !cJSON_AddNumberToObject(stats,"full_count",(double)s->full_count) ||
     !cJSON_AddNumberToObject(stats,"delta_count",(double)s->delta_count) ||
     !cJSON_AddNumberToObject(stats,"resync_count",(double)s->resync_count) ||
     !cJSON_AddNumberToObject(stats,"attempt_body_bytes",(double)s->attempt_bytes) ||
     !cJSON_AddNumberToObject(stats,"equivalent_full_body_bytes",(double)s->full_bytes)) goto done;
 full_wire=cJSON_PrintUnformatted(full);
 if (!full_wire) goto done;
 if (s->base && s->revision[0] && same_identity(full,s->base) && now_ns >= s->full_at_ns &&
     now_ns-s->full_at_ns < 900ULL*1000000000ULL) {
  delta=make_delta(s,full);
  if (!delta) goto done;
  delta_wire=cJSON_PrintUnformatted(delta);
  if (!delta_wire) goto done;
  is_delta=strlen(delta_wire)<strlen(full_wire);
 }
 s->full_bytes += strlen(full_wire);
 s->attempt_bytes += strlen(is_delta ? delta_wire : full_wire);
 rc=send(is_delta ? delta_wire : full_wire,reply,sizeof(reply),ctx);
 response=cJSON_Parse(reply);
 const cJSON *error=cJSON_GetObjectItemCaseSensitive(response,"error");
 const cJSON *code=cJSON_GetObjectItemCaseSensitive(error,"code");
 if (!code) code=cJSON_GetObjectItemCaseSensitive(response,"code");
 if (rc != 0 && is_delta && cJSON_IsString(code) &&
     strcmp(code->valuestring,"ENGINE_HEALTH_BASE_MISMATCH")==0) {
  s->resync_count++;
  cJSON_Delete(response); response=NULL; reply[0]=0;
  s->attempt_bytes += strlen(full_wire);
  rc=send(full_wire,reply,sizeof(reply),ctx);
  response=cJSON_Parse(reply); is_delta=0;
 }
 if (rc != 0) goto done;
 if (is_delta) s->delta_count++; else { s->full_count++; s->full_at_ns=now_ns; }
 const cJSON *data=cJSON_GetObjectItemCaseSensitive(response,"data");
 const cJSON *version=cJSON_GetObjectItemCaseSensitive(data,"health_delta_version");
 const cJSON *revision=cJSON_GetObjectItemCaseSensitive(data,"health_revision");
 const cJSON *accepted=cJSON_GetObjectItemCaseSensitive(data,"accepted");
 if (cJSON_IsTrue(accepted) && cJSON_IsNumber(version) && version->valuedouble==1 &&
     cJSON_IsString(revision) && revision->valuestring[0] && strlen(revision->valuestring)<sizeof(s->revision)) {
  cJSON_Delete(s->base); s->base=full; full=NULL;
  strcpy(s->revision,revision->valuestring);
 } else { edr_health_upload_reset(s); }
done:
 if (rc != 0) edr_health_upload_reset(s);
 cJSON_Delete(full); cJSON_Delete(delta); cJSON_Delete(response);
 cJSON_free(full_wire); cJSON_free(delta_wire);
 return rc;
}
