#include "edr/health_upload.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
 cJSON *latest;
 unsigned seq, calls, deltas;
 int fail, mismatch, legacy, invalid_ack;
} Server;
static int send_body(const char *body, char *reply, size_t cap, void *ctx) {
 Server *s=ctx; s->calls++;
 if (s->invalid_ack) { snprintf(reply,cap,"{\"data\":{\"accepted\":false}}"); return 0; }
 cJSON *root=cJSON_Parse(body); assert(root);
 const cJSON *health=cJSON_GetObjectItemCaseSensitive(root,"engine_health");
 const cJSON *update=cJSON_GetObjectItemCaseSensitive(root,"engine_health_update");
 if (s->fail || (s->mismatch && update)) {
  snprintf(reply,cap,"{\"code\":\"%s\"}",s->fail ? "UNAVAILABLE" : "ENGINE_HEALTH_BASE_MISMATCH");
  cJSON_Delete(root); return -1;
 }
 if (update) {
  assert(s->latest); s->deltas++;
  char revision[32]; snprintf(revision,sizeof(revision),"r%u",s->seq);
  assert(strcmp(cJSON_GetObjectItemCaseSensitive(update,"base")->valuestring,revision)==0);
  const cJSON *item;
  cJSON_ArrayForEach(item,cJSON_GetObjectItemCaseSensitive(update,"removed"))
   cJSON_DeleteItemFromObjectCaseSensitive(s->latest,item->valuestring);
  cJSON_ArrayForEach(item,health) {
   cJSON_DeleteItemFromObjectCaseSensitive(s->latest,item->string);
   assert(cJSON_AddItemToObject(s->latest,item->string,cJSON_Duplicate(item,1)));
  }
 } else { cJSON_Delete(s->latest); s->latest=cJSON_Duplicate(health,1); }
 s->seq++;
 snprintf(reply,cap,s->legacy ? "{\"data\":{\"accepted\":true}}" :
  "{\"data\":{\"accepted\":true,\"health_delta_version\":1,\"health_revision\":\"r%u\"}}",s->seq);
 cJSON_Delete(root); return 0;
}
static void equal_health(Server *s,const char *body) {
 cJSON *r=cJSON_Parse(body),*got=cJSON_Duplicate(s->latest,1);
 cJSON_DeleteItemFromObjectCaseSensitive(got,"health_upload");
 assert(cJSON_Compare(got,cJSON_GetObjectItemCaseSensitive(r,"engine_health"),1));
 cJSON_Delete(r); cJSON_Delete(got);
}
static int raw_send(const char *body, char *reply, size_t cap, void *ctx) {
 assert(strcmp(body,(const char *)ctx)==0);
 snprintf(reply,cap,"{\"data\":{\"accepted\":true,\"health_delta_version\":1,\"health_revision\":\"raw\"}}");
 return 0;
}
int main(void) {
 EdrHealthUpload state={0}; Server server={0};
 const char *a="{\"endpoint_id\":\"ep\",\"agent_version\":\"1\",\"policy_version\":\"p1\",\"engine_health\":{\"static\":\"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\",\"object\":{\"capability\":true},\"list\":[1,2],\"nullable\":1,\"removed\":{},\"number\":1}}";
 cJSON *r=cJSON_Parse(a), *h=cJSON_GetObjectItemCaseSensitive(r,"engine_health");
 cJSON_DeleteItemFromObjectCaseSensitive(h,"removed");
 cJSON_ReplaceItemInObjectCaseSensitive(h,"nullable",cJSON_CreateNull());
 cJSON_ReplaceItemInObjectCaseSensitive(h,"number",cJSON_CreateNumber(2));
 cJSON_ReplaceItemInObjectCaseSensitive(h,"object",cJSON_CreateObject());
 cJSON *list=cJSON_Parse("[2,1]");cJSON_ReplaceItemInObjectCaseSensitive(h,"list",list);
 char *b=cJSON_PrintUnformatted(r);cJSON_Delete(r);
 assert(edr_health_upload(&state,a,1,send_body,&server)==0);equal_health(&server,a);
 assert(edr_health_upload(&state,b,60000000001ULL,send_body,&server)==0);equal_health(&server,b);
 assert(state.full_count==1 && state.delta_count==1 && server.deltas==1);
 /* A lost server base causes exactly one full recovery in the same call. */
 server.mismatch=1;unsigned before=server.calls;
 assert(edr_health_upload(&state,a,120000000001ULL,send_body,&server)==0);
 assert(server.calls==before+2 && state.resync_count==1);equal_health(&server,a);
 server.mismatch=0;
 /* Ambiguous failure invalidates the local base; never advance from an ACK
  * that might not have committed or that the client did not receive. */
 server.fail=1;before=server.calls;
 assert(edr_health_upload(&state,b,180000000001ULL,send_body,&server)!=0);
 assert(server.calls==before+1 && state.base==NULL);
 server.fail=0;
 assert(edr_health_upload(&state,b,240000000001ULL,send_body,&server)==0);equal_health(&server,b);
 unsigned deltas=server.deltas;
 assert(edr_health_upload(&state,a,1140000000001ULL,send_body,&server)==0);
 assert(server.deltas==deltas); /* periodic full checkpoint */
 server.legacy=1;edr_health_upload_reset(&state);
 assert(edr_health_upload(&state,a,1200000000001ULL,send_body,&server)==0);
 assert(edr_health_upload(&state,b,1260000000001ULL,send_body,&server)==0);
 assert(state.base==NULL && server.deltas==deltas);
 server.legacy=0;
 assert(edr_health_upload(&state,a,1300000000001ULL,send_body,&server)==0);
 r=cJSON_Parse(a);cJSON_ReplaceItemInObjectCaseSensitive(r,"endpoint_id",cJSON_CreateString("other"));
 char *other=cJSON_PrintUnformatted(r);cJSON_Delete(r);
 assert(edr_health_upload(&state,other,1310000000001ULL,send_body,&server)==0);
 assert(server.deltas==deltas); /* endpoint identity changed */
 assert(state.attempt_bytes>0 && state.full_bytes>0);
 server.invalid_ack=1;uint64_t acknowledged=state.full_count+state.delta_count;
 assert(edr_health_upload(&state,a,1315000000001ULL,send_body,&server)!=0);
 assert(state.base==NULL && state.full_count+state.delta_count==acknowledged);
 server.invalid_ack=0;
 const char *wide="{\"endpoint_id\":\"ep\",\"engine_health\":{\"wide\":18446744073709551615}}";
 assert(edr_health_upload(&state,wide,1320000000001ULL,raw_send,(void *)wide)==0);
 assert(state.base==NULL);
 edr_health_upload_reset(&state);cJSON_Delete(server.latest);cJSON_free(b);cJSON_free(other);
 return 0;
}
