#include "edr/agent_update_event.h"
#include "edr/egress_request_policy.h"

#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

static int s_calls;
static uint64_t s_seq[8];
static int s_accept = 1;

static void require_true(int value, const char *message) {
  if (!value) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}

static int post_event(const char *body, char *response, size_t response_cap, void *user) {
  (void)user;
  cJSON *root = cJSON_Parse(body);
  const cJSON *task = cJSON_GetObjectItemCaseSensitive(root, "task_id");
  const cJSON *command = cJSON_GetObjectItemCaseSensitive(root, "command_id");
  const cJSON *event_id = cJSON_GetObjectItemCaseSensitive(root, "event_id");
  const cJSON *seq = cJSON_GetObjectItemCaseSensitive(root, "event_seq");
  const cJSON *detail = cJSON_GetObjectItemCaseSensitive(root, "detail");
  require_true(cJSON_IsString(task) && strcmp(task->valuestring, "task-1") == 0,
               "event task identity serialized");
  require_true(cJSON_IsString(command) && strcmp(command->valuestring, "cmd-1") == 0,
               "event command identity serialized");
  require_true(cJSON_IsString(event_id) && strstr(event_id->valuestring, "cmd-1-"),
               "stable event id serialized");
  require_true(cJSON_IsNumber(seq) && cJSON_IsObject(detail), "event sequence and detail serialized");
  require_true(cJSON_IsString(cJSON_GetObjectItemCaseSensitive(detail, "artifact_id")),
               "artifact identity included in detail");
  s_seq[s_calls++] = (uint64_t)seq->valuedouble;
  snprintf(response, response_cap, "%s", s_accept ? "{\"accepted\":true}" : "{\"accepted\":false}");
  cJSON_Delete(root);
  return 0;
}

int edr_ingest_http_post_json_suffix(const char *suffix, const char *body_json,
                                     char *resp_body, size_t resp_body_cap) {
  require_true(strcmp(suffix, "ingest/agent-upgrade-event") == 0,
               "ingest flush uses upgrade-event suffix");
  char why[128];
  require_true(edr_egress_request_validate_for_scope("POST",suffix,"application/json",body_json,strlen(body_json),"tenant","ep",why,sizeof(why))==0,"actual final scoped gate accepts minimal event");
  require_true(edr_egress_request_validate_for_scope("POST",suffix,"application/json",body_json,strlen(body_json),"other","ep",why,sizeof(why))==EDR_EGRESS_REQUEST_DENIED,"cross-tenant event denied");
  return post_event(body_json, resp_body, resp_body_cap, NULL);
}

static int policy_result;
static int task_scope(const char *id,EdrEgressTaskScope *out) {
  if(policy_result)return policy_result;
  memset(out,0,sizeof(*out));
  snprintf(out->tenant_id,sizeof(out->tenant_id),"tenant");snprintf(out->endpoint_id,sizeof(out->endpoint_id),"ep");
  snprintf(out->command_id,sizeof(out->command_id),"%s",id);snprintf(out->task_id,sizeof(out->task_id),"task-1");
  snprintf(out->operation,sizeof(out->operation),"upgrade");snprintf(out->artifact_id,sizeof(out->artifact_id),"artifact-1");
  snprintf(out->artifact_sha256,sizeof(out->artifact_sha256),"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  snprintf(out->target_version,sizeof(out->target_version),"2.1.0");return 0;
}
static int denied_post(const char *body,char *response,size_t cap,void *user) {
  (void)body;(void)response;(void)cap;(void)user;s_calls++;return policy_result;
}
int main(int argc,char **argv) {
  edr_egress_set_task_scope_lookup(task_scope);
  if(argc==3 && !strcmp(argv[1],"--held-restart")) {
    uint64_t acked=0;
    require_true(edr_agent_update_event_flush_ingest(argv[2],&acked)==EDR_EGRESS_PAYLOAD_POLICY_HELD && acked==4 && s_calls==0,"exec restart keeps payload hold without reading/sending first event");
    return 0;
  }
  char dir[256];
  snprintf(dir, sizeof(dir), "/tmp/edr-agent-update-event-%ld", (long)getpid());
  mkdir(dir, 0700);
  EdrAgentUpdateEventContext context;
  memset(&context, 0, sizeof(context));
  snprintf(context.task_id, sizeof(context.task_id), "task-1");
  snprintf(context.campaign_id, sizeof(context.campaign_id), "campaign-1");
  snprintf(context.command_id, sizeof(context.command_id), "cmd-1");
  snprintf(context.operation, sizeof(context.operation), "upgrade");
  snprintf(context.artifact_id, sizeof(context.artifact_id), "artifact-1");
  snprintf(context.artifact_sha256, sizeof(context.artifact_sha256),
           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  snprintf(context.target_version, sizeof(context.target_version), "2.1.0");

  require_true(edr_agent_update_event_persist(dir, &context, 2, "downloaded", 20,
                                               "{\"stage\":\"downloaded\"}", NULL) == 0,
               "seq 2 persisted atomically");
  require_true(edr_agent_update_event_persist(dir, &context, 1, "downloading", 5,
                                               "{\"stage\":\"downloading\"}", NULL) == 0,
               "seq 1 persisted atomically");
  uint64_t acked = 0;
  require_true(edr_agent_update_event_flush(dir, post_event, NULL, &acked) == 2,
               "pending events flushed");
  require_true(s_calls == 2 && s_seq[0] == 1 && s_seq[1] == 2 && acked == 2,
               "events flush in sequence order");

  require_true(edr_agent_update_event_persist(dir, &context, 3, "verified", 35,
                                               "{}", NULL) == 0,
               "seq 3 persisted");
  s_accept = 0;
  require_true(edr_agent_update_event_flush(dir, post_event, NULL, &acked) == EDR_EGRESS_OUTCOME_UNKNOWN,
               "unaccepted response is unknown and retains event");
  s_accept = 1;
  require_true(edr_agent_update_event_flush_ingest(dir, &acked) == 1 && acked == 3,
               "accepted ingest response deletes retained event");
  acked = 0;
  require_true(edr_agent_update_event_flush(dir, post_event, NULL, &acked) == 0 && acked == 3,
               "empty outbox restores durable highest ACK checkpoint");
  require_true(edr_agent_update_event_persist(dir,&context,4,"failed",100,"{\"stage\":\"artifact_download\",\"error\":\"secret URL\"}",NULL)==0,"failed event persisted with local evidence");
  policy_result=EDR_EGRESS_REQUEST_DENIED;int calls=s_calls;
  for(int i=0;i<3;i++)require_true(edr_agent_update_event_flush(dir,denied_post,NULL,&acked)==EDR_EGRESS_REQUEST_DENIED && acked==3,"policy hold does not ACK");
  require_true(s_calls==calls+1,"held restart/polls do not reread or post first event");
  policy_result=EDR_EGRESS_PAYLOAD_POLICY_HELD;
  /* Explicit scope renewal retries an authorization hold; payload hold remains sticky. */
  policy_result=0;require_true(edr_agent_update_event_flush_ingest(dir,&acked)==1 && acked==4,"renewed scope resumes original minimal bytes");
  require_true(edr_agent_update_event_persist(dir,&context,5,"verified",35,"{}",NULL)==0,"legacy event fixture");
  char legacy_path[512];snprintf(legacy_path,sizeof(legacy_path),"%s/cmd-1-%020u.pending.json",dir,5u);
  FILE *legacy=fopen(legacy_path,"rb");require_true(legacy!=NULL,"legacy wire open");char original[4096];size_t original_len=fread(original,1,sizeof(original)-1u,legacy);fclose(legacy);original[original_len]=0;
  cJSON *wide=cJSON_Parse(original);cJSON_AddStringToObject(cJSON_GetObjectItemCaseSensitive(wide,"detail"),"unrelated","preserve locally");char *wide_wire=cJSON_PrintUnformatted(wide);cJSON_Delete(wide);
  legacy=fopen(legacy_path,"wb");require_true(legacy && fputs(wide_wire,legacy)>=0 && fclose(legacy)==0,"legacy wide bytes persisted");
  calls=s_calls;
  for(int i=0;i<3;i++)require_true(edr_agent_update_event_flush_ingest(dir,&acked)==EDR_EGRESS_PAYLOAD_POLICY_HELD && acked==4,"legacy payload hold retains ACK");
  require_true(s_calls==calls,"legacy wire is never transmitted");
  pid_t child=fork();require_true(child>=0,"fork restart");
  if(!child){execl(argv[0],argv[0],"--held-restart",dir,(char*)NULL);_exit(127);}
  int status=0;require_true(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0,"fresh process reopens durable hold");
  legacy=fopen(legacy_path,"rb");size_t after_len=fread(original,1,sizeof(original)-1u,legacy);fclose(legacy);original[after_len]=0;require_true(!strcmp(original,wide_wire),"legacy original bytes unchanged");free(wide_wire);
  char checkpoint[320];
  snprintf(checkpoint, sizeof(checkpoint), "%s/acked.seq", dir);
  unlink(checkpoint);
  rmdir(dir);
  puts("ok");
  return 0;
}
