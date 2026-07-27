#include "edr/agent_update_event.h"

#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
  return post_event(body_json, resp_body, resp_body_cap, NULL);
}

int main(void) {
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
  require_true(edr_agent_update_event_flush(dir, post_event, NULL, &acked) == 0,
               "unaccepted response retains event");
  s_accept = 1;
  require_true(edr_agent_update_event_flush_ingest(dir, &acked) == 1 && acked == 3,
               "accepted ingest response deletes retained event");
  acked = 0;
  require_true(edr_agent_update_event_flush(dir, post_event, NULL, &acked) == 0 && acked == 3,
               "empty outbox restores durable highest ACK checkpoint");
  char checkpoint[320];
  snprintf(checkpoint, sizeof(checkpoint), "%s/acked.seq", dir);
  unlink(checkpoint);
  rmdir(dir);
  puts("ok");
  return 0;
}
