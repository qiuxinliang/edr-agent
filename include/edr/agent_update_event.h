#ifndef EDR_AGENT_UPDATE_EVENT_H
#define EDR_AGENT_UPDATE_EVENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EdrAgentUpdateEventContext {
  char task_id[129];
  char campaign_id[129];
  char command_id[129];
  char operation[16];
  char artifact_id[129];
  char artifact_sha256[65];
  char target_version[65];
} EdrAgentUpdateEventContext;

typedef int (*EdrAgentUpdateEventPostFn)(const char *body_json, char *response,
                                         size_t response_cap, void *user);

void edr_agent_update_event_default_dir(char *out, size_t cap);
int edr_agent_update_event_persist(const char *outbox_dir,
                                   const EdrAgentUpdateEventContext *context,
                                   uint64_t event_seq, const char *status,
                                   int progress, const char *detail_json,
                                   const char *reported_at);
int edr_agent_update_event_flush(const char *outbox_dir,
                                 EdrAgentUpdateEventPostFn post_fn, void *user,
                                 uint64_t *last_acked_seq);
int edr_agent_update_event_flush_ingest(const char *outbox_dir,
                                        uint64_t *last_acked_seq);

#ifdef __cplusplus
}
#endif

#endif
