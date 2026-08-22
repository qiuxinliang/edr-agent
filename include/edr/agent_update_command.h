#ifndef EDR_AGENT_UPDATE_COMMAND_H
#define EDR_AGENT_UPDATE_COMMAND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDR_AGENT_UPDATE_EXIT_UNSUPPORTED 95
#define EDR_AGENT_UPDATE_EXIT_LAUNCHED 96
#define EDR_AGENT_UPDATE_MAX_ARTIFACT_BYTES (256u * 1024u * 1024u)
#define EDR_AGENT_UPDATE_UPDATER_PROTOCOL_VERSION 5

typedef struct EdrAgentUpdateRuntimeInfo {
  int ready;
  int protocol_version;
  int materialized;
  char source[32];
  char version[65];
  char sha256[65];
  char error_code[64];
  int full_installer_ready;
  char full_installer_reason[96];
  char installation_family[32];
  char installation_baseline[65];
  char runtime_identity_sha256[65];
} EdrAgentUpdateRuntimeInfo;

typedef struct EdrAgentUpdateRecovery {
  char task_id[129];
  char command_id[129];
  char operation[16];
  char artifact_id[129];
  char artifact_sha256[65];
  char target_version[65];
  char status[32];
  char stage[64];
  char detail[1024];
  uint64_t last_event_seq;
  int succeeded;
  int exit_code;
  int terminal_event_acked;
  char installer_log_file[260];
  char installer_log_sha256[65];
  uint64_t installer_log_size;
  uint64_t installer_log_original_size;
  char installer_log_evidence_id[160];
  char installer_log_storage_key[512];
  char installer_evidence_status[32];
  char installer_artifact_json[2048];
} EdrAgentUpdateRecovery;

typedef int (*EdrAgentUpdateRecoveryUploadFn)(
    const char *command_id, const char *upload_id, const char *file_path,
    const char *sha256_hex, char *out_storage_key,
    size_t out_storage_key_cap, void *user);

typedef int (*EdrAgentUpdateRecoveryFlushFn)(
    const char *outbox_dir, uint64_t *last_acked_seq, void *user);

typedef struct EdrAgentUpdateRequest {
  char schema[32];
  char task_id[129];
  char campaign_id[129];
  char operation[16];
  char initiated_by[32];
  char artifact_id[129];
  char artifact_url[2049];
  char sha256[65];
  char target_version[65];
  char architecture[16];
  char internal_name[65];
  char publisher_thumbprint[129];
  char publisher_subject[257];
  char min_current_version[65];
  char max_current_version[65];
  char runtime_manifest_url[2049];
  char runtime_manifest_sha256[65];
  char upgrade_class[32];
  char deployment_mode[24];
  char scheduled_task_name[129];
  char scheduled_task_path[129];
  char service_name[129];
  uint64_t min_free_bytes;
  uint64_t issued_at_unix_ms;
  uint64_t deadline_unix_ms;
  uint64_t health_observe_ms;
} EdrAgentUpdateRequest;

int edr_agent_update_parse_request(const uint8_t *payload, size_t payload_len,
                                   EdrAgentUpdateRequest *out,
                                   char *reason, size_t reason_cap);
int edr_agent_update_semver_compare(const char *left, const char *right, int *comparison);
int edr_agent_update_journal_is_terminal(const char *status);
int edr_agent_update_journal_blocks_replacement(const char *stage);
int edr_agent_update_parse_journal(const char *json, EdrAgentUpdateRecovery *out);
int edr_agent_update_get_runtime_info(EdrAgentUpdateRuntimeInfo *info,
                                      char *script_path, size_t script_path_cap);
/* Executes the real platform adapters (filesystem, uninstall registry and
 * SCM/Task Scheduler identity) used by the manifest producer. */
int edr_agent_update_probe_full_installer_baseline(
    const char *installation_directory, char *reason, size_t reason_cap);
int edr_agent_update_resolve_script_path(char *out, size_t out_cap);
int edr_agent_update_create_directories(const char *path);
int edr_agent_update_execute(const char *command_id, const uint8_t *payload,
                             size_t payload_len, char *detail, size_t detail_cap);
int edr_agent_update_recover(const char *command_id, const uint8_t *payload,
                             size_t payload_len, EdrAgentUpdateRecovery *out);
/* Production recovery ordering boundary.  Installer evidence is uploaded and
 * durably indexed before terminal events may be flushed.  The callback form
 * keeps the safety sequence directly testable without duplicating it. */
int edr_agent_update_finalize_recovery(
    EdrAgentUpdateRecovery *recovery, const char *installer_log_path,
    const char *event_outbox_dir, EdrAgentUpdateRecoveryUploadFn upload,
    EdrAgentUpdateRecoveryFlushFn flush, void *user);

#ifdef __cplusplus
}
#endif

#endif
