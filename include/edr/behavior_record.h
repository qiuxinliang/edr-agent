/**
 * 与《端点设计》§6.1 BehaviorEvent 对齐的内存表示（子集，供预处理 → 序列化）。
 */
#ifndef EDR_BEHAVIOR_RECORD_H
#define EDR_BEHAVIOR_RECORD_H

#include "types.h"

#include <stdint.h>
#include <stddef.h>

#define EDR_BR_STR_SHORT 256u
#define EDR_BR_STR_LONG 4096u
#define EDR_BR_STR_MID 512u
#define EDR_BR_ID_LEN 48u
#define EDR_BR_MAX_MITRE 8u
/* Source-side omissions are named explicitly before any protobuf projection.
 * Keep this below the wire field capacity so a complete bounded list can be
 * carried alongside independently detected transport clipping. */
#define EDR_BR_SOURCE_TRUNCATED_FIELDS_LEN 384u

typedef struct {
  char event_id[EDR_BR_ID_LEN];
  char endpoint_id[EDR_BR_ID_LEN];
  char tenant_id[64];
  int64_t event_time_ns;
  uint32_t pid;
  uint32_t ppid;
  char process_name[EDR_BR_STR_SHORT];
  char cmdline[EDR_BR_STR_LONG];
  char exe_hash[65];
  char exe_path[EDR_BR_STR_LONG];
  /* Original Windows path and its resolution state are retained separately.
   * An unresolved device namespace path is not safe for path-rule evaluation. */
  char image_path_raw[EDR_BR_STR_LONG];
  char image_path_canonical[EDR_BR_STR_LONG];
  char image_path_namespace[32];
  char image_path_resolution_status[32];
  char image_path_resolution_source[32];
  char source_completeness[32];
  /* Comma-delimited `source.<field>` names withheld before rule evaluation.
   * This is source provenance, distinct from encoder-side clipping. */
  char source_truncated_fields[EDR_BR_SOURCE_TRUNCATED_FIELDS_LEN];
  uint32_t evidence_revision;
  char username[EDR_BR_STR_SHORT];
  /* effective process identity; username/domain retain their legacy meaning. */
  char user_sid[EDR_BR_STR_SHORT];
  char logon_id[64];
  char creator_username[EDR_BR_STR_SHORT];
  char creator_domain[EDR_BR_STR_SHORT];
  char creator_sid[EDR_BR_STR_SHORT];
  char creator_logon_id[64];
  /* target_4688 > token_sid > cache > creator_fallback > none */
  char identity_source[32];
  char identity_quality[32];
  uint32_t session_id;
  /** 自根向上的父链跳数（与平台 `process_chain_depth` / R-ANOM-001 对齐）；0=未算 */
  uint32_t process_chain_depth;
  EdrEventType type;
  /* Internal source provenance. Never serialized: Security EventLog 4688 must
   * not become authoritative process-tree lifecycle evidence. */
  uint8_t is_security_4688;
  uint32_t priority;

  char parent_name[EDR_BR_STR_SHORT];
  char parent_path[EDR_BR_STR_MID];
  char parent_resolution_status[32];
  char parent_resolution_source[32];

  char file_op[32];
  /** 《11》§5.3 维 35：文件类事件 MOTW；上报 `FileDetail.target_has_motw` */
  uint8_t file_target_has_motw;
  char file_path[EDR_BR_STR_LONG];
  char file_old_path[EDR_BR_STR_LONG];
  /* Kernel-File FileKey is meaningful only with the event-time NameCreate
   * binding.  It is retained internally so a collector evidence gate can
   * report precisely which binding could not be held; it is not a rule
   * predicate. It is serialized in typed gate or FileWrite provenance only. */
  uint64_t file_key;
  /* Internal provenance: never accepted from an ETW1 key or serialized. */
  uint8_t kernel_file_write;
  uint8_t kernel_file_activity;
  uint8_t file_actor_generation_validated;
  uint8_t file_activity_enriched;
  /* Internal collector snapshot. The ransomware counter may consume it only
   * after exact process-generation validation succeeds. */
  uint64_t ransom_sample_process_start_key;
  float ransom_content_entropy;
  uint32_t ransom_content_sample_bytes;
  uint8_t ransom_content_sampled;
  /* A collector capability gate is source-only metadata, never a rule hit.
   * The reason is constrained by p0_source_only_contract.h before it crosses
   * the durable queue. */
  char collector_evidence_gate[64];
  char collector_evidence_reason[96];
  char net_src[64];
  char net_dst[64];
  uint32_t net_sport;
  uint32_t net_dport;
  char net_proto[16];
  /** 少数 network 规则用 `file_path_regex_any` 时对 `NetworkAuxPath` 求值（与平台 payload 一致） */
  char network_aux_path[EDR_BR_STR_LONG];

  char dns_query[EDR_BR_STR_MID];
  /** 注册表（ETW Kernel-Registry → `RegistryDetail` / payload category=registry） */
  char reg_key_path[1024];
  char reg_value_name[512];
  char reg_value_data[8192];
  char reg_old_value_data[2048];
  char reg_op[32];
  char reg_source[48];
  char reg_attribution[32];
  char reg_detail_status[48];

  char script_snippet[EDR_BR_STR_LONG];
  /** 最近一次 PMFE 扫描摘要（JSON，`edr_pid_history_pmfe_fill_record`）；无则空 */
  char pmfe_snapshot[512];
  /** 轻量检测决策（JSON）：组合评分、降噪原因，供服务端/前端稳定消费。 */
  char detection_context[4096];

  /**
   * 《11》§5.5 维 56：证书链祖先吊销（0/1）。可由 ETW1 载荷键 **`cert_revoked_ancestor` / `cert_ra`** 注入，
   * 或由上游证书子系统写入；**`behavior_proto.c`** 填入 **`AveBehaviorEventFeed.cert_revoked_ancestor`**。
   */
  uint8_t cert_revoked_ancestor;

  char mitre_ttps[EDR_BR_MAX_MITRE][16];
  int mitre_ttp_count;

  /* 取证增强字段 */
  char hostname[EDR_BR_STR_SHORT];
  char domain[EDR_BR_STR_SHORT];
  char desktop_session[EDR_BR_STR_SHORT];
  uint32_t desktop_session_id;
  char current_directory[EDR_BR_STR_LONG];
  char logon_guid[64];
  uint64_t logon_time_ns;
  char integrity_level[32];
  uint32_t token_elevation;
  char process_path_hash[65];
  char parent_cmdline[EDR_BR_STR_LONG];
  uint32_t grandparent_pid;
  char grandparent_name[EDR_BR_STR_SHORT];
  char grandparent_path[EDR_BR_STR_MID];
  char sibling_names[EDR_BR_STR_LONG];
  char child_pids[256];
  char network_isolation_level[32];
  char process_creation_time[64];
  /* Target process generation key. For Kernel-Process Start this comes from
   * the event payload; for actor events it may come from the ETW extended
   * header. The two sources are never interchangeable. */
  uint64_t process_start_key;
  /* Raw Windows FILETIME from the target process payload or a validated live
   * ProcessTelemetryIdInformation query. */
  uint64_t process_creation_filetime_100ns;
  char process_generation_source[64];
  char parent_creation_time[64];
  char command_line_origin[64];
  char encoded_command_type[32];
  char powershell_script_block[4096];
  char wmi_filter[512];
  char scheduled_task_path[1024];
} EdrBehaviorRecord;

void edr_behavior_record_init(EdrBehaviorRecord *r);

int edr_behavior_source_field_truncated(const EdrBehaviorRecord *r, const char *field);
void edr_behavior_mark_source_truncated(EdrBehaviorRecord *r, const char *field);
/* Only after replacing this field from a verified complete fact. Does not
 * clear other loss markers, list overflow, or NOT_EVALUABLE. */
void edr_behavior_resolve_source_truncated(EdrBehaviorRecord *r, const char *field);

void edr_behavior_record_enrich_system_context(EdrBehaviorRecord *r);

/** Security EventLog process-create observations carry useful identity but are
 * not authoritative process lifecycle evidence for process_tree_cache. */
int edr_process_create_is_lifecycle_authoritative(const EdrBehaviorRecord *r);

/** Event families whose PID denotes the process actor. This selects context
 * work only; callers must independently validate the process generation. */
int edr_behavior_has_process_actor(const EdrBehaviorRecord *r);

/** Preserve the nanosecond representation used by process-generation edges.
 * Output is empty when the input or destination cannot represent it. */
void edr_behavior_format_time_ns(int64_t ns, char *out, size_t cap);

#endif
