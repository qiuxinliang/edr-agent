/**
 * 与《端点设计》§6.1 BehaviorEvent 对齐的内存表示（子集，供预处理 → 序列化）。
 */
#ifndef EDR_BEHAVIOR_RECORD_H
#define EDR_BEHAVIOR_RECORD_H

#include "types.h"

#include <stdint.h>

#define EDR_BR_STR_SHORT 256u
#define EDR_BR_STR_LONG 1024u
#define EDR_BR_STR_MID 512u
#define EDR_BR_ID_LEN 48u
#define EDR_BR_MAX_MITRE 8u

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
  char username[EDR_BR_STR_SHORT];
  uint32_t session_id;
  /** 自根向上的父链跳数（与平台 `process_chain_depth` / R-ANOM-001 对齐）；0=未算 */
  uint32_t process_chain_depth;
  EdrEventType type;
  uint32_t priority;

  char parent_name[EDR_BR_STR_SHORT];
  char parent_path[EDR_BR_STR_MID];

  char file_op[32];
  /** 《11》§5.3 维 35：文件类事件 MOTW；上报 `FileDetail.target_has_motw` */
  uint8_t file_target_has_motw;
  char file_path[EDR_BR_STR_LONG];
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
  char reg_op[32];

  char script_snippet[EDR_BR_STR_LONG];
  /** 最近一次 PMFE 扫描摘要（JSON，`edr_pid_history_pmfe_fill_record`）；无则空 */
  char pmfe_snapshot[512];

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
  char grandparent_name[EDR_BR_STR_SHORT];
  char grandparent_path[EDR_BR_STR_MID];
  char sibling_names[EDR_BR_STR_LONG];
  char child_pids[256];
  char network_isolation_level[32];
  char process_creation_time[64];
  char parent_creation_time[64];
  char command_line_origin[64];
  char encoded_command_type[32];
  char powershell_script_block[4096];
  char wmi_filter[512];
  char scheduled_task_path[1024];
} EdrBehaviorRecord;

void edr_behavior_record_init(EdrBehaviorRecord *r);

#endif
