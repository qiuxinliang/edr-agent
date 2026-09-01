/**
 * 从 p0_rule_bundle_ir_v1.json 加载 P0 条件（B2.1），用 PCRE2 对 command_* 与 *_regex 求值，语义对齐
 * edr-backend `internal/dynamicrules`（process_create / file_read|file_write / network_connect / registry_set）。
 * 生产/发布构建必须链接经契约验证的静态 PCRE2。唯一的无 PCRE2 实现是显式
 * 非生产 CTest source-only 桩：它 fail-closed，不会回退到 legacy 启发式。
 */
#ifndef EDR_P0_RULE_IR_H
#define EDR_P0_RULE_IR_H

#include <stddef.h>
#include <stdint.h>
#include "edr/behavior_record.h"

/* One Agent-owned matcher contract.  The release PCRE2 producer hashes this
 * header and exports these literals, so a backend provenance record cannot
 * name a parser schema, capacity, or source grammar that this binary does
 * not actually compile. */
#define EDR_P0_MATCHER_SOURCE_SCHEMA "edr.dynamic-rules.source.v1"
#define EDR_P0_MATCHER_RULE_SCHEMA "edr_p0_rule_bundle_ir_v1@2"
#define EDR_P0_RULE_IR_BUNDLE_KIND "edr_p0_rule_bundle_ir_v1"
#define EDR_P0_RULE_IR_SCHEMA_VERSION 2u
#define EDR_P0_RULE_IR_MAX_RULES 256u

typedef struct {
  char rules_bundle_version[128];
  char artifact_sha256[65];
  char sensor_interest_manifest_sha256[65];
  char sensor_interest_manifest_hash_mode[64];
  uint32_t rule_count;
  uint64_t snapshot_epoch;
} EdrP0RuleIrBinding;

/* A direct P0 emission must never compose its rule ID, metadata, and bundle
 * identity from separately acquired snapshots.  This copied result is built
 * while one immutable IR snapshot is retained; callers own `matches` and
 * release it with edr_p0_rule_ir_evaluation_free(). */
typedef struct {
  char rule_id[64];
  char title[512];
  char mitre_csv[512];
  int severity;
} EdrP0RuleIrMatch;

/* This is bounded by the parser's EDR_P0_RULE_IR_MAX_RULES.  The public fixed bound
 * lets an evaluation retain an immutable snapshot without allocating on the
 * ETW/preprocess hot path. */
#define EDR_P0_RULE_IR_MAX_MATCHES EDR_P0_RULE_IR_MAX_RULES

typedef struct {
  EdrP0RuleIrBinding binding;
  uint16_t match_indices[EDR_P0_RULE_IR_MAX_MATCHES];
  uint32_t match_count;
  /* Opaque retained immutable snapshot; release only through
   * edr_p0_rule_ir_evaluation_free(). */
  void *snapshot;
} EdrP0RuleIrEvaluation;

enum {
  EDR_P0_IR_FULL_ADMISSION_FILE_READ = 1u << 0,
  EDR_P0_IR_FULL_ADMISSION_FILE_WRITE = 1u << 1,
  EDR_P0_IR_FULL_ADMISSION_REGISTRY_SET = 1u << 2,
};

/* 在首次需匹配时惰性加载；可多次调用。 */
void edr_p0_rule_ir_lazy_init(void);

/* 热重载：清空已加载规则，重新从外部文件 / embed 加载。 */
void edr_p0_rule_ir_reload(void);

/* Retire the active snapshot.  In-flight readers complete before its regex
 * objects are released; a later lazy init may load a fresh snapshot. */
void edr_p0_rule_ir_shutdown(void);

/* Fully decrypt/parse/compile a file in an isolated candidate without
 * modifying the active ruleset.  Returns 1 only for a usable candidate. */
int edr_p0_rule_ir_validate_candidate_path(const char *path);

/* Atomically install a fully validated same-filesystem staged bundle.  The
 * staged file is fsynced, then renamed to destination before its immutable
 * candidate becomes active.  On failure both prior disk and memory state are
 * retained; the caller owns cleanup of the staged path. */
int edr_p0_rule_ir_install_staged_bundle(const char *staged_path, const char *destination_path);

#if defined(EDR_P0_RULE_IR_TESTING)
/* Inject the Nth parent-directory durability barrier failure.  The test seam
 * verifies that an after-rename failure restores the previous on-disk bundle
 * before the candidate is published. */
void edr_p0_rule_ir_test_fail_parent_sync_after(unsigned int nth_call);
/* Fail `count` consecutive parent-directory barriers beginning at `nth_call`.
 * Used to model a failed rollback durability barrier after a failed rename
 * commit; production code must recover it on the next lifecycle start. */
void edr_p0_rule_ir_test_fail_parent_sync_after_count(unsigned int nth_call,
                                                      unsigned int count);
/* Pause candidate I/O/parse/compile while the publication mutex is held.
 * This proves the paired SensorInterest admission reader is never held by a
 * slow ruleset reload. */
void edr_p0_rule_ir_test_pause_preparation(int pause);
int edr_p0_rule_ir_test_preparation_paused(void);
#endif

/* 获取 P0 bundle 目标路径（edr_config/ 下的 .json 文件）。返回值 0=成功，-1=无法解析路径。 */
int edr_p0_bundle_dst_path(char *out, size_t cap);

/* 1 = 已从 JSON 成功编译至少一条 P0 规则。 */
int edr_p0_rule_ir_is_ready(void);
int edr_p0_rule_ir_get_bundle_info(const char **out_source, size_t *out_plain_size, const char **out_plain_sha256);
/* Returns 1 only when no unresolved P0 artifact transaction has disabled the
 * matcher.  `out_reason` receives a stable, non-secret capability reason. */
int edr_p0_rule_ir_artifact_healthy(char *out_reason, size_t out_reason_cap);
/* SensorInterest uses these only for a durably unresolved manifest
 * transaction.  They disable direct P0 enforcement while leaving the raw
 * collector fail-full, and they never overwrite an IR-artifact failure. */
void edr_p0_rule_ir_set_sensor_artifact_terminal_unhealthy(const char *reason);
void edr_p0_rule_ir_clear_sensor_artifact_terminal_unhealthy(void);
/* Immutable binding for consumers whose pre-filter contract must be derived
 * from the exact active P0 artifact rather than a separately supplied hint.
 * This accessor never lazy-initializes: callers inside the paired sensor
 * admission reader must receive "unavailable" rather than upgrade to writer. */
int edr_p0_rule_ir_get_binding(EdrP0RuleIrBinding *out_binding);
/* SensorInterest holds this read-side guard while it decides whether a raw
 * provider event may be narrowed.  IR publication takes the paired writer
 * side before changing generation, so an event is evaluated wholly against
 * the old pair or conservatively retained for the new one. */
void edr_p0_rule_ir_sensor_admission_lock(void);
void edr_p0_rule_ir_sensor_admission_unlock(void);
uint64_t edr_p0_rule_ir_sensor_admission_generation(void);
/* Evaluate a source record and retain one immutable snapshot plus its exact
 * binding.  Match indexes are bounded and allocation-free; copy an immutable
 * descriptor out with edr_p0_rule_ir_evaluation_get_match() before emitting.
 * Returns 1 for a usable snapshot (including zero matches), 0 otherwise. */
int edr_p0_rule_ir_evaluate_record(const EdrBehaviorRecord *br,
                                   EdrP0RuleIrEvaluation *out_evaluation);
int edr_p0_rule_ir_evaluation_get_match(const EdrP0RuleIrEvaluation *evaluation,
                                        uint32_t index,
                                        EdrP0RuleIrMatch *out_match);
void edr_p0_rule_ir_evaluation_free(EdrP0RuleIrEvaluation *evaluation);
/* Conservative collector-admission requirements derived from the active
 * matcher.  A regex or an unbounded path predicate cannot be narrowed safely
 * before the full IR evaluation. */
unsigned edr_p0_rule_ir_required_full_admission_mask(void);

/* 在 IR 已就绪时，对单条已加载规则按 rule_id 求值（仅对 event_type=process_create 有效；对拍/legacy）。 */
int edr_p0_rule_ir_matches(
    const char *rule_id, const char *process_name, const char *cmdline, const char *parent_name, int process_chain_depth);

/* 为直出取元数据；若未加载或无该 id 则返回 0 且 *title=*mitre= 置空。 */
int edr_p0_rule_ir_get_meta(const char *rule_id, const char **out_title, const char **out_mitre_csv);
int edr_p0_rule_ir_get_severity(const char *rule_id);

/* 已加载且 event_type=process_create 的规则条数（供直出遍历）。 */
int edr_p0_rule_ir_process_create_count(void);

int edr_p0_rule_ir_process_create_id_at(int index, const char **out_id);

/* 已加载规则总条数（各 event_type）。 */
int edr_p0_rule_ir_rule_count(void);
int edr_p0_rule_ir_rule_id_at(int index, const char **out_id);
/* 根据 br 的 type 与规则 event_type 是否一致 + 条件求值；用于直出遍历。 */
int edr_p0_rule_ir_br_matches_index(const EdrBehaviorRecord *br, int index);
/* 采集/缓存前置降噪：判断事件、端口或进程名是否落入 P0 动态规则兴趣面。 */
int edr_p0_rule_ir_br_matches_any(const EdrBehaviorRecord *br);
int edr_p0_rule_ir_is_interesting_remote_port(uint32_t port);
int edr_p0_rule_ir_is_interesting_process_name(const char *process_name);

/* Conservative metadata-lane projection for Kernel-File NameCreate.  It
 * evaluates only the immutable snapshot's file_read path predicates and
 * deliberately ignores process/user predicates: false positives are safe,
 * a false negative would let a later FileRead lose its FileKey binding.  A
 * missing/invalid snapshot or an unbounded file_read rule returns 1. */
int edr_p0_rule_ir_file_read_path_may_match(const char *path, uint64_t *out_snapshot_epoch);

/* P0规则命中率统计 - 性能优化辅助数据 */
void edr_p0_rule_ir_stats_record(int rule_idx, int hit);
void edr_p0_rule_ir_stats_dump(void);
void edr_p0_rule_ir_stats_init(void);

#endif
