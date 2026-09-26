#ifndef EDR_PREPROCESS_H
#define EDR_PREPROCESS_H

#include "edr/config.h"
#include "edr/behavior_record.h"
#include "edr/error.h"

#include <stdint.h>

struct EdrEventBus;
struct EdrDetectionDecision;
/* Evidence owner sees every evaluated record, independent of upload selection
 * and deduplication. Returns nonzero only for telemetry admission. */
int edr_preprocess_admit_telemetry(const EdrBehaviorRecord *record,
                                  const struct EdrDetectionDecision *decision);
/* Called after local detectors and evidence capture. A false result skips only
 * the ordinary standalone upload; P0 combined/source-only delivery is separate. */
int edr_preprocess_upload_admit(const EdrBehaviorRecord *record,
                               const struct EdrDetectionDecision *decision,
                               int p0_proven_miss, int local_forensics_dispatched);
uint64_t edr_preprocess_baseline_rename_upload_skipped_count(void);
uint64_t edr_preprocess_baseline_file_upload_skipped_count(void);

/** cfg 为 NULL 时使用 edr_config_apply_defaults 等价默认值 */
EdrError edr_preprocess_start(struct EdrEventBus *bus, const EdrConfig *cfg);
/** 1 only after the worker exited and pending batches were durably handed off.
 * A 0 result retains resources and forbids restart/owner teardown. */
int edr_preprocess_stop(void);

/** 运行中更新预处理参数（当前：去重/限流）；不涉及批次缓冲重建。 */
void edr_preprocess_apply_config(const EdrConfig *cfg);
void edr_preprocess_apply_sampling_pct(uint32_t pct);

/** 拷贝当前缓存的 agent endpoint_id / tenant_id（供行为告警批次编码与 §12.4 对齐）。 */
void edr_preprocess_copy_agent_ids(char *endpoint_id, size_t endpoint_cap, char *tenant_id, size_t tenant_cap);

uint64_t edr_preprocess_sampling_dropped_count(void);
uint64_t edr_preprocess_sampling_kept_count(void);
uint32_t edr_preprocess_sampling_pct(void);

/** getenv(key) 按十进制解析为 int；未设置或空串则返回 defv（供预处理链与 P0 IR 等共用）。 */
int edr_getenv_int_default(const char *key, int defv);

#endif
