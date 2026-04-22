#ifndef EDR_PREPROCESS_H
#define EDR_PREPROCESS_H

#include "edr/config.h"
#include "edr/error.h"

struct EdrEventBus;

/** cfg 为 NULL 时使用 edr_config_apply_defaults 等价默认值 */
EdrError edr_preprocess_start(struct EdrEventBus *bus, const EdrConfig *cfg);
void edr_preprocess_stop(void);

/** 运行中更新预处理参数（当前：去重/限流）；不涉及批次缓冲重建。 */
void edr_preprocess_apply_config(const EdrConfig *cfg);

/** 拷贝当前缓存的 agent endpoint_id / tenant_id（供行为告警批次编码与 §12.4 对齐）。 */
void edr_preprocess_copy_agent_ids(char *endpoint_id, size_t endpoint_cap, char *tenant_id, size_t tenant_cap);

#endif
