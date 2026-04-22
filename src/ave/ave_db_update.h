/**
 * L2/L3 规则库最小热写入（SQLite），供 AVE_UpdateWhitelist / AVE_UpdateIOC 使用。
 */
#ifndef EDR_AVE_DB_UPDATE_H
#define EDR_AVE_DB_UPDATE_H

#include "edr/error.h"

struct EdrConfig;

/**
 * **白名单** `entries_json`：
 * - JSON 字符串数组：`["64位hex", ...]`
 * - JSON 对象数组（仅取 `sha256`）：`[{"sha256":"64位hex"}, ...]`
 * - 非 `[` 开头：裸 hex 列表（空白 / `,` / `;` 分隔，或连续 128 字符为两条）
 */
EdrError edr_ave_update_whitelist_json(const struct EdrConfig *cfg, const char *entries_json);

/**
 * **IOC** `ioc_json`：
 * - 字符串数组 / 裸 hex：每条 **`severity=3`**
 * - 对象数组：`[{"sha256":"...","severity":2}, ...]`（`severity` 可选，缺省为 3；合法值 **1–3**）
 */
EdrError edr_ave_update_ioc_json(const struct EdrConfig *cfg, const char *ioc_json);

#endif
