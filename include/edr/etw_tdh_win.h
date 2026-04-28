/**
 * TDH 解析辅助（§3.1.3）— 仅 Windows / 仅 collector 内部使用。
 */
#ifndef EDR_ETW_TDH_WIN_H
#define EDR_ETW_TDH_WIN_H

#if !defined(_WIN32)
#error etw_tdh_win is Windows-only
#endif

#include <stddef.h>
#include <stdint.h>
#include <windows.h>

#include <guiddef.h>
#include <basetsd.h>
#include <initguid.h>
#include <ntdef.h>

#include <evntcons.h>

#include "edr/types.h"
#include <stdint.h>

/**
 * 将 TDH 读出的属性写入 slot 载荷：文本格式 `ETW1\nkey=value\n...`，UTF-8。
 * 始终写入 `pid=`（来自 EVENT_RECORD 头）与 `prov=`（Provider 简名）。
 * 返回写入字节数（含结尾 0）；失败则写回原始 UserData 截断副本并返回其长度。
 * A3.3：可选 `EDR_TDH_LIGHT_PATH=1`（**仅** DNS-Client 省 `QueryType` Tdh 调用，见 `README`）；
 * 另 **`EDR_TDH_LIGHT_PATH_PS=1`**：PowerShell 先 `ScriptBlockText` 再全量，须 会签 v1.1+ / 白名单（见 Cauld）。
 */
size_t edr_tdh_build_slot_payload(PEVENT_RECORD rec, const char *prov_tag,
                                  uint8_t *out, size_t out_cap);

/**
 * 从网络/DNS 类 ETW 记录提取远端 IP、DNS 查询名（UTF-8），供 `AVEBehaviorEvent.target_*` 与 IOC 匹配。
 * 无则保持空串。返回非 0 表示已尝试解析。
 */
size_t edr_tdh_extract_ave_net_fields(PEVENT_RECORD rec, EdrEventType ty, char *ip_out, size_t ip_cap,
                                      char *dom_out, size_t dom_cap);

/**
 * 可观测性（A1）：TdhGetProperty* 失败累加 与 成功写出一行 UTF-8 的条数，用于粗算失败率与压力。
 * 在 ETW 热路径中调用，为 Interlocked 计数。
 */
void edr_tdh_win_get_property_stats(int64_t *out_tdh_api_err, int64_t *out_tdh_line_ok);

#endif
