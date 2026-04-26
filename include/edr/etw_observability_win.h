/**
 * Windows ETW 可观测性（A1）：回调次数、按 prov_tag 分桶、payload 建失败、与总线 push/drop 同读。
 * 行输出由 EDR_ETW_OBS=1 触发，与 console heartbeat 同周期（见 EDR_CONSOLE_HEARTBEAT_SEC，建议 60）。
 * 设 EDR_ETW_OBS_EXPORT_PATH=本地文件路径 时，同一行**追加**写入该文件（需与 EDR_ETW_OBS 同用；供 shipper/基线归档）。
 */
#ifndef EDR_ETW_OBSERVABILITY_WIN_H
#define EDR_ETW_OBSERVABILITY_WIN_H

#if !defined(_WIN32)
#error etw observability is Windows-only
#endif

#include <stdint.h>

struct EdrEventBus;

void edr_etw_observability_on_callback(const char *prov_tag);
void edr_etw_observability_on_slot_payload_empty(void);
/** A4.4 第一期：=1 时在 ETW 回调里累计 pre-TDH / TDH / 总线 的 QPC 用时（与 `edr_etw_observability_print_line` 输出）。默认关。 */
int edr_etw_observability_a44_cb_phase_meas_enabled(void);
void edr_etw_observability_add_a44_phase_ns(unsigned phase, int64_t ns);
void edr_etw_observability_print_line(const struct EdrEventBus *bus);

#endif
