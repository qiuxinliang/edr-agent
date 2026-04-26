/**
 * A4.4 第二期（仅 Windows、默认关）：`EDR_A44_SPLIT_PATH=1` 时 ETW 收/解 有界分径，见
 * Cauld `ADR_A4.4_ETW_Receive_Path_Decouple.md` v0.3+。
 */
#ifndef EDR_EDR_A44_SPLIT_PATH_WIN_H
#define EDR_EDR_A44_SPLIT_PATH_WIN_H

#if defined(_WIN32)
#include "edr/error.h"
#include "edr/event_bus.h"
#include "edr/types.h"
#include <evntcons.h>
#include <stdint.h>

#ifndef EDR_A44_MAX_USERDATA
#define EDR_A44_MAX_USERDATA 32768u
#endif

/** 有界入队一帧。解线程栈上 `EVENT_RECORD::UserData` 指向本副本 `ud`。 */
typedef struct {
  uint64_t ts_ns;
  EdrEventType ty;
  char tag[16];
  EVENT_HEADER evh;
  uint16_t udlen;
  uint16_t edcount;
  uint8_t resv[4];
  uint64_t buffer_context;
  uint8_t ud[EDR_A44_MAX_USERDATA];
} EdrA44QueueItem;

int edr_a44_split_path_enabled(void);
EdrError edr_a44_split_path_start(EdrEventBus *bus);
void edr_a44_split_path_stop(void);

/**
 * 填 `out`。reason_sync：0=可入队 1=ExtendedData 非 0 须同步 2=UserData 超长须同步
 * 成功返回 0；否则不填可入队字段。
 */
int edr_a44_item_pack(PEVENT_RECORD r, uint64_t ts_ns, EdrEventType ty, const char *tag, EdrA44QueueItem *out,
                      int *reason_sync);

int edr_a44_try_push(const EdrA44QueueItem *it);
uint64_t edr_a44_dropped_total(void);
void edr_a44_item_to_event_record(const EdrA44QueueItem *it, EVENT_RECORD *er);

#endif /* _WIN32 */
#endif /* EDR_EDR_A44_SPLIT_PATH_WIN_H */
