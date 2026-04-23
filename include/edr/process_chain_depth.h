/**
 * 为 `EdrBehaviorRecord` 填 `process_chain_depth`（与平台 `payload_json.process_chain_depth` 对齐）。
 */
#ifndef EDR_PROCESS_CHAIN_DEPTH_H
#define EDR_PROCESS_CHAIN_DEPTH_H

#include "edr/behavior_record.h"

void edr_behavior_record_fill_process_chain_depth(EdrBehaviorRecord *r);

#endif
