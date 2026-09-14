/* External consumers only. TDH, cache lifetimes, resolver, slot construction,
 * source-only staging and ETW1 projection all use their production code.
 * Keep unreachable service dependencies explicit: some PE linkers retain
 * their references even with function-level garbage collection enabled. */
#include "collector_file_io_test.h"
#include "edr/adaptive_collection.h"
#include "edr/ave_sdk.h"
#include "edr/command.h"
#include "edr/edr_a44_split_path_win.h"
#include "edr/etw_observability_win.h"
#include "edr/p0_rule_ir.h"
#include "edr/pmfe.h"
#include "edr/policy_v2.h"
#include "edr/process_tree_cache.h"
#include "edr/sensor_interest.h"
#include "../src/collector/ave_etw_feed_win.h"
#include <assert.h>
#include <stdlib.h>

/* Every intact fixture path is interesting. This isolates binding behavior
 * from the machine's installed rules without skipping collector admission. */
int edr_p0_rule_ir_file_read_path_may_match(const char *path, uint64_t *epoch) {
  assert(path && path[0]);
  if (epoch) *epoch = 1u;
  return 1;
}

int edr_sensor_interest_should_admit(const EdrSensorInterestEvent *event) {
  assert(event && event->type == EDR_EVENT_FILE_READ && event->path[0]);
  return 1;
}

void edr_ave_etw_feed_from_event(EVENT_RECORD *record, EdrEventType type,
                                uint64_t at, const char *ip, const char *domain) {
  assert(record && type == EDR_EVENT_FILE_READ && at);
  assert(!ip && !domain);
}

/* An unexpected side effect or entry into another event family is a test
 * failure, not a successful mock operation. abort also works with NDEBUG. */
int edr_policy_v2_ransomware_enabled(const char *control) { abort(); }
void edr_isolate_auto_from_ransom_alarm(const EdrBehaviorRecord *record) { abort(); }
int edr_p0_rule_ir_br_matches_any(const EdrBehaviorRecord *record) { abort(); }
int edr_p0_rule_ir_is_interesting_remote_port(uint32_t port) { abort(); }
int edr_p0_rule_ir_is_interesting_process_name(const char *name) { abort(); }
int edr_adaptive_collection_should_admit_record(const EdrBehaviorRecord *record) { abort(); }
void edr_adaptive_collection_get_status(EdrAdaptiveCollectionStatus *status) { abort(); }
void edr_sensor_interest_lazy_init(void) { abort(); }
void edr_sensor_interest_get_status(EdrSensorInterestStatus *status) { abort(); }
void edr_pmfe_on_process_lifecycle_hint(void) { abort(); }
int edr_pt_cache_mark_exit_generation(uint32_t pid, uint64_t key, uint64_t at) { abort(); }
void AVE_CALL AVE_NotifyProcessExit(uint32_t pid) { abort(); }
void edr_etw_observability_on_slot_payload_empty(void) { abort(); }
void edr_etw_observability_on_callback(const char *tag) { abort(); }
uint64_t edr_event_bus_dropped_total(EdrEventBus *bus) { abort(); }
int edr_a44_split_path_enabled(void) { abort(); }
EdrError edr_a44_split_path_start(EdrEventBus *bus) { abort(); }
int edr_a44_split_path_stop(void) { abort(); }
int edr_a44_item_pack(EVENT_RECORD *r, uint64_t at, EdrEventType type,
                      const char *tag, EdrA44QueueItem *out, int *reason) { abort(); }
int edr_a44_try_push(const EdrA44QueueItem *item) { abort(); }
void edr_a44_note_sync_fallback(void) { abort(); }
void edr_a44_item_to_event_record(const EdrA44QueueItem *item, EVENT_RECORD *record) { abort(); }
