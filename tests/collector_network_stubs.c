/* Isolate unrelated consumers, never admission, identity validation or TDH
 * decoding. No ETW session, network traffic or response action is started. */
#include "collector_network_test.h"
#include "edr/ave_sdk.h"
#include "edr/edr_a44_split_path_win.h"
#include "edr/etw_observability_win.h"
#include "edr/policy_v2.h"
#include "edr/pmfe.h"
#include "edr/process_tree_cache.h"
#include "edr/sensor_interest.h"
#include "../src/collector/ave_etw_feed_win.h"
#include <assert.h>
#include <stdlib.h>
void edr_correlation_observe_interest(const EdrSensorInterestEvent *event) { (void)event; }
void edr_ave_etw_feed_from_event(EVENT_RECORD *record, EdrEventType type,
                                uint64_t at, const char *ip, const char *domain) {
  assert(record && type == EDR_EVENT_NET_CONNECT && at && ip && !domain);
}
int edr_policy_v2_ransomware_enabled(const char *control) { abort(); }
void edr_isolate_auto_from_ransom_alarm(const EdrBehaviorRecord *record) { abort(); }
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
