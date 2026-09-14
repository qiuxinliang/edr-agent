#include "edr/process_evidence_pending.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static uint64_t s_ready_generation;
static unsigned s_timeouts;
void edr_process_evidence_note_wait_timeout(void) { s_timeouts++; }
int edr_process_evidence_poll(const char *path, uint64_t generation, uint64_t now, EdrProcessEvidence *out) {
  (void)now;
  assert(strcmp(path, "C:\\Fixture\\original.exe") == 0);
  memset(out, 0, sizeof(*out));
  if (generation != s_ready_generation) return 0;
  strcpy(out->hash_quality, "captured");
  strcpy(out->sha256, "fixture-hash");
  return 1;
}
int main(void) {
  EdrBehaviorRecord r = {0}, out;
  EdrEventSlot slot = {0}, out_slot;
  EdrProcessEvidence initial = {0}, result;
  int has_slot;
  r.pid = 10u;
  r.process_start_key = 1u;
  r.process_creation_filetime_100ns = 111u;
  strcpy(r.exe_path, "C:\\Fixture\\original.exe");
  strcpy(r.event_id, "fixture-original");
  memset(r.cmdline, 'a', sizeof(r.cmdline) - 1u);
  slot.priority = 1u;
  slot.size = 2u;
  slot.data[0] = 8u;
  strcpy(initial.file_identity, "fixture-identity");
  initial.file_write_time = 123u;
  assert(edr_process_evidence_pending_add(&r, &slot, &initial, 100u));
  strcpy(r.event_id, "mutated-caller");
  slot.data[0] = 9u;
  assert(!edr_process_evidence_pending_take(101u, 0, &out, &out_slot, &has_slot, &result));
  /* A ready second generation is not held behind an earlier slow request. */
  r.process_start_key = 2u;
  assert(edr_process_evidence_pending_add(&r, NULL, &initial, 101u));
  s_ready_generation = 2u;
  assert(edr_process_evidence_pending_take(102u, 0, &out, &out_slot, &has_slot, &result));
  assert(out.process_start_key == 2u && !has_slot);
  assert(strcmp(result.sha256, "fixture-hash") == 0);
  assert(strcmp(result.file_identity, "fixture-identity") == 0);
  assert(edr_process_evidence_pending_take(1000000100u, 0, &out, &out_slot, &has_slot, &result));
  assert(strcmp(out.event_id, "fixture-original") == 0);
  assert(strlen(out.cmdline) == sizeof(out.cmdline) - 1u);
  assert(out.process_start_key == 1u && has_slot && out_slot.data[0] == 8u);
  assert(strcmp(result.hash_reason, "evidence_wait_timeout") == 0);
  assert(s_timeouts == 1u);
  s_ready_generation = 0u;
  for (unsigned i=0; i<EDR_PROCESS_EVIDENCE_CAPACITY; ++i)
    assert(edr_process_evidence_pending_add(&r, NULL, &initial, 1000000200u));
  assert(!edr_process_evidence_pending_add(&r, NULL, &initial, 1000000200u));
  unsigned cancelled = 0u;
  while (edr_process_evidence_pending_take(1000000201u, 1, &out, &out_slot, &has_slot, &result)) {
    assert(strcmp(result.hash_reason, "shutdown_cancelled") == 0);
    cancelled++;
  }
  assert(cancelled == EDR_PROCESS_EVIDENCE_CAPACITY);
  assert(s_timeouts == 1u);
  assert(edr_process_evidence_pending_add(&r, NULL, &initial, 1000000202u));
  assert(edr_process_evidence_pending_take(1000000203u, 1, &out, &out_slot, &has_slot, &result));
  return 0;
}
