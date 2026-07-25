/**
 * Test-only runtime hooks for AVE pipeline/link tests. These tests exercise the
 * behavior pipeline without linking the full command dispatcher or resource
 * monitor.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "edr/command.h"
#include "edr/command_executor.h"
#include "edr/command_state.h"

bool edr_resource_preprocess_throttle_active(void) {
  return false;
}

void edr_command_on_envelope(const char *command_id, const char *command_type, const uint8_t *payload,
                             size_t payload_len, const EdrSoarCommandMeta *soar_meta) {
  (void)command_id;
  (void)command_type;
  (void)payload;
  (void)payload_len;
  (void)soar_meta;
}

void edr_command_on_internal_envelope(const char *command_id, const char *command_type,
                                      const uint8_t *payload, size_t payload_len,
                                      const EdrSoarCommandMeta *soar_meta) {
  edr_command_on_envelope(command_id, command_type, payload, payload_len, soar_meta);
}

int edr_command_receive_envelope(const char *command_id, const char *command_type,
                                 const uint8_t *payload, size_t payload_len,
                                 const EdrSoarCommandMeta *soar_meta) {
  (void)command_id;
  (void)command_type;
  (void)payload;
  (void)payload_len;
  (void)soar_meta;
  return 0;
}

void edr_command_executor_wake(void) {}

void edr_command_audit_both(const char *cmd_id, const char *msg) {
  (void)cmd_id;
  (void)msg;
}

int edr_command_state_upsert_pending_ack(const EdrControlAckRecord *record) {
  (void)record;
  return 0;
}

int edr_command_state_collect_pending_acks(EdrControlAckRecord *out, size_t cap) {
  (void)out;
  (void)cap;
  return 0;
}

void edr_command_state_delete_pending_ack(const char *command_id) {
  (void)command_id;
}
