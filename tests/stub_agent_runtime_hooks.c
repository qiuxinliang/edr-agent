/**
 * Test-only runtime hooks for AVE pipeline/link tests. These tests exercise the
 * behavior pipeline without linking the full command dispatcher or resource
 * monitor.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "edr/command.h"

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
