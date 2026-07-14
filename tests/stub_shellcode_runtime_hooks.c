#include "edr/command.h"
#include "edr/event_bus.h"
#include "edr/resource.h"
#include "edr/transport_v2.h"

#include <stddef.h>

/* The Windows shellcode unit targets compile the real capture adapter without
 * linking the full Agent runtime. These hooks keep that boundary explicit. */
bool edr_event_bus_try_push(EdrEventBus *bus, const EdrEventSlot *slot) {
  (void)bus;
  (void)slot;
  return true;
}

int edr_transport_v2_upload_file(const char *upload_id, const char *file_path,
                                 const char *sha256_hex, char *out_minio_key,
                                 size_t out_minio_key_cap) {
  (void)upload_id;
  (void)file_path;
  (void)sha256_hex;
  if (out_minio_key && out_minio_key_cap > 0u) {
    out_minio_key[0] = '\0';
  }
  return -1;
}

void edr_isolate_auto_from_shellcode_alarm(void) {}

bool edr_resource_preprocess_throttle_active(void) {
  return false;
}
