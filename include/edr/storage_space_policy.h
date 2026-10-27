#ifndef EDR_STORAGE_SPACE_POLICY_H
#define EDR_STORAGE_SPACE_POLICY_H

#include "edr/config.h"
#include "edr/storage_physical_guard.h"
#include <stdio.h>

/* Shared by accepted startup configuration and the installer-only preflight.
 * Config parsing alone must never change the running process's storage policy. */
static inline int edr_storage_policy_setenv(const char *key, const char *value) {
#ifdef _WIN32
  return _putenv_s(key, value);
#else
  return setenv(key, value, 1);
#endif
}

enum EdrStoragePolicyInventory {
  EDR_STORAGE_POLICY_DEFAULTS,
  EDR_STORAGE_POLICY_STARTUP,
  EDR_STORAGE_POLICY_READ_ONLY
};

enum {
  EDR_STORAGE_POLICY_INVENTORY_LOCK_TIMEOUT = -3,
  EDR_STORAGE_POLICY_INVENTORY_LOCK_GRANTED_EXPIRED = -4,
  EDR_STORAGE_POLICY_INVENTORY_DEADLINE_BEFORE_REQUEST = -5
};

static inline int edr_storage_policy_apply(const EdrConfig *cfg, enum EdrStoragePolicyInventory inventory_owner) {
  char owner_bytes[32], free_mb[32], protected_bytes[32];
  EdrCommandStateCapacityStats owner = {0};
  if (!cfg) return -1;
  snprintf(owner_bytes, sizeof(owner_bytes), "%llu",
           (unsigned long long)cfg->offline.command_state_owner_budget_mb * 1024u * 1024u);
  snprintf(free_mb, sizeof(free_mb), "%u", cfg->offline.storage_min_free_mb);
  if (edr_storage_policy_setenv("EDR_COMMAND_STATE_OWNER_BUDGET_BYTES", owner_bytes) ||
      edr_storage_policy_setenv("EDR_STORAGE_MIN_FREE_MB", free_mb)) return -1;
  int owner_rc = inventory_owner ? (inventory_owner == EDR_STORAGE_POLICY_READ_ONLY
    ? edr_command_state_read_capacity_inventory(&owner)
    : edr_command_state_get_capacity_stats(&owner)) : 0;
  int unavailable = owner_rc != 0;
  if (unavailable) snprintf(protected_bytes, sizeof(protected_bytes), "unavailable");
  else snprintf(protected_bytes, sizeof(protected_bytes), "%llu",
                (unsigned long long)owner.protected_floor_bytes);
  if (edr_storage_policy_setenv("EDR_STORAGE_OWNER_PROTECTED_BYTES", protected_bytes)) return -1;
  if (inventory_owner == EDR_STORAGE_POLICY_READ_ONLY) {
    if(edr_storage_reservation_readonly_snapshot(unavailable ? UINT64_MAX : owner.artifact_reserved_bytes))
      return -2;
    if (owner_rc == EDR_COMMAND_STATE_INVENTORY_LOCK_TIMEOUT)
      return EDR_STORAGE_POLICY_INVENTORY_LOCK_TIMEOUT;
    if (owner_rc == EDR_COMMAND_STATE_INVENTORY_LOCK_GRANTED_EXPIRED)
      return EDR_STORAGE_POLICY_INVENTORY_LOCK_GRANTED_EXPIRED;
    if (owner_rc == EDR_COMMAND_STATE_INVENTORY_DEADLINE_BEFORE_REQUEST)
      return EDR_STORAGE_POLICY_INVENTORY_DEADLINE_BEFORE_REQUEST;
  }
  return unavailable ? -2 : 0;
}

#endif
