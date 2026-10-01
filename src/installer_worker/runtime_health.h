#ifndef EDR_INSTALLER_RUNTIME_HEALTH_H
#define EDR_INSTALLER_RUNTIME_HEALTH_H

/* A point-in-time presence check; detector/connection health is separate. */
typedef enum {
  EDR_HEALTH_UNKNOWN, EDR_HEALTH_MISSING, EDR_HEALTH_PRESENT,
  EDR_HEALTH_RUNNING, EDR_HEALTH_STOPPED, EDR_HEALTH_PENDING, EDR_HEALTH_PAUSED
} EdrHealthState;

static const char *edr_health_state_name(EdrHealthState state) {
  static const char *names[] = {"unknown", "missing", "present", "running", "stopped", "pending", "paused"};
  return state >= EDR_HEALTH_UNKNOWN && state <= EDR_HEALTH_PAUSED ? names[state] : "unknown";
}

static const char *edr_health_presence_status(EdrHealthState config, EdrHealthState binary,
                                             EdrHealthState process, EdrHealthState service,
                                             int service_required) {
  if (config == EDR_HEALTH_MISSING || binary == EDR_HEALTH_MISSING ||
      process == EDR_HEALTH_MISSING ||
      (service_required && (service == EDR_HEALTH_MISSING || service == EDR_HEALTH_STOPPED)))
    return "failed";
  if (config == EDR_HEALTH_UNKNOWN || binary == EDR_HEALTH_UNKNOWN ||
      process == EDR_HEALTH_UNKNOWN || (service_required && service == EDR_HEALTH_UNKNOWN))
    return "unknown";
  if (service_required && service != EDR_HEALTH_RUNNING) return "warning";
  return "ok";
}
#endif
