#ifndef EDR_SHUTDOWN_PROGRESS_H
#define EDR_SHUTDOWN_PROGRESS_H

/* Fixed diagnostic stages, not elapsed-time promises or subsystem success.
 * Only the Windows service owner publishes these to SCM during STOP_PENDING.
 * A skipped/no-op subsystem may pass its phase; NULL leaves other owners alone.
 * Values are explicit so a sampler can bind a checkpoint to this source. */
typedef enum {
    EDR_SHUTDOWN_STOP_REQUESTED = 1,
    EDR_SHUTDOWN_MAIN_LOOP_EXITED = 2,
    EDR_SHUTDOWN_FORENSIC_ABORT_RETURNED = 3,
    EDR_SHUTDOWN_WATCHDOG_STOP_RETURNED = 4,
    EDR_SHUTDOWN_COLLECTOR_ENTERED = 5,
    EDR_SHUTDOWN_ETW_CONTROL_RETURNED = 6,
    EDR_SHUTDOWN_REGISTRY_STOP_SIGNAL_RETURNED = 7,
    EDR_SHUTDOWN_SECURITY_CLOSE_RETURNED = 8,
    EDR_SHUTDOWN_ETW_JOIN_PHASE_DONE = 9,
    EDR_SHUTDOWN_REGISTRY_JOIN_PHASE_DONE = 10,
    EDR_SHUTDOWN_A44_JOIN_PHASE_DONE = 11,
    EDR_SHUTDOWN_NETWORK_TRACE_STOP_RETURNED = 12,
    EDR_SHUTDOWN_COLLECTOR_CLEANUP_DONE = 13,
    EDR_SHUTDOWN_AGENT_RUN_DRAIN_DONE = 14,
    EDR_SHUTDOWN_CONTROL_TRANSPORT_STOPPED = 15,
    EDR_SHUTDOWN_RESULT_DELIVERY_STOPPED = 16,
    EDR_SHUTDOWN_COMMAND_WORKERS_STOPPED = 17,
    EDR_SHUTDOWN_PREPROCESS_STOPPED = 18,
    EDR_SHUTDOWN_SHUTDOWN_STATS_DONE = 19,
    EDR_SHUTDOWN_PMFE_STOP_RETURNED = 20,
    EDR_SHUTDOWN_SHELLCODE_STOP_RETURNED = 21,
    EDR_SHUTDOWN_WEBSHELL_STOP_RETURNED = 22,
    EDR_SHUTDOWN_NET_FANOUT_STOP_RETURNED = 23,
    EDR_SHUTDOWN_TELEMETRY_STOPPED = 24,
    EDR_SHUTDOWN_VALIDATION_TRACE_STOP_RETURNED = 25,
    EDR_SHUTDOWN_EVIDENCE_CACHE_CLOSE_RETURNED = 26,
    EDR_SHUTDOWN_QUEUE_CLOSE_RETURNED = 27,
    EDR_SHUTDOWN_AGENT_DESTROY_RETURNED = 28
} EdrShutdownStage;

typedef struct {
    void (*report)(void *context, EdrShutdownStage stage);
    void *context;
} EdrShutdownObserver;

static inline void edr_shutdown_progress(const EdrShutdownObserver *observer,
                                         EdrShutdownStage stage) {
    if (observer && observer->report) {
        observer->report(observer->context, stage);
    }
}
#endif
