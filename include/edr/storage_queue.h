/**
 * §10 离线队列 — SQLite（可选编译）；用于批次落盘与后续补传。
 */
#ifndef EDR_STORAGE_QUEUE_H
#define EDR_STORAGE_QUEUE_H

#include <stddef.h>
#include <stdint.h>

#include "edr/error.h"

/** 打开/创建队列库；path 为 NULL 时使用 ./edr_queue.db */
EdrError edr_storage_queue_open(const char *path);
void edr_storage_queue_close(void);

/** 打开前设置容量和 TTL；0 表示沿用环境变量/默认。 */
void edr_storage_queue_configure(uint32_t max_db_mb, uint32_t retention_hours);

/** 是否已成功打开 SQLite 队列（用于 on_fail 策略仅在库可用时入队） */
int edr_storage_queue_is_open(void);

/* A P0 source-only admission fault means the endpoint could not preserve the
 * only fail-closed disposition for a collector/ruleset capability.  The
 * latch is one fixed row in the queue database (queue_meta), not a second
 * queue, outbox, sidecar, or worker.  Its CSPRNG queue nonce and signed
 * counter identify a capability-loss audit across database recreation and
 * restarts; the normal event_queue owns the actual source record. */
#define EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES 16u
#define EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_EVENT_ID_MAX 96u
#define EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_BATCH_ID_MAX 128u

typedef struct {
  uint8_t queue_nonce[EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES];
  uint64_t latch_counter;
  uint64_t latch_epoch;
  char recovery_event_id[EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_EVENT_ID_MAX];
  char recovery_batch_id[EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_BATCH_ID_MAX];
  int latched;
  int recovery_required;
} EdrStorageQueueP0SourceOnlyLatch;

/* Persists a latch before a severity-2 record is attempted.  If another
 * latch is already awaiting its central ACK, this conservatively converts it
 * to recovery-required before accepting another source assertion. */
EdrError edr_storage_queue_p0_source_only_latch_prepare(
    EdrStorageQueueP0SourceOnlyLatch *out);
int edr_storage_queue_p0_source_only_latch_is_set(void);
EdrError edr_storage_queue_p0_source_only_latch_get(
    EdrStorageQueueP0SourceOnlyLatch *out);
/* Inserts/replays one severity-2 event and binds it to a prepared latch in
 * the same FULL transaction.  The matching latch is cleared only later by
 * the central 2xx ACK's event_queue DELETE transaction. */
EdrError edr_storage_queue_p0_source_only_enqueue_bound(
    const EdrStorageQueueP0SourceOnlyLatch *expected, const char *event_id,
    const char *batch_id, const uint8_t *payload, size_t payload_len,
    int compressed, int recovery_audit);
/* Proves one FULL queue transaction without modifying a latch.  A historic
 * latch is never cleared by this probe; recovery waits for its central ACK. */
EdrError edr_storage_queue_p0_source_only_recovery_probe(void);

/* A matched P0 rule that cannot proceed while its owning event family is
 * unhealthy is retained in the queue database before the live record is
 * released.  The snapshot is opaque, versioned JSON owned by the P0 codec;
 * this layer verifies only durable identity, size and SHA-256 integrity.
 *
 * Keys are exactly the 64-character SHA-256 of payload_json. Family masks
 * may contain only the four currently defined family bits (0x01..0x08).
 * Retaining the same key/family/payload is idempotent in pending, failed and
 * completed states; reusing a key for different content is rejected.
 * Pending and failed snapshots share the retained-payload owner limit below;
 * fail preserves its existing slot and never needs another admission. Neither
 * state expires. Completed tombstones release the payload slot but still
 * count toward logical bytes until the configured retention TTL removes them.
 * Deferred admission shares terminal priority/reserve, excluding the dedicated
 * P0 source-only reserve. */
#define EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_HEX_LEN 64u
#define EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_BUFSIZE 65u
#define EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_RETAINED 1024u
#define EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_PAYLOAD_BYTES (512u * 1024u)
EdrError edr_storage_queue_p0_deferred_retain(
    const char key_hex[EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_BUFSIZE],
    uint32_t family_mask, const uint8_t *payload_json, size_t payload_len);
/* Durable ownership survives event_queue ACK deletion and covers every
 * deferred state. Returns 0 absent, 1 owned, or -1 on error. */
int edr_storage_queue_p0_deferred_contains(const char *key_hex);
/* Returns 1 with malloc-owned payload, 0 when no due healthy-family row is
 * available, and -1 on error.  Corrupt durable rows are moved to failed while
 * preserving their payload, then selection continues so poison cannot starve
 * later snapshots. */
int edr_storage_queue_p0_deferred_peek(
    uint32_t healthy_family_mask,
    char key_out[EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_BUFSIZE],
    uint8_t **payload_out, size_t *payload_len_out);
/* Atomically hands a replay result to severity-1 event_queue storage and
 * replaces the large snapshot with a completed dedup tombstone.  batch_id and
 * wire must either both be supplied or both be NULL.  A no-wire completion
 * requires a non-empty reason such as policy_denied/governor_suppressed. */
EdrError edr_storage_queue_p0_deferred_complete(
    const char key_hex[EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_BUFSIZE],
    const char *batch_id, const uint8_t *wire, size_t wire_len,
    const char *reason);
/* Explicitly terminally isolates a snapshot that cannot be safely replayed.
 * The original payload and digest remain durable for operator diagnosis. */
EdrError edr_storage_queue_p0_deferred_fail(
    const char key_hex[EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_BUFSIZE],
    const char *reason);
/* Schedules another replay using durable exponential backoff capped at 60s. */
EdrError edr_storage_queue_p0_deferred_retry(
    const char key_hex[EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_BUFSIZE],
    const char *reason);

/**
 * 持久化一批：payload 为 §6.2 完整 wire（12 字节头 + 体），与 ReportEvents 一致，便于出队补传。
 * compressed: 与传输层一致，仅作记录。
 * severity: ordinary traffic is 0; terminal ownership is 1; P0 source-only
 * capability evidence is 2.  Values 1 and 2 are both sent as high priority,
 * but capacity admission keeps a small lane for value 2 so terminal replay
 * cannot consume the only durable space for a collector/ruleset fail-closed
 * disposition.
 */
#define EDR_STORAGE_QUEUE_SEVERITY_ORDINARY 0
#define EDR_STORAGE_QUEUE_SEVERITY_TERMINAL 1
#define EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY 2
EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,
                                   size_t payload_len, int compressed, int severity);

/* A block-policy action has two terminal audit frames: the source/result and
 * its combined alert.  The intent is committed before execution; an exact
 * replay returns EXISTING and must not perform the action again. */
typedef enum {
  EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR = 0,
  EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED = 1,
  EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING = 2,
  EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT = -1,
} EdrEnforcementTerminalPrecreate;

typedef struct {
  uint64_t pending;
  uint64_t backpressure;
  uint64_t failed;
  /* Valid calls while the queue is open. Every durable precreate resolution
   * has one outcome: attempts = created + existing + conflicts + rejected +
   * transaction_failures. `commit_failures` is a subset of the latter.
   * `existing` is an exact terminal replay; callers must not execute again. */
  uint64_t precreate_requests;
  uint64_t precreate_attempts;
  uint64_t precreate_created;
  uint64_t precreate_existing;
  uint64_t precreate_conflicts;
  uint64_t precreate_rejected;
  uint64_t precreate_transaction_failures;
  uint64_t precreate_commit_failures;
  /* A corrupt durable idempotency key matched the persisted owner digest.
   * The row is quarantined and this call resolves
   * as CONFLICT, never CREATED, so the action cannot execute again. */
  uint64_t precreate_metadata_corruption_failures;
  /* Legacy owner metadata was already corrupt before an immutable digest
   * existed. The durable latch blocks precreate rather than treating that
   * unknown owner as absent; zero is healthy and one is fail-closed. */
  uint64_t owner_metadata_unresolved;
  uint64_t outcome_unknown;
  /* A selected durable frame could not be copied or read for replay because
   * local resources/SQLite were transiently unavailable. The row remains in
   * its pending/ready state and its frame retry counter records the retry. */
  uint64_t replay_selection_transient_failures;
  /* A durable row selected for replay had impossible required metadata
   * (empty idempotency or batch id). It is quarantined by immutable row id so
   * one poison row cannot starve later terminal evidence. */
  uint64_t replay_metadata_corruption_failures;
} EdrEnforcementTerminalJournalMetrics;

/* Logical live bytes are the admission authority. Database, WAL, and SHM
 * sidecars remain diagnostics because SQLite physical files are high-water
 * allocations and cannot safely decide whether an empty queue may accept new
 * evidence. Ordinary events stop before the reserved P0 lane; high-priority
 * evidence may use that lane but never deletes pending ordinary evidence. */
typedef struct {
  uint64_t db_bytes;
  uint64_t wal_bytes;
  uint64_t shm_bytes;
  uint64_t physical_bytes;
  /* Logical live allocation is the admission authority; physical SQLite
   * files are high-water diagnostics and do not strand an empty queue. */
  uint64_t used_bytes;
  uint64_t max_bytes;
  uint64_t ordinary_limit_bytes;
  /* `critical_reserve_bytes` is the total excluded from ordinary admission.
   * The two component fields make terminal versus P0 source-only ownership
   * observable to health and capacity tests. */
  uint64_t critical_reserve_bytes;
  uint64_t terminal_reserve_bytes;
  uint64_t p0_source_only_reserve_bytes;
  uint64_t ordinary_rejected;
  uint64_t high_priority_rejected;
  uint64_t p0_source_only_rejected;
  /* Direct edr_storage_queue_enqueue calls only. Exact matching rows are
   * current durable replays, not new admissions:
   * requests = reused + conflicts + admission_attempts;
   * admission_attempts = admitted + capacity_rejected + transaction_failures.
   * A commit failure is a transaction-failure subset. */
  uint64_t enqueue_requests;
  uint64_t enqueue_reused;
  uint64_t enqueue_conflicts;
  uint64_t enqueue_admission_attempts;
  uint64_t enqueue_admitted;
  uint64_t enqueue_capacity_rejected;
  uint64_t enqueue_transaction_failures;
  uint64_t enqueue_commit_failures;
  /* Replay lifecycle counters make every durable handoff stage observable:
   * selected rows either remain pending, are ACK-deleted, or receive an
   * explicit terminal disposition. `sent` counts actual transport calls. */
  uint64_t delivery_selected;
  uint64_t delivery_sent;
  uint64_t delivery_acked;
  uint64_t delivery_requeued;
  uint64_t delivery_failed;
  /* Durable event_queue batch metadata that cannot safely cross SQLite TEXT
   * to the C-string transport boundary is terminally isolated by row id.
   * This is a process-lifetime counter; the row's status/reason is durable. */
  uint64_t event_queue_metadata_corruption_failures;
  /* Retention removes completed/ordinary records only; capacity never evicts
   * a pending record to make room for a later producer. */
  uint64_t retention_evicted_rows;
  uint64_t pending_rows;
  /* Matched P0 snapshots awaiting replay or retained after an explicit unsafe
   * replay decision. Their payload bytes and the metadata-only completed
   * tombstones contribute to used_bytes; only completed tombstones follow the
   * configured retention TTL (72h by default). */
  uint64_t p0_deferred_pending_rows;
  uint64_t p0_deferred_failed_rows;
  uint64_t oldest_pending_created_unix_s;
  uint64_t oldest_pending_age_s;
  /* 10,000 = 100%. When max_bytes is zero the queue is deliberately
   * unbounded, so utilization_bps is 0 rather than a percentage. */
  uint32_t utilization_bps;
  uint32_t accounting_available;
} EdrStorageQueueCapacityMetrics;

EdrEnforcementTerminalPrecreate edr_storage_queue_enforcement_terminal_precreate(
    const char *idempotency_key, const char *source_event_key, const char *rule_id,
    const char *process_generation_key, const char *intent_batch_id, const uint8_t *intent_wire,
    size_t intent_wire_len);
/* Stores both final one-frame BAT1 wires atomically.  It does not enqueue
 * them; callers may use the normal queue for prompt delivery and this journal
 * replays only frames that remain unacknowledged. */
EdrError edr_storage_queue_enforcement_terminal_update(
    const char *idempotency_key, const char *source_batch_id, const uint8_t *source_wire,
    size_t source_wire_len, const char *combined_batch_id, const uint8_t *combined_wire,
    size_t combined_wire_len);
void edr_storage_queue_enforcement_terminal_get_metrics(
    EdrEnforcementTerminalJournalMetrics *out);
void edr_storage_queue_get_capacity_metrics(EdrStorageQueueCapacityMetrics *out);
#ifdef EDR_STORAGE_QUEUE_TESTING
/* Focused SQLite commit-hook injection for tests: aborts the next durable
 * journal COMMIT attempts from inside SQLite itself. */
void edr_storage_queue_test_fail_next_terminal_commits(unsigned count);
/* Aborts the next explicit high-priority queue enqueue COMMIT attempts. */
void edr_storage_queue_test_fail_next_enqueue_commits(unsigned count);
/* Aborts the next queue_meta FULL commits, exercising the same SQLite
 * durable-failure boundary used by P0 source-only recovery. */
void edr_storage_queue_test_fail_next_p0_latch_commits(unsigned count);
/* Aborts the next deferred-match FULL commits, including atomic handoff. */
void edr_storage_queue_test_fail_next_p0_deferred_commits(unsigned count);
/* Simulates a checked journal ACK statement failure while the normal-row
 * delete is still in the enclosing terminal FULL transaction. */
void edr_storage_queue_test_fail_next_terminal_ack_steps(unsigned count);
/* Fails the next selected terminal-frame copy allocation at each named
 * boundary. It exercises replay selection only; no durable journal content
 * is modified by the injector. */
void edr_storage_queue_test_fail_next_terminal_select_allocations(
    unsigned key_count, unsigned batch_id_count, unsigned wire_count);
/* Forces retention cleanup in a focused SQLite test without waiting for its
 * production one-minute cadence. */
void edr_storage_queue_test_run_cleanup(void);
#endif

uint64_t edr_storage_queue_pending_count(void);
/** Terminal high-priority rows retained for audit rather than deleted. */
uint64_t edr_storage_queue_dead_letter_count(void);

/**
 * 从 SQLite 取 pending 批次，经 HTTP ingest 补传（与 flush 时 ReportEvents 载荷一致）。
 * 在预处理循环中周期性调用；内部节流，失败行保留并增加 retry_count。
 */
void edr_storage_queue_poll_drain(void);

#endif
