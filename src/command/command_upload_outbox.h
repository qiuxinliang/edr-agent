#ifndef EDR_COMMAND_UPLOAD_OUTBOX_H
#define EDR_COMMAND_UPLOAD_OUTBOX_H

#include <stddef.h>
#include "edr/command_state.h"

/* Private file-delivery boundary shared by the legacy and async collectors. */
void edr_command_upload_outbox_dir(char *out, size_t cap);
int edr_command_upload_outbox_write_legacy(const char *command_id, const char *bundle,
                                         const char *sha256, const char *manifest);
enum { EDR_UPLOAD_OUTBOX_RETRY_PERSIST_FAILED = -8 };
/* 1: uploaded/delivered, 0: failed record retired, -1: network retry,
 * -2/-5: local retry, -3/-4/-7: durable policy hold, -6: durable retry not due.
 * -8: network failed and its durable retry update also failed (local brake).
 * Holds and scheduled retries are never success.
 * Only actual network attempts consume the upload budget. */
int edr_command_upload_outbox_flush_one(const char *path, int *upload_attempted);
/* Continue the existing command owner's frozen publication intent. No network
 * call; successful handoff releases only staging growth, never local evidence. */
int edr_command_upload_outbox_publish_stage(const EdrCommandArtifactStage *stage);

#endif
