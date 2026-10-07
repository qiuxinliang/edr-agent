#ifndef EDR_COMMAND_UPLOAD_OUTBOX_H
#define EDR_COMMAND_UPLOAD_OUTBOX_H

#include <stddef.h>

/* Private file-delivery boundary shared by the legacy and async collectors. */
void edr_command_upload_outbox_dir(char *out, size_t cap);
int edr_command_upload_outbox_write_legacy(const char *command_id, const char *bundle,
                                         const char *sha256, const char *manifest);
/* 1: uploaded/delivered, 0: failed record retired, -1: network retry,
 * -2/-5: local retry, -3/-4: durable policy hold. Holds are never success.
 * Only actual network attempts consume the upload budget. */
int edr_command_upload_outbox_flush_one(const char *path, int *upload_attempted);

#endif
