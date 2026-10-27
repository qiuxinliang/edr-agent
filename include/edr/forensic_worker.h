#ifndef EDR_FORENSIC_WORKER_H
#define EDR_FORENSIC_WORKER_H
#include "edr/response_utils.h"
#include <stdint.h>
/* Private self-exec protocol. No network, command-state writes or background
 * Agent initialization in the child. Only an inherited IPC endpoint is used. */
#define EDR_FORENSIC_WORKER_ARG "--forensic-io-worker-v1"
typedef struct {
  uint32_t version, operation, timeout_ms, payload_len;
  char workspace[700], staging[1024], manifest[4096];
  unsigned char payload[8192];
} EdrForensicIoRequest;
typedef struct { uint32_t version, phase; int32_t rc; char sha256[65]; } EdrForensicIoResult;
int edr_forensic_io_run(const EdrForensicIoRequest *request,EdrForensicIoResult *result,
                       EdrResponseCancelCheck cancel,void *user);
int edr_forensic_io_worker_main(const char *endpoint);
#endif
