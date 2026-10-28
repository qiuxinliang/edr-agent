#ifndef EDR_FORENSIC_WORKER_H
#define EDR_FORENSIC_WORKER_H
#include "edr/response_utils.h"
#include "edr/command.h"
#include <stdint.h>
/* Private self-exec protocol. Only an inherited IPC endpoint is used; there
 * is no network or background Agent initialization. Version mismatch fails
 * closed (including an executable replaced during an upgrade). */
#define EDR_FORENSIC_WORKER_ARG "--forensic-io-worker-v1"
#define EDR_FORENSIC_IO_VERSION 3u
typedef struct {
  uint32_t version, operation, timeout_ms, payload_len;
  char workspace[700], staging[1024], manifest[4096];
  unsigned char payload[8192];
  char command_id[128];
  char endpoint_id[128], tenant_id[128];
  char expected_parent[65];
  EdrSoarCommandMeta meta;
  uint32_t allow_dangerous, report_pending;
  int32_t preflight_failure;
} EdrForensicIoRequest;
typedef struct { uint32_t version, phase, command_failed, command_rejected; int32_t rc; char sha256[65], directory_identity[65]; } EdrForensicIoResult;
typedef int (*EdrForensicCommandWorker)(const EdrForensicIoRequest *,EdrForensicIoResult *);
void edr_forensic_io_set_command_worker(EdrForensicCommandWorker worker);
int edr_forensic_io_in_worker(void);
int edr_forensic_io_run(const EdrForensicIoRequest *request,EdrForensicIoResult *result,
                       EdrResponseCancelCheck cancel,void *user);
int edr_forensic_io_worker_main(const char *endpoint);
#endif
