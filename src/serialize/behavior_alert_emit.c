#include "edr/behavior_alert_emit.h"

#include "edr/behavior_proto.h"
#include "edr/event_batch.h"
#include "edr/preprocess.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void warn_encoding_once(void) {
  static int s_done;
  const char *enc = getenv("EDR_BEHAVIOR_ENCODING");
  if (s_done) {
    return;
  }
  if (enc && strcmp(enc, "protobuf") != 0 && strcmp(enc, "protobuf_c") != 0) {
    fprintf(stderr,
            "[edr] behavior alert frames use protobuf; for platform ingest use "
            "EDR_BEHAVIOR_ENCODING=protobuf (or protobuf_c) so batches are uniformly decodable.\n");
  }
  s_done = 1;
}

void edr_behavior_alert_emit_to_batch(const AVEBehaviorAlert *a) {
  if (!a) {
    return;
  }
#ifdef EDR_HAVE_NANOPB
  warn_encoding_once();
  char ep[128];
  char te[128];
  edr_preprocess_copy_agent_ids(ep, sizeof(ep), te, sizeof(te));
  uint8_t buf[13000];
  size_t n = edr_behavior_alert_encode_protobuf(a, ep, te, buf, sizeof(buf));
  if (n > 0) {
    (void)edr_event_batch_push(buf, n);
  }
#else
  (void)a;
#endif
}
