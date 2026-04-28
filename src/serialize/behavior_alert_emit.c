#include "edr/behavior_alert_emit.h"

#include "edr/behavior_proto.h"
#include "edr/event_batch.h"
#include "edr/preprocess.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EDR_HAVE_NANOPB
#pragma message("WARNING: EDR_HAVE_NANOPB not defined; ALL P0 and AVE behavior alerts will be silently dropped. Build with nanopb support for production use.")
#endif

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
  uint8_t buf[32768];
  size_t n = edr_behavior_alert_encode_protobuf(a, ep, te, buf, sizeof(buf));
  if (n > 0) {
    (void)edr_event_batch_push(buf, n);
    static int s_debug_enabled = -1;
    if (s_debug_enabled < 0) {
      s_debug_enabled = (getenv("EDR_P0_DEBUG") != NULL) ? 1 : 0;
    }
    if (s_debug_enabled) {
      fprintf(stderr, "[P0 DEBUG] Alert emitted: endpoint=%s tenant=%s size=%zu\n", 
              ep, te, n);
    }
  } else {
    static int s_logged_once = 0;
    if (!s_logged_once) {
      fprintf(stderr, "[P0 WARN] Alert encode failed: endpoint=%s tenant=%s\n", ep, te);
      s_logged_once = 1;
    }
  }
#else
  {
    static int s_no_nanopb_logged = 0;
    if (!s_no_nanopb_logged) {
      fprintf(stderr,
              "[edr] FATAL: EDR_HAVE_NANOPB is not defined; ALL behavior alerts "
              "(P0 direct emit + AVE ONNX) are being SILENTLY DISCARDED. "
              "Rebuild with nanopb support enabled.\n");
      s_no_nanopb_logged = 1;
    }
  }
  (void)a;
#endif
}
