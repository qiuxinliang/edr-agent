#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_all(const char *path, char **out) {
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
  long n = ftell(f);
  if (n < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
  char *p = (char *)malloc((size_t)n + 1u);
  if (!p) { fclose(f); return -1; }
  size_t got = fread(p, 1, (size_t)n, f);
  fclose(f);
  p[got] = '\0';
  *out = p;
  return 0;
}

static int require_text(const char *text, const char *needle) {
  if (strstr(text, needle)) return 0;
  fprintf(stderr, "missing contract text: %s\n", needle);
  return 1;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  if (!root || !root[0]) root = ".";
  char path[2048];
  char *capture = NULL;
  char *agent = NULL;
  char *pmfe_preprocess = NULL;
  char *pmfe_engine = NULL;
  char *decision = NULL;
  snprintf(path, sizeof(path), "%s/src/shellcode_detector/windivert_capture.c", root);
  if (read_all(path, &capture) != 0) return 2;
  snprintf(path, sizeof(path), "%s/src/core/agent.c", root);
  if (read_all(path, &agent) != 0) { free(capture); return 2; }
  snprintf(path, sizeof(path), "%s/src/pmfe/pmfe_etw_preprocess.c", root);
  if (read_all(path, &pmfe_preprocess) != 0) { free(capture); free(agent); return 2; }
  snprintf(path, sizeof(path), "%s/src/pmfe/pmfe_engine.c", root);
  if (read_all(path, &pmfe_engine) != 0) {
    free(capture); free(agent); free(pmfe_preprocess); return 2;
  }
  snprintf(path, sizeof(path), "%s/src/preprocess/detection_decision.c", root);
  if (read_all(path, &decision) != 0) {
    free(capture); free(agent); free(pmfe_preprocess); free(pmfe_engine); return 2;
  }

  int failed = 0;
  failed |= require_text(capture, "WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY");
  failed |= require_text(capture, "return EDR_ERR_WINDIVERT_OPEN;");
  failed |= require_text(capture, "windivert_dll_load_failed");
  failed |= require_text(capture, "windivert_open_failed");
  failed |= require_text(capture, "capture_running");
  failed |= require_text(capture, "scan_queue_push");
  failed |= require_text(capture, "edr_tcp_reassembly_submit");
  failed |= require_text(capture, "scan_queue_capacity");
  failed |= require_text(agent, "\\\"shellcode_network\\\"");
  failed |= require_text(agent, "\\\"driver_open\\\"");
  failed |= require_text(agent, "\\\"runtime_detail\\\"");
  failed |= require_text(pmfe_preprocess, "pmfe_recommended");
  failed |= require_text(pmfe_preprocess, "shellcode:%.46s");
  failed |= require_text(pmfe_engine, "source_alert_id");
  failed |= require_text(pmfe_engine, "completed_clean");
  failed |= require_text(decision, "pmfe_followup_inconclusive");
  failed |= require_text(decision, "action = \"emit_context\"");
  free(capture);
  free(agent);
  free(pmfe_preprocess);
  free(pmfe_engine);
  free(decision);
  return failed ? 1 : 0;
}
