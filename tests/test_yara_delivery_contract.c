#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
  long size = ftell(f);
  if (size < 0) { fclose(f); return NULL; }
  rewind(f);
  char *data = (char *)calloc((size_t)size + 1u, 1u);
  if (!data) { fclose(f); return NULL; }
  if (fread(data, 1u, (size_t)size, f) != (size_t)size) {
    free(data);
    fclose(f);
    return NULL;
  }
  fclose(f);
  return data;
}

static int contains(const char *text, const char *needle) {
  return text && needle && strstr(text, needle) != NULL;
}

static int require_contains(const char *text, const char *needle, const char *message) {
  if (contains(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (missing %s)\n", message, needle);
  return 0;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  if (!root || !root[0]) root = ".";
  char path[1200];

  snprintf(path, sizeof(path), "%s/scripts/edr_agent_install.ps1", root);
  char *installer = read_file(path);
  if (!installer) {
    fprintf(stderr, "FAIL: cannot read Windows installer script\n");
    return 1;
  }
  int ok = 1;
  ok &= require_contains(installer, "$d.request_signing_enabled", "installer must read request-signing enrollment state");
  ok &= require_contains(installer, "$d.request_signing_key_id", "installer must read request-signing key id");
  ok &= require_contains(installer, "$d.request_signing_secret", "installer must read request-signing secret");
  ok &= require_contains(installer, "[platform.request_signing]", "installer must write request-signing TOML section");
  ok &= require_contains(installer, "Get-ExistingAgentTomlRequestSigningIssue", "upgrade must repair legacy unsigned config");
  ok &= require_contains(installer, "minimal-parser-fallback", "installer must recover from template parser failures");
  ok &= require_contains(installer, "Generated agent.toml failed Agent parser validation",
                         "installer must fail before handoff when minimal TOML is rejected");
  ok &= require_contains(installer, "rest_bearer_token|secret|signing_public_key_path",
                         "installer diagnostics must redact request-signing secrets");
  free(installer);

  snprintf(path, sizeof(path), "%s/src/installer_worker/installer_worker_win.c", root);
  char *installer_worker = read_file(path);
  if (!installer_worker) {
    fprintf(stderr, "FAIL: cannot read native installer worker source\n");
    return 1;
  }
  ok &= require_contains(installer_worker, "STARTF_USESTDHANDLES",
                         "native installer worker must capture child process diagnostics");
  ok &= require_contains(installer_worker, "si.hStdError = child_log",
                         "native installer worker must preserve Agent parser stderr");
  free(installer_worker);

  snprintf(path, sizeof(path), "%s/src/response/response_forensic.c", root);
  char *response = read_file(path);
  if (!response) {
    fprintf(stderr, "FAIL: cannot read YARA response source\n");
    return 1;
  }
  ok &= require_contains(response, "static int yara_external_enabled(void)", "YARA must have an execution-path policy");
  ok &= require_contains(response, "#ifdef EDR_HAVE_YARA\n  return 0;", "libyara builds must default to the local path");
  ok &= require_contains(response, "edr.yara_scan.result.v1", "YARA must emit its dedicated result schema");
  ok &= require_contains(response, "root_open_failed", "directory YARA must distinguish an inaccessible root");
  ok &= require_contains(response, "yd.scan_completed == 0", "directory YARA must reject zero completed scans");
  ok &= require_contains(response, "no eligible readable files completed YARA scanning", "zero-scan failure must be explicit");
  ok &= require_contains(response, "pl, len, \"tar.gz\", 1", "external YARA artifact type must match collector output");
  ok &= require_contains(response, "if (rc == 0 || rc == 2)", "collector partial exit must be a terminal success state");
  free(response);

  snprintf(path, sizeof(path), "%s/src/command/command_stub.c", root);
  char *commands = read_file(path);
  if (!commands) {
    fprintf(stderr, "FAIL: cannot read command handler source\n");
    return 1;
  }
  ok &= require_contains(commands, "velo_load_validated_output", "Velo output must be validated before success");
  ok &= require_contains(commands, "query output is missing the required rows array", "Velo output must require rows");
  ok &= require_contains(commands, "collector returned an error", "Velo must preserve collector failures");
  ok &= require_contains(commands, "provider_status", "Velo must preserve provider status provenance");
  free(commands);

  snprintf(path, sizeof(path), "%s/src/transport/ingest_http.c", root);
  char *transport = read_file(path);
  if (!transport) {
    fprintf(stderr, "FAIL: cannot read upload transport source\n");
    return 1;
  }
  ok &= require_contains(transport, "failed_h2", "upload transport must expose h2 failure state");
  ok &= require_contains(transport, "note_upload_failure();", "upload transport must count failures");
  free(transport);
  return ok ? 0 : 1;
}
