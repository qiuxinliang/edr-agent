#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require_true(int value, const char *message) {
  if (!value) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}

static char *read_file(const char *path) {
  FILE *file = fopen(path, "rb");
  if (!file) return NULL;
  fseek(file, 0, SEEK_END); long size = ftell(file); rewind(file);
  char *data = (char *)malloc((size_t)size + 1u);
  if (!data || fread(data, 1, (size_t)size, file) != (size_t)size) { free(data); fclose(file); return NULL; }
  data[size] = 0; fclose(file); return data;
}

static void contains(const char *text, const char *needle, const char *message) {
  require_true(text && strstr(text, needle), message);
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  require_true(root && root[0], "EDR_SOURCE_DIR is configured");
  char path[4096];
  snprintf(path, sizeof(path), "%s/scripts/edr_agent_inplace_update.ps1", root);
  char *script = read_file(path);
  require_true(script != NULL, "read Windows updater script without executing it");
  contains(script, "Get-AuthenticodeSignature", "Authenticode validity gate exists");
  contains(script, "TrustedPublisherThumbprint", "trusted publisher thumbprint gate exists");
  contains(script, "TrustedPublisherSubject", "trusted publisher subject gate exists");
  contains(script, "SHA256_ONLY_UNSIGNED", "explicit optional-signing update mode exists");
  contains(script, "already verified task-pinned SHA-256", "unsigned mode remains pinned to the task artifact hash");
  contains(script, "Compare-SemVer", "semantic version direction checks exist");
  contains(script, "$Operation -eq 'upgrade' -and $versionDirection -le 0", "upgrade rejects downgrade and same-version targets");
  contains(script, "$Operation -eq 'rollback' -and $versionDirection -ge 0", "rollback requires an older target version");
  contains(script, "InternalName", "PE InternalName check exists");
  contains(script, "ProductVersion", "PE ProductVersion check exists");
  contains(script, "Get-PSDrive", "disk-space preflight exists");
  contains(script, "Resolve-DeploymentMode", "auto deployment mode exists");
  contains(script, "Stop-Service", "service stop path exists");
  contains(script, "Start-ScheduledTask", "scheduled-task start path exists");
  contains(script, "replacement_committed", "durable replacement journal exists");
  contains(script, "schema_version = 2", "journal uses strict v2 schema");
  contains(script, "task_id = $TaskId", "journal binds task identity");
  contains(script, "command_id = $CommandId", "journal binds command identity");
  contains(script, "hash = $expectedHash", "journal binds artifact hash");
  contains(script, "version = $TargetVersion", "journal binds target version");
  contains(script, "last_event_seq", "journal persists event sequence");
  contains(script, "Add-UpdateEvent", "PowerShell stages durable update events");
  contains(script, "rollback_health_check", "rollback health event is recorded");
  contains(script, "$env:ProgramData", "journal survives install-directory binary replacement");
  contains(script, "if ([string]$prior.status -eq 'succeeded') { exit 0 }", "only prior success exits successfully");
  contains(script, "Write-AtomicJson", "journal and report use atomic writes");
  free(script);

  snprintf(path, sizeof(path), "%s/src/command/agent_update_command.c", root);
  char *command = read_file(path);
  require_true(command != NULL, "read Agent update command implementation");
  contains(command, "before_download", "update can be cancelled before download");
  contains(command, "artifact_downloaded", "update can be cancelled after artifact download");
  contains(command, "runtime_manifest_downloaded", "update can be cancelled after runtime manifest download");
  contains(command, "before_updater_launch", "update can be cancelled before replacement process starts");
  contains(command, "operator_cancelled_before_replacement", "cancel event records the safe cancellation boundary");
  free(command);

  snprintf(path, sizeof(path), "%s/CMakeLists.txt", root);
  char *cmake = read_file(path);
  contains(cmake, "src/command/agent_update_command.c", "command helper is compiled");
  contains(cmake, "src/command/agent_update_event.c", "durable update event outbox is compiled");
  require_true(!strstr(cmake, "src/core/agent_update.c"), "dormant self-overwrite implementation remains disabled");
  contains(cmake, "edr_agent_inplace_update.ps1", "updater script is staged by CMake");
  contains(cmake, "shell32", "Windows external updater launch dependency is linked");
  free(cmake);

  snprintf(path, sizeof(path), "%s/src/command/command_stub.c", root);
  char *dispatch = read_file(path);
  contains(dispatch, "EDR_AGENT_UPDATE_EXIT_LAUNCHED", "launch result is handled as nonterminal");
  contains(dispatch, "edr_agent_update_recover", "startup inbox replay consumes update journal");
  contains(dispatch, "awaiting terminal updater journal", "replay-blocked update waits instead of failing or relaunching");
  contains(dispatch, "durable inbox is retained", "launch does not delete durable inbox");
  free(dispatch);

  snprintf(path, sizeof(path), "%s/resources/FDSensor.rc", root);
  char *resource = read_file(path);
  contains(resource, "InternalName", "Windows version resource has InternalName");
  contains(resource, "ProductVersion", "Windows version resource has ProductVersion");
  free(resource);

  snprintf(path, sizeof(path), "%s/.github/workflows/edr-agent-client-release.yml", root);
  char *workflow = read_file(path);
  contains(workflow, "Authenticode sign release executables", "release requires Authenticode signing");
  contains(workflow, "WINDOWS_SIGNING_THUMBPRINT", "release verifies trusted signing thumbprint");
  contains(workflow, "artifact-manifest.json", "release publishes artifact hash manifest");
  contains(workflow, "SignedCms", "release produces detached signed manifest");
  contains(workflow, "signer_thumbprint", "manifest binds expected signer thumbprint");
  contains(workflow, "CMS signer subject does not match", "release verifies CMS signer identity binding");
  contains(workflow, "edr_agent_inplace_update.ps1", "release package contains updater script");
  free(workflow);

  puts("ok (pure source contract; Windows execution intentionally not simulated)");
  return 0;
}
