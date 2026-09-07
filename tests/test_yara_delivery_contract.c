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

static int require_absent(const char *text, const char *needle, const char *message) {
  if (!contains(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (unexpected %s)\n", message, needle);
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
  ok &= require_contains(installer, "Generated agent.toml failed Agent config validation",
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
  ok &= require_contains(response, "spec.fixed_local_binary = 1;",
                         "C forensic fallback must be marked as a fixed local recovery binary");
  ok &= require_contains(response, "GetModuleFileNameA(NULL, executable",
                         "Windows YARA must resolve rules relative to the installed executable");
  ok &= require_contains(response, "readlink(\"/proc/self/exe\"",
                         "POSIX YARA must resolve rules relative to the installed executable");
  ok &= require_contains(response, "edr_response_yara_runtime_status",
                         "YARA must expose a runtime rules preflight for capability reporting");
  ok &= require_contains(response, "fy_compile_rules_dir(path, &loaded",
                         "YARA readiness must compile, not merely count, the installed rules");
  ok &= require_contains(response, "yr_rules_destroy(compiled)",
                         "YARA readiness preflight must release compiled rules");
  free(response);

  snprintf(path, sizeof(path), "%s/src/core/agent.c", root);
  char *agent = read_file(path);
  if (!agent) {
    fprintf(stderr, "FAIL: cannot read Agent core source\n");
    return 1;
  }
  ok &= require_contains(agent, "edr_agent_apply_remote_command_policy",
                         "remote command policy must merge only explicit fields");
  ok &= require_contains(agent, "edr_agent_toml_section_has_key",
                         "remote command policy merge must preserve omitted local settings");
  ok &= require_contains(agent,
                         "edr_agent_toml_section_has_key(toml_path, \"command.rtr_shell\", \"allowlist\")",
                         "remote policy must hot-reload the nested RTR allowlist");
  ok &= require_contains(agent,
                         "edr_agent_toml_section_has_key(toml_path, \"command.rtr_shell\", \"max_timeout_sec\")",
                         "remote policy must hot-reload the nested RTR timeout");
  ok &= require_absent(agent, "agent->cfg.command = remote->command;",
                       "remote policy must not replace the complete command configuration");
  ok &= require_contains(agent,
                         "\\\"targeted_forensic_process\\\":{\\\"code_supported\\\":false",
                         "process targeted forensic must not be advertised before it is implemented");
  ok &= require_contains(agent,
                         "\\\"targeted_forensic_registry\\\":{\\\"code_supported\\\":false",
                         "registry targeted forensic must not be advertised before it is implemented");
  ok &= require_contains(agent,
                         "\\\"targeted_forensic_memory\\\":{\\\"code_supported\\\":false",
                         "memory targeted forensic must use the dedicated memory-dump capability");
  ok &= require_contains(agent, "yara_rules_ready",
                         "capability manifest must distinguish compiled YARA from ready rules");
  ok &= require_contains(agent, "edr_deep_collector_schedule_runtime_refresh();",
                         "collector manifest refresh must be scheduled outside query execution");
  free(agent);

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
  ok &= require_contains(commands, "spec.cpu_limit_percent = 40u;",
                         "Velo query must run under the approved 40 percent CPU quota");
  ok &= require_contains(commands, "cJSON_AddNumberToObject(result, \"cpu_limit_percent\", spec.cpu_limit_percent)",
                         "Velo result contracts must expose the applied CPU quota");
  ok &= require_contains(commands, "cJSON_AddItemToObject(result, \"timings_ms\", timings)",
                         "Velo large-result contract must include phase timings without fixed-buffer JSON");
  free(commands);

  snprintf(path, sizeof(path), "%s/src/forensic/deep_collector.c", root);
  char *collector = read_file(path);
  if (!collector) {
    fprintf(stderr, "FAIL: cannot read deep collector source\n");
    return 1;
  }
  ok &= require_contains(collector, "spec->cpu_limit_percent ? spec->cpu_limit_percent : 10u",
                         "collector Job Object must apply per-command CPU quotas");
  ok &= require_contains(collector, "collector CPU quota setup failed percent=%u",
                         "an explicit Velo CPU quota must fail closed when Windows rejects the hard cap");
  ok &= require_contains(collector, "collector CPU quota assignment failed percent=%u",
                         "an explicit Velo CPU quota must fail closed when the process cannot join the Job Object");
  ok &= require_contains(collector, "edr_deep_collector_schedule_runtime_refresh",
                         "existing collector binaries must refresh asynchronously");
  ok &= require_contains(collector, "if (fixed_local_binary)",
                         "fixed local fallback must bypass adapter autofetch and adapter pins");
  ok &= require_contains(collector, "dc_prepare_velociraptor",
                         "Velo preparation must reuse a ready binary without blocking on version checks");
  ok &= require_contains(collector, "GetMachineTypeAttributes",
                         "ARM64 Velociraptor execution must probe Windows x64 user-mode emulation");
  ok &= require_contains(collector, "DC_MACHINE_ATTRIBUTE_USER_ENABLED = 0x00000001",
                         "Windows machine capability probe must test the UserEnabled bit");
  ok &= require_contains(collector, "typedef LONG(WINAPI *PFN_IsWow64GuestMachineSupported)",
                         "legacy Windows guest capability probe must preserve HRESULT semantics");
  ok &= require_contains(collector, "if (hr >= 0) return supported ? 1 : 0;",
                         "successful HRESULT zero must not be treated as a false API call result");
  ok &= require_contains(collector, "collector PE architecture mismatch",
                         "downloaded collector PE architecture must match manifest metadata");
  ok &= require_contains(collector, "emulated collector cannot declare network packet capture",
                         "emulated Velociraptor must reject driver packet-capture claims");
  free(collector);

  snprintf(path, sizeof(path), "%s/src/attack_surface/security_policy_collect.c", root);
  char *security = read_file(path);
  if (!security) {
    fprintf(stderr, "FAIL: cannot read Windows security policy collector source\n");
    return 1;
  }
  ok &= require_contains(security, "PeekNamedPipe", "Windows subprocess output must be polled without blocking");
  ok &= require_contains(security, "TerminateJobObject(job, 124u)",
                         "Windows subprocess timeout must terminate the complete process tree");
  ok &= require_contains(security, "$all=@(Get-NetFirewallRule -PolicyStore ActiveStore",
                         "Windows firewall rules must be enumerated once per snapshot");
  ok &= require_absent(security, "static int ps_count_rules(",
                       "legacy repeated firewall PowerShell queries must stay removed");
  free(security);

  snprintf(path, sizeof(path), "%s/install/windows-inno/Build-BundledInstaller.ps1", root);
  char *build_installer = read_file(path);
  if (!build_installer) {
    fprintf(stderr, "FAIL: cannot read bundled installer build script\n");
    return 1;
  }
  ok &= require_contains(build_installer, "$requiredForensicRules = @(",
                         "Windows release build must gate on the complete forensic rule set");
  ok &= require_contains(build_installer, "Missing required forensic YARA rule asset",
                         "missing YARA assets must fail the release build");
  free(build_installer);

  snprintf(path, sizeof(path), "%s/install/windows-inno/EDRAgentSetup.bundled.iss", root);
  char *inno = read_file(path);
  if (!inno) {
    fprintf(stderr, "FAIL: cannot read bundled Inno setup source\n");
    return 1;
  }
  ok &= require_contains(inno, "Source: \"..\\..\\rules\\forensic\\*\"; DestDir: \"{app}\\rules\\forensic\"; Flags: ignoreversion recursesubdirs createallsubdirs",
                         "bundled installer must always package forensic YARA rules");
  ok &= require_absent(inno, "rules\\forensic\\*\"; DestDir: \"{app}\\rules\\forensic\"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist",
                       "bundled installer must not silently omit forensic YARA rules");
  free(inno);

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
