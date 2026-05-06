/* §8 响应指令执行器 — Subscribe 分发；处置动作见 src/response/response_actions.c */
#include "edr/attack_surface_report.h"
#include "edr/command.h"
#include "edr/command_util.h"
#include "edr/response.h"
#include "edr/ave.h"
#include "edr/ave_sdk.h"
#include "edr/config.h"
#include "edr/error.h"
#include "edr/grpc_client.h"
#include "edr/self_protect.h"
#include "edr/edr_log.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

static unsigned long s_unknown;

unsigned long edr_command_handled_count(void) { return g_cmd_handled; }
unsigned long edr_command_unknown_count(void) { return s_unknown; }
unsigned long edr_command_rejected_count(void) { return g_cmd_rejected; }
unsigned long edr_command_exec_ok_count(void) { return g_cmd_exec_ok; }
unsigned long edr_command_exec_fail_count(void) { return g_cmd_exec_fail; }

static void do_ave_status(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  int mf = 0, nf = 0, rd = 0;
  edr_ave_get_scan_counts(&mf, &nf, &rd);
  char detail[256];
  snprintf(detail, sizeof(detail), "model_files=%d non_dir_files=%d ready=%d", mf, nf, rd);
  g_cmd_handled++;
  g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, detail);
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static const char *ave_verdict_tag(EDRVerdict v) {
  switch (v) {
    case VERDICT_CLEAN:
      return "CLEAN";
    case VERDICT_SUSPICIOUS:
      return "SUSPICIOUS";
    case VERDICT_MALWARE:
      return "MALWARE";
    case VERDICT_TRUSTED_CERT:
      return "TRUSTED_CERT";
    case VERDICT_WHITELISTED:
      return "WHITELISTED";
    case VERDICT_IOC_CONFIRMED:
      return "IOC_CONFIRMED";
    case VERDICT_CERT_REVOKED:
      return "CERT_REVOKED";
    case VERDICT_CERT_TAMPERED:
      return "CERT_TAMPERED";
    case VERDICT_TIMEOUT:
      return "TIMEOUT";
    case VERDICT_ERROR:
      return "ERROR";
    default:
      return "UNKNOWN";
  }
}

static void do_ave_fingerprint(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm) {
  char path[4096];
  if (edr_command_parse_path_json(pl, len, path, sizeof(path)) != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "ave_fingerprint: payload 需 JSON {\"path\":\"...\"}");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 10, "invalid path payload");
    return;
  }
  char hex[32];
  if (edr_ave_file_fingerprint(path, hex, sizeof(hex)) != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "ave_fingerprint: 读文件或指纹失败");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 11, "fingerprint failed");
    return;
  }
  char detail[220];
  snprintf(detail, sizeof(detail), "fp=%s", hex);
  g_cmd_handled++;
  g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, detail);
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_ave_infer(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_get_config()) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "ave_infer: 未绑定配置（内部错误）");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 20, "config not bound");
    return;
  }
  char path[4096];
  if (edr_command_parse_path_json(pl, len, path, sizeof(path)) != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "ave_infer: payload 需 JSON {\"path\":\"...\"}");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 10, "invalid path payload");
    return;
  }
  AVEScanResult res;
  memset(&res, 0, sizeof(res));
  int ar = AVE_ScanFile(path, &res);
  if (ar == AVE_ERR_NOT_INITIALIZED) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "ave_infer: AVE 未初始化（需先 edr_agent_init）");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 22, "ave not initialized");
    return;
  }
  if (ar == AVE_ERR_NOT_IMPL) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "ave_infer: 推理后端未实现（可设 EDR_AVE_INFER_DRY_RUN=1）");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, (int)EDR_ERR_NOT_IMPL, "infer not implemented");
    return;
  }
  if (ar == AVE_ERR_FILE_NOT_FOUND) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "ave_infer: 文件不存在");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 23, "file not found");
    return;
  }
  if (ar == AVE_ERR_ACCESS_DENIED) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "ave_infer: 无读取权限");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 24, "access denied");
    return;
  }
  if (ar != AVE_OK) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "ave_infer: 扫描失败");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 21, "scan error");
    return;
  }

  char detail[512];
  snprintf(detail, sizeof(detail),
           "final=%s raw=%s final_conf=%.4f raw_conf=%.4f layer=%.3s sha256=%s dur_ms=%lld",
           ave_verdict_tag(res.final_verdict), ave_verdict_tag(res.raw_ai_verdict),
           (double)res.final_confidence, (double)res.raw_confidence, res.verification_layer, res.sha256,
           (long long)res.scan_duration_ms);
  g_cmd_handled++;
  g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, detail);
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_self_protect_status(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  char detail[512];
  edr_self_protect_format_status(detail, sizeof(detail));
  g_cmd_handled++;
  g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, detail);
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_update_server_address(const char *cmd_id, const uint8_t *pl, size_t len,
                                     const EdrSoarCommandMeta *sm) {
  char addr[256];
  if (edr_command_parse_server_address_json(pl, len, addr, sizeof(addr)) != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "update_server_address: payload 需 JSON {\"server_address\":\"host:port\"}");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 12, "invalid server address payload");
    return;
  }
  if (strstr(addr, "://") || strchr(addr, '/')) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "update_server_address: 仅支持 host:port");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 13, "server address must be host:port");
    return;
  }
  int rc = edr_grpc_client_reconnect_to_target(addr);
  if (rc != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "update_server_address: gRPC 重连失败");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 14, "grpc reconnect failed");
    return;
  }
  g_cmd_handled++;
  g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, "update_server_address: gRPC 目标已切换");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "grpc target switched");
}

void edr_command_on_envelope(const char *command_id, const char *command_type, const uint8_t *payload,
                             size_t payload_len, const EdrSoarCommandMeta *soar_meta) {
  EdrSoarCommandMeta empty;
  memset(&empty, 0, sizeof(empty));
  const EdrSoarCommandMeta *sm = soar_meta ? soar_meta : &empty;
  const char *t = command_type ? command_type : "";
  const char *id = command_id ? command_id : "";

  if (edr_command_streq(t, "noop") || edr_command_streq(t, "ping")) {
    EDR_LOGV("[command] ok id=%s type=%s\n", id, t);
    g_cmd_handled++;
    edr_command_soar_emit(id, sm, EdrCmdExecOk, 0, t);
    return;
  }

  if (edr_command_streq(t, "echo")) {
    EDR_LOGV("[command] echo id=%s len=%zu\n", id, payload_len);
    if (payload && payload_len > 0u && payload_len < 4096u) {
      fwrite(payload, 1, payload_len, stderr);
      fputc('\n', stderr);
    }
    g_cmd_handled++;
    edr_command_soar_emit(id, sm, EdrCmdExecOk, 0, "echo");
    return;
  }

  if (edr_command_streq(t, "isolate_host") || edr_command_streq(t, "isolate")) {
    edr_response_isolate(id, sm);
    return;
  }
  if (edr_command_streq(t, "kill_process") || edr_command_streq(t, "kill")) {
    edr_response_kill(id, payload, payload_len, sm);
    return;
  }
  if (edr_command_streq(t, "collect_forensic") || edr_command_streq(t, "forensic")) {
    edr_response_collect_forensic(id, payload, payload_len, sm);
    return;
  }
  if (edr_command_streq(t, "pmfe_scan") || edr_command_streq(t, "CMD_PMFE_SCAN")) {
    edr_response_pmfe_scan(id, payload, payload_len, sm);
    return;
  }

  if (edr_command_streq(t, "ave_status") || edr_command_streq(t, "ave_model_status")) {
    do_ave_status(id, sm);
    return;
  }
  if (edr_command_streq(t, "ave_fingerprint") || edr_command_streq(t, "ave_fp")) {
    do_ave_fingerprint(id, payload, payload_len, sm);
    return;
  }
  if (edr_command_streq(t, "ave_infer")) {
    do_ave_infer(id, payload, payload_len, sm);
    return;
  }

  if (edr_command_streq(t, "self_protect_status") || edr_command_streq(t, "agent_health") || edr_command_streq(t, "health_status")) {
    do_self_protect_status(id, sm);
    return;
  }

  if (edr_command_streq(t, "update_server_address") || edr_command_streq(t, "set_server_address")) {
    do_update_server_address(id, payload, payload_len, sm);
    return;
  }

  if (edr_command_streq(t, "rtr_shell") || edr_command_streq(t, "shell_exec")) {
    edr_response_rtr_shell(id, payload, payload_len, sm);
    return;
  }
  if (edr_command_streq(t, "rtr_get") || edr_command_streq(t, "file_get")) {
    edr_response_get_file(id, payload, payload_len, sm);
    return;
  }
  if (edr_command_streq(t, "rtr_put") || edr_command_streq(t, "file_put")) {
    edr_response_put_file(id, payload, payload_len, sm);
    return;
  }
  if (edr_command_streq(t, "rtr_rm") || edr_command_streq(t, "file_rm")) {
    edr_response_remove_file(id, payload, payload_len, sm);
    return;
  }

  if (edr_command_streq(t, "forensic_targeted") || edr_command_streq(t, "targeted_forensic")) {
    edr_response_targeted_forensic(id, payload, payload_len, sm);
    return;
  }
  if (edr_command_streq(t, "memory_dump")) {
    edr_response_memory_dump(id, payload, payload_len, sm);
    return;
  }
  if (edr_command_streq(t, "yara_scan")) {
    edr_response_yara_scan(id, payload, payload_len, sm);
    return;
  }

  if (edr_command_streq(t, "quarantine_file") || edr_command_streq(t, "quarantine")) {
    edr_response_quarantine_file(id, payload, payload_len, sm);
    return;
  }
  if (edr_command_streq(t, "restore_file") || edr_command_streq(t, "unquarantine")) {
    edr_response_restore_file(id, payload, payload_len, sm);
    return;
  }

  if (edr_command_streq(t, "shell_open")) {
    edr_response_shell_open(id, payload, payload_len, sm);
    return;
  }
  if (edr_command_streq(t, "shell_input")) {
    edr_response_shell_input(id, payload, payload_len, sm);
    return;
  }
  if (edr_command_streq(t, "shell_close")) {
    edr_response_shell_close(id, payload, payload_len, sm);
    return;
  }

  if (edr_command_streq(t, "forensic_deep")) {
    edr_response_deep_forensic(id, payload, payload_len, sm);
    return;
  }

  if (edr_command_streq(t, "GET_ATTACK_SURFACE") || edr_command_streq(t, "get_attack_surface") || edr_command_streq(t, "REFRESH_ATTACK_SURFACE")) {
    char detail[256];
    int r = edr_attack_surface_execute(id, edr_command_get_config(), detail, sizeof(detail));
    if (r != 0) {
      g_cmd_exec_fail++;
      edr_command_audit_both(id, "GET_ATTACK_SURFACE: failed");
      edr_command_soar_emit(id, sm, EdrCmdExecFailed, r, detail[0] ? detail : "attack_surface_failed");
    } else {
      g_cmd_handled++;
      g_cmd_exec_ok++;
      edr_command_audit_both(id, "GET_ATTACK_SURFACE: ok");
      edr_command_soar_emit(id, sm, EdrCmdExecOk, 0, detail[0] ? detail : "attack_surface_ok");
    }
    return;
  }

  fprintf(stderr, "[command] 未知类型 id=%s type=%s\n", id, t);
  s_unknown++;
  edr_command_soar_emit(id, sm, EdrCmdExecUnknownType, 1, "unknown command_type");
}
