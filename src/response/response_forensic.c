#include "edr/response.h"
#include "edr/command_util.h"
#include "edr/config.h"
#include "edr/deep_collector.h"
#include "edr/error.h"
#include "edr/grpc_client.h"
#include "edr/ingest_http.h"
#include "edr/pmfe.h"
#include "edr/sha256.h"
#include "edr/shell_session.h"
#include "edr/edr_log.h"
#include "edr/pe_verify.h"
#include "edr/shell_exec.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <process.h>
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "edr/response_utils.h"

/* ── Forensic Actions ── */

void edr_response_collect_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                    const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject forensic: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char base[512];
  const char *o = getenv("EDR_FORENSIC_OUT");
  if (o && o[0]) {
    snprintf(base, sizeof(base), "%s", o);
  } else {
#ifdef _WIN32
    const char *tmp = getenv("TEMP");
    if (!tmp || !tmp[0]) {
      tmp = getenv("TMP");
    }
    if (!tmp || !tmp[0]) {
      tmp = ".";
    }
    snprintf(base, sizeof(base), "%s\\edr_forensic", tmp);
#else
    snprintf(base, sizeof(base), "%s", "/tmp/edr_forensic");
#endif
  }
  char job[96];
  response_sanitize_job_name(cmd_id, job, sizeof(job));
  char dir[700];
#ifdef _WIN32
  snprintf(dir, sizeof(dir), "%s\\%s", base, job);
#else
  snprintf(dir, sizeof(dir), "%s/%s", base, job);
#endif
  if (response_mkdir_p(dir) != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "forensic: 创建输出目录失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "mkdir failed");
    return;
  }
  char manifest[800];
#ifdef _WIN32
  snprintf(manifest, sizeof(manifest), "%s\\manifest.txt", dir);
#else
  snprintf(manifest, sizeof(manifest), "%s/manifest.txt", dir);
#endif
  FILE *f = fopen(manifest, "w");
  if (!f) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "forensic: 写 manifest 失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "manifest write failed");
    return;
  }
  fprintf(f, "command_id=%s\npayload_len=%zu\n", cmd_id ? cmd_id : "", len);
  {
    char shahex[65];
    if (pl && len > 0u) {
      (void)edr_sha256_hex(pl, len, shahex);
      fprintf(f, "payload_sha256=%s\n", shahex);
    } else {
      fprintf(f, "payload_sha256=\n");
    }
  }
#ifdef _WIN32
  fprintf(f, "platform=windows\n");
  {
    char hn[256];
    DWORD hnl = sizeof(hn);
    if (GetComputerNameA(hn, &hnl)) {
      fprintf(f, "hostname=%s\n", hn);
    }
  }
#else
  fprintf(f, "platform=posix\n");
  {
    char hn[256];
    if (gethostname(hn, sizeof(hn)) == 0) {
      hn[sizeof(hn) - 1] = '\0';
      fprintf(f, "hostname=%s\n", hn);
    }
  }
#endif
  {
    const EdrConfig *cfg = edr_command_get_config();
    if (cfg) {
      fprintf(f, "endpoint_id=%s\ntenant_id=%s\n", cfg->agent.endpoint_id[0] ? cfg->agent.endpoint_id : "",
              cfg->agent.tenant_id[0] ? cfg->agent.tenant_id : "");
    }
  }
  fclose(f);
  response_forensic_copy_lines(dir, pl, len);
#ifdef _WIN32
  char bundle[1100];
  snprintf(bundle, sizeof(bundle), "%s\\bundle.tgz", dir);
#else
  char bundle[1000];
  snprintf(bundle, sizeof(bundle), "%s/bundle.tgz", dir);
#endif
  if (response_make_tar_bundle(dir, bundle) == 0) {
    edr_cmd_inc_exec_ok();
    edr_command_audit_both(cmd_id, "forensic: manifest + bundle.tgz");
    char minio_key[512];
    minio_key[0] = '\0';
    edr_ingest_http_upload_file_multipart(cmd_id, bundle, NULL, minio_key, sizeof(minio_key));
    char result[1024];
    if (minio_key[0]) {
      snprintf(result, sizeof(result), "forensic bundle ok minio_key=%s", minio_key);
    } else {
      snprintf(result, sizeof(result), "forensic bundle ok");
    }
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
  } else {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "forensic: tar bundle 失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "tar bundle failed");
  }
}

void edr_response_pmfe_scan(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject pmfe_scan: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  long pid = -1;
  if (edr_command_parse_pid_json(pl, len, &pid) != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "pmfe_scan: payload 缺少有效 pid（JSON 需含 \"pid\"）");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid json");
    return;
  }
  if (edr_pmfe_submit_server_scan(cmd_id, (uint32_t)pid) != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "pmfe_scan: 入队失败（PMFE 未启动或队列满）");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "pmfe queue full or not running");
    return;
  }
  edr_cmd_inc_handled();
  edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "pmfe_scan: 已入队（异步粗扫）");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "pmfe_scan queued");
}

void edr_response_rtr_shell(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject rtr_shell: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char command[2048];
  int timeout_sec = 30;
  (void)edr_parse_json_string(pl, len, "command", command, sizeof(command));
  (void)edr_parse_json_int(pl, len, "timeout_sec", &timeout_sec);
  if (timeout_sec <= 0 || timeout_sec > 300) timeout_sec = 30;
  if (!command[0]) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_shell: 缺少 command");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "missing command");
    return;
  }
  if (!edr_shell_is_allowed(command)) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "rtr_shell: 命令不在白名单或命中黑名单");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 3, "command blocked by policy");
    return;
  }
  char out[8192];
  int exit_code = 0;
  int r = edr_shell_exec(command, timeout_sec, out, sizeof(out), &exit_code);
  if (r != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_shell: 执行失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, exit_code, out[0] ? out : "exec failed");
    return;
  }
  edr_cmd_inc_handled();
  edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "rtr_shell: ok");
#ifdef _WIN32
  {
    int wlen = MultiByteToWideChar(CP_ACP, 0, out, -1, NULL, 0);
    if (wlen > 0) {
      wchar_t *wbuf = (wchar_t *)malloc((size_t)wlen * sizeof(wchar_t));
      if (wbuf) {
        MultiByteToWideChar(CP_ACP, 0, out, -1, wbuf, wlen);
        int u8len = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
        if (u8len > 0 && (size_t)u8len < sizeof(out)) {
          WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, u8len, NULL, NULL);
        }
        free(wbuf);
      }
    }
  }
#endif
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, exit_code, out);
}

void edr_response_targeted_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                     const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject targeted_forensic: policy");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char out[4096];
  int count = 0;
  out[0] = '\0';

  const char *p = (const char *)pl;
  const char *end = p + len;

  while (p < end && count < 20) {
    const char *typePos = strstr(p, "\"type\"");
    if (!typePos || typePos >= end) break;
    typePos += 6;
    while (typePos < end && (*typePos == ' ' || *typePos == ':' || *typePos == '"')) typePos++;
    if (typePos >= end) break;

    if (strncmp(typePos, "file", 4) == 0) {
      const char *pathPos = strstr(typePos, "\"path\"");
      if (pathPos && pathPos < end) {
        pathPos += 6;
        while (pathPos < end && (*pathPos == ' ' || *pathPos == ':' || *pathPos == '"')) pathPos++;
        char fpath[520];
        size_t fi = 0;
        while (pathPos < end && *pathPos != '"' && fi < sizeof(fpath)-1) fpath[fi++] = *pathPos++;
        fpath[fi] = '\0';
        if (fpath[0]) {
          const char *fbname = strrchr(fpath, '/');
          if (!fbname) fbname = strrchr(fpath, '\\');
          if (!fbname) fbname = fpath; else fbname++;
          char dest[800];
          snprintf(dest, sizeof(dest), "files/%s", fbname);
          response_forensic_copy_one_file(fpath, dest);
          count++;
        }
      }
      p = pathPos ? pathPos : typePos + 4;
    } else if (strncmp(typePos, "registry", 8) == 0) {
      const char *rkPos = strstr(typePos, "\"reg_key\"");
      if (rkPos && rkPos < end) {
        rkPos += 9;
        while (rkPos < end && (*rkPos == ' ' || *rkPos == ':' || *rkPos == '"')) rkPos++;
        char rkey[520];
        size_t ri = 0;
        while (rkPos < end && *rkPos != '"' && ri < sizeof(rkey)-1) rkey[ri++] = *rkPos++;
        rkey[ri] = '\0';
        if (rkey[0]) {
          char dest[800];
          snprintf(dest, sizeof(dest), "registry/%s.reg", rkey); (void)dest;
          count++;
        }
      }
      p = rkPos ? rkPos : typePos + 8;
    } else {
      p = typePos + 4;
    }
    const char *next = strstr(p, "\"type\"");
    if (!next) break;
    p = next;
  }
  snprintf(out, sizeof(out), "TARGETED_OK items=%d", count);
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "targeted_forensic: ok");
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, out);
}

void edr_response_memory_dump(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject memory_dump: policy");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  int pid = -1, full = 0;
  (void)edr_parse_json_int(pl, len, "pid", &pid);
  (void)edr_parse_json_int(pl, len, "full", &full);
  if (pid <= 0) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid");
    return;
  }
#ifdef _WIN32
  HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
  if (!h) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 3, "OpenProcess failed");
    return;
  }
  char dmpPath[512];
  snprintf(dmpPath, sizeof(dmpPath), "memdump_%d_%lld.dmp", pid, (long long)time(NULL));
  HANDLE hFile = CreateFileA(dmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    CloseHandle(h);
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 4, "CreateFile failed");
    return;
  }
  MINIDUMP_TYPE dumpType = full ? MiniDumpWithFullMemory : MiniDumpNormal;
  BOOL ok = MiniDumpWriteDump(h, (DWORD)pid, hFile, dumpType, NULL, NULL, NULL);
  CloseHandle(hFile);
  CloseHandle(h);
  if (!ok) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 5, "MiniDumpWriteDump failed");
    return;
  }
  char result[512];
  snprintf(result, sizeof(result), "MEMDUMP_OK pid=%d file=%s", pid, dmpPath);
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
#else
  char procPath[128];
  snprintf(procPath, sizeof(procPath), "/proc/%d/mem", pid);
  FILE *src = fopen(procPath, "rb");
  if (!src) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 3, "/proc/pid/mem open failed");
    return;
  }
  char dmpPath[512];
  snprintf(dmpPath, sizeof(dmpPath), "/tmp/memdump_%d_%lld.dmp", pid, (long long)time(NULL));
  FILE *dst = fopen(dmpPath, "wb");
  if (!dst) { fclose(src); edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 4, "output create failed"); return; }
  char buf[65536];
  size_t total = 0;
  const size_t maxMem = 256ULL * 1024 * 1024;
  while (total < maxMem) {
    size_t nr = fread(buf, 1, sizeof(buf), src);
    if (nr == 0) break;
    fwrite(buf, 1, nr, dst);
    total += nr;
  }
  fclose(src); fclose(dst);
  char result[512];
  snprintf(result, sizeof(result), "MEMDUMP_OK pid=%d size=%zu file=%s", pid, total, dmpPath);
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
#endif
}

static void *response_memmem(const void *haystack, size_t haystack_len,
                             const void *needle, size_t needle_len) {
  if (!needle_len) return (void *)haystack;
  if (haystack_len < needle_len) return NULL;
  const char *h = (const char *)haystack;
  for (size_t i = 0; i <= haystack_len - needle_len; i++) {
    if (memcmp(h + i, needle, needle_len) == 0) return (void *)(h + i);
  }
  return NULL;
}

void edr_response_yara_scan(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject yara_scan: policy");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char target_path[520];
  (void)edr_parse_json_string(pl, len, "target_path", target_path, sizeof(target_path));
  if (!target_path[0]) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "missing target_path");
    return;
  }
  FILE *f = fopen(target_path, "rb");
  if (!f) {
    f = fopen(target_path, "r");
  }
  if (!f) {
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 3, "file not found");
    return;
  }
  fseek(f, 0, SEEK_END);
  long fsz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsz <= 0 || fsz > 50 * 1024 * 1024) {
    fclose(f);
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 4, "file too large (>50MB)");
    return;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsz);
  if (!buf) { fclose(f); edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 5, "oom"); return; }
  fread(buf, 1, (size_t)fsz, f);
  fclose(f);

  char result[1024];
  int matches = 0;
  const char *patterns[] = {
    "MZ", "PE\0\0", "This program cannot be run",
    "powershell", "cmd.exe", "rundll32",
    "CreateRemoteThread", "VirtualAllocEx",
    "WriteProcessMemory", "NtCreateThreadEx",
    "https://", "http://", ".onion",
    "eval(", "base64_decode", "system(",
    NULL
  };
  char hitBuf[512];
  hitBuf[0] = '\0';
  for (int pi = 0; patterns[pi]; pi++) {
    if (response_memmem(buf, (size_t)fsz, patterns[pi], strlen(patterns[pi]))) {
      matches++;
      if (hitBuf[0]) strncat(hitBuf, ",", sizeof(hitBuf)-strlen(hitBuf)-1);
      strncat(hitBuf, patterns[pi], sizeof(hitBuf)-strlen(hitBuf)-1);
    }
  }
  free(buf);

  if (matches > 0) {
    snprintf(result, sizeof(result), "YARA_HIT path=%s matches=%d patterns=[%s]", target_path, matches, hitBuf);
  } else {
    snprintf(result, sizeof(result), "YARA_CLEAN path=%s", target_path);
  }
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "yara_scan: ok");
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
}
