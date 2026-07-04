#include "edr/response.h"
#include "edr/command_util.h"
#include "edr/config.h"
#include "edr/deep_collector.h"
#include "edr/error.h"
#include "edr/ingest_http.h"
#include "edr/pmfe.h"
#include "edr/sha256.h"
#include "edr/shell_session.h"
#include "edr/edr_log.h"
#include "edr/pe_verify.h"
#include "edr/shell_exec.h"
#include "edr/transport_v2.h"

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

/* ── File Actions ── */

static int response_get_tmp_path(const char *cmd_id, char *out, size_t out_cap) {
  const char *tmp = getenv("EDR_FILE_TMP");
  if (!tmp || !tmp[0]) {
#ifdef _WIN32
    tmp = getenv("TEMP");
    if (!tmp || !tmp[0]) tmp = getenv("TMP");
    if (!tmp || !tmp[0]) tmp = ".";
    snprintf(out, out_cap, "%s\\edr_get_%s", tmp, cmd_id ? cmd_id : "unknown");
#else
    snprintf(out, out_cap, "/tmp/edr_get_%s", cmd_id ? cmd_id : "unknown");
#endif
  } else {
    snprintf(out, out_cap, "%s%sedr_get_%s", tmp,
#ifdef _WIN32
             "\\",
#else
             "/",
#endif
             cmd_id ? cmd_id : "unknown");
  }
  return 0;
}

static int response_b64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap) {
  static const uint8_t tbl[256] = {
    ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,['I']=8,['J']=9,
    ['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,['T']=19,
    ['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,
    ['e']=30,['f']=31,['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
    ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,
    ['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,
    ['8']=60,['9']=61,['+']=62,['-']=62,['/']=63,['_']=63,
  };
  size_t o = 0;
  for (size_t i = 0; i + 3 < in_len && o + 2 < out_cap; i += 4) {
    uint8_t a = tbl[(uint8_t)in[i]], b = tbl[(uint8_t)in[i+1]];
    uint8_t c = tbl[(uint8_t)in[i+2]], d = tbl[(uint8_t)in[i+3]];
    out[o++] = (uint8_t)((a << 2) | (b >> 4));
    if (in[i+2] != '=' && in[i+2] != 0) out[o++] = (uint8_t)((b << 4) | (c >> 2));
    if (in[i+3] != '=' && in[i+3] != 0) out[o++] = (uint8_t)((c << 6) | d);
  }
  return (int)o;
}

void edr_response_get_file(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject rtr_get: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  int max_size_bytes = 100 * 1024 * 1024;
  int pe_only_flag = 0;
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  (void)edr_parse_json_int(pl, len, "max_size_bytes", &max_size_bytes);
  (void)edr_parse_json_int(pl, len, "pe_only", &pe_only_flag);
  if (!path[0]) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_get: 缺少 path");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    edr_cmd_inc_exec_fail();
    char errbuf[600];
    snprintf(errbuf, sizeof(errbuf), "rtr_get: file not found path=%s", path);
    edr_command_audit_both(cmd_id, errbuf);
    snprintf(errbuf, sizeof(errbuf), "file not found: %s", path);
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 3, errbuf);
    return;
  }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsize <= 0 || fsize > max_size_bytes) {
    fclose(f);
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_get: 文件大小超限");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 4, "file size out of range");
    return;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
  if (!buf) {
    fclose(f);
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 5, "oom");
    return;
  }
  if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
    free(buf); fclose(f);
    edr_cmd_inc_exec_fail();
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 6, "read error");
    return;
  }
  fclose(f);

  char sha[65];
  edr_sha256_hex(buf, (size_t)fsize, sha);

  if (pe_only_flag) {
    char pe_info[512];
    if (!edr_pe_verify(buf, (size_t)fsize, pe_info, sizeof(pe_info))) {
      free(buf);
      edr_cmd_inc_rejected();
      edr_command_audit_both(cmd_id, "rtr_get: 非有效PE文件");
      edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 7, "not a valid PE file");
      return;
    }
    char tmp_path[1024];
    response_get_tmp_path(cmd_id, tmp_path, sizeof(tmp_path));
    FILE *tf = fopen(tmp_path, "wb");
    if (tf) {
      fwrite(buf, 1, (size_t)fsize, tf);
      fclose(tf);
      char minio_key[256] = {0};
      edr_transport_v2_upload_file(cmd_id, tmp_path, sha, minio_key, sizeof(minio_key));
      remove(tmp_path);
      char result[1280];
      snprintf(result, sizeof(result), "PE_OK sha256=%s size=%ld path=%s minio_key=%s %s",
               sha, fsize, path, minio_key[0] ? minio_key : "", pe_info);
      free(buf);
      edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
      edr_command_audit_both(cmd_id, "rtr_get: PE验证通过+上传");
      edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
    } else {
      free(buf);
      char result[1024];
      snprintf(result, sizeof(result), "PE_OK sha256=%s size=%ld path=%s (upload failed) %s", sha, fsize, path, pe_info);
      edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
      edr_command_audit_both(cmd_id, "rtr_get: PE验证通过, 上传失败");
      edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
    }
    return;
  }

  char tmp_path[1024];
  response_get_tmp_path(cmd_id, tmp_path, sizeof(tmp_path));
  FILE *tf = fopen(tmp_path, "wb");
  if (tf) {
    fwrite(buf, 1, (size_t)fsize, tf);
    fclose(tf);
    char minio_key[256] = {0};
    edr_transport_v2_upload_file(cmd_id, tmp_path, sha, minio_key, sizeof(minio_key));
    remove(tmp_path);
    char result[768];
    snprintf(result, sizeof(result), "FILE_OK sha256=%s size=%ld path=%s minio_key=%s",
             sha, fsize, path, minio_key[0] ? minio_key : "");
    free(buf);
    edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
    edr_command_audit_both(cmd_id, "rtr_get: 文件读取+上传成功");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
  } else {
    char result[512];
    snprintf(result, sizeof(result), "FILE_OK sha256=%s size=%ld path=%s (upload to backend failed, tmp write error)",
             sha, fsize, path);
    free(buf);
    edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
    edr_command_audit_both(cmd_id, "rtr_get: 文件读取成功, tmp写入失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
  }
}

void edr_response_put_file(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject rtr_put: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  if (!path[0]) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_put: 缺少 path");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }
  /* data_b64 按 payload 实际大小堆分配,消除原 512KB 栈缓冲(栈溢出风险)与 ~384KB 人为上限;
     单条命令的文件大小上限改由传输层命令体大小决定。 */
  char *data_b64 = (char *)malloc(len + 1u);
  if (!data_b64) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_put: oom (b64 buffer)");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "oom");
    return;
  }
  data_b64[0] = '\0';
  (void)edr_parse_json_string(pl, len, "data_b64", data_b64, len + 1u);
  /* 可选 offset:>=0 时为顺序分块写入(大文件由后端拆成多条 put,按偏移续写);
     缺省 -1 = 整文件单发(行为与旧版一致)。 */
  int offset = -1;
  (void)edr_parse_json_int(pl, len, "offset", &offset);

  if (!data_b64[0]) {
    free(data_b64);
    FILE *f = fopen(path, "ab");
    if (!f) {
      edr_cmd_inc_exec_fail();
      edr_command_audit_both(cmd_id, "rtr_put: 无法创建文件");
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "cannot create file");
      return;
    }
    fclose(f);
    char action[80];
    snprintf(action, sizeof(action), "PUT_OK (empty) %s", path);
    edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
    edr_command_audit_both(cmd_id, "rtr_put: ok (empty file)");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, action);
    return;
  }
  size_t b64_len = strlen(data_b64);
  size_t dec_cap = (b64_len / 4 * 3) + 16;
  uint8_t *dec = (uint8_t *)malloc(dec_cap);
  if (!dec) {
    free(data_b64);
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_put: oom");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "oom");
    return;
  }
  int dlen = response_b64_decode(data_b64, b64_len, dec, dec_cap);
  free(data_b64);
  if (dlen <= 0) {
    free(dec);
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_put: base64 decode failed");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "base64 decode failed");
    return;
  }
  {
    char dir_copy[520];
    snprintf(dir_copy, sizeof(dir_copy), "%s", path);
#ifdef _WIN32
    char *slash = strrchr(dir_copy, '\\');
#else
    char *slash = strrchr(dir_copy, '/');
#endif
    if (slash) { *slash = '\0'; response_mkdir_p(dir_copy); }
  }
  /* offset<=0:整文件/首块 → 截断创建;offset>0:对已有文件按偏移续写(顺序分块)。 */
  FILE *f;
  if (offset > 0) {
    f = fopen(path, "r+b");
    if (!f) {
      f = fopen(path, "wb"); /* 容错:目标尚不存在则新建 */
    }
    if (f) {
      (void)fseek(f, (long)offset, SEEK_SET);
    }
  } else {
    f = fopen(path, "wb");
  }
  if (!f) {
    free(dec);
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_put: 无法创建文件");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, "cannot create file");
    return;
  }
  size_t written = fwrite(dec, 1, (size_t)dlen, f);
  fclose(f);
  char sha[65] = {0};
  if (written > 0) edr_sha256_hex(dec, written, sha);
  free(dec);
  /* sha256(若给出)校验本次写入分片的内容;分块场景下不匹配即中止整次传输。 */
  char expected_sha[65] = {0};
  (void)edr_parse_json_string(pl, len, "sha256", expected_sha, sizeof(expected_sha));
  if (expected_sha[0] && sha[0] && strcmp(expected_sha, sha) != 0) {
    remove(path);
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_put: sha256 mismatch");
    char msg[300];
    snprintf(msg, sizeof(msg), "SHA256_MISMATCH expected=%s actual=%s", expected_sha, sha);
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 7, msg);
    return;
  }
  char action[220];
  if (offset >= 0) {
    snprintf(action, sizeof(action), "PUT_OK %s offset=%d size=%d sha256=%s", path, offset, dlen, sha);
  } else {
    snprintf(action, sizeof(action), "PUT_OK %s size=%d sha256=%s", path, dlen, sha);
  }
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "rtr_put: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, action);
}

void edr_response_remove_file(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject rtr_rm: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  if (!path[0]) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_rm: 缺少 path");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }
  if (remove(path) != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "rtr_rm: 删除失败");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "remove failed");
    return;
  }
  char result[600];
  snprintf(result, sizeof(result), "RM_OK %s", path);
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "rtr_rm: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
}

void edr_response_quarantine_file(const char *cmd_id, const uint8_t *pl, size_t len,
                                   const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject quarantine_file: policy");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  if (!path[0]) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "quarantine_file: 缺少 path");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }
  FILE *src = fopen(path, "rb");
  if (!src) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "quarantine_file: 文件不存在");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "file not found");
    return;
  }
  fseek(src, 0, SEEK_END);
  long fsize = ftell(src);
  fseek(src, 0, SEEK_SET);
  if (fsize <= 0 || fsize > 256 * 1024 * 1024) {
    fclose(src);
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "file too large");
    return;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
  if (!buf) { fclose(src); edr_cmd_inc_exec_fail(); return; }
  if (fread(buf, 1, (size_t)fsize, src) != (size_t)fsize) {
    free(buf); fclose(src); edr_cmd_inc_exec_fail(); return;
  }
  fclose(src);
  char sha[65];
  edr_sha256_hex(buf, (size_t)fsize, sha);
  const char *bname = strrchr(path, '/');
  if (!bname) bname = strrchr(path, '\\');
  if (!bname) bname = path; else bname++;
  char qpath[1024];
#ifdef _WIN32
  snprintf(qpath, sizeof(qpath), "C:\\Program Files\\FDSecurity\\quarantine\\%s_%s", sha, bname);
#else
  snprintf(qpath, sizeof(qpath), "/var/lib/edr/quarantine/%s_%s", sha, bname);
#endif
  {
    char qdir[1024];
    snprintf(qdir, sizeof(qdir), "%s", qpath);
    char *slash = strrchr(qdir, '/');
    if (!slash) slash = strrchr(qdir, '\\');
    if (slash) { *slash = '\0'; (void)response_mkdir_p(qdir); }
  }
  FILE *dst = fopen(qpath, "wb");
  if (!dst) { free(buf); edr_cmd_inc_exec_fail(); edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "quarantine write failed"); return; }
  fwrite(buf, 1, (size_t)fsize, dst);
  fclose(dst);
  free(buf);
  if (remove(path) != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, "original remove failed");
    return;
  }
  char result[1024];
  snprintf(result, sizeof(result), "QUARANTINE_OK path=%s sha256=%s size=%ld", qpath, sha, fsize);
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "quarantine_file: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
}

void edr_response_restore_file(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject restore_file: policy");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char qpath[520], dest[520];
  (void)edr_parse_json_string(pl, len, "quarantine_path", qpath, sizeof(qpath));
  (void)edr_parse_json_string(pl, len, "dest", dest, sizeof(dest));
  if (!qpath[0] || !dest[0]) {
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing quarantine_path or dest");
    return;
  }
  if (response_forensic_copy_one_file(qpath, dest) != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "restore copy failed");
    return;
  }
  remove(qpath);
  char result[600];
  snprintf(result, sizeof(result), "RESTORE_OK %s -> %s", qpath, dest);
  edr_cmd_inc_handled(); edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "restore_file: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
}
