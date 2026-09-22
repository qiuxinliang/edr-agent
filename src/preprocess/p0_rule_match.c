#include "edr/p0_rule_match.h"

#include "edr/p0_rule_ir.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
typedef volatile LONG64 EdrP0Stat64;
static void p0_stat_inc(EdrP0Stat64 *p) { (void)InterlockedIncrement64(p); }
static void p0_stat_store(EdrP0Stat64 *p, uint64_t v) { (void)InterlockedExchange64(p, (LONG64)v); }
static uint64_t p0_stat_load(EdrP0Stat64 *p) { return (uint64_t)InterlockedCompareExchange64(p, 0, 0); }
#else
typedef volatile uint64_t EdrP0Stat64;
static void p0_stat_inc(EdrP0Stat64 *p) { (void)__atomic_add_fetch(p, 1u, __ATOMIC_RELAXED); }
static void p0_stat_store(EdrP0Stat64 *p, uint64_t v) { __atomic_store_n(p, v, __ATOMIC_RELAXED); }
static uint64_t p0_stat_load(EdrP0Stat64 *p) { return __atomic_load_n(p, __ATOMIC_RELAXED); }
#endif

static EdrP0Stat64 s_p0_total_calls;
static EdrP0Stat64 s_p0_env_not_set_skip;
static EdrP0Stat64 s_p0_ir_mode_matches;
static EdrP0Stat64 s_p0_fallback_mode_matches;
static EdrP0Stat64 s_p0_rule_r_exec_001_hits;
static EdrP0Stat64 s_p0_rule_r_cred_001_hits;
static EdrP0Stat64 s_p0_rule_r_fileless_001_hits;
static EdrP0Stat64 s_p0_rule_other_hits;
static EdrP0Stat64 s_p0_powershell_detected;
static EdrP0Stat64 s_p0_encoded_cmd_detected;
static EdrP0Stat64 s_p0_base64_string_detected;
static EdrP0Stat64 s_p0_remote_download_detected;

static void ascii_lower_in_place(char *p) {
  for (; p && *p; p++) {
    if (*p >= 'A' && *p <= 'Z') {
      *p = (char)(*p - 'A' + 'a');
    }
  }
}

static int cistr_find(const char *hay, const char *needle) {
  if (!hay || !needle || !*needle) {
    return 0;
  }
  char hbuf[2048];
  char nbuf[256];
  size_t hlen = strnlen(hay, sizeof(hbuf) - 1u);
  size_t nlen = strnlen(needle, sizeof(nbuf) - 1u);
  if (hlen == sizeof(hbuf) - 1u || nlen == sizeof(nbuf) - 1u) {
    return 0;
  }
  memcpy(hbuf, hay, hlen);
  hbuf[hlen] = 0;
  memcpy(nbuf, needle, nlen);
  nbuf[nlen] = 0;
  ascii_lower_in_place(hbuf);
  ascii_lower_in_place(nbuf);
  return strstr(hbuf, nbuf) != NULL;
}

int edr_p0_normalize_command_for_evidence(const char *input, char *out,
                                          size_t out_cap) {
  size_t used = 0u;
  int pending_space = 0;
  int truncated = 0;
  if (!out || out_cap == 0u) return input && input[0] ? 1 : 0;
  out[0] = '\0';
  if (!input) return 0;
  for (const char *p = input; *p; ++p) {
    char c = *p;
    if (c == '"' || c == '\'') continue;
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      pending_space = used > 0u ? 1 : 0;
      continue;
    }
    if (pending_space) {
      if (used + 2u >= out_cap) {
        truncated = 1;
        break;
      }
      out[used++] = ' ';
      pending_space = 0;
    }
    if (used + 1u >= out_cap) {
      truncated = 1;
      break;
    }
    if (c == '\\') c = '/';
    else if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    out[used++] = c;
  }
  out[used] = '\0';
  return truncated;
}

static int p0_command_token_next(const char **cursor, char *out,
                                 size_t out_cap) {
  const char *p;
  char quote = '\0';
  size_t used = 0u;
  int overflow = 0;
  if (!cursor || !*cursor || !out || out_cap == 0u) return 0;
  p = *cursor;
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
  if (!*p) {
    out[0] = '\0';
    *cursor = p;
    return 0;
  }
  if (*p == '"' || *p == '\'') quote = *p++;
  while (*p) {
    if (quote) {
      if (*p == quote) {
        ++p;
        break;
      }
    } else if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
      break;
    }
    if (used + 1u < out_cap) out[used++] = *p;
    else overflow = 1;
    ++p;
  }
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
  out[used] = '\0';
  *cursor = p;
  return !overflow && used > 0u;
}

static int p0_command_token_equals_ci(const char *value, const char *expected) {
  if (!value || !expected) return 0;
  while (*value && *expected) {
    char a = *value++;
    char b = *expected++;
    if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
    if (a != b) return 0;
  }
  return *value == '\0' && *expected == '\0';
}

static int p0_command_token_is_script(const char *value) {
  static const char *extensions[] = {".ps1", ".psm1", ".psd1", ".bat",
                                     ".cmd", ".vbs", ".vbe", ".js", ".jse",
                                     ".wsf", ".wsh"};
  size_t value_len;
  if (!value || !value[0]) return 0;
  value_len = strlen(value);
  for (size_t i = 0u; i < sizeof(extensions) / sizeof(extensions[0]); ++i) {
    size_t ext_len = strlen(extensions[i]);
    if (value_len >= ext_len &&
        p0_command_token_equals_ci(value + value_len - ext_len, extensions[i])) {
      return 1;
    }
  }
  return 0;
}

int edr_p0_extract_script_path(const char *command_line, char *out,
                               size_t out_cap) {
  const char *cursor = command_line;
  char token[1024];
  int first = 1;
  int next_is_script = 0;
  if (!out || out_cap == 0u) return 0;
  out[0] = '\0';
  if (!command_line) return 0;
  while (p0_command_token_next(&cursor, token, sizeof(token))) {
    if (next_is_script) {
      if (!p0_command_token_is_script(token) || strlen(token) >= out_cap) return 0;
      memcpy(out, token, strlen(token) + 1u);
      return 1;
    }
    if (!first && (p0_command_token_equals_ci(token, "-file") ||
                   p0_command_token_equals_ci(token, "/file") ||
                   p0_command_token_equals_ci(token, "-f"))) {
      next_is_script = 1;
    } else if (!first && p0_command_token_is_script(token)) {
      if (strlen(token) >= out_cap) return 0;
      memcpy(out, token, strlen(token) + 1u);
      return 1;
    }
    first = 0;
  }
  return 0;
}

static int proc_name_ends(const char *name, const char *exe) {
  if (!name || !*name || !exe || !*exe) {
    return 0;
  }
  char nbuf[320];
  char ebuf[96];
  size_t nl = strnlen(name, sizeof(nbuf) - 1u);
  size_t el = strnlen(exe, sizeof(ebuf) - 1u);
  if (nl == sizeof(nbuf) - 1u || el == sizeof(ebuf) - 1u) {
    return 0;
  }
  memcpy(nbuf, name, nl);
  nbuf[nl] = 0;
  memcpy(ebuf, exe, el);
  ebuf[el] = 0;
  ascii_lower_in_place(nbuf);
  ascii_lower_in_place(ebuf);
  size_t nlen = strlen(nbuf);
  size_t elen = strlen(ebuf);
  if (nlen < elen) {
    return 0;
  }
  return strcmp(nbuf + (nlen - elen), ebuf) == 0;
}

static int is_powershell_name(const char *name) {
  if (!name) return 0;
  const char *base = strrchr(name, '\\');
  base = base ? base + 1 : name;
  return proc_name_ends(base, "powershell.exe") ||
         proc_name_ends(base, "pwsh.exe") ||
         proc_name_ends(base, "powershell_ise.exe") ||
         proc_name_ends(base, "powershellfx.exe") ||
         proc_name_ends(base, "wsmprovhost.exe") ||
         proc_name_ends(base, "winrshost.exe") ||
         proc_name_ends(base, "powershell") ||
         proc_name_ends(base, "pwsh");
}

static int match_r_exec_001(const char *cmd) {
  if (!cmd) return 0;

  // 检查编码命令参数变体
  static const char *enc_args[] = {
      "encodedcommand", "enc", "-enc", "/enc",
      "-encodedcommand", "/encodedcommand", "-e", "/e",
      "-encoded", "/encoded"
  };
  for (int i = 0; i < 9; i++) {
    if (cistr_find(cmd, enc_args[i])) {
      return 1;
    }
  }

  // 检查Base64相关函数
  if (cistr_find(cmd, "frombase64string") ||
      cistr_find(cmd, "convert.frombase64string") ||
      cistr_find(cmd, "[system.convert]::frombase64") ||
      cistr_find(cmd, "-join") ||
      cistr_find(cmd, "[io.file]::readallbytes")) {
    return 1;
  }

  // 检查IEX/Invoke-Expression变体
  if (cistr_find(cmd, "iex ") ||
      cistr_find(cmd, "& {") ||
      cistr_find(cmd, ".downloadstring") ||
      cistr_find(cmd, ".downloadfile") ||
      cistr_find(cmd, "invoke-expression") ||
      cistr_find(cmd, "invoke-webrequest") ||
      cistr_find(cmd, "new-object net.webclient") ||
      cistr_find(cmd, "net.webclient") ||
      cistr_find(cmd, "[net.webclient]") ||
      cistr_find(cmd, "system.net.webclient")) {
    return 1;
  }

  // 检查远程脚本下载
  if (cistr_find(cmd, "http://") || cistr_find(cmd, "https://")) {
    if (cistr_find(cmd, ".ps1") || cistr_find(cmd, ".txt") ||
        cistr_find(cmd, "downloadstring") || cistr_find(cmd, "downloadfile")) {
      return 1;
    }
  }

  // 检查可疑的编码格式（以-或/开头，后面跟着可疑的字符串）
  for (const char *p = cmd; p && *p; p++) {
    if (p[0] != '-' && p[0] != '/') {
      continue;
    }
    if ((p[1] == 'e' || p[1] == 'E') && (p[2] == 'n' || p[2] == 'N') && (p[3] == 'c' || p[3] == 'C')) {
      if (p[4] == 0 || !isalnum((unsigned char)p[4])) {
        if (p == cmd || !isalnum((unsigned char)p[-1])) {
          return 1;
        }
      }
    }
  }

  // 检查Base64字符串模式（以空格开头，后面跟着长Base64字符串）
  const char *b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  for (const char *p = cmd; p && *p; p++) {
    if (*p == ' ' && *(p + 1) && strchr(b64_chars, *(p + 1))) {
      int b64_len = 0;
      const char *q = p + 1;
      while (*q && strchr(b64_chars, *q)) {
        b64_len++;
        q++;
      }
      if (b64_len >= 20) {
        return 1;
      }
    }
  }

  return 0;
}

static int match_r_cred_001(const char *cmd) {
  if (!cistr_find(cmd, "save") || !cistr_find(cmd, "hklm")) {
    return 0;
  }
  if (cistr_find(cmd, "hklm\\sam") || cistr_find(cmd, "hklm/sam")) {
    return 1;
  }
  if (cistr_find(cmd, "hklm\\system") || cistr_find(cmd, "hklm/system")) {
    return 1;
  }
  if (cistr_find(cmd, "hklm\\security") || cistr_find(cmd, "hklm/security")) {
    return 1;
  }
  return 0;
}

static int is_wordish_iex(const char *p) {
  return (p[0] == 'i' || p[0] == 'I') && (p[1] == 'e' || p[1] == 'E') && (p[2] == 'x' || p[2] == 'X') &&
         !isalnum((unsigned char)p[3]);
}

static int match_r_fileless_001(const char *cmd) {
  if (cistr_find(cmd, "invoke-expression")) {
    return 1;
  }
  if (cistr_find(cmd, "[reflection.assembly]::load") || cistr_find(cmd, "::loadfrom")) {
    return 1;
  }
  for (const char *p = cmd; p && *p; p++) {
    if (is_wordish_iex(p)) {
      if (p == cmd || !isalnum((unsigned char)p[-1])) {
        return 1;
      }
    }
  }
  return 0;
}

/* IR 未加载时（如缺 pcre2/缺 JSON）的兜底，与历史行为一致。 */
static int p0_match_legacy(
    const char *rule_id, const char *process_name, const char *cmdline, int process_chain_depth) {
  const char *pn = process_name ? process_name : "";
  const char *cmd = cmdline ? cmdline : "";
  (void)process_chain_depth;
  if (!rule_id) {
    return 0;
  }
  if (strcmp(rule_id, "R-EXEC-001") == 0) {
    return (is_powershell_name(pn) && match_r_exec_001(cmd)) ? 1 : 0;
  }
  if (strcmp(rule_id, "R-CRED-001") == 0) {
    return (proc_name_ends(pn, "reg.exe") && match_r_cred_001(cmd)) ? 1 : 0;
  }
  if (strcmp(rule_id, "R-FILELESS-001") == 0) {
    return (is_powershell_name(pn) && match_r_fileless_001(cmd)) ? 1 : 0;
  }
  return 0;
}

int edr_p0_rule_matches3(
    const char *rule_id, const char *process_name, const char *cmdline, const char *parent_name, int process_chain_depth) {
  p0_stat_inc(&s_p0_total_calls);
  edr_p0_rule_ir_lazy_init();
  if (edr_p0_rule_ir_is_ready()) {
    int result = edr_p0_rule_ir_matches(rule_id, process_name, cmdline, parent_name, process_chain_depth) ? 1 : 0;
    if (result) {
      p0_stat_inc(&s_p0_ir_mode_matches);
    }
    return result;
  }
  int result = p0_match_legacy(rule_id, process_name, cmdline, process_chain_depth);
  if (result) {
    p0_stat_inc(&s_p0_fallback_mode_matches);
  }
  return result;
}

int edr_p0_rule_matches2(
    const char *rule_id, const char *process_name, const char *cmdline, int process_chain_depth) {
  return edr_p0_rule_matches3(rule_id, process_name, cmdline, NULL, process_chain_depth);
}

int edr_p0_rule_get_stats(EdrP0RuleStats *out_stats) {
  if (!out_stats) {
    return -1;
  }
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->total_calls = p0_stat_load(&s_p0_total_calls);
  out_stats->env_not_set_skip = p0_stat_load(&s_p0_env_not_set_skip);
  out_stats->ir_mode_matches = p0_stat_load(&s_p0_ir_mode_matches);
  out_stats->fallback_mode_matches = p0_stat_load(&s_p0_fallback_mode_matches);
  out_stats->rule_r_exec_001_hits = p0_stat_load(&s_p0_rule_r_exec_001_hits);
  out_stats->rule_r_cred_001_hits = p0_stat_load(&s_p0_rule_r_cred_001_hits);
  out_stats->rule_r_fileless_001_hits = p0_stat_load(&s_p0_rule_r_fileless_001_hits);
  out_stats->rule_other_hits = p0_stat_load(&s_p0_rule_other_hits);
  out_stats->powershell_detected = p0_stat_load(&s_p0_powershell_detected);
  out_stats->encoded_cmd_detected = p0_stat_load(&s_p0_encoded_cmd_detected);
  out_stats->base64_string_detected = p0_stat_load(&s_p0_base64_string_detected);
  out_stats->remote_download_detected = p0_stat_load(&s_p0_remote_download_detected);
  return 0;
}

void edr_p0_rule_reset_stats(void) {
  p0_stat_store(&s_p0_total_calls, 0);
  p0_stat_store(&s_p0_env_not_set_skip, 0);
  p0_stat_store(&s_p0_ir_mode_matches, 0);
  p0_stat_store(&s_p0_fallback_mode_matches, 0);
  p0_stat_store(&s_p0_rule_r_exec_001_hits, 0);
  p0_stat_store(&s_p0_rule_r_cred_001_hits, 0);
  p0_stat_store(&s_p0_rule_r_fileless_001_hits, 0);
  p0_stat_store(&s_p0_rule_other_hits, 0);
  p0_stat_store(&s_p0_powershell_detected, 0);
  p0_stat_store(&s_p0_encoded_cmd_detected, 0);
  p0_stat_store(&s_p0_base64_string_detected, 0);
  p0_stat_store(&s_p0_remote_download_detected, 0);
}
