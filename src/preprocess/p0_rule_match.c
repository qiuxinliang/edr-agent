#include "edr/p0_rule_match.h"

#include "edr/p0_rule_ir.h"

#include <ctype.h>
#include <stddef.h>
#include <string.h>

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
  return proc_name_ends(name, "powershell.exe") || proc_name_ends(name, "pwsh.exe");
}

static int match_r_exec_001(const char *cmd) {
  if (cistr_find(cmd, "encodedcommand") || cistr_find(cmd, "frombase64string")) {
    return 1;
  }
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
  edr_p0_rule_ir_lazy_init();
  if (edr_p0_rule_ir_is_ready()) {
    return edr_p0_rule_ir_matches(rule_id, process_name, cmdline, parent_name, process_chain_depth) ? 1 : 0;
  }
  return p0_match_legacy(rule_id, process_name, cmdline, process_chain_depth);
}

int edr_p0_rule_matches2(
    const char *rule_id, const char *process_name, const char *cmdline, int process_chain_depth) {
  return edr_p0_rule_matches3(rule_id, process_name, cmdline, NULL, process_chain_depth);
}
