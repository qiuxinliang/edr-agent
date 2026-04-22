/* §19.3.3 P1：securityPolicy 采集（Windows：netsh/注册表/PowerShell；Linux：iptables/ufw/proc） */

#include "edr/security_policy_collect.h"

#include "edr/config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#else
#include <unistd.h>
#endif

static void json_escape_str_fp(FILE *f, const char *s) {
  fputc('"', f);
  for (; s && *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      fputc('\\', f);
      fputc((int)c, f);
    } else if (c < 32u) {
      fprintf(f, "\\u%04x", (unsigned)c);
    } else {
      fputc((int)c, f);
    }
  }
  fputc('"', f);
}

#if defined(_WIN32) || defined(__linux__)
static void trim_crlf(char *s) {
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) {
    s[--n] = 0;
  }
}
#endif

static void snap_clear(EdrSecurityPolicySnap *o) {
  memset(o, 0, sizeof(*o));
  snprintf(o->sp_default_inbound, sizeof(o->sp_default_inbound), "%s", "UNKNOWN");
  snprintf(o->sp_default_outbound, sizeof(o->sp_default_outbound), "%s", "UNKNOWN");
}

#ifdef _WIN32

static int reg_dword_wow64(HKEY root, const char *subkey, const char *name, DWORD *out) {
  HKEY h = NULL;
  if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) {
    return -1;
  }
  DWORD type = 0;
  DWORD data = 0;
  DWORD sz = sizeof(data);
  LONG e = RegQueryValueExA(h, name, NULL, &type, (LPBYTE)&data, &sz);
  RegCloseKey(h);
  if (e != ERROR_SUCCESS || type != REG_DWORD) {
    return -1;
  }
  *out = data;
  return 0;
}

static void map_fw_policy_tokens(const char *pol, char *in_out, size_t in_cap, char *out_out, size_t out_cap) {
  snprintf(in_out, in_cap, "%s", "UNKNOWN");
  snprintf(out_out, out_cap, "%s", "UNKNOWN");
  if (!pol || !pol[0]) {
    return;
  }
  char buf[160];
  snprintf(buf, sizeof(buf), "%s", pol);
  trim_crlf(buf);
  char *inb = strstr(buf, "BlockInbound");
  char *ina = strstr(buf, "AllowInbound");
  char *outb = strstr(buf, "BlockOutbound");
  char *outa = strstr(buf, "AllowOutbound");
  if (inb) {
    snprintf(in_out, in_cap, "%s", "BLOCK");
  } else if (ina) {
    snprintf(in_out, in_cap, "%s", "ALLOW");
  }
  if (outb) {
    snprintf(out_out, out_cap, "%s", "BLOCK");
  } else if (outa) {
    snprintf(out_out, out_cap, "%s", "ALLOW");
  }
}

static int parse_netsh_state(const char *line, int *on_out) {
  const char *p = strstr(line, "State");
  if (!p) {
    return -1;
  }
  p += 5;
  while (*p == ' ' || *p == '\t') {
    p++;
  }
  if (p[0] == 'O' && p[1] == 'N' && (p[2] == 0 || p[2] == '\r' || isspace((unsigned char)p[2]))) {
    *on_out = 1;
    return 0;
  }
  if (p[0] == 'O' && p[1] == 'F' && p[2] == 'F') {
    *on_out = 0;
    return 0;
  }
  return -1;
}

static int parse_netsh_fw_policy(const char *line, char *inb, size_t in_cap, char *outb, size_t out_cap) {
  const char *p = strstr(line, "Firewall Policy");
  if (!p) {
    return -1;
  }
  p += (int)strlen("Firewall Policy");
  while (*p == ' ' || *p == '\t') {
    p++;
  }
  char val[128];
  snprintf(val, sizeof(val), "%s", p);
  trim_crlf(val);
  map_fw_policy_tokens(val, inb, in_cap, outb, out_cap);
  return 0;
}

static int ps_count_rules(const char *filter_expr) {
  char cmd[1400];
  snprintf(cmd, sizeof(cmd),
           "powershell.exe -NoProfile -NoLogo -Command "
           "\"(Get-NetFirewallRule | Where-Object { %s } | Measure-Object).Count\"",
           filter_expr);
  FILE *pf = _popen(cmd, "r");
  if (!pf) {
    return -1;
  }
  char line[64];
  if (!fgets(line, sizeof(line), pf)) {
    (void)_pclose(pf);
    return -1;
  }
  (void)_pclose(pf);
  trim_crlf(line);
  return (int)strtol(line, NULL, 10);
}

/** 与 §19.2.4 `highRiskAllowPorts` 对齐：入站 Allow 且 LocalPort 在配置或默认高危列表中 */
static void collect_win_high_risk_allow_ports(const EdrConfig *cfg, EdrSecurityPolicySnap *o) {
  if (!cfg || !o) {
    return;
  }
  o->sp_hr_allow_ports_count = 0;
  static const uint16_t fb[] = {23, 445, 3389, 6379, 27017, 1433, 3306};
  const uint16_t *plist = fb;
  size_t pn = sizeof(fb) / sizeof(fb[0]);
  if (cfg->attack_surface.high_risk_immediate_ports &&
      cfg->attack_surface.high_risk_immediate_ports_count > 0) {
    plist = cfg->attack_surface.high_risk_immediate_ports;
    pn = cfg->attack_surface.high_risk_immediate_ports_count;
  }
  for (size_t k = 0; k < pn && o->sp_hr_allow_ports_count < 16; k++) {
    int port = (int)plist[k];
    if (port < 1 || port > 65535) {
      continue;
    }
    char cmd[2200];
    int nw = snprintf(
        cmd, sizeof(cmd),
        "powershell.exe -NoProfile -NoLogo -Command "
        "\"if ((Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true -and $_.Direction -eq "
        "'Inbound' -and $_.Action -eq 'Allow' } | ForEach-Object { Get-NetFirewallPortFilter "
        "-AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue } | Where-Object { $_.LocalPort "
        "-eq %d }).Count -gt 0) { '1' } else { '0' }\"",
        port);
    if (nw <= 0 || (size_t)nw >= sizeof(cmd)) {
      continue;
    }
    FILE *pf = _popen(cmd, "r");
    if (!pf) {
      continue;
    }
    char line[8];
    if (!fgets(line, sizeof(line), pf)) {
      (void)_pclose(pf);
      continue;
    }
    (void)_pclose(pf);
    trim_crlf(line);
    if (line[0] != '1') {
      continue;
    }
    snprintf(o->sp_hr_allow_ports[o->sp_hr_allow_ports_count], sizeof(o->sp_hr_allow_ports[0]),
             "%d/tcp", port);
    o->sp_hr_allow_ports_count++;
  }
}

static void collect_win_firewall(const EdrConfig *cfg, EdrSecurityPolicySnap *o) {
  int d_on = 0, p_on = 0, u_on = 0;
  int d_ok = 0, p_ok = 0, u_ok = 0;
  char d_in[24], d_out[24], pr_in[24], pr_out[24], pub_in[24], pub_out[24];
  snprintf(d_in, sizeof(d_in), "%s", "UNKNOWN");
  snprintf(d_out, sizeof(d_out), "%s", "UNKNOWN");
  snprintf(pr_in, sizeof(pr_in), "%s", "UNKNOWN");
  snprintf(pr_out, sizeof(pr_out), "%s", "UNKNOWN");
  snprintf(pub_in, sizeof(pub_in), "%s", "UNKNOWN");
  snprintf(pub_out, sizeof(pub_out), "%s", "UNKNOWN");

  FILE *pf = _popen("netsh advfirewall show allprofiles 2>nul", "r");
  if (!pf) {
    return;
  }
  char line[512];
  enum { SEC_NONE, SEC_DOMAIN, SEC_PRIVATE, SEC_PUBLIC } sec = SEC_NONE;
  while (fgets(line, sizeof(line), pf)) {
    trim_crlf(line);
    if (strncmp(line, "Domain Profile", 14) == 0) {
      sec = SEC_DOMAIN;
      continue;
    }
    if (strncmp(line, "Private Profile", 15) == 0) {
      sec = SEC_PRIVATE;
      continue;
    }
    if (strncmp(line, "Public Profile", 14) == 0) {
      sec = SEC_PUBLIC;
      continue;
    }
    if (strstr(line, "----")) {
      continue;
    }
    int st = 0;
    if (parse_netsh_state(line, &st) == 0) {
      if (sec == SEC_DOMAIN) {
        d_on = st;
        d_ok = 1;
      } else if (sec == SEC_PRIVATE) {
        p_on = st;
        p_ok = 1;
      } else if (sec == SEC_PUBLIC) {
        u_on = st;
        u_ok = 1;
      }
      continue;
    }
    if (strstr(line, "Firewall Policy")) {
      if (sec == SEC_DOMAIN) {
        parse_netsh_fw_policy(line, d_in, sizeof(d_in), d_out, sizeof(d_out));
      } else if (sec == SEC_PRIVATE) {
        parse_netsh_fw_policy(line, pr_in, sizeof(pr_in), pr_out, sizeof(pr_out));
      } else if (sec == SEC_PUBLIC) {
        parse_netsh_fw_policy(line, pub_in, sizeof(pub_in), pub_out, sizeof(pub_out));
      }
    }
  }
  (void)_pclose(pf);

  if (d_ok || p_ok || u_ok) {
    o->top_fw_enabled_known = 1;
    o->sp_fw_enabled_known = 1;
    o->top_fw_enabled = (d_ok && d_on) || (p_ok && p_on) || (u_ok && u_on);
    o->sp_fw_enabled = o->top_fw_enabled;
    snprintf(o->top_fw_profile, sizeof(o->top_fw_profile), "domain=%s,private=%s,public=%s",
             d_ok ? (d_on ? "ON" : "OFF") : "?",
             p_ok ? (p_on ? "ON" : "OFF") : "?",
             u_ok ? (u_on ? "ON" : "OFF") : "?");
    /* 工作站优先 Private 的默认策略作为细摘要 */
    snprintf(o->sp_default_inbound, sizeof(o->sp_default_inbound), "%s", pr_in);
    snprintf(o->sp_default_outbound, sizeof(o->sp_default_outbound), "%s", pr_out);
    if (strcmp(pr_in, "UNKNOWN") == 0 && d_ok) {
      snprintf(o->sp_default_inbound, sizeof(o->sp_default_inbound), "%s", d_in);
      snprintf(o->sp_default_outbound, sizeof(o->sp_default_outbound), "%s", d_out);
    }
  }

  int ia = ps_count_rules("$_.Enabled -eq $true -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'");
  int ib = ps_count_rules("$_.Enabled -eq $true -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block'");
  int oa = ps_count_rules("$_.Enabled -eq $true -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Allow'");
  int ob = ps_count_rules("$_.Enabled -eq $true -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block'");
  if (ia >= 0 && ib >= 0 && oa >= 0 && ob >= 0) {
    o->sp_in_allow_known = o->sp_in_block_known = o->sp_out_allow_known = o->sp_out_block_known = 1;
    o->sp_in_allow = (uint32_t)ia;
    o->sp_in_block = (uint32_t)ib;
    o->sp_out_allow = (uint32_t)oa;
    o->sp_out_block = (uint32_t)ob;
    int sum = ia + ib + oa + ob;
    if (sum >= 0) {
      o->top_rule_count_known = 1;
      o->top_rule_count = sum;
    }
  }
  if (cfg) {
    collect_win_high_risk_allow_ports(cfg, o);
  }
}

static void collect_win_os(EdrSecurityPolicySnap *o) {
  DWORD v = 0;
  if (reg_dword_wow64(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA",
                      &v) == 0) {
    o->os_uac_known = 1;
    o->os_uac = (int)(v != 0);
  }
  if (reg_dword_wow64(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                      "RequireSecuritySignature", &v) == 0) {
    o->os_smb_sign_known = 1;
    o->os_smb_sign = (int)(v != 0);
  }
  if (reg_dword_wow64(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\mrxsmb10", "Start", &v) ==
      0) {
    o->os_smbv1_known = 1;
    /* Start 4 = disabled */
    o->os_smbv1 = (int)(v != 4);
  }
  if (reg_dword_wow64(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                      "UserAuthentication", &v) == 0) {
    o->os_rdp_nla_known = 1;
    o->os_rdp_nla = (int)(v != 0);
  }
  /* DEP：策略注册表项在不同 SKU 上不一致，P1 不填 */
  FILE *pf = _popen("powershell.exe -NoProfile -NoLogo -Command \"try { if (Confirm-SecureBootUEFI) { '1' } "
                    "else { '0' } } catch { 'x' }\" 2>nul",
                    "r");
  if (pf) {
    char line[16];
    if (fgets(line, sizeof(line), pf)) {
      trim_crlf(line);
      if (line[0] == '1' || line[0] == '0') {
        o->os_secure_boot_known = 1;
        o->os_secure_boot = line[0] == '1' ? 1 : 0;
      }
    }
    (void)_pclose(pf);
  }
  char bn[32] = "";
  char dv[64] = "";
  DWORD bnv = 0;
  if (reg_dword_wow64(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuild",
                      &bnv) == 0) {
    snprintf(bn, sizeof(bn), "%lu", (unsigned long)bnv);
  }
  HKEY h = NULL;
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
                    KEY_READ | KEY_WOW64_64KEY, &h) == ERROR_SUCCESS) {
    DWORD type = 0;
    char disp[96];
    DWORD dsz = sizeof(disp);
    if (RegQueryValueExA(h, "DisplayVersion", NULL, &type, (LPBYTE)disp, &dsz) == ERROR_SUCCESS &&
        type == REG_SZ) {
      disp[sizeof(disp) - 1u] = 0;
      snprintf(dv, sizeof(dv), "%s", disp);
    }
    RegCloseKey(h);
  }
  if (bn[0] || dv[0]) {
    snprintf(o->os_patch, sizeof(o->os_patch), "%s%s%s", dv[0] ? dv : "", (dv[0] && bn[0]) ? " " : "",
             bn[0] ? bn : "");
  }
}

static void collect_impl(const EdrConfig *cfg, EdrSecurityPolicySnap *o) {
  collect_win_firewall(cfg, o);
  collect_win_os(o);
}

#elif defined(__linux__)

static int read_small_file(const char *path, char *buf, size_t cap) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    return -1;
  }
  size_t n = fread(buf, 1, cap - 1u, fp);
  fclose(fp);
  buf[n] = 0;
  trim_crlf(buf);
  return 0;
}

static int popen_one_line(const char *cmd, char *buf, size_t cap) {
  FILE *pf = popen(cmd, "r");
  if (!pf) {
    return -1;
  }
  if (!fgets(buf, (int)cap, pf)) {
    buf[0] = 0;
    (void)pclose(pf);
    return -1;
  }
  (void)pclose(pf);
  trim_crlf(buf);
  return 0;
}

static int popen_count_lines(const char *cmd) {
  FILE *pf = popen(cmd, "r");
  if (!pf) {
    return -1;
  }
  char line[64];
  if (!fgets(line, sizeof(line), pf)) {
    (void)pclose(pf);
    return -1;
  }
  (void)pclose(pf);
  trim_crlf(line);
  return (int)strtol(line, NULL, 10);
}

static void collect_linux_fw(EdrSecurityPolicySnap *o) {
  int nlines = -1;
  char ufw[256];
  if (popen_one_line("sh -c 'command -v ufw >/dev/null && ufw status 2>/dev/null | head -n1'", ufw,
                     sizeof(ufw)) == 0 &&
      strstr(ufw, "active")) {
    o->top_fw_enabled_known = o->sp_fw_enabled_known = 1;
    o->top_fw_enabled = o->sp_fw_enabled = 1;
    snprintf(o->top_fw_profile, sizeof(o->top_fw_profile), "%s", "ufw:active");
    snprintf(o->sp_default_inbound, sizeof(o->sp_default_inbound), "%s", "UNKNOWN");
    snprintf(o->sp_default_outbound, sizeof(o->sp_default_outbound), "%s", "UNKNOWN");
  }
  char pol_in[24] = "UNKNOWN";
  char pol_out[24] = "UNKNOWN";
  FILE *pf = popen("iptables -S 2>/dev/null", "r");
  if (pf) {
    char line[256];
    while (fgets(line, sizeof(line), pf)) {
      trim_crlf(line);
      if (strncmp(line, "-P INPUT ", 9) == 0) {
        if (strstr(line, "DROP")) {
          snprintf(pol_in, sizeof(pol_in), "%s", "BLOCK");
        } else if (strstr(line, "ACCEPT")) {
          snprintf(pol_in, sizeof(pol_in), "%s", "ALLOW");
        }
      } else if (strncmp(line, "-P OUTPUT ", 10) == 0) {
        if (strstr(line, "DROP")) {
          snprintf(pol_out, sizeof(pol_out), "%s", "BLOCK");
        } else if (strstr(line, "ACCEPT")) {
          snprintf(pol_out, sizeof(pol_out), "%s", "ALLOW");
        }
      }
    }
    (void)pclose(pf);
  }
  nlines = popen_count_lines("sh -c \"iptables-save 2>/dev/null | wc -l\"");
  if (nlines >= 0) {
    o->top_rule_count_known = 1;
    o->top_rule_count = nlines;
  }
  if (strcmp(pol_in, "UNKNOWN") != 0 || strcmp(pol_out, "UNKNOWN") != 0 || nlines > 0) {
    if (!o->sp_fw_enabled_known) {
      /* 有 iptables 表即认为主机具备包过滤栈；是否“等同 Windows 防火墙开启”不强行等同 */
      o->sp_fw_enabled_known = 1;
      o->sp_fw_enabled = (strcmp(pol_in, "BLOCK") == 0 || strcmp(pol_out, "BLOCK") == 0 || nlines > 8);
      o->top_fw_enabled_known = 1;
      o->top_fw_enabled = o->sp_fw_enabled;
      if (!o->top_fw_profile[0]) {
        snprintf(o->top_fw_profile, sizeof(o->top_fw_profile), "%s", "iptables");
      }
    }
    snprintf(o->sp_default_inbound, sizeof(o->sp_default_inbound), "%s", pol_in);
    snprintf(o->sp_default_outbound, sizeof(o->sp_default_outbound), "%s", pol_out);
  }
  int ac = popen_count_lines("sh -c \"iptables-save 2>/dev/null | grep -c '^-A' || true\"");
  if (ac >= 0) {
    o->sp_in_allow_known = o->sp_out_allow_known = 1;
    o->sp_in_allow = (uint32_t)ac;
    o->sp_out_allow = 0;
  }
  /* nft 存在但 iptables 空时给提示性 profile */
  if (!o->top_fw_profile[0]) {
    char nftc[8];
    if (popen_one_line("sh -c 'command -v nft >/dev/null && echo y || echo n'", nftc, sizeof(nftc)) == 0 &&
        nftc[0] == 'y') {
      snprintf(o->top_fw_profile, sizeof(o->top_fw_profile), "%s", "nftables:present");
    }
  }
}

static void collect_linux_os(EdrSecurityPolicySnap *o) {
  char b[32];
  if (read_small_file("/proc/sys/kernel/randomize_va_space", b, sizeof(b)) == 0 && b[0]) {
    int v = (int)strtol(b, NULL, 10);
    o->os_aslr_known = 1;
    o->os_aslr = v != 0;
  }
  char pretty[512];
  if (read_small_file("/etc/os-release", pretty, sizeof(pretty)) == 0) {
    const char *p = strstr(pretty, "PRETTY_NAME=");
    if (p) {
      p += (int)strlen("PRETTY_NAME=");
      while (*p == '"' || *p == '\'') {
        p++;
      }
      const char *end = p;
      while (*end && *end != '\n' && *end != '"') {
        end++;
      }
      size_t n = (size_t)(end - p);
      if (n >= sizeof(o->os_patch)) {
        n = sizeof(o->os_patch) - 1u;
      }
      memcpy(o->os_patch, p, n);
      o->os_patch[n] = 0;
      trim_crlf(o->os_patch);
    }
  }
  char un[64];
  if (popen_one_line("uname -r", un, sizeof(un)) == 0 && un[0]) {
    size_t L = strlen(o->os_patch);
    if (L > 0 && L + strlen(un) + 12u < sizeof(o->os_patch)) {
      snprintf(o->os_patch + L, sizeof(o->os_patch) - L, " (kernel %s)", un);
    } else if (L == 0) {
      snprintf(o->os_patch, sizeof(o->os_patch), "kernel %s", un);
    }
  }
}

static void collect_impl(const EdrConfig *cfg, EdrSecurityPolicySnap *o) {
  (void)cfg;
  collect_linux_fw(o);
  collect_linux_os(o);
}

#else

static void collect_impl(const EdrConfig *cfg, EdrSecurityPolicySnap *o) {
  (void)cfg;
  (void)o;
}

#endif

void edr_security_policy_snap_collect(const EdrConfig *cfg, EdrSecurityPolicySnap *out) {
  snap_clear(out);
  if (!cfg || !out) {
    return;
  }
  collect_impl(cfg, out);
}

static void fp_bool(FILE *f, int known, int v) {
  if (!known) {
    fprintf(f, "null");
  } else {
    fprintf(f, "%s", v ? "true" : "false");
  }
}

void edr_security_policy_snap_write_policy_object(FILE *f, const struct EdrConfig *cfg,
                                                  const EdrSecurityPolicySnap *s) {
  if (!f || !s) {
    fprintf(f, "{}");
    return;
  }
  fprintf(f, "{");
  if (cfg) {
    fprintf(f, "\"edrPolicy\":{");
    fprintf(f, "\"aveSensitivity\":");
    json_escape_str_fp(f, (cfg->ave.sensitivity[0] != 0) ? cfg->ave.sensitivity : "MEDIUM");
    fprintf(f, ",\"webshellMonitorEnabled\":%s", cfg->webshell_detector.enabled ? "true" : "false");
    fprintf(f, ",\"shellcodeDetectEnabled\":%s", cfg->shellcode_detector.enabled ? "true" : "false");
    fprintf(f, ",\"whitelistRuleCount\":%u", (unsigned)cfg->preprocessing.rules_count);
    fprintf(f, "},");
  }
  fprintf(f, "\"firewall\":{");
  fprintf(f, "\"firewallEnabled\":");
  fp_bool(f, s->sp_fw_enabled_known, s->sp_fw_enabled);
  fprintf(f, ",\"defaultInbound\":");
  json_escape_str_fp(f, s->sp_default_inbound);
  fprintf(f, ",\"defaultOutbound\":");
  json_escape_str_fp(f, s->sp_default_outbound);
  fprintf(f, ",\"inboundAllowRules\":");
  if (s->sp_in_allow_known) {
    fprintf(f, "%u", (unsigned)s->sp_in_allow);
  } else {
    fprintf(f, "null");
  }
  fprintf(f, ",\"inboundBlockRules\":");
  if (s->sp_in_block_known) {
    fprintf(f, "%u", (unsigned)s->sp_in_block);
  } else {
    fprintf(f, "null");
  }
  fprintf(f, ",\"outboundAllowRules\":");
  if (s->sp_out_allow_known) {
    fprintf(f, "%u", (unsigned)s->sp_out_allow);
  } else {
    fprintf(f, "null");
  }
  fprintf(f, ",\"outboundBlockRules\":");
  if (s->sp_out_block_known) {
    fprintf(f, "%u", (unsigned)s->sp_out_block);
  } else {
    fprintf(f, "null");
  }
  fprintf(f, ",\"highRiskAllowPorts\":[");
  for (int i = 0; i < s->sp_hr_allow_ports_count; i++) {
    if (i) {
      fputc(',', f);
    }
    json_escape_str_fp(f, s->sp_hr_allow_ports[i]);
  }
  fprintf(f, "]");
  fprintf(f, "},\"osSecurity\":{");
  fprintf(f, "\"uacEnabled\":");
  fp_bool(f, s->os_uac_known, s->os_uac);
  fprintf(f, ",\"depEnabled\":");
  fp_bool(f, s->os_dep_known, s->os_dep);
  fprintf(f, ",\"aslrEnabled\":");
  fp_bool(f, s->os_aslr_known, s->os_aslr);
  fprintf(f, ",\"smbSigningEnabled\":");
  fp_bool(f, s->os_smb_sign_known, s->os_smb_sign);
  fprintf(f, ",\"smbv1Enabled\":");
  fp_bool(f, s->os_smbv1_known, s->os_smbv1);
  fprintf(f, ",\"rdpNlaEnabled\":");
  fp_bool(f, s->os_rdp_nla_known, s->os_rdp_nla);
  fprintf(f, ",\"powershellConstrained\":null");
  fprintf(f, ",\"secureBootEnabled\":");
  fp_bool(f, s->os_secure_boot_known, s->os_secure_boot);
  fprintf(f, ",\"osPatchLevel\":");
  if (s->os_patch[0]) {
    json_escape_str_fp(f, s->os_patch);
  } else {
    fprintf(f, "null");
  }
  fprintf(f, "}}");
}
