#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef EDR_HAVE_YARA
#include <yara.h>
#endif

#ifndef EDR_FORENSIC_RULES_DIR
#define EDR_FORENSIC_RULES_DIR "rules/forensic"
#endif
#ifndef EDR_SHELLCODE_RULES_DIR
#define EDR_SHELLCODE_RULES_DIR "src/shellcode_detector/rules"
#endif
#ifndef EDR_WEBSHELL_RULES_DIR
#define EDR_WEBSHELL_RULES_DIR "src/webshell_detector/rules"
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#endif

#ifdef EDR_HAVE_YARA
static int is_yara_file(const char *path) {
  const char *dot = strrchr(path, '.');
  if (!dot) return 0;
  char ext[8];
  size_t i = 0;
  for (; dot[i] && i < sizeof(ext) - 1; i++) ext[i] = (char)tolower((unsigned char)dot[i]);
  ext[i] = '\0';
  return strcmp(ext, ".yar") == 0 || strcmp(ext, ".yara") == 0;
}
typedef struct {
  char first_error[512];
} CompileState;

static void compile_cb(int level, const char *fn, int line, const YR_RULE *rule, const char *msg, void *ud) {
  (void)rule;
  CompileState *st = (CompileState *)ud;
  if (level != YARA_ERROR_LEVEL_WARNING && st && st->first_error[0] == '\0') {
    snprintf(st->first_error, sizeof(st->first_error), "%s:%d %s", fn ? fn : "-", line, msg ? msg : "-");
  }
}

static int add_file(YR_COMPILER *c, const char *path) {
  if (!is_yara_file(path)) return 0;
  FILE *f = fopen(path, "rb");
  assert(f != NULL);
  int nerr = yr_compiler_add_file(c, f, NULL, path);
  fclose(f);
  if (nerr > 0) {
    fprintf(stderr, "compile failed: %s\n", path);
    assert(nerr == 0);
  }
  return 1;
}

static int add_dir(YR_COMPILER *c, const char *dir) {
  int loaded = 0;
#ifdef _WIN32
  char pat[1024];
  snprintf(pat, sizeof(pat), "%s\\*", dir);
  WIN32_FIND_DATAA ffd;
  HANDLE h = FindFirstFileA(pat, &ffd);
  assert(h != INVALID_HANDLE_VALUE);
  do {
    if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) continue;
    char full[1200];
    snprintf(full, sizeof(full), "%s\\%s", dir, ffd.cFileName);
    loaded += add_file(c, full);
  } while (FindNextFileA(h, &ffd));
  FindClose(h);
#else
  DIR *d = opendir(dir);
  assert(d != NULL);
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
    char full[1200];
    snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
    struct stat st;
    if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;
    loaded += add_file(c, full);
  }
  closedir(d);
#endif
  return loaded;
}

typedef struct {
  const char *want;
  int matched;
} MatchCtx;

#if defined(YR_VERSION_HEX) && YR_VERSION_HEX >= 0x040500
static int scan_cb(YR_SCAN_CONTEXT *ctx, int message, void *message_data, void *user_data) {
  (void)ctx;
#else
static int scan_cb(int message, void *message_data, void *user_data) {
#endif
  MatchCtx *mc = (MatchCtx *)user_data;
  if (message == CALLBACK_MSG_RULE_MATCHING) {
    const YR_RULE *rule = (const YR_RULE *)message_data;
    if (rule && rule->identifier && mc && strcmp(rule->identifier, mc->want) == 0) mc->matched = 1;
  }
  return CALLBACK_CONTINUE;
}

static void compile_all_and_scan_samples(void) {
  assert(yr_initialize() == ERROR_SUCCESS);
  YR_COMPILER *c = NULL;
  assert(yr_compiler_create(&c) == ERROR_SUCCESS && c != NULL);
  CompileState st;
  memset(&st, 0, sizeof(st));
  yr_compiler_set_callback(c, compile_cb, &st);
  int loaded = 0;
  loaded += add_dir(c, EDR_FORENSIC_RULES_DIR);
  loaded += add_dir(c, EDR_SHELLCODE_RULES_DIR);
  loaded += add_dir(c, EDR_WEBSHELL_RULES_DIR);
  assert(loaded >= 3);
  YR_RULES *rules = NULL;
  int rc = yr_compiler_get_rules(c, &rules);
  if (rc != ERROR_SUCCESS || !rules) {
    fprintf(stderr, "finalize failed: %s\n", st.first_error);
    assert(rc == ERROR_SUCCESS && rules != NULL);
  }
  yr_compiler_destroy(c);

  struct Sample { const char *rule; const char *text; } samples[] = {
    {"Injection_API_Combo", "VirtualAllocEx WriteProcessMemory CreateRemoteThread"},
    {"Credential_Mimikatz_Family_Strings", "mimikatz sekurlsa::logonpasswords privilege::debug"},
    {"Lateral_Impacket_Exec_Family", "impacket wmiexec.py cmd.exe /Q /c __output"},
    {"Privilege_Potato_PrintSpoofer_Family", "PrintSpoofer SeImpersonatePrivilege \\pipe\\spoolss"},
  };
  for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
    MatchCtx mc = { samples[i].rule, 0 };
    assert(yr_rules_scan_mem(rules, (const uint8_t *)samples[i].text, strlen(samples[i].text), 0, scan_cb, &mc, 0) == ERROR_SUCCESS);
    if (!mc.matched) fprintf(stderr, "sample did not match rule: %s\n", samples[i].rule);
    assert(mc.matched == 1);
  }
  yr_rules_destroy(rules);
  yr_finalize();
}
#endif

int main(void) {
#ifdef EDR_HAVE_YARA
  compile_all_and_scan_samples();
  puts("yara rule catalog compile ok");
#else
  puts("skip: EDR_HAVE_YARA not enabled");
#endif
  return 0;
}
