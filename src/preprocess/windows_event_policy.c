#include "edr/windows_event_policy.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static int is_file_event(EdrEventType t) {
  return t == EDR_EVENT_FILE_CREATE || t == EDR_EVENT_FILE_WRITE ||
         t == EDR_EVENT_FILE_DELETE || t == EDR_EVENT_FILE_RENAME ||
         t == EDR_EVENT_FILE_PERMISSION_CHANGE;
}

static int is_registry_event(EdrEventType t) {
  return t == EDR_EVENT_REG_CREATE_KEY || t == EDR_EVENT_REG_SET_VALUE ||
         t == EDR_EVENT_REG_DELETE_KEY;
}

static char fold_char(char c) {
  if (c == '/') {
    c = '\\';
  }
  return (char)tolower((unsigned char)c);
}

static int has_ci_path(const char *hay, const char *needle) {
  if (!needle || !needle[0]) {
    return 1;
  }
  if (!hay || !hay[0]) {
    return 0;
  }
  for (; *hay; hay++) {
    const char *a = hay;
    const char *b = needle;
    while (*a && *b && fold_char(*a) == fold_char(*b)) {
      a++;
      b++;
    }
    if (!*b) {
      return 1;
    }
  }
  return 0;
}

static int ends_ci_path(const char *s, const char *suffix) {
  size_t a;
  size_t b;
  if (!s || !suffix) {
    return 0;
  }
  a = strlen(s);
  b = strlen(suffix);
  if (b == 0u || a < b) {
    return 0;
  }
  return has_ci_path(s + (a - b), suffix);
}

static int any_contains(const char *s, const char *const *items, size_t count) {
  for (size_t i = 0; i < count; i++) {
    if (has_ci_path(s, items[i])) {
      return 1;
    }
  }
  return 0;
}

static int any_ends(const char *s, const char *const *items, size_t count) {
  for (size_t i = 0; i < count; i++) {
    if (ends_ci_path(s, items[i])) {
      return 1;
    }
  }
  return 0;
}

static void set_reason(EdrWindowsEventPolicy *p, const char *reason) {
  if (p && reason && reason[0] && !p->reason[0]) {
    snprintf(p->reason, sizeof(p->reason), "%s", reason);
  }
}

static void add_tag(EdrWindowsEventPolicy *p, const char *tag) {
  size_t n;
  if (!p || !tag || !tag[0]) {
    return;
  }
  if (has_ci_path(p->tags, tag)) {
    return;
  }
  n = strlen(p->tags);
  if (n && n + 1u < sizeof(p->tags)) {
    p->tags[n++] = ',';
    p->tags[n] = '\0';
  }
  (void)snprintf(p->tags + n, sizeof(p->tags) - n, "%s", tag);
}

static void mark_high(EdrWindowsEventPolicy *p, const char *reason, const char *tag) {
  p->high_value = 1u;
  p->should_emit = 1u;
  p->should_persist = 1u;
  set_reason(p, reason);
  add_tag(p, tag);
}

static void mark_suspicious(EdrWindowsEventPolicy *p, const char *reason, const char *tag) {
  mark_high(p, reason, tag);
  p->suspicious = 1u;
}

static void classify_file(const EdrBehaviorRecord *r, EdrWindowsEventPolicy *p) {
  const char *path = r->file_path[0] ? r->file_path : r->exe_path;
  static const char *const web_roots[] = {
      "\\inetpub\\wwwroot\\", "\\wwwroot\\", "\\xampp\\htdocs\\",
      "\\phpstudy\\", "\\tomcat\\webapps\\", "\\nginx\\html\\",
      "\\apache\\htdocs\\", "\\wamp64\\www\\", "\\laragon\\www\\",
  };
  static const char *const script_exts[] = {
      ".php", ".phtml", ".asp", ".aspx", ".ashx", ".asmx", ".jsp",
      ".jspx", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta",
      ".ps1", ".psm1", ".sct", ".cmd", ".bat",
  };
  static const char *const executable_exts[] = {
      ".exe", ".dll", ".scr", ".com", ".msi", ".cpl", ".ocx",
  };
  static const char *const initial_access_exts[] = {
      ".iso", ".img", ".lnk", ".url", ".sct", ".hta", ".chm",
      ".docm", ".xlsm", ".xlam", ".one",
  };
  static const char *const staging_dirs[] = {
      "\\users\\", "\\downloads\\", "\\desktop\\", "\\appdata\\local\\temp\\",
      "\\appdata\\roaming\\", "\\windows\\temp\\", "\\programdata\\",
  };
  static const char *const startup_dirs[] = {
      "\\microsoft\\windows\\start menu\\programs\\startup\\",
      "\\windows\\system32\\tasks\\", "\\windows\\tasks\\",
  };
  static const char *const noisy_dirs[] = {
      "\\windows\\prefetch\\", "\\windows\\softwaredistribution\\",
      "\\windows\\logs\\", "\\windows\\system32\\winevt\\logs\\",
      "\\programdata\\microsoft\\windows defender\\",
      "\\appdata\\local\\microsoft\\windows\\inetcache\\",
      "\\appdata\\local\\microsoft\\edge\\user data\\",
      "\\appdata\\local\\google\\chrome\\user data\\",
      "\\appdata\\local\\packages\\", "\\appdata\\local\\crashdumps\\",
  };
  static const char *const cred_files[] = {
      "\\ntds.dit", "\\config\\sam", "\\config\\system", "\\config\\security",
      "\\config\\software", "lsass.dmp", "\\lsass", "\\sam.save", "\\system.save",
  };
  static const char *const ransom_markers[] = {
      "readme", "decrypt", "recover", "ransom", "restore-files", "how_to_decrypt",
  };

  if (!path || !path[0]) {
    return;
  }

  if (any_contains(path, cred_files, sizeof(cred_files) / sizeof(cred_files[0]))) {
    mark_suspicious(p, "credential_store_or_dump_path", "credential_access");
  }
  if (any_contains(path, web_roots, sizeof(web_roots) / sizeof(web_roots[0]))) {
    mark_high(p, "web_root_file_activity", "web_root");
    if (any_ends(path, script_exts, sizeof(script_exts) / sizeof(script_exts[0]))) {
      mark_suspicious(p, "webshell_script_in_web_root", "webshell_candidate");
    }
  }
  if (any_contains(path, startup_dirs, sizeof(startup_dirs) / sizeof(startup_dirs[0]))) {
    mark_suspicious(p, "startup_or_scheduled_task_path", "persistence_path");
  }
  if (has_ci_path(path, "\\windows\\system32\\drivers\\") &&
      (ends_ci_path(path, ".sys") || r->type == EDR_EVENT_FILE_CREATE ||
       r->type == EDR_EVENT_FILE_WRITE)) {
    mark_suspicious(p, "driver_path_modified", "driver_persistence");
  }
  if (any_contains(path, staging_dirs, sizeof(staging_dirs) / sizeof(staging_dirs[0]))) {
    if (any_ends(path, script_exts, sizeof(script_exts) / sizeof(script_exts[0]))) {
      mark_suspicious(p, "script_drop_in_user_or_temp_path", "script_staging");
    } else if (any_ends(path, executable_exts, sizeof(executable_exts) / sizeof(executable_exts[0]))) {
      mark_high(p, "executable_drop_in_user_or_temp_path", "executable_staging");
    } else if (any_ends(path, initial_access_exts, sizeof(initial_access_exts) / sizeof(initial_access_exts[0]))) {
      mark_suspicious(p, "initial_access_artifact_drop", "phishing_artifact");
    }
  }
  if (any_contains(path, ransom_markers, sizeof(ransom_markers) / sizeof(ransom_markers[0])) ||
      has_ci_path(r->script_snippet, "ransom_counter=1")) {
    mark_suspicious(p, "ransomware_note_or_file_burst", "ransomware_behavior");
  }
  if (has_ci_path(path, "\\users\\public\\") &&
      (any_ends(path, executable_exts, sizeof(executable_exts) / sizeof(executable_exts[0])) ||
       any_ends(path, script_exts, sizeof(script_exts) / sizeof(script_exts[0])))) {
    mark_suspicious(p, "public_directory_execution_artifact", "public_staging");
  }
  if (!p->high_value && any_contains(path, noisy_dirs, sizeof(noisy_dirs) / sizeof(noisy_dirs[0]))) {
    p->noisy = 1u;
    set_reason(p, "known_windows_noise_path");
    add_tag(p, "noise_path");
  }
}

static int reg_value_is(const EdrBehaviorRecord *r, const char *name) {
  return has_ci_path(r->reg_value_name, name) || has_ci_path(r->reg_value_data, name);
}

static void classify_registry(const EdrBehaviorRecord *r, EdrWindowsEventPolicy *p) {
  const char *key = r->reg_key_path;
  static const char *const noisy_keys[] = {
      "\\software\\classes\\local settings\\software\\microsoft\\windows\\shell\\bags",
      "\\software\\microsoft\\windows\\currentversion\\explorer\\",
      "\\software\\microsoft\\windows\\currentversion\\search\\",
      "\\software\\microsoft\\windows nt\\currentversion\\appcompatflags\\compatibility assistant\\store",
      "\\software\\microsoft\\windows\\currentversion\\internet settings\\connections",
  };

  if (!key || !key[0]) {
    return;
  }

  if (has_ci_path(key, "\\software\\microsoft\\windows\\currentversion\\run") ||
      has_ci_path(key, "\\software\\microsoft\\windows\\currentversion\\runonce") ||
      has_ci_path(key, "\\software\\wow6432node\\microsoft\\windows\\currentversion\\run")) {
    mark_suspicious(p, "autorun_registry_modified", "autorun_persistence");
  }
  if (has_ci_path(key, "\\system\\currentcontrolset\\services\\")) {
    mark_suspicious(p, "service_registry_modified", "service_persistence");
  }
  if (has_ci_path(key, "\\windows nt\\currentversion\\winlogon") &&
      (reg_value_is(r, "shell") || reg_value_is(r, "userinit") || reg_value_is(r, "notify"))) {
    mark_suspicious(p, "winlogon_persistence_modified", "winlogon_persistence");
  }
  if (has_ci_path(key, "\\image file execution options\\") ||
      has_ci_path(key, "\\silentprocessexit\\")) {
    mark_suspicious(p, "ifeo_debugger_persistence_modified", "ifeo_persistence");
  }
  if (has_ci_path(key, "\\windows nt\\currentversion\\windows") &&
      reg_value_is(r, "appinit_dlls")) {
    mark_suspicious(p, "appinit_dlls_modified", "appinit_persistence");
  }
  if (has_ci_path(key, "\\control\\lsa") || has_ci_path(key, "\\securitypackages") ||
      has_ci_path(key, "\\wdigest")) {
    mark_suspicious(p, "lsa_or_wdigest_modified", "credential_access");
  }
  if (has_ci_path(key, "\\windows defender") ||
      has_ci_path(key, "\\policies\\microsoft\\windows defender") ||
      has_ci_path(key, "\\security center")) {
    mark_suspicious(p, "security_product_policy_modified", "defense_evasion");
  }
  if (has_ci_path(key, "\\terminal server") && reg_value_is(r, "fdenytsconnections")) {
    mark_high(p, "rdp_exposure_policy_modified", "rdp_exposure");
  }
  if (has_ci_path(key, "\\firewallpolicy\\") || has_ci_path(key, "\\sharedaccess\\parameters\\firewallpolicy")) {
    mark_high(p, "firewall_policy_modified", "firewall_policy");
  }
  if (has_ci_path(key, "\\software\\microsoft\\office\\") &&
      (has_ci_path(key, "\\security") || reg_value_is(r, "vbawarnings") ||
       reg_value_is(r, "accessvbom"))) {
    mark_high(p, "office_macro_policy_modified", "office_macro_policy");
  }
  if (has_ci_path(key, "\\software\\microsoft\\windows\\currentversion\\policies\\system") &&
      (reg_value_is(r, "enablelua") || reg_value_is(r, "consentpromptbehavioradmin"))) {
    mark_high(p, "uac_policy_modified", "uac_policy");
  }
  if (!p->high_value && any_contains(key, noisy_keys, sizeof(noisy_keys) / sizeof(noisy_keys[0]))) {
    p->noisy = 1u;
    set_reason(p, "known_windows_registry_noise");
    add_tag(p, "noise_registry");
  }
}

void edr_windows_event_policy_evaluate(const EdrBehaviorRecord *r,
                                       EdrWindowsEventPolicy *out) {
  if (!out) {
    return;
  }
  memset(out, 0, sizeof(*out));
  out->should_emit = 1u;
  out->should_persist = 1u;
  if (!r) {
    return;
  }
  if (is_file_event(r->type)) {
    out->applies = 1u;
    out->should_emit = 0u;
    out->should_persist = 0u;
    classify_file(r, out);
  } else if (is_registry_event(r->type)) {
    out->applies = 1u;
    out->should_emit = 0u;
    out->should_persist = 0u;
    classify_registry(r, out);
  } else {
    return;
  }

  if (r->priority == 0u || has_ci_path(r->detection_context, "\"confidence\":0.7") ||
      has_ci_path(r->detection_context, "\"confidence\":0.8") ||
      has_ci_path(r->detection_context, "\"confidence\":0.9") ||
      has_ci_path(r->detection_context, "\"confidence\":1")) {
    out->should_emit = 1u;
    out->should_persist = 1u;
  }
  if (!out->reason[0]) {
    set_reason(out, out->noisy ? "ordinary_windows_noise" : "ordinary_windows_metadata_only");
  }
  if (!out->tags[0]) {
    add_tag(out, out->noisy ? "noise" : "metadata_only");
  }
}

void edr_windows_event_policy_apply(EdrBehaviorRecord *r) {
  EdrWindowsEventPolicy p;
  size_t n;
  if (!r) {
    return;
  }
  edr_windows_event_policy_evaluate(r, &p);
  if (!p.applies) {
    return;
  }
  if (p.suspicious && r->priority > 0u) {
    r->priority = 0u;
  } else if (p.high_value && r->priority > 1u) {
    r->priority = 1u;
  } else if (!p.high_value && r->priority > 0u && r->priority < 2u &&
             (is_file_event(r->type) || is_registry_event(r->type))) {
    r->priority = 2u;
  }
  n = strlen(r->script_snippet);
  if (n + 32u >= sizeof(r->script_snippet)) {
    return;
  }
  (void)snprintf(r->script_snippet + n, sizeof(r->script_snippet) - n,
                 "%swin_policy=%s win_policy_tags=%s",
                 n ? " " : "", p.reason, p.tags);
}

int edr_windows_event_policy_should_emit(const EdrBehaviorRecord *r) {
  EdrWindowsEventPolicy p;
  edr_windows_event_policy_evaluate(r, &p);
  return (!p.applies || p.should_emit) ? 1 : 0;
}

int edr_windows_event_policy_should_persist(const EdrBehaviorRecord *r) {
  EdrWindowsEventPolicy p;
  edr_windows_event_policy_evaluate(r, &p);
  return (!p.applies || p.should_persist) ? 1 : 0;
}
