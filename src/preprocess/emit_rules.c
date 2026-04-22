#include "edr/emit_rules.h"

#include "edr/config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static EdrEmitRule *s_rules;
static uint32_t s_count;

static int hay_icase_has(const char *hay, const char *ndl) {
  if (!ndl || !ndl[0]) {
    return 1;
  }
  if (!hay) {
    hay = "";
  }
  for (; *hay; hay++) {
    const char *a = hay;
    const char *b = ndl;
    for (; *b; a++, b++) {
      if (!*a) {
        return 0;
      }
      if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
        break;
      }
    }
    if (!*b) {
      return 1;
    }
  }
  return 0;
}

static int field_match(const char *field, const char *pat, int icase) {
  if (!pat || !pat[0]) {
    return 1;
  }
  if (!field) {
    field = "";
  }
  if (icase) {
    return hay_icase_has(field, pat);
  }
  return strstr(field, pat) != NULL;
}

static int rule_matches(const EdrEmitRule *rule, const EdrBehaviorRecord *r) {
  if (rule->event_type >= 0 && (int32_t)r->type != rule->event_type) {
    return 0;
  }
  if (!field_match(r->exe_path, rule->exe_path_contains, rule->icase_exe_path)) {
    return 0;
  }
  if (!field_match(r->cmdline, rule->cmdline_contains, rule->icase_cmdline)) {
    return 0;
  }
  if (!field_match(r->file_path, rule->file_path_contains, rule->icase_file_path)) {
    return 0;
  }
  if (!field_match(r->dns_query, rule->dns_query_contains, rule->icase_dns)) {
    return 0;
  }
  if (!field_match(r->script_snippet, rule->script_snippet_contains, rule->icase_script)) {
    return 0;
  }
  return 1;
}

void edr_emit_rules_configure(const EdrConfig *cfg) {
  free(s_rules);
  s_rules = NULL;
  s_count = 0;
  if (!cfg || !cfg->preprocessing.rules || cfg->preprocessing.rules_count == 0u) {
    return;
  }
  size_t bytes = (size_t)cfg->preprocessing.rules_count * sizeof(EdrEmitRule);
  s_rules = (EdrEmitRule *)malloc(bytes);
  if (!s_rules) {
    fprintf(stderr, "[emit_rules] malloc(%zu) failed\n", bytes);
    return;
  }
  memcpy(s_rules, cfg->preprocessing.rules, bytes);
  s_count = cfg->preprocessing.rules_count;
}

int edr_emit_rules_evaluate(const EdrBehaviorRecord *r) {
  if (!r || s_count == 0u || !s_rules) {
    return -1;
  }
  for (uint32_t i = 0; i < s_count; i++) {
    const EdrEmitRule *rule = &s_rules[i];
    if (rule->action == EdrEmitRuleActionUnset) {
      continue;
    }
    if (!rule_matches(rule, r)) {
      continue;
    }
    if (rule->action == EdrEmitRuleActionDrop) {
      return 0;
    }
    if (rule->action == EdrEmitRuleActionEmitAlways) {
      return 1;
    }
  }
  return -1;
}
