#ifndef EDR_WEBSHELL_SEMANTIC_H
#define EDR_WEBSHELL_SEMANTIC_H

#include <stddef.h>

typedef struct EdrWebshellSemanticResult {
  char rule_name[128];
  char reason[192];
  float confidence;
  float ast_score;
  float token_score;
  int matched;
} EdrWebshellSemanticResult;

int edr_webshell_semantic_match_text(const char *text, EdrWebshellSemanticResult *out);

#endif
