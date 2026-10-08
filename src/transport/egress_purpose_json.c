#include "edr/egress_request_policy.h"
#include "edr/egress_batch_policy.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>

/* Shared complete-object boundary for producer purposes and final egress. */
static int duplicate_keys(const cJSON *v) {
  const cJSON *a, *b;
  cJSON_ArrayForEach(a, v) {
    if (cJSON_IsObject(v)) for (b = a->next; b; b = b->next)
      if (a->string && b->string && strcmp(a->string, b->string) == 0) return 1;
    if (duplicate_keys(a)) return 1;
  }
  return 0;
}
cJSON *edr_egress_parse_purpose_object(const void *body, size_t len) {
  if (!body || !len || len > EDR_EGRESS_BATCH_WIRE_MAX_BYTES) return NULL;
  const unsigned char *bytes = body;
  if (memchr(body, 0, len)) return NULL;
  /* cJSON exposes C strings. A decoded NUL would conceal a key/value suffix
   * from every whitelist comparison while the original bytes still leave. */
  for (size_t i = 0; i < len; ++i) {
    if (bytes[i] != '\\' || i + 1u >= len) continue;
    if (bytes[i + 1u] == 'u' && i + 5u < len && !memcmp(bytes + i + 2u, "0000", 4u)) return NULL;
    ++i; /* An escaped backslash is literal, not a following Unicode escape. */
  }
  char *copy = malloc(len + 1u);
  if (!copy) return NULL;
  memcpy(copy, body, len); copy[len] = 0;
  const char *end = NULL;
  cJSON *root = cJSON_ParseWithLengthOpts(copy, len + 1u, &end, 1);
  if (!cJSON_IsObject(root) || end != copy + len || duplicate_keys(root)) { cJSON_Delete(root); root = NULL; }
  free(copy);
  return root;
}
