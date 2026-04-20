#include "edr/fl_feature_provider.h"

#include <stddef.h>

static EdrFLFeatureLookupFn s_fn;
static void *s_user;

void edr_fl_register_feature_lookup(EdrFLFeatureLookupFn fn, void *user) {
  s_fn = fn;
  s_user = user;
}

void edr_fl_unregister_feature_lookup(void) {
  s_fn = NULL;
  s_user = NULL;
}

int edr_fl_feature_lookup_dispatch(const char *sha256_64hex, float *out, size_t dim, int target) {
  if (!s_fn || !sha256_64hex || !out) {
    return -1;
  }
  return s_fn(sha256_64hex, out, dim, target, s_user);
}
