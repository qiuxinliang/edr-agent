#ifndef EDR_RESPONSE_CAPABILITY_MANIFEST_H
#define EDR_RESPONSE_CAPABILITY_MANIFEST_H

#include <stddef.h>

int edr_response_capability_manifest_json(int platform_supported,
                                          int dangerous_policy,
                                          char *out,
                                          size_t out_cap);

#endif
