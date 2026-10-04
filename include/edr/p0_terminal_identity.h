#ifndef EDR_P0_TERMINAL_IDENTITY_H
#define EDR_P0_TERMINAL_IDENTITY_H
#include <stddef.h>
#include <stdint.h>
/* Existing P0 journal commitment, shared by its producer and egress consumer.
 * This preserves the current protocol and does not establish a rule hit. */
int edr_p0_terminal_identity_key(const char *tenant,const char *endpoint,
    const char *rule,const char *event,uint32_t pid,uint64_t start_key,
    uint64_t birth,const char *canonical_path,const char *file_identity,
    char *out,size_t capacity);
#endif
