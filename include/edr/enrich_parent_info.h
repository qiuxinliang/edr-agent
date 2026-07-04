#ifndef EDR_ENRICH_PARENT_INFO_H
#define EDR_ENRICH_PARENT_INFO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int enrich_parent_info_by_pid(uint32_t ppid, char *parent_name, size_t name_len,
                             char *parent_path, size_t path_len);

#ifdef __cplusplus
}
#endif

#endif
