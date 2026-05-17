#ifndef EDR_MMAP_STORAGE_H
#define EDR_MMAP_STORAGE_H

#include <stdint.h>

#define MMAP_STORAGE_MAX_ENTRIES 16384
#define MMAP_STORAGE_FILE_NAME "edr_process_history.dat"

typedef struct {
  uint32_t pid;
  uint32_t ppid;
  uint64_t create_time;
  uint64_t exit_time;
  uint32_t generation;
  char name[64];
  char cmdline[256];
  char exe_path[512];
  char parent_name[64];
  int exited;
} MMapProcessEntry;

typedef struct {
  uint64_t magic;
  uint32_t version;
  uint32_t count;
  uint32_t capacity;
  uint64_t oldest_time;
  MMapProcessEntry entries[MMAP_STORAGE_MAX_ENTRIES];
} MMapStorageHeader;

int edr_mmap_storage_init(const char *base_path);
int edr_mmap_storage_add(MMapProcessEntry *entry);
int edr_mmap_storage_get(uint32_t pid, uint64_t timestamp, MMapProcessEntry *out);
int edr_mmap_storage_find_parent(uint32_t pid, uint64_t timestamp, MMapProcessEntry *out);
void edr_mmap_storage_cleanup(void);
uint32_t edr_mmap_storage_get_count(void);
void edr_mmap_storage_cleanup_old(uint64_t max_age_ns);

#endif