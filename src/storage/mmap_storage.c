#include "edr/mmap_storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define MMAP_MAGIC 0xEDR_PROC_HISTORY
#define MMAP_VERSION 1

static MMapStorageHeader *g_mmap = NULL;
#if defined(_WIN32)
static HANDLE g_file_handle = NULL;
static HANDLE g_mapping_handle = NULL;
#else
static int g_file_fd = -1;
#endif

static char g_file_path[512] = {0};

static int mmap_create_file(const char *path) {
#if defined(_WIN32)
  g_file_handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 
                             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (g_file_handle == INVALID_HANDLE_VALUE) return -1;
  
  g_mapping_handle = CreateFileMappingA(g_file_handle, NULL, PAGE_READWRITE, 0, 
                                        sizeof(MMapStorageHeader), NULL);
  if (!g_mapping_handle) {
    CloseHandle(g_file_handle);
    return -1;
  }
  
  g_mmap = (MMapStorageHeader *)MapViewOfFile(g_mapping_handle, 
                                              FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
  if (!g_mmap) {
    CloseHandle(g_mapping_handle);
    CloseHandle(g_file_handle);
    return -1;
  }
#else
  g_file_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (g_file_fd < 0) return -1;
  
  if (ftruncate(g_file_fd, sizeof(MMapStorageHeader)) != 0) {
    close(g_file_fd);
    return -1;
  }
  
  g_mmap = (MMapStorageHeader *)mmap(NULL, sizeof(MMapStorageHeader), 
                                      PROT_READ | PROT_WRITE, MAP_SHARED, g_file_fd, 0);
  if (g_mmap == MAP_FAILED) {
    close(g_file_fd);
    return -1;
  }
#endif
  
  memset(g_mmap, 0, sizeof(MMapStorageHeader));
  g_mmap->magic = MMAP_MAGIC;
  g_mmap->version = MMAP_VERSION;
  g_mmap->capacity = MMAP_STORAGE_MAX_ENTRIES;
  g_mmap->count = 0;
  
  return 0;
}

static int mmap_open_file(const char *path) {
#if defined(_WIN32)
  g_file_handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 
                             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (g_file_handle == INVALID_HANDLE_VALUE) return -1;
  
  g_mapping_handle = CreateFileMappingA(g_file_handle, NULL, PAGE_READWRITE, 0, 
                                        sizeof(MMapStorageHeader), NULL);
  if (!g_mapping_handle) {
    CloseHandle(g_file_handle);
    return -1;
  }
  
  g_mmap = (MMapStorageHeader *)MapViewOfFile(g_mapping_handle, 
                                              FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
  if (!g_mmap) {
    CloseHandle(g_mapping_handle);
    CloseHandle(g_file_handle);
    return -1;
  }
#else
  g_file_fd = open(path, O_RDWR, 0644);
  if (g_file_fd < 0) return -1;
  
  struct stat st;
  if (fstat(g_file_fd, &st) != 0) {
    close(g_file_fd);
    return -1;
  }
  
  g_mmap = (MMapStorageHeader *)mmap(NULL, sizeof(MMapStorageHeader), 
                                      PROT_READ | PROT_WRITE, MAP_SHARED, g_file_fd, 0);
  if (g_mmap == MAP_FAILED) {
    close(g_file_fd);
    return -1;
  }
#endif
  
  if (g_mmap->magic != MMAP_MAGIC || g_mmap->version != MMAP_VERSION) {
    return -2;
  }
  
  return 0;
}

int edr_mmap_storage_init(const char *base_path) {
  if (!base_path) return -1;
  snprintf(g_file_path, sizeof(g_file_path), "%s/%s", base_path, MMAP_STORAGE_FILE_NAME);
  
  int ret = mmap_open_file(g_file_path);
  if (ret == -1) {
    return mmap_create_file(g_file_path);
  } else if (ret == -2) {
    return mmap_create_file(g_file_path);
  }
  
  return 0;
}

int edr_mmap_storage_add(MMapProcessEntry *entry) {
  if (!g_mmap || !entry) return -1;
  
  for (size_t i = 0; i < g_mmap->count; i++) {
    MMapProcessEntry *e = &g_mmap->entries[i];
    if (e->pid == entry->pid && e->create_time == entry->create_time) {
      memcpy(e, entry, sizeof(MMapProcessEntry));
      return 0;
    }
  }
  
  if (g_mmap->count >= g_mmap->capacity) {
    edr_mmap_storage_cleanup_old(604800000000000ULL);
  }
  
  if (g_mmap->count >= g_mmap->capacity) {
    memmove(g_mmap->entries, g_mmap->entries + 1, 
            (g_mmap->capacity - 1) * sizeof(MMapProcessEntry));
    g_mmap->count--;
  }
  
  memcpy(&g_mmap->entries[g_mmap->count], entry, sizeof(MMapProcessEntry));
  g_mmap->count++;
  
  if (g_mmap->oldest_time == 0 || entry->create_time < g_mmap->oldest_time) {
    g_mmap->oldest_time = entry->create_time;
  }
  
  return 0;
}

int edr_mmap_storage_get(uint32_t pid, uint64_t timestamp, MMapProcessEntry *out) {
  if (!g_mmap || !out) return -1;
  
  for (size_t i = 0; i < g_mmap->count; i++) {
    MMapProcessEntry *e = &g_mmap->entries[i];
    if (e->pid == pid) {
      if (timestamp >= e->create_time && 
          (e->exit_time == 0 || timestamp <= e->exit_time)) {
        memcpy(out, e, sizeof(MMapProcessEntry));
        return 0;
      }
    }
  }
  
  return -1;
}

int edr_mmap_storage_find_parent(uint32_t pid, uint64_t timestamp, MMapProcessEntry *out) {
  if (!g_mmap || !out) return -1;
  
  uint64_t best_diff = UINT64_MAX;
  int best_idx = -1;
  
  for (size_t i = 0; i < g_mmap->count; i++) {
    MMapProcessEntry *e = &g_mmap->entries[i];
    if (e->pid == pid || !e->exited) continue;
    
    uint64_t end_time = e->exit_time ? e->exit_time : e->create_time;
    if (timestamp >= e->create_time && timestamp <= end_time + 60000000000ULL) {
      uint64_t diff = timestamp > e->create_time ? 
                      timestamp - e->create_time : e->create_time - timestamp;
      if (diff < best_diff) {
        best_diff = diff;
        best_idx = (int)i;
      }
    }
  }
  
  if (best_idx >= 0) {
    memcpy(out, &g_mmap->entries[best_idx], sizeof(MMapProcessEntry));
    return 0;
  }
  
  return -1;
}

void edr_mmap_storage_cleanup_old(uint64_t max_age_ns) {
  if (!g_mmap) return;
  
  uint64_t cutoff = (uint64_t)time(NULL) * 1000000000ULL - max_age_ns;
  
  size_t write_idx = 0;
  for (size_t i = 0; i < g_mmap->count; i++) {
    MMapProcessEntry *e = &g_mmap->entries[i];
    if (e->create_time > cutoff) {
      if (i != write_idx) {
        memcpy(&g_mmap->entries[write_idx], e, sizeof(MMapProcessEntry));
      }
      write_idx++;
    }
  }
  
  g_mmap->count = write_idx;
}

uint32_t edr_mmap_storage_get_count(void) {
  return g_mmap ? g_mmap->count : 0;
}

void edr_mmap_storage_cleanup(void) {
  if (!g_mmap) return;
  
#if defined(_WIN32)
  UnmapViewOfFile(g_mmap);
  CloseHandle(g_mapping_handle);
  CloseHandle(g_file_handle);
#else
  munmap(g_mmap, sizeof(MMapStorageHeader));
  close(g_file_fd);
#endif
  
  g_mmap = NULL;
}
