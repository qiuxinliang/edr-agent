#ifndef EDR_PEB_PARSER_H
#define EDR_PEB_PARSER_H

#include <stdint.h>

typedef struct {
  uint32_t pid;
  char process_name[256];
  char exe_path[512];
  char cmdline[1024];
  char current_dir[512];
  char user[64];
  char domain[64];
  uint32_t session_id;
  int is_elevated;
  char environment[4096];
} PEBProcessInfo;

int edr_peb_parse(DWORD pid, PEBProcessInfo *info);

int edr_peb_get_command_line(DWORD pid, char *buffer, size_t buffer_size);

int edr_peb_get_environment(DWORD pid, char *buffer, size_t buffer_size);

int edr_peb_get_user_info(DWORD pid, char *user, size_t user_size, char *domain, size_t domain_size);

#endif