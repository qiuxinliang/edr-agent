#include "edr/process_generation.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <string.h>

int main(void) {
  char command_line[4096];
  char reason[64];
  char tiny[2];

  if (!edr_process_command_line_query_live(GetCurrentProcess(), command_line,
                                           sizeof(command_line), reason,
                                           sizeof(reason))) {
    fprintf(stderr, "same-handle command-line query failed: %s\n", reason);
    return 1;
  }
  if (!strstr(command_line, "test_process_generation_windows")) {
    fprintf(stderr, "unexpected current-process command line: %s\n", command_line);
    return 1;
  }
  if (edr_process_command_line_query_live(GetCurrentProcess(), tiny, sizeof(tiny),
                                          reason, sizeof(reason)) || tiny[0] != '\0' ||
      strcmp(reason, "command_line_too_long") != 0) {
    fprintf(stderr, "bounded output did not fail closed: %s\n", reason);
    return 1;
  }
  return 0;
}
