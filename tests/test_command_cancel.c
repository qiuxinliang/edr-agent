#include "edr/command_cancel.h"

#include <stdio.h>
#include <stdlib.h>

static void require_true(int ok, const char *message) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
  }
}

int main(void) {
  require_true(edr_command_cancel_begin("cmd-1"), "register active command");
  require_true(!edr_command_cancel_begin("cmd-1"), "reject duplicate active command");
  require_true(!edr_command_cancel_requested("cmd-1"), "command starts without cancellation");
  require_true(edr_command_cancel_request("cmd-1"), "request cancellation for active command");
  require_true(edr_command_cancel_requested("cmd-1"), "active command observes cancellation");
  edr_command_cancel_end("cmd-1");
  require_true(!edr_command_cancel_request("cmd-1"), "finished command is no longer cancellable");
  printf("ok\n");
  return 0;
}
