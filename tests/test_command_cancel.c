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
  require_true(edr_command_cancel_begin("cmd-2"), "register first shutdown command");
  require_true(edr_command_cancel_begin("cmd-3"), "register second shutdown command");
  require_true(edr_command_cancel_request_all() == 2, "shutdown requests cancellation for every active command");
  require_true(edr_command_cancel_requested("cmd-2") && edr_command_cancel_requested("cmd-3"),
               "all active commands observe shutdown cancellation");
  require_true(edr_command_cancel_begin("cmd-late"), "register command racing with shutdown");
  require_true(edr_command_cancel_requested("cmd-late"),
               "command registered after shutdown inherits cancellation");
  edr_command_cancel_end("cmd-2");
  edr_command_cancel_end("cmd-3");
  edr_command_cancel_end("cmd-late");
  edr_command_cancel_reset_all();
  require_true(edr_command_cancel_begin("cmd-after-restart"), "register command after executor restart");
  require_true(!edr_command_cancel_requested("cmd-after-restart"),
               "executor restart clears shutdown cancellation generation");
  edr_command_cancel_end("cmd-after-restart");
  printf("ok\n");
  return 0;
}
