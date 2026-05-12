#include <stdio.h>
#include <string.h>
#include "edr/shell_exec.h"

static const char *custom_allow[] = {
  "whoami", "hostname", "ls", "cat", "find", "grep",
  "tasklist", "ps", "netstat", "curl", "wget",
  NULL
};

static const char *custom_block[] = {
  "rm ", "del ", "shutdown", "reboot",
  NULL
};

static int fail(const char *msg) {
  fprintf(stderr, "FAIL: %s\n", msg);
  return 1;
}

int main(void) {
  edr_shell_load_policy(custom_allow, custom_block);

  if (!edr_shell_is_allowed("whoami"))
    return fail("whoami should be allowed");
  if (!edr_shell_is_allowed("ls -la"))
    return fail("ls should be allowed");
  if (!edr_shell_is_allowed("curl https://example.com"))
    return fail("curl should be allowed");

  if (edr_shell_is_allowed("shutdown -s"))
    return fail("shutdown should be blocked");
  if (edr_shell_is_allowed("rm -rf /"))
    return fail("rm should be blocked");
  if (edr_shell_is_allowed("del /f /s"))
    return fail("del should be blocked");

  edr_shell_reset_policy();

  if (!edr_shell_is_allowed("whoami"))
    return fail("after reset, whoami should be allowed (default)");
  if (!edr_shell_is_allowed("powershell"))
    return fail("after reset, powershell should be allowed (default)");

  printf("ALL TESTS PASSED\n");
  return 0;
}