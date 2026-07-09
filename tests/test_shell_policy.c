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

  const char *json = "{\"rules\":\"rule T { condition: filesize \\u003c 200KB and filesize \\u003e 1KB and \\\"a\\u0026b\\\" }\"}";
  char rules[256];
  if (!edr_parse_json_string((const uint8_t *)json, strlen(json), "rules", rules, sizeof(rules)))
    return fail("rules should parse from json");
  if (strstr(rules, "\\u003c") || strstr(rules, "\\u003e") || strstr(rules, "\\u0026"))
    return fail("unicode escapes should be decoded");
  if (!strstr(rules, "filesize < 200KB") || !strstr(rules, "filesize > 1KB") || !strstr(rules, "a&b"))
    return fail("decoded YARA operators should be present");

  printf("ALL TESTS PASSED\n");
  return 0;
}
