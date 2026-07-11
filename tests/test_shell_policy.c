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

static int cancel_now(void *user) {
  (void)user;
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

  const char *structured =
      "{\"nested\":{\"path\":\"wrong\"},\"path\":\"C:\\\\Temp\\\\sample.exe\","
      "\"pid\":123,\"recursive\":true}";
  char path[128];
  int parsed_int = 0;
  int parsed_bool = 0;
  if (!edr_parse_json_string((const uint8_t *)structured, strlen(structured),
                             "path", path, sizeof(path)) ||
      strcmp(path, "C:\\Temp\\sample.exe") != 0)
    return fail("parser must read the top-level decoded string value");
  if (!edr_parse_json_int((const uint8_t *)structured, strlen(structured),
                          "pid", &parsed_int) || parsed_int != 123)
    return fail("parser must read an exact integer");
  if (!edr_parse_json_bool((const uint8_t *)structured, strlen(structured),
                           "recursive", &parsed_bool) || parsed_bool != 1)
    return fail("parser must read a JSON boolean");
  const char *wrong_types = "{\"pid\":\"123\",\"fraction\":1.5,\"recursive\":1}";
  if (edr_parse_json_int((const uint8_t *)wrong_types, strlen(wrong_types),
                         "pid", &parsed_int) ||
      edr_parse_json_int((const uint8_t *)wrong_types, strlen(wrong_types),
                         "fraction", &parsed_int) ||
      edr_parse_json_bool((const uint8_t *)wrong_types, strlen(wrong_types),
                          "recursive", &parsed_bool))
    return fail("parser must reject coercion between JSON types");
  const char *trailing = "{\"pid\":123} trailing";
  if (edr_parse_json_int((const uint8_t *)trailing, strlen(trailing),
                         "pid", &parsed_int))
    return fail("parser must reject trailing non-JSON data");

  char output[256];
  int exit_code = 0;
#ifdef _WIN32
  const char *long_command = "ping -n 10 127.0.0.1 >NUL";
#else
  const char *long_command = "sleep 10";
#endif
  if (edr_shell_exec_cancellable(long_command, 20, output, sizeof(output), &exit_code,
                                 cancel_now, NULL) != 0 || exit_code != 130)
    return fail("cancellable shell should hard-stop child process with exit 130");

  printf("ALL TESTS PASSED\n");
  return 0;
}
