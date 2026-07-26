#include "edr/response.h"

#include "edr/command_util.h"
#include "edr/response_utils.h"
#include "edr/sha256.h"
#include "edr/shell_exec.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int response_b64_value(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
  if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
  if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
  if (c == '+' || c == '-') return 62;
  if (c == '/' || c == '_') return 63;
  return -1;
}

static int response_b64_decode(const char *in, size_t in_len, uint8_t *out,
                               size_t out_cap) {
  if (!in || !out || in_len % 4u != 0u) {
    return -1;
  }
  size_t offset = 0u;
  for (size_t i = 0; i < in_len; i += 4u) {
    int a = response_b64_value((unsigned char)in[i]);
    int b = response_b64_value((unsigned char)in[i + 1u]);
    int c = in[i + 2u] == '=' ? 0 : response_b64_value((unsigned char)in[i + 2u]);
    int d = in[i + 3u] == '=' ? 0 : response_b64_value((unsigned char)in[i + 3u]);
    if (a < 0 || b < 0 || c < 0 || d < 0 || offset >= out_cap) {
      return -1;
    }
    out[offset++] = (uint8_t)((a << 2) | (b >> 4));
    if (in[i + 2u] != '=') {
      if (offset >= out_cap) return -1;
      out[offset++] = (uint8_t)((b << 4) | (c >> 2));
    }
    if (in[i + 3u] != '=') {
      if (offset >= out_cap) return -1;
      out[offset++] = (uint8_t)((c << 6) | d);
    }
  }
  return (int)offset;
}

void edr_response_put_file(const char *cmd_id, const uint8_t *pl, size_t len,
                           const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject rtr_put: dangerous commands disabled");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  if (!path[0]) {
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }

  char *data_b64 = (char *)malloc(len + 1u);
  if (!data_b64) {
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "oom");
    return;
  }
  data_b64[0] = '\0';
  (void)edr_parse_json_string(pl, len, "data_b64", data_b64, len + 1u);
  int offset = -1;
  (void)edr_parse_json_int(pl, len, "offset", &offset);

  if (!data_b64[0]) {
    free(data_b64);
    FILE *empty = fopen(path, offset > 0 ? "ab" : "wb");
    if (!empty) {
      edr_cmd_inc_exec_fail();
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "cannot create file");
      return;
    }
    fclose(empty);
    edr_cmd_inc_handled();
    edr_cmd_inc_exec_ok();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "PUT_OK empty file");
    return;
  }

  size_t b64_len = strlen(data_b64);
  size_t decoded_capacity = (b64_len / 4u * 3u) + 3u;
  uint8_t *decoded = (uint8_t *)malloc(decoded_capacity);
  if (!decoded) {
    free(data_b64);
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "oom");
    return;
  }
  int decoded_len = response_b64_decode(data_b64, b64_len, decoded, decoded_capacity);
  free(data_b64);
  if (decoded_len <= 0) {
    free(decoded);
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "base64 decode failed");
    return;
  }

  char directory[520];
  snprintf(directory, sizeof(directory), "%s", path);
#ifdef _WIN32
  char *slash = strrchr(directory, '\\');
#else
  char *slash = strrchr(directory, '/');
#endif
  if (slash) {
    *slash = '\0';
    if (directory[0]) (void)response_mkdir_p(directory);
  }

  FILE *output = NULL;
  if (offset > 0) {
    output = fopen(path, "r+b");
    if (output && fseek(output, (long)offset, SEEK_SET) != 0) {
      fclose(output);
      output = NULL;
    }
  } else {
    output = fopen(path, "wb");
  }
  if (!output) {
    free(decoded);
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, "cannot create file");
    return;
  }
  size_t written = fwrite(decoded, 1, (size_t)decoded_len, output);
  int close_ok = fclose(output) == 0;
  if (!close_ok || written != (size_t)decoded_len) {
    free(decoded);
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, "file write failed");
    return;
  }

  char actual_sha[65];
  actual_sha[0] = '\0';
  (void)edr_sha256_hex(decoded, written, actual_sha);
  free(decoded);
  char expected_sha[65];
  expected_sha[0] = '\0';
  (void)edr_parse_json_string(pl, len, "sha256", expected_sha, sizeof(expected_sha));
  if (expected_sha[0] && strcmp(expected_sha, actual_sha) != 0) {
    (void)remove(path);
    edr_cmd_inc_exec_fail();
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 7, "sha256 mismatch");
    return;
  }

  char detail[820];
  snprintf(detail, sizeof(detail), "PUT_OK path=%s offset=%d size=%d sha256=%s",
           path, offset, decoded_len, actual_sha);
  edr_cmd_inc_handled();
  edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "rtr_put: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}
