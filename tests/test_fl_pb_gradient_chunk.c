/**
 * `UploadGradientsRequest` 分块 protobuf 编码自检（不依赖网络）。
 */
#include "fl_pb_wire.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  uint8_t buf[512];
  uint8_t big[70000];
  size_t n;
  const uint8_t *p;
  size_t i;

  memset(big, 0x5a, sizeof(big));

  n = fl_pb_encode_upload_gradients(buf, sizeof(buf), "ep1", 42u, (const uint8_t *)"ab", 2u, "t1");
  if (n == 0u || n > sizeof(buf)) {
    fprintf(stderr, "legacy encode failed\n");
    return 1;
  }

  n = fl_pb_encode_upload_gradients_chunked(buf, sizeof(buf), "ep1", 42u, (const uint8_t *)"xy", 2u, "t1", "flu-test", 0u,
                                            2u);
  if (n == 0u) {
    fprintf(stderr, "chunked encode failed\n");
    return 1;
  }
  p = buf;
  for (i = 0; i + 2 < n; i++) {
    if (p[i] == 0x2au && p[i + 1] == 0x08u && memcmp(p + i + 2, "flu-test", 8u) == 0) {
      break;
    }
  }
  if (i + 2 >= n) {
    fprintf(stderr, "field 5 gradient_upload_id not found\n");
    return 1;
  }

  n = fl_pb_encode_upload_gradients_chunked(big, sizeof(big), "e", 1u, big, 65535u, "", "id", 0u, 1u);
  if (n == 0u) {
    fprintf(stderr, "large chunk encode failed\n");
    return 1;
  }

  fprintf(stderr, "fl_pb_gradient_chunk ok\n");
  return 0;
}
