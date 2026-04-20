#ifndef EDR_FL_B64_H
#define EDR_FL_B64_H

#include <stddef.h>

/** 标准 Base64；`out` 长度至少 `4 * ((len + 2) / 3) + 1` */
size_t fl_b64_encode(const unsigned char *in, size_t len, char *out, size_t out_cap);

#endif
