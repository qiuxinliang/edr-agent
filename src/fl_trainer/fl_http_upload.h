#ifndef EDR_FL_HTTP_UPLOAD_H
#define EDR_FL_HTTP_UPLOAD_H

#include <stddef.h>

/** POST `body` 到 `url`（当前支持 `http://`，`https://` 在启用 OpenSSL 时） */
int fl_http_post_body(const char *url, const char *content_type, const char *body, size_t body_len);

#endif
