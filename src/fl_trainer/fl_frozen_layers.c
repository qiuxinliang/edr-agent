#include "fl_frozen_layers.h"

#include <stdio.h>
#include <string.h>

static int s_logged;

static void json_escape_value(const char *s, char *out, size_t cap) {
  size_t o = 0;
  const char *p = s ? s : "";
  while (*p && o + 2u < cap) {
    if (*p == '"' || *p == '\\') {
      if (o + 2u >= cap) {
        break;
      }
      out[o++] = '\\';
    }
    out[o++] = *p++;
  }
  if (o < cap) {
    out[o] = '\0';
  } else if (cap > 0u) {
    out[cap - 1u] = '\0';
  }
}

void fl_frozen_layers_apply_feature_delta(const FLTConfig *cfg, float *delta, size_t dim) {
  (void)cfg;
  (void)delta;
  (void)dim;
  /* 特征均值路径：无按层切片；名称仍经 HTTP 上报。详见 docs/FL_ROUND_TRAINING_SEMANTICS.md §frozen_layers */
}

void fl_frozen_layers_log_once(const FLTConfig *cfg) {
  size_t ns = 0, nb = 0;
  if (!cfg || s_logged) {
    return;
  }
  s_logged = 1;
  ns = cfg->frozen_layer_count_static;
  nb = cfg->frozen_layer_count_behavior;
  if (ns == 0u && nb == 0u) {
    return;
  }
  fprintf(stderr, "[fl] frozen_layers: static=%zu behavior=%zu (T-015; feature-mean path uses names for HTTP metadata only)\n",
          ns, nb);
}

int fl_frozen_http_json_suffix(const FLTConfig *cfg, char *buf, size_t cap) {
  size_t n;
  size_t i;
  size_t off = 0;
  char esc[EDR_FL_FROZEN_NAME_MAX + 16u];
  int w;

  if (!cfg || !buf || cap < 32u) {
    return 0;
  }
  if (strncmp(cfg->model_target, "behavior", 8u) == 0) {
    n = cfg->frozen_layer_count_behavior;
  } else {
    n = cfg->frozen_layer_count_static;
  }
  if (n == 0u) {
    return 0;
  }

  w = snprintf(buf, cap, ",\"frozen_layer_names\":[");
  if (w < 0 || (size_t)w >= cap) {
    return 0;
  }
  off = (size_t)w;

  for (i = 0; i < n; i++) {
    const char *name = (strncmp(cfg->model_target, "behavior", 8u) == 0) ? cfg->frozen_layer_behavior[i]
                                                                         : cfg->frozen_layer_static[i];
    json_escape_value(name, esc, sizeof(esc));
    if (i > 0u) {
      w = snprintf(buf + off, cap - off, ",");
      if (w < 0 || (size_t)w >= cap - off) {
        return 0;
      }
      off += (size_t)w;
    }
    w = snprintf(buf + off, cap - off, "\"%s\"", esc);
    if (w < 0 || (size_t)w >= cap - off) {
      return 0;
    }
    off += (size_t)w;
  }
  if (off + 2u >= cap) {
    return 0;
  }
  buf[off++] = ']';
  buf[off] = '\0';
  return (int)off;
}
