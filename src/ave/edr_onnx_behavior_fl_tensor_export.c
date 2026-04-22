/**
 * 《11_behavior.onnx详细设计》§9.4：从 **behavior.onnx** 磁盘文件解析 **Graph.initializer**，
 * 导出 **FP32** 张量拼接（排除名称含 **tactic** / **head_b** 的战术头等冻结权重）。
 * 无 protobuf 生成代码：仅 wire 解析 ModelProto.graph（field 7）与 initializer（field 5）。
 */

#include "ave_onnx_infer.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ONNX_TAG_GRAPH ((7u << 3) | 2u)
#define ONNX_TAG_INIT ((5u << 3) | 2u)
#define TB_DIM ((1u << 3) | 0u)
#define TB_DIM_PACK ((1u << 3) | 2u)
#define TB_DTYPE ((2u << 3) | 0u)
#define TB_FDATA ((4u << 3) | 2u)
#define TB_NAME ((8u << 3) | 2u)
#define TB_RAW ((9u << 3) | 2u)
#define TB_DATA_LOC ((14u << 3) | 0u)

#define ONNX_FLOAT 1
#define FL_MAX_INITS 384u
#define FL_MAX_FLOATS (8u * 1024u * 1024u)

typedef struct {
  char name[256];
  float *data;
  size_t n;
} FlTensorRec;

static int pb_read_varint(const uint8_t **pp, const uint8_t *end, uint64_t *out) {
  const uint8_t *p = *pp;
  uint64_t r = 0;
  int s = 0;
  while (p < end) {
    unsigned b = *p++;
    r |= (uint64_t)(b & 127) << s;
    if ((b & 128u) == 0u) {
      *out = r;
      *pp = p;
      return 0;
    }
    s += 7;
    if (s > 63) {
      return -1;
    }
  }
  return -1;
}

static int pb_skip_value(const uint8_t **pp, const uint8_t *end, uint32_t key) {
  uint32_t wt = key & 7u;
  if (wt == 0u) {
    uint64_t v;
    return pb_read_varint(pp, end, &v);
  }
  if (wt == 1u) {
    if ((size_t)(end - *pp) < 8u) {
      return -1;
    }
    *pp += 8;
    return 0;
  }
  if (wt == 5u) {
    if ((size_t)(end - *pp) < 4u) {
      return -1;
    }
    *pp += 4;
    return 0;
  }
  if (wt == 2u) {
    uint64_t ln;
    if (pb_read_varint(pp, end, &ln) != 0) {
      return -1;
    }
    if ((size_t)(end - *pp) < ln) {
      return -1;
    }
    *pp += (size_t)ln;
    return 0;
  }
  return -1;
}

static int fl_substr_ci(const char *h, const char *n) {
  size_t nl = strlen(n);
  if (nl == 0u) {
    return 0;
  }
  for (const char *p = h; *p; p++) {
    size_t j = 0;
    for (; j < nl && p[j]; j++) {
      if (tolower((unsigned char)p[j]) != tolower((unsigned char)n[j])) {
        break;
      }
    }
    if (j == nl) {
      return 1;
    }
  }
  return 0;
}

static int fl_name_excluded(const char *name) {
  if (!name || !name[0]) {
    return 1;
  }
  return fl_substr_ci(name, "tactic") || fl_substr_ci(name, "head_b");
}

static int find_graph(const uint8_t *buf, size_t n, const uint8_t **gptr, size_t *glen) {
  const uint8_t *p = buf;
  const uint8_t *end = buf + n;
  while (p < end) {
    uint64_t keyu;
    if (pb_read_varint(&p, end, &keyu) != 0) {
      return -1;
    }
    uint32_t key = (uint32_t)keyu;
    if (key == ONNX_TAG_GRAPH) {
      uint64_t ln;
      if (pb_read_varint(&p, end, &ln) != 0) {
        return -1;
      }
      if ((size_t)(end - p) < ln) {
        return -1;
      }
      *gptr = p;
      *glen = (size_t)ln;
      return 0;
    }
    if (pb_skip_value(&p, end, key) != 0) {
      return -1;
    }
  }
  return -1;
}

static int64_t fl_dim_product(const int64_t *dims, int nd) {
  int64_t p = 1;
  if (nd == 0) {
    return 1;
  }
  for (int i = 0; i < nd; i++) {
    if (dims[i] <= 0) {
      return -1;
    }
    if (p > INT64_MAX / dims[i]) {
      return -1;
    }
    p *= dims[i];
  }
  return p;
}

static int parse_tensor_proto(const uint8_t *t, size_t tlen, char *name, size_t name_cap, int64_t *dims, int *ndim,
                              int *dtype_out, int *external_out, const uint8_t **raw_out, size_t *raw_len,
                              const uint8_t **fd_out, size_t *fd_len) {
  const uint8_t *p = t;
  const uint8_t *end = t + tlen;
  name[0] = '\0';
  *ndim = 0;
  *dtype_out = 0;
  *external_out = 0;
  *raw_out = NULL;
  *raw_len = 0;
  *fd_out = NULL;
  *fd_len = 0;
  while (p < end) {
    uint64_t keyu;
    if (pb_read_varint(&p, end, &keyu) != 0) {
      return -1;
    }
    uint32_t key = (uint32_t)keyu;
    if (key == TB_NAME) {
      uint64_t ln;
      if (pb_read_varint(&p, end, &ln) != 0) {
        return -1;
      }
      if ((size_t)(end - p) < ln) {
        return -1;
      }
      size_t cpy = (size_t)ln;
      if (cpy >= name_cap) {
        cpy = name_cap - 1u;
      }
      memcpy(name, p, cpy);
      name[cpy] = '\0';
      p += (size_t)ln;
    } else if (key == TB_DIM) {
      uint64_t v;
      if (pb_read_varint(&p, end, &v) != 0) {
        return -1;
      }
      if (*ndim < 16) {
        dims[*ndim] = (int64_t)v;
        (*ndim)++;
      }
    } else if (key == TB_DIM_PACK) {
      uint64_t ln;
      if (pb_read_varint(&p, end, &ln) != 0) {
        return -1;
      }
      if ((size_t)(end - p) < ln) {
        return -1;
      }
      const uint8_t *ip = p;
      const uint8_t *iend = p + (size_t)ln;
      p = iend;
      while (ip < iend) {
        uint64_t v;
        if (pb_read_varint(&ip, iend, &v) != 0) {
          return -1;
        }
        if (*ndim < 16) {
          dims[*ndim] = (int64_t)v;
          (*ndim)++;
        }
      }
    } else if (key == TB_DTYPE) {
      uint64_t v;
      if (pb_read_varint(&p, end, &v) != 0) {
        return -1;
      }
      *dtype_out = (int)v;
    } else if (key == TB_RAW) {
      uint64_t ln;
      if (pb_read_varint(&p, end, &ln) != 0) {
        return -1;
      }
      if ((size_t)(end - p) < ln) {
        return -1;
      }
      *raw_out = p;
      *raw_len = (size_t)ln;
      p += (size_t)ln;
    } else if (key == TB_FDATA) {
      uint64_t ln;
      if (pb_read_varint(&p, end, &ln) != 0) {
        return -1;
      }
      if ((size_t)(end - p) < ln) {
        return -1;
      }
      *fd_out = p;
      *fd_len = (size_t)ln;
      p += (size_t)ln;
    } else if (key == TB_DATA_LOC) {
      uint64_t v;
      if (pb_read_varint(&p, end, &v) != 0) {
        return -1;
      }
      if (v == 1u) {
        *external_out = 1;
      }
    } else {
      if (pb_skip_value(&p, end, key) != 0) {
        return -1;
      }
    }
  }
  return 0;
}

static int fl_rec_cmp(const void *a, const void *b) {
  const FlTensorRec *x = (const FlTensorRec *)a;
  const FlTensorRec *y = (const FlTensorRec *)b;
  return strcmp(x->name, y->name);
}

static void fl_free_recs(FlTensorRec *r, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(r[i].data);
  }
  free(r);
}

static int collect_one_init(const uint8_t *t, size_t tlen, FlTensorRec **out_recs, size_t *out_n, size_t *out_total) {
  char name[256];
  int64_t dims[16];
  int nd = 0;
  int dtype = 0;
  int ext = 0;
  const uint8_t *raw = NULL;
  size_t rln = 0;
  const uint8_t *fd = NULL;
  size_t fln = 0;
  if (parse_tensor_proto(t, tlen, name, sizeof(name), dims, &nd, &dtype, &ext, &raw, &rln, &fd, &fln) != 0) {
    return -1;
  }
  if (ext) {
    return 0;
  }
  if (fl_name_excluded(name)) {
    return 0;
  }
  int64_t ne = fl_dim_product(dims, nd);
  const uint8_t *src = NULL;
  size_t nbytes = 0;
  if (raw && rln > 0u) {
    src = raw;
    nbytes = rln;
  } else if (fd && fln > 0u) {
    src = fd;
    nbytes = fln;
  } else {
    return 0;
  }
  if (dtype != ONNX_FLOAT && dtype != 0) {
    return 0;
  }
  if (nbytes % 4u != 0u) {
    return 0;
  }
  size_t nf = nbytes / 4u;
  if (dtype == ONNX_FLOAT) {
    if (nf != (size_t)ne) {
      return 0;
    }
  } else if (nd > 0 && nf != (size_t)ne) {
    return 0;
  }
  if (nf == 0u || nf > FL_MAX_FLOATS) {
    return 0;
  }
  if (*out_total + nf > FL_MAX_FLOATS) {
    return -1;
  }
  if (*out_n >= FL_MAX_INITS) {
    return -1;
  }
  FlTensorRec *nr = (FlTensorRec *)realloc(*out_recs, (*out_n + 1u) * sizeof(FlTensorRec));
  if (!nr) {
    return -1;
  }
  *out_recs = nr;
  FlTensorRec *slot = &nr[*out_n];
  memset(slot, 0, sizeof(*slot));
  snprintf(slot->name, sizeof(slot->name), "%s", name);
  slot->data = (float *)malloc(nf * sizeof(float));
  if (!slot->data) {
    return -1;
  }
  memcpy(slot->data, src, nbytes);
  slot->n = nf;
  *out_total += nf;
  (*out_n)++;
  return 0;
}

static int walk_inits(const uint8_t *g, size_t glen, FlTensorRec **recs, size_t *rn, size_t *total_nf) {
  const uint8_t *p = g;
  const uint8_t *end = g + glen;
  while (p < end) {
    uint64_t keyu;
    if (pb_read_varint(&p, end, &keyu) != 0) {
      return -1;
    }
    uint32_t key = (uint32_t)keyu;
    if (key == ONNX_TAG_INIT) {
      uint64_t ln;
      if (pb_read_varint(&p, end, &ln) != 0) {
        return -1;
      }
      if ((size_t)(end - p) < ln) {
        return -1;
      }
      if (collect_one_init(p, (size_t)ln, recs, rn, total_nf) != 0) {
        return -1;
      }
      p += (size_t)ln;
    } else {
      if (pb_skip_value(&p, end, key) != 0) {
        return -1;
      }
    }
  }
  return 0;
}

static void fl_sanitize_json_str(const char *in, char *out, size_t out_cap) {
  size_t j = 0;
  for (size_t i = 0; in[i] && j + 1u < out_cap; i++) {
    unsigned char c = (unsigned char)in[i];
    if (c == '"' || c == '\\' || c < 32u) {
      out[j++] = '_';
    } else {
      out[j++] = (char)c;
    }
  }
  out[j] = '\0';
}

static int build_manifest(const FlTensorRec *recs, size_t rn, size_t total_nf, char *manifest_json,
                            size_t manifest_cap) {
  if (!manifest_json || manifest_cap == 0u) {
    return 0;
  }
  size_t off = 0;
  size_t w = snprintf(manifest_json + off, manifest_cap - off, "{\"total_floats\":%zu,\"tensors\":[",
                      total_nf);
  if (w >= manifest_cap - off) {
    return -1;
  }
  off += w;
  size_t base = 0;
  for (size_t i = 0; i < rn; i++) {
    char nm[288];
    fl_sanitize_json_str(recs[i].name, nm, sizeof(nm));
    if (i > 0u) {
      if (off + 2 >= manifest_cap) {
        return -1;
      }
      manifest_json[off++] = ',';
    }
    w = snprintf(manifest_json + off, manifest_cap - off, "{\"name\":\"%s\",\"n\":%zu,\"o\":%zu}", nm, recs[i].n,
                 base);
    if (w >= manifest_cap - off) {
      return -1;
    }
    off += w;
    base += recs[i].n;
  }
  w = snprintf(manifest_json + off, manifest_cap - off, "]}");
  if (w >= manifest_cap - off) {
    return -1;
  }
  return 0;
}

int edr_onnx_behavior_export_fl_trainable_floats(float *out_floats, size_t *out_nelem_io, char *manifest_json,
                                                size_t manifest_cap) {
  if (!out_nelem_io) {
    return -1;
  }
  const char *path = edr_onnx_behavior_loaded_path();
  if (!path || !path[0]) {
    return 1;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 3;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return 3;
  }
  long fsz = ftell(f);
  if (fsz <= 0 || fsz > (long)(256 * 1024 * 1024)) {
    fclose(f);
    return 3;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsz);
  if (!buf) {
    fclose(f);
    return 3;
  }
  rewind(f);
  if (fread(buf, 1, (size_t)fsz, f) != (size_t)fsz) {
    free(buf);
    fclose(f);
    return 3;
  }
  fclose(f);

  const uint8_t *g = NULL;
  size_t glen = 0;
  if (find_graph(buf, (size_t)fsz, &g, &glen) != 0) {
    free(buf);
    return 3;
  }

  FlTensorRec *recs = NULL;
  size_t rn = 0;
  size_t total = 0;
  if (walk_inits(g, glen, &recs, &rn, &total) != 0) {
    fl_free_recs(recs, rn);
    free(buf);
    return 3;
  }
  free(buf);

  if (rn == 0u) {
    *out_nelem_io = 0;
    if (manifest_json && manifest_cap > 0u) {
      (void)snprintf(manifest_json, manifest_cap, "{\"total_floats\":0,\"tensors\":[]}");
    }
    return 0;
  }

  qsort(recs, rn, sizeof(FlTensorRec), fl_rec_cmp);

  if (out_floats == NULL) {
    *out_nelem_io = total;
    int mf = build_manifest(recs, rn, total, manifest_json, manifest_cap);
    fl_free_recs(recs, rn);
    return mf != 0 ? 3 : 0;
  }

  if (*out_nelem_io < total) {
    *out_nelem_io = total;
    fl_free_recs(recs, rn);
    return 2;
  }

  if (build_manifest(recs, rn, total, manifest_json, manifest_cap) != 0) {
    fl_free_recs(recs, rn);
    return 3;
  }

  size_t o = 0;
  for (size_t i = 0; i < rn; i++) {
    memcpy(out_floats + o, recs[i].data, recs[i].n * sizeof(float));
    o += recs[i].n;
  }
  *out_nelem_io = o;
  fl_free_recs(recs, rn);
  return 0;
}
