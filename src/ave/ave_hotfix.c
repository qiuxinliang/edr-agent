#include "ave_hotfix.h"

#include "edr/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

static int path_is_dir(const char *p) {
#ifdef _WIN32
  DWORD a = GetFileAttributesA(p);
  return (a != INVALID_FILE_ATTRIBUTES) && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
  struct stat st;
  return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static const char *path_leaf(const char *p) {
  const char *a = strrchr(p, '/');
  const char *b = strrchr(p, '\\');
  const char *m = (a || b) ? (a > b ? a : b) : NULL;
  return m ? m + 1 : p;
}

static void join2(char *out, size_t cap, const char *dir, const char *leaf) {
#ifdef _WIN32
  snprintf(out, cap, "%s\\%s", dir, leaf);
#else
  snprintf(out, cap, "%s/%s", dir, leaf);
#endif
}

static int copy_file(const char *src, const char *dst) {
  FILE *a = fopen(src, "rb");
  if (!a) {
    return -1;
  }
  FILE *b = fopen(dst, "wb");
  if (!b) {
    fclose(a);
    return -1;
  }
  char buf[65536];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), a)) > 0) {
    if (fwrite(buf, 1, n, b) != n) {
      fclose(a);
      fclose(b);
      return -1;
    }
  }
  fclose(a);
  fclose(b);
  return 0;
}

EdrError edr_ave_apply_hotfix_path(const EdrConfig *cfg, const char *path) {
  if (!cfg || !path || !path[0]) {
    return EDR_ERR_INVALID_ARG;
  }
  const char *md = cfg->ave.model_dir;
  if (!md || !md[0]) {
    return EDR_ERR_INVALID_ARG;
  }
  if (path_is_dir(path)) {
    char src[1400], dst[1400];
    size_t copied = 0;
    const char *names[] = {"static.onnx", "behavior.onnx"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
      join2(src, sizeof(src), path, names[i]);
      join2(dst, sizeof(dst), md, names[i]);
      FILE *t = fopen(src, "rb");
      if (!t) {
        continue;
      }
      fclose(t);
      if (copy_file(src, dst) != 0) {
        return EDR_ERR_INTERNAL;
      }
      copied++;
    }
    if (copied == 0) {
      return EDR_ERR_INVALID_ARG;
    }
    return EDR_OK;
  }
  const char *leaf = path_leaf(path);
  if (!strstr(leaf, ".onnx") && !strstr(leaf, ".ONNX")) {
    return EDR_ERR_INVALID_ARG;
  }
  char dst[1400];
  join2(dst, sizeof(dst), md, leaf);
  if (copy_file(path, dst) != 0) {
    return EDR_ERR_INTERNAL;
  }
  return EDR_OK;
}
