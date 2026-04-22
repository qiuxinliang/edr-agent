/* Load synthetic baseline carriers from test_data/shellcode_corpus/baselines (manifest.tsv). */

#include "edr/proto_parse.h"
#include "edr/shellcode_known.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EDR_SHELLCODE_CORPUS_DIR
#error "EDR_SHELLCODE_CORPUS_DIR must be set by CMake when building test_shellcode_corpus"
#endif

#define CORPUS_DIR EDR_SHELLCODE_CORPUS_DIR

static int fail(const char *msg) {
  fprintf(stderr, "shellcode_corpus: %s\n", msg);
  return 1;
}

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return -1;
  }
  long z = ftell(fp);
  if (z < 0 || z > (long)(512u * 1024u)) {
    fclose(fp);
    return -1;
  }
  rewind(fp);
  uint8_t *buf = (uint8_t *)malloc((size_t)z + 1u);
  if (!buf) {
    fclose(fp);
    return -1;
  }
  size_t n = fread(buf, 1, (size_t)z, fp);
  fclose(fp);
  if (n != (size_t)z) {
    free(buf);
    return -1;
  }
  *out = buf;
  *out_len = n;
  return 0;
}

static EdrProtoKind parse_kind(int v) {
  switch (v) {
    case 0:
      return EDR_PROTO_KIND_UNKNOWN;
    case 1:
      return EDR_PROTO_KIND_SMB2;
    case 2:
      return EDR_PROTO_KIND_SMB1;
    case 3:
      return EDR_PROTO_KIND_RDP;
    case 4:
      return EDR_PROTO_KIND_HTTP;
    default:
      return EDR_PROTO_KIND_UNKNOWN;
  }
}

int main(void) {
  char manpath[1024];
  (void)snprintf(manpath, sizeof(manpath), "%s/manifest.tsv", CORPUS_DIR);
  FILE *mf = fopen(manpath, "r");
  if (!mf) {
    return fail("missing manifest.tsv (run scripts/shellcode_corpus/emit_baseline_variants.py)");
  }
  char line[768];
  int nline = 0;
  int expected = 0;
  while (fgets(line, (int)sizeof(line), mf)) {
    nline++;
    if (line[0] == '#' || line[0] == '\r' || line[0] == '\n') {
      continue;
    }
    char fname_ct[256];
    int kind_ct = 0;
    char expect_ct[96];
    if (sscanf(line, "%255[^\t]\t%d\t%94[^\t\n\r]", fname_ct, &kind_ct, expect_ct) == 3) {
      expected++;
    }
  }
  if (expected < 1) {
    fclose(mf);
    return fail("manifest.tsv has no data rows");
  }
  rewind(mf);
  nline = 0;
  int tested = 0;
  while (fgets(line, (int)sizeof(line), mf)) {
    nline++;
    if (line[0] == '#' || line[0] == '\r' || line[0] == '\n') {
      continue;
    }
    char fname[256];
    int kind_i = 0;
    char expect[96];
    if (sscanf(line, "%255[^\t]\t%d\t%94[^\t\n\r]", fname, &kind_i, expect) < 3) {
      fclose(mf);
      fprintf(stderr, "bad manifest line %d: %s", nline, line);
      return 1;
    }
    char fpath[1200];
    (void)snprintf(fpath, sizeof(fpath), "%s/%s", CORPUS_DIR, fname);
    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_file(fpath, &buf, &len) != 0) {
      free(buf);
      fclose(mf);
      fprintf(stderr, "missing corpus file: %s\n", fpath);
      return 1;
    }
    EdrProtoKind k = parse_kind(kind_i);
    char rule[128];
    int m = edr_shellcode_match_known_exploit(buf, (uint32_t)len, k, rule, sizeof(rule));
    free(buf);
    if (!m) {
      fclose(mf);
      fprintf(stderr, "no match file=%s kind=%d expected=%s\n", fname, kind_i, expect);
      return 1;
    }
    if (strcmp(rule, expect) != 0) {
      fclose(mf);
      fprintf(stderr, "rule mismatch file=%s got=%s want=%s\n", fname, rule, expect);
      return 1;
    }
    tested++;
  }
  fclose(mf);
  if (tested != expected) {
    fprintf(stderr, "manifest row count mismatch: expected %d tested %d\n", expected, tested);
    return 1;
  }
  return 0;
}
