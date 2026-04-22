/**
 * 用 test_data/shellcode_corpus/baselines 评估 §17 已知利用匹配 + 熵/启发式。
 *
 * 用法:
 *   eval_shellcode_corpus [--mode manifest|pipeline] [--yara <rules_dir>] [--expect-builtin] [--strict] [corpus_dir]
 *
 * - manifest: 与 test_shellcode_corpus 一致 — 整段缓冲 + manifest 中的 proto_kind（签名回归）。
 * - pipeline: 先 edr_proto_find_shellcode_region，再对 payload 子区间检测（与 windivert_capture 路径接近）。
 *
 * 环境变量 EDR_YARA_RULES_DIR 等价于 --yara（便于 CI 注入）。
 */

#include "edr/proto_parse.h"
#include "edr/shellcode_detector.h"
#include "edr/shellcode_known.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EDR_EVAL_DEFAULT_CORPUS_DIR
#error "EDR_EVAL_DEFAULT_CORPUS_DIR must be set by CMake"
#endif

typedef enum {
  EVAL_MODE_MANIFEST = 0,
  EVAL_MODE_PIPELINE = 1,
} EvalMode;

static const char *kind_label(EdrProtoKind k) {
  switch (k) {
    case EDR_PROTO_KIND_UNKNOWN:
      return "UNKNOWN";
    case EDR_PROTO_KIND_SMB2:
      return "SMB2";
    case EDR_PROTO_KIND_SMB1:
      return "SMB1";
    case EDR_PROTO_KIND_RDP:
      return "RDP";
    case EDR_PROTO_KIND_HTTP:
      return "HTTP";
    default:
      return "?";
  }
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

static void usage(void) {
  fprintf(stderr,
          "usage: eval_shellcode_corpus [--mode manifest|pipeline] [--yara <dir>] [--expect-builtin] [--strict] "
          "[corpus_dir]\n"
          " default corpus: " EDR_EVAL_DEFAULT_CORPUS_DIR "\n"
          " --strict: exit 3 if any row rule_ok=0 (default exits 0 after printing)\n"
          " --expect-builtin: do not load YARA (builtin C matchers only); mutually exclusive with --yara / "
          "EDR_YARA_RULES_DIR\n");
}

int main(int argc, char **argv) {
  EvalMode mode = EVAL_MODE_MANIFEST;
  const char *corp = EDR_EVAL_DEFAULT_CORPUS_DIR;
  const char *yara = getenv("EDR_YARA_RULES_DIR");
  int strict = 0;
  int expect_builtin = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
      i++;
      if (strcmp(argv[i], "pipeline") == 0) {
        mode = EVAL_MODE_PIPELINE;
      } else if (strcmp(argv[i], "manifest") == 0) {
        mode = EVAL_MODE_MANIFEST;
      } else {
        usage();
        return 2;
      }
      continue;
    }
    if (strcmp(argv[i], "--yara") == 0 && i + 1 < argc) {
      yara = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--expect-builtin") == 0) {
      expect_builtin = 1;
      continue;
    }
    if (strcmp(argv[i], "--strict") == 0) {
      strict = 1;
      continue;
    }
    if (argv[i][0] == '-') {
      usage();
      return 2;
    }
    corp = argv[i];
  }

  if (expect_builtin) {
    if (yara && yara[0]) {
      fprintf(stderr, "eval_shellcode_corpus: --expect-builtin conflicts with YARA (--yara or EDR_YARA_RULES_DIR)\n");
      return 2;
    }
    edr_shellcode_known_shutdown();
    yara = NULL;
  } else if (yara && yara[0]) {
    (void)edr_shellcode_known_init(yara);
  }

  char manpath[1024];
  (void)snprintf(manpath, sizeof(manpath), "%s/manifest.tsv", corp);
  FILE *mf = fopen(manpath, "r");
  if (!mf) {
    fprintf(stderr, "eval_shellcode_corpus: cannot open %s\n", manpath);
    if (yara && yara[0]) {
      edr_shellcode_known_shutdown();
    }
    return 1;
  }

  printf("# mode=%s yara=%s expect_builtin=%d\n", mode == EVAL_MODE_PIPELINE ? "pipeline" : "manifest",
         (yara && yara[0]) ? yara : "(off)", expect_builtin);
  printf(
      "file\tmanifest_kind\tparse_ok\tregion_kind\tmatch_kind\tscan_len\texpected_rule\tmatched\tgot_rule\trule_ok\t"
      "entropy_bits\theuristic\n");

  char line[768];
  int nline = 0;
  int rows = 0;
  int rule_ok = 0;
  while (fgets(line, (int)sizeof(line), mf)) {
    nline++;
    if (line[0] == '#' || line[0] == '\r' || line[0] == '\n') {
      continue;
    }
    char fname[256];
    int kind_i = 0;
    char expect[96];
    if (sscanf(line, "%255[^\t]\t%d\t%94[^\t\n\r]", fname, &kind_i, expect) < 3) {
      fprintf(stderr, "bad manifest line %d\n", nline);
      fclose(mf);
      if (yara && yara[0]) {
        edr_shellcode_known_shutdown();
      }
      return 1;
    }
    char fpath[1200];
    (void)snprintf(fpath, sizeof(fpath), "%s/%s", corp, fname);
    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_file(fpath, &buf, &len) != 0) {
      fprintf(stderr, "missing %s\n", fpath);
      free(buf);
      fclose(mf);
      if (yara && yara[0]) {
        edr_shellcode_known_shutdown();
      }
      return 1;
    }

    EdrProtoShellcodeRegion reg;
    EdrProtoParseResult pr = edr_proto_find_shellcode_region(buf, (uint32_t)len, &reg);
    int parse_ok = (pr == EDR_PROTO_PARSE_OK && reg.payload_len > 0u) ? 1 : 0;
    EdrProtoKind region_k = EDR_PROTO_KIND_UNKNOWN;
    if (parse_ok) {
      region_k = reg.kind;
    }

    const uint8_t *scan = buf;
    uint32_t slen = (uint32_t)len;
    EdrProtoKind match_k = parse_kind(kind_i);

    if (mode == EVAL_MODE_PIPELINE) {
      if (parse_ok) {
        scan = buf + reg.payload_off;
        slen = reg.payload_len;
        match_k = reg.kind;
      } else {
        match_k = EDR_PROTO_KIND_UNKNOWN;
      }
    }

    double ent = edr_shellcode_shannon_entropy_bits(scan, slen);
    double heur = edr_shellcode_heuristic_score(scan, slen);
    char rule[128];
    int m = edr_shellcode_match_known_exploit(scan, slen, match_k, rule, sizeof(rule));
    int ok = (m != 0 && strcmp(rule, expect) == 0);
    if (ok) {
      rule_ok++;
    }
    rows++;
    printf("%s\t%s\t%d\t%s\t%s\t%u\t%s\t%d\t%s\t%d\t%.4f\t%.4f\n", fname, kind_label(parse_kind(kind_i)), parse_ok,
           kind_label(region_k), kind_label(match_k), (unsigned)slen, expect, m, m ? rule : "-", ok, ent, heur);
    free(buf);
  }
  fclose(mf);

  printf("# summary rows=%d rule_ok=%d rule_ok_pct=%.1f\n", rows, rule_ok,
         rows > 0 ? (100.0 * (double)rule_ok / (double)rows) : 0.0);

  if (yara && yara[0]) {
    edr_shellcode_known_shutdown();
  }
  if (rows < 1) {
    return 1;
  }
  if (strict && rule_ok != rows) {
    return 3;
  }
  return 0;
}
