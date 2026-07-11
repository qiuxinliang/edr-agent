/**
 * 端侧有状态关联引擎（骨架）。见 include/edr/correlation_engine.h 的设计说明。
 *
 * 本文件提供“基础设施”：总开关、规则 IR 结构、两张分线程独占的状态表、
 * FNV64 索引 + LRU 淘汰、时间窗口过期、原子指标、发射节流与发射通道。
 * 具体规则定义与命中谓词由后续提交填充（阈值：SCAN/RANSOM；序列：INJECT/CRED-EXFIL），
 * 填充点已用 CORR_RULE_TABLE / corr_threshold_step / corr_sequence_step 标注。
 */
#include "edr/correlation_engine.h"

#include "edr/ave_sdk.h"
#include "edr/behavior_alert_emit.h"
#include "edr/sha256.h"
#include "edr/time_util.h"

#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

/* ------------------------------------------------------------------ 常量 */

#define CORR_MAX_RULES 128u
#define CORR_THRESHOLD_SLOTS 1024u   /* 集成点 A（采集线程独占） */
#define CORR_SEQUENCE_SLOTS 2048u    /* 集成点 B（预处理线程独占） */
#define CORR_DISTINCT_CAP 64u        /* 阈值规则每窗口去重维度上限 */
#define CORR_EVIDENCE_MAX 6u         /* 每个活跃关联最多保留的证据引用数 */
#define CORR_EV_FIELD 96u            /* 证据关键字段截断长度 */
#define CORR_MAX_STEPS 6u            /* 序列规则最大步数 */
#define CORR_EMIT_MIN_INTERVAL_MS 3000u /* 同一 (rule,key) 最小发射间隔（内建去抖） */
#define CORR_DEFAULT_MAX_EMITS_PER_MIN 32u /* 引擎级全局发射上限（agent 单端点即端点级上限） */

typedef enum {
  CORR_KIND_THRESHOLD = 1, /* 窗口内某维度计数/去重达阈值 */
  CORR_KIND_SEQUENCE = 2,  /* 窗口内按序集齐多步 */
} CorrRuleKind;

/* 关联键选择：决定状态归并粒度。 */
typedef enum {
  CORR_KEY_PID = 1,
  CORR_KEY_PPID = 2,
  CORR_KEY_HOST = 3,
} CorrKeySel;

/* 阈值规则的去重/计数维度。 */
typedef enum {
  CORR_DIM_NONE = 0,   /* 纯计数 */
  CORR_DIM_PORT = 1,   /* 远程端口（SCAN） */
  CORR_DIM_PATH = 2,   /* 文件路径（RANSOM，可按目录归并） */
} CorrDimSel;

/* ------------------------------------------------------------ 规则 IR */

/* 步谓词标志：在 event_type 之外附加约束，用于压制误报。 */
#define CORR_STEP_REQUIRE_EXTERNAL (1u << 0)  /* 网络步：目的地必须是公网出站（排除本地/内网） */
#define CORR_STEP_REQUIRE_CRED_PATH (1u << 1) /* 文件步：路径须为凭证类存储（排除普通文件读） */

typedef struct {
  EdrEventType event_type; /* 该步关心的事件类型 */
  uint32_t flags;          /* CORR_STEP_* 谓词位；0=仅按 event_type 匹配 */
} CorrStep;

typedef struct {
  int in_use;
  char id[48];             /* 形如 R-CORR-SCAN-001 */
  char title[160];
  int severity;            /* 1..4 */
  char mitre_csv[128];
  CorrRuleKind kind;
  CorrKeySel key_sel;
  int64_t window_ms;

  /* 阈值类 */
  EdrEventType th_event_type;
  CorrDimSel th_dim;         /* 去重/计数维度 */
  int th_distinct;           /* 1=按维度去重计数，0=纯计数 */
  uint32_t th_threshold;
  int th_skip_safe_proc;     /* 1=白名单进程（备份/索引/编译器等）不计入，降误报 */
  int th_dns_long_label;     /* 1=仅统计“长标签/隧道特征”的 DNS 查询（DNS 隧道降误报） */

  /* 序列类 */
  CorrStep steps[CORR_MAX_STEPS];
  int n_steps;
  int ordered;
} CorrRule;

static CorrRule s_rules[CORR_MAX_RULES];
static uint32_t s_rule_count;

/* ------------------------------------------------------------ 状态槽 */

typedef struct {
  uint32_t type;
  uint32_t pid;
  int64_t event_time_ns;
  char key_field[CORR_EV_FIELD];
} CorrEvidence;

typedef struct {
  uint8_t used;
  uint64_t key_hash;       /* FNV64(rule_idx ^ 关联键) */
  uint16_t rule_idx;
  uint16_t step;           /* 序列：已推进到第几步 */
  uint32_t count;          /* 阈值：累计计数 */
  uint32_t n_distinct;
  uint32_t distinct[CORR_DISTINCT_CAP]; /* 去重维度指纹（open-addressed 小集合） */
  int64_t first_seen_ns;
  int64_t last_seen_ns;
  int64_t last_emit_ms;
  CorrEvidence ev[CORR_EVIDENCE_MAX];
  uint8_t ev_count;
} CorrStateSlot;

static CorrStateSlot s_threshold[CORR_THRESHOLD_SLOTS];
static CorrStateSlot s_sequence[CORR_SEQUENCE_SLOTS];

/* ---------------------------------------- 注入回灌 pending 环（跨线程无锁投递）
 * AVE 裁决线程写入，预处理线程排空。仅承载低频注入信号，容量小；满则丢弃（计入指标）。
 * 采用「原子领取写索引」的单生产快照式写入：AVE 裁决本就串行低频，读侧只在预处理线程。
 */
#define CORR_INJECT_PENDING_SLOTS 32u

/* AVE 裁决回灌信号类别：决定 drain 时合成哪种事件喂序列表。 */
typedef enum {
  CORR_SIG_INJECT = 0,      /* 进程注入 → 合成 PROCESS_INJECT */
  CORR_SIG_CRED_ACCESS = 1, /* 凭证转储(LSASS/SAM/NTDS) → 合成带凭证标记的 FILE_READ */
} CorrSignalKind;

typedef struct {
  volatile uint32_t ready; /* 0=空/写入中，1=可读 */
  uint32_t pid;
  uint32_t kind;           /* CorrSignalKind */
  int64_t event_time_ns;
  char process_name[EDR_BR_STR_SHORT];
  char technique[32]; /* 子技法（AVE behavior_flags 派生），空=通用 */
} CorrInjectPending;

static CorrInjectPending s_inject_pending[CORR_INJECT_PENDING_SLOTS];
static volatile long s_inject_write_seq; /* 单调递增，取模定位槽 */

#define CORR_INJECT_HISTORY_SLOTS 128u
typedef struct {
  volatile uint32_t ready;
  uint64_t sequence;
  uint32_t pid;
  int64_t event_time_ns;
  char process_name[256];
  char technique[32];
} CorrInjectHistory;
static CorrInjectHistory s_inject_history[CORR_INJECT_HISTORY_SLOTS];
static volatile long s_inject_history_seq;

/* ------------------------------------------------------------ 运行态/指标 */

static volatile long s_inited;
static int s_enabled_cache = -1;
static int s_loaded;
static char s_bundle_version[128] = "edr-corr-rules-v1-builtin";

static volatile uint64_t s_stat_observed;
static volatile uint64_t s_stat_evaluated;
static volatile uint64_t s_stat_fired;
static volatile uint64_t s_stat_suppressed;
static volatile uint64_t s_stat_evicted;
static volatile uint64_t s_stat_inject_fed;     /* AVE 注入回灌被排空并入表的条数 */
static volatile uint64_t s_stat_inject_dropped; /* pending 环满/覆盖丢弃的条数 */
static volatile uint64_t s_stat_rate_dropped;   /* 触发引擎级发射上限被丢弃的条数 */

/* 引擎级全局发射限流（60s 滑窗）。两线程共享，用原子；best-effort 略微超发可接受。 */
static volatile uint64_t s_emit_window_ms;
static volatile uint64_t s_emit_count;
static volatile long s_max_emits_per_min = -1; /* -1=未初始化 */

/* 全表清扫节流时间戳（仅预处理线程访问）。 */
static int64_t s_last_sweep_ms;

/* 原子自增 long，返回自增前的旧值（跨平台）。 */
static long corr_fetch_inc_long(volatile long *p) {
#if defined(_WIN32)
  return (long)InterlockedIncrement(p) - 1L;
#elif defined(__GNUC__) || defined(__clang__)
  return __sync_fetch_and_add(p, 1);
#else
  long old = *p;
  *p = old + 1;
  return old;
#endif
}

static void corr_inc64(volatile uint64_t *p) {
#if defined(_WIN32)
  (void)InterlockedIncrement64((volatile LONG64 *)p);
#elif defined(__GNUC__) || defined(__clang__)
  (void)__sync_add_and_fetch(p, 1);
#else
  (*p)++;
#endif
}

static uint64_t corr_load64(volatile uint64_t *p) {
#if defined(_WIN32)
  return (uint64_t)InterlockedCompareExchange64((volatile LONG64 *)p, 0, 0);
#elif defined(__GNUC__) || defined(__clang__)
  return __sync_add_and_fetch(p, 0);
#else
  return *p;
#endif
}

/* ------------------------------------------------------------ 小工具 */

static uint64_t corr_fnv64_str(uint64_t seed, const char *s) {
  uint64_t h = seed ? seed : 1469598103934665603ULL;
  if (!s) {
    return h;
  }
  while (*s) {
    h ^= (unsigned char)*s++;
    h *= 1099511628211ULL;
  }
  return h ? h : 1ULL;
}

static uint64_t corr_fnv64_u32(uint64_t seed, uint32_t v) {
  uint64_t h = seed ? seed : 1469598103934665603ULL;
  for (int i = 0; i < 4; i++) {
    h ^= (uint8_t)(v & 0xffu);
    h *= 1099511628211ULL;
    v >>= 8;
  }
  return h ? h : 1ULL;
}

static int corr_env_bool(const char *name, int fallback) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return fallback;
  }
  return !(v[0] == '0' || v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F');
}

int edr_correlation_enabled(void) {
  if (s_enabled_cache < 0) {
    s_enabled_cache = corr_env_bool("EDR_CORRELATION_ENABLE", 0);
  }
  return s_enabled_cache;
}

/* ------------------------------------------------------------ 规则加载 */

static CorrRule *corr_rule_new(const char *id, const char *title, int severity,
                               const char *mitre_csv, CorrRuleKind kind,
                               CorrKeySel key_sel, int64_t window_ms) {
  CorrRule *r;
  if (s_rule_count >= CORR_MAX_RULES) {
    return NULL;
  }
  r = &s_rules[s_rule_count++];
  memset(r, 0, sizeof(*r));
  r->in_use = 1;
  snprintf(r->id, sizeof(r->id), "%s", id);
  snprintf(r->title, sizeof(r->title), "%s", title);
  r->severity = severity;
  snprintf(r->mitre_csv, sizeof(r->mitre_csv), "%s", mitre_csv);
  r->kind = kind;
  r->key_sel = key_sel;
  r->window_ms = window_ms;
  return r;
}

/* 环境变量整型覆盖（阈值调参用），缺省返回 fallback。 */
static uint32_t corr_env_u32(const char *name, uint32_t fallback) {
  const char *v = getenv(name);
  char *end = NULL;
  unsigned long n;
  if (!v || !v[0]) {
    return fallback;
  }
  n = strtoul(v, &end, 10);
  if (end == v || n == 0ul || n > 0xfffffffful) {
    return fallback;
  }
  return (uint32_t)n;
}

static void corr_load_builtin_rules(void) {
  CorrRule *r;

  /* R-CORR-SCAN-001：单进程短窗口内连接大量不同远程端口 → 端口扫描。
   * 取代脆弱的 nmap.exe 进程名匹配；消费采集门前的全量 net_connect 火喉。 */
  r = corr_rule_new("R-CORR-SCAN-001", "端口扫描（高频异构连接）", 3, "T1046",
                    CORR_KIND_THRESHOLD, CORR_KEY_PID,
                    (int64_t)corr_env_u32("EDR_CORR_SCAN_WINDOW_MS", 10000));
  if (r) {
    r->th_event_type = EDR_EVENT_NET_CONNECT;
    r->th_dim = CORR_DIM_PORT;
    r->th_distinct = 1;
    r->th_threshold = corr_env_u32("EDR_CORR_SCAN_THRESHOLD", 30);
  }

  /* R-CORR-RANSOM-001：单进程短窗口内改写大量不同文件 → 批量加密。
   * 消费采集门前的全量 file_write/rename 火喉（个体事件仍照常丢弃）。 */
  r = corr_rule_new("R-CORR-RANSOM-001", "疑似勒索批量加密（高频异构文件改写）", 4,
                    "T1486", CORR_KIND_THRESHOLD, CORR_KEY_PID,
                    (int64_t)corr_env_u32("EDR_CORR_RANSOM_WINDOW_MS", 10000));
  if (r) {
    r->th_event_type = EDR_EVENT_FILE_WRITE;
    r->th_dim = CORR_DIM_PATH;
    r->th_distinct = 1;
    r->th_threshold = corr_env_u32("EDR_CORR_RANSOM_THRESHOLD", 40);
    r->th_skip_safe_proc = 1; /* 备份/索引/压缩/编译/同步类进程豁免 */
  }

  /* R-CORR-INJECT-001：有序注入序列（同进程内 API 序列）。
   * 步：进程注入(OpenProcess/VirtualAllocEx) → 进程注入(WriteProcessMemory) → 远程线程创建。
   *
   * 平台依赖：Linux 经 ptrace 产生 EDR_EVENT_PROCESS_INJECT（collector_linux.c），
   * 本规则可直接生效。Windows 上注入信号当前被转为 AVE_EVT_PROCESS_INJECT 送入 AVE
   * 行为 ONNX 管道（ave_etw_feed_win.c / ave_cross_engine_feed.c），不以 BehaviorRecord
   * 流经 process_one_slot —— 故 Windows 触发需后续将该 AVE 交叉引擎信号也回灌到
   * edr_correlation_evaluate（或让注入检测器同时 emit 记录）。机制已就绪，缺的是事件源接线。 */
  r = corr_rule_new("R-CORR-INJECT-001", "远程线程注入序列", 4, "T1055",
                    CORR_KIND_SEQUENCE, CORR_KEY_PID,
                    (int64_t)corr_env_u32("EDR_CORR_INJECT_WINDOW_MS", 5000));
  if (r) {
    r->ordered = 1;
    r->steps[0].event_type = EDR_EVENT_PROCESS_INJECT;
    r->steps[1].event_type = EDR_EVENT_PROCESS_INJECT;
    r->steps[2].event_type = EDR_EVENT_THREAD_CREATE_REMOTE;
    r->n_steps = 3;
  }

  /* R-CORR-INJECT-C2-001：注入后外联（同进程，允许乱序）。
   * 消费 Windows 注入回灌信号（edr_correlation_note_injection 合成的 PROCESS_INJECT）
   * + 该进程后续外部网络连接。注入单发噪声大，注入+活跃外联才是高置信 C2 植入。
   * Windows：AVE 注入裁决回灌 PROCESS_INJECT，且回灌处 raise 自适应采集 → 该 pid 的
   * NET_CONNECT 得以被采集门放行、经 process_one_slot 进入本评估，两步集齐即命中。
   * Linux：ptrace 注入 + net_connect 同样可命中。 */
  r = corr_rule_new("R-CORR-INJECT-C2-001", "注入后外联（疑似 C2 植入）", 4,
                    "T1055,T1071", CORR_KIND_SEQUENCE, CORR_KEY_PID,
                    (int64_t)corr_env_u32("EDR_CORR_INJECT_C2_WINDOW_MS", 120000));
  if (r) {
    r->ordered = 0;
    r->steps[0].event_type = EDR_EVENT_PROCESS_INJECT;
    r->steps[1].event_type = EDR_EVENT_NET_CONNECT;
    /* 仅公网出站才计入：合法注入类软件多与本地/内网通信，此约束显著降低误报。 */
    r->steps[1].flags = CORR_STEP_REQUIRE_EXTERNAL;
    r->n_steps = 2;
  }

  /* R-CORR-CRED-EXFIL-001：凭证访问→外联合流（同进程，允许乱序）。
   * 步：凭证访问(file_read + require_cred_path) + 外部网络连接(net_connect + require_external)。
   * 凭证访问来源有二：(a) 真实读取凭证库/Hive 文件；(b) AVE 凭证转储裁决经
   * edr_correlation_note_cred_access 回灌的合成记录（file_path="avecred:*"，覆盖 LSASS
   * 内存转储等无落地文件的头号手法）。单事件均不足以定性，合流才升级。 */
  r = corr_rule_new("R-CORR-CRED-EXFIL-001", "凭证访问后外联（合流）", 4,
                    "T1003,T1041", CORR_KIND_SEQUENCE, CORR_KEY_PID,
                    (int64_t)corr_env_u32("EDR_CORR_CREDEXFIL_WINDOW_MS", 60000));
  if (r) {
    r->ordered = 0;
    r->steps[0].event_type = EDR_EVENT_FILE_READ;
    /* 仅凭证类文件读才计入，排除“任意配置文件读+外联”误报。 */
    r->steps[0].flags = CORR_STEP_REQUIRE_CRED_PATH;
    r->steps[1].event_type = EDR_EVENT_NET_CONNECT;
    /* 外泄=公网出站；凭证读取+内网连接不计入，降低运维/备份类误报。 */
    r->steps[1].flags = CORR_STEP_REQUIRE_EXTERNAL;
    r->n_steps = 2;
  }
}

/* ---------------------------------------- 规则云端下发（JSON bundle 加载） */

/* 读取整文件（≤512KiB）。成功返回 1 并分配 *out（调用方 free）。 */
static int corr_read_file(const char *path, char **out, size_t *out_len) {
  FILE *f;
  long sz;
  char *b;
  size_t n;
  if (!path || !path[0]) {
    return 0;
  }
  f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return 0;
  }
  sz = ftell(f);
  if (sz <= 0 || sz > 512 * 1024) {
    fclose(f);
    return 0;
  }
  rewind(f);
  b = (char *)malloc((size_t)sz + 1u);
  if (!b) {
    fclose(f);
    return 0;
  }
  n = fread(b, 1, (size_t)sz, f);
  fclose(f);
  if (n != (size_t)sz) {
    free(b);
    return 0;
  }
  b[n] = '\0';
  *out = b;
  *out_len = n;
  return 1;
}

static CorrKeySel corr_parse_key_sel(const char *s) {
  if (!s) {
    return CORR_KEY_PID;
  }
  if (strcmp(s, "ppid") == 0) {
    return CORR_KEY_PPID;
  }
  if (strcmp(s, "host") == 0) {
    return CORR_KEY_HOST;
  }
  return CORR_KEY_PID;
}

static CorrDimSel corr_parse_dim(const char *s) {
  if (!s) {
    return CORR_DIM_NONE;
  }
  if (strcmp(s, "port") == 0) {
    return CORR_DIM_PORT;
  }
  if (strcmp(s, "path") == 0) {
    return CORR_DIM_PATH;
  }
  return CORR_DIM_NONE;
}

static uint32_t corr_parse_step_flags(cJSON *flags_arr) {
  uint32_t f = 0;
  cJSON *it;
  if (!cJSON_IsArray(flags_arr)) {
    return 0;
  }
  cJSON_ArrayForEach(it, flags_arr) {
    if (!cJSON_IsString(it) || !it->valuestring) {
      continue;
    }
    if (strcmp(it->valuestring, "require_external") == 0) {
      f |= CORR_STEP_REQUIRE_EXTERNAL;
    } else if (strcmp(it->valuestring, "require_cred_path") == 0) {
      f |= CORR_STEP_REQUIRE_CRED_PATH;
    }
  }
  return f;
}

/* 解析一条规则 JSON 对象到规则表。返回 1=成功注册。 */
static int corr_parse_one_rule(cJSON *o) {
  cJSON *j;
  CorrRule *r;
  const char *id, *title, *mitre, *kind_s, *key_s;
  int severity;
  int64_t window_ms;
  CorrRuleKind kind;
  j = cJSON_GetObjectItemCaseSensitive(o, "id");
  if (!cJSON_IsString(j) || !j->valuestring) {
    return 0;
  }
  id = j->valuestring;
  j = cJSON_GetObjectItemCaseSensitive(o, "enabled");
  if (cJSON_IsBool(j) && !cJSON_IsTrue(j)) {
    return 0; /* 显式禁用 */
  }
  title = (j = cJSON_GetObjectItemCaseSensitive(o, "title"), cJSON_IsString(j) && j->valuestring) ? j->valuestring : id;
  mitre = (j = cJSON_GetObjectItemCaseSensitive(o, "mitre"), cJSON_IsString(j) && j->valuestring) ? j->valuestring : "";
  severity = (j = cJSON_GetObjectItemCaseSensitive(o, "severity"), cJSON_IsNumber(j)) ? j->valueint : 3;
  kind_s = (j = cJSON_GetObjectItemCaseSensitive(o, "kind"), cJSON_IsString(j) && j->valuestring) ? j->valuestring : "";
  key_s = (j = cJSON_GetObjectItemCaseSensitive(o, "key"), cJSON_IsString(j) && j->valuestring) ? j->valuestring : "pid";
  window_ms = (j = cJSON_GetObjectItemCaseSensitive(o, "window_ms"), cJSON_IsNumber(j)) ? (int64_t)j->valuedouble : 10000;
  if (strcmp(kind_s, "threshold") == 0) {
    kind = CORR_KIND_THRESHOLD;
  } else if (strcmp(kind_s, "sequence") == 0) {
    kind = CORR_KIND_SEQUENCE;
  } else {
    return 0; /* 未知类型 */
  }
  r = corr_rule_new(id, title, severity, mitre, kind, corr_parse_key_sel(key_s), window_ms);
  if (!r) {
    return 0;
  }
  if (kind == CORR_KIND_THRESHOLD) {
    j = cJSON_GetObjectItemCaseSensitive(o, "th_event_type");
    r->th_event_type = (EdrEventType)(cJSON_IsNumber(j) ? j->valueint : 0);
    j = cJSON_GetObjectItemCaseSensitive(o, "th_dim");
    r->th_dim = corr_parse_dim(cJSON_IsString(j) ? j->valuestring : NULL);
    j = cJSON_GetObjectItemCaseSensitive(o, "th_distinct");
    r->th_distinct = cJSON_IsBool(j) ? (cJSON_IsTrue(j) ? 1 : 0) : 1;
    j = cJSON_GetObjectItemCaseSensitive(o, "th_threshold");
    r->th_threshold = (uint32_t)(cJSON_IsNumber(j) && j->valueint > 0 ? j->valueint : 30);
    j = cJSON_GetObjectItemCaseSensitive(o, "th_skip_safe_proc");
    r->th_skip_safe_proc = cJSON_IsTrue(j) ? 1 : 0;
    j = cJSON_GetObjectItemCaseSensitive(o, "th_dns_long_label");
    r->th_dns_long_label = cJSON_IsTrue(j) ? 1 : 0;
  } else {
    cJSON *steps = cJSON_GetObjectItemCaseSensitive(o, "steps");
    cJSON *st;
    j = cJSON_GetObjectItemCaseSensitive(o, "ordered");
    r->ordered = cJSON_IsTrue(j) ? 1 : 0;
    r->n_steps = 0;
    if (cJSON_IsArray(steps)) {
      cJSON_ArrayForEach(st, steps) {
        cJSON *et;
        if (r->n_steps >= (int)CORR_MAX_STEPS || !cJSON_IsObject(st)) {
          break;
        }
        et = cJSON_GetObjectItemCaseSensitive(st, "event_type");
        if (!cJSON_IsNumber(et)) {
          continue;
        }
        r->steps[r->n_steps].event_type = (EdrEventType)et->valueint;
        r->steps[r->n_steps].flags =
            corr_parse_step_flags(cJSON_GetObjectItemCaseSensitive(st, "flags"));
        r->n_steps++;
      }
    }
    if (r->n_steps <= 0) {
      r->in_use = 0; /* 无有效步：作废该规则 */
      s_rule_count--;
      return 0;
    }
  }
  return 1;
}

/* 从 JSON 文本加载规则包。成功（≥1 条）返回 1，并更新 s_bundle_version（含 SHA256）。 */
static int corr_load_from_json(const char *label, const char *data, size_t len) {
  cJSON *root, *rules, *ver, *it;
  char sha[65];
  root = cJSON_ParseWithLength(data, len);
  if (!root) {
    fprintf(stderr, "[correlation] JSON parse failed: %s\n", label ? label : "?");
    return 0;
  }
  rules = cJSON_GetObjectItemCaseSensitive(root, "rules");
  if (!cJSON_IsArray(rules)) {
    cJSON_Delete(root);
    return 0;
  }
  cJSON_ArrayForEach(it, rules) {
    if (s_rule_count >= CORR_MAX_RULES) {
      break;
    }
    if (cJSON_IsObject(it)) {
      (void)corr_parse_one_rule(it);
    }
  }
  ver = cJSON_GetObjectItemCaseSensitive(root, "version");
  sha[0] = '\0';
  (void)edr_sha256_hex((const uint8_t *)data, len, sha);
  if (cJSON_IsString(ver) && ver->valuestring && ver->valuestring[0]) {
    snprintf(s_bundle_version, sizeof(s_bundle_version), "%s", ver->valuestring);
  } else {
    snprintf(s_bundle_version, sizeof(s_bundle_version), "edr-corr-rules-sha-%.16s", sha[0] ? sha : "unknown");
  }
  cJSON_Delete(root);
  if (s_rule_count > 0) {
    fprintf(stderr, "[correlation] loaded %u rules from %s (%s) sha256=%.16s\n",
            s_rule_count, label ? label : "?", s_bundle_version, sha[0] ? sha : "?");
    return 1;
  }
  return 0;
}

/* 依次尝试 env 指定路径与若干默认路径。成功返回 1。 */
static int corr_try_load_json_paths(void) {
  const char *env = getenv("EDR_CORRELATION_RULES_PATH");
  static const char *const defaults[] = {
      "edr_config/correlation_rule_bundle_v1.json",
      "config/correlation_rule_bundle_v1.json",
      "correlation_rule_bundle_v1.json",
  };
  char *data = NULL;
  size_t len = 0;
  if (env && env[0] && corr_read_file(env, &data, &len)) {
    int ok = corr_load_from_json(env, data, len);
    free(data);
    if (ok) {
      return 1;
    }
  }
  for (size_t i = 0; i < sizeof(defaults) / sizeof(defaults[0]); i++) {
    data = NULL;
    len = 0;
    if (corr_read_file(defaults[i], &data, &len)) {
      int ok = corr_load_from_json(defaults[i], data, len);
      free(data);
      if (ok) {
        return 1;
      }
    }
  }
  return 0;
}

static void corr_load_rules(void) {
  memset(s_rules, 0, sizeof(s_rules));
  s_rule_count = 0;
  snprintf(s_bundle_version, sizeof(s_bundle_version), "edr-corr-rules-v1-builtin");
  /* 优先云端下发的 JSON 规则包；无/解析失败则回退内建规则，保证始终有可用规则。 */
  if (!corr_try_load_json_paths()) {
    corr_load_builtin_rules();
    fprintf(stderr, "[correlation] using %u builtin rules (no bundle)\n", s_rule_count);
  }
  s_loaded = 1;
}

static void corr_do_init(void) {
  memset(s_threshold, 0, sizeof(s_threshold));
  memset(s_sequence, 0, sizeof(s_sequence));
  memset(s_inject_pending, 0, sizeof(s_inject_pending));
  s_inject_write_seq = 0;
  s_stat_observed = s_stat_evaluated = s_stat_fired = 0;
  s_stat_suppressed = s_stat_evicted = 0;
  s_stat_inject_fed = s_stat_inject_dropped = 0;
  s_stat_rate_dropped = 0;
  s_emit_window_ms = 0;
  s_emit_count = 0;
  s_max_emits_per_min = -1;
  s_last_sweep_ms = 0;
  corr_load_rules();
}

void edr_correlation_lazy_init(void) {
#if defined(_WIN32)
  if (InterlockedCompareExchange(&s_inited, 1, 0) == 0) {
    corr_do_init();
  }
#elif defined(__GNUC__) || defined(__clang__)
  if (__sync_bool_compare_and_swap(&s_inited, 0, 1)) {
    corr_do_init();
  }
#else
  if (!s_inited) {
    s_inited = 1;
    corr_do_init();
  }
#endif
}

void edr_correlation_reload(void) {
  s_enabled_cache = -1;
#if defined(_WIN32)
  InterlockedExchange(&s_inited, 1);
#elif defined(__GNUC__) || defined(__clang__)
  __sync_lock_test_and_set(&s_inited, 1);
#else
  s_inited = 1;
#endif
  corr_do_init();
}

/* ------------------------------------------------------ 状态槽通用机制 */

/* 在给定表内 find-or-create 一个 (rule,key) 槽；满则 LRU（最旧 last_seen）淘汰。 */
static CorrStateSlot *corr_slot_acquire(CorrStateSlot *table, uint32_t cap,
                                        uint64_t key_hash, uint16_t rule_idx,
                                        int64_t now_ns, int64_t window_ms) {
  uint32_t start = (uint32_t)(key_hash % cap);
  CorrStateSlot *lru = NULL;
  for (uint32_t probe = 0; probe < cap; probe++) {
    CorrStateSlot *s = &table[(start + probe) % cap];
    if (s->used && s->key_hash == key_hash && s->rule_idx == rule_idx) {
      /* 窗口过期则重置复用 */
      if (window_ms > 0 && now_ns - s->first_seen_ns > window_ms * 1000000LL) {
        uint8_t keep_used = 1;
        memset(s, 0, sizeof(*s));
        s->used = keep_used;
        s->key_hash = key_hash;
        s->rule_idx = rule_idx;
        s->first_seen_ns = now_ns;
      }
      return s;
    }
    if (!s->used) {
      memset(s, 0, sizeof(*s));
      s->used = 1;
      s->key_hash = key_hash;
      s->rule_idx = rule_idx;
      s->first_seen_ns = now_ns;
      return s;
    }
    if (!lru || s->last_seen_ns < lru->last_seen_ns) {
      lru = s;
    }
  }
  /* 表满：淘汰最旧 */
  if (lru) {
    corr_inc64(&s_stat_evicted);
    memset(lru, 0, sizeof(*lru));
    lru->used = 1;
    lru->key_hash = key_hash;
    lru->rule_idx = rule_idx;
    lru->first_seen_ns = now_ns;
    return lru;
  }
  return NULL;
}

/* 去重维度：返回 1 表示是本窗口内的新值。 */
static int corr_distinct_add(CorrStateSlot *s, uint32_t fp) {
  if (fp == 0u) {
    fp = 1u;
  }
  for (uint32_t i = 0; i < s->n_distinct; i++) {
    if (s->distinct[i] == fp) {
      return 0;
    }
  }
  if (s->n_distinct < CORR_DISTINCT_CAP) {
    s->distinct[s->n_distinct++] = fp;
  }
  return 1;
}

static void corr_evidence_push(CorrStateSlot *s, uint32_t type, uint32_t pid,
                               int64_t ns, const char *key_field) {
  if (s->ev_count >= CORR_EVIDENCE_MAX) {
    return;
  }
  CorrEvidence *e = &s->ev[s->ev_count++];
  e->type = type;
  e->pid = pid;
  e->event_time_ns = ns;
  if (key_field && key_field[0]) {
    snprintf(e->key_field, sizeof(e->key_field), "%s", key_field);
  }
}

static void corr_slot_reset_window(CorrStateSlot *s, int64_t now_ns) {
  uint64_t key_hash;
  uint16_t rule_idx;
  int64_t last_emit_ms;
  if (!s) {
    return;
  }
  key_hash = s->key_hash;
  rule_idx = s->rule_idx;
  last_emit_ms = s->last_emit_ms;
  memset(s, 0, sizeof(*s));
  s->used = 1;
  s->key_hash = key_hash;
  s->rule_idx = rule_idx;
  s->first_seen_ns = now_ns;
  s->last_seen_ns = now_ns;
  s->last_emit_ms = last_emit_ms;
}

/* ------------------------------------------------------------ 发射通道 */

/* 内建去抖：同一 (rule,key) 槽在 CORR_EMIT_MIN_INTERVAL_MS 内只发一次。 */
static int corr_emit_allow(CorrStateSlot *s, int64_t now_ms) {
  if (s->last_emit_ms != 0 &&
      now_ms - s->last_emit_ms < (int64_t)CORR_EMIT_MIN_INTERVAL_MS) {
    corr_inc64(&s_stat_suppressed);
    return 0;
  }
  s->last_emit_ms = now_ms;
  return 1;
}

/* 引擎级全局发射上限（60s 滑窗）。0=不限。跨线程 best-effort。 */
static int corr_global_emit_allow(int64_t now_ms) {
  long limit;
  uint64_t win, used;
  if (s_max_emits_per_min < 0) {
    s_max_emits_per_min =
        (long)corr_env_u32("EDR_CORR_MAX_EMITS_PER_MIN", CORR_DEFAULT_MAX_EMITS_PER_MIN);
  }
  limit = s_max_emits_per_min;
  if (limit == 0) {
    return 1; /* 显式关闭限流 */
  }
  win = corr_load64(&s_emit_window_ms);
  if (win == 0u || (uint64_t)now_ms < win || (uint64_t)now_ms - win >= 60000ULL) {
#if defined(_WIN32)
    (void)InterlockedExchange64((volatile LONG64 *)&s_emit_window_ms, (LONG64)now_ms);
    (void)InterlockedExchange64((volatile LONG64 *)&s_emit_count, 0);
#elif defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(&s_emit_window_ms, (uint64_t)now_ms, __ATOMIC_RELAXED);
    __atomic_store_n(&s_emit_count, 0ULL, __ATOMIC_RELAXED);
#else
    s_emit_window_ms = (uint64_t)now_ms;
    s_emit_count = 0;
#endif
  }
#if defined(_WIN32)
  used = (uint64_t)InterlockedIncrement64((volatile LONG64 *)&s_emit_count);
#elif defined(__GNUC__) || defined(__clang__)
  used = __sync_add_and_fetch(&s_emit_count, 1);
#else
  used = ++s_emit_count;
#endif
  if (used > (uint64_t)limit) {
    corr_inc64(&s_stat_rate_dropped);
    return 0;
  }
  return 1;
}

static void corr_json_escape(const char *in, char *out, size_t cap, size_t max_chars) {
  size_t o = 0;
  size_t used_chars = 0;
  if (!out || cap == 0) {
    return;
  }
  out[0] = '\0';
  if (!in) {
    return;
  }
  for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
    unsigned char c = *p;
    if (max_chars > 0 && used_chars >= max_chars) {
      break;
    }
    used_chars++;
    if (c == '"' || c == '\\') {
      if (o + 2 >= cap) break;
      out[o++] = '\\';
      out[o++] = (char)c;
      continue;
    }
    switch (c) {
    case '\b':
      if (o + 2 >= cap) goto done;
      out[o++] = '\\';
      out[o++] = 'b';
      break;
    case '\f':
      if (o + 2 >= cap) goto done;
      out[o++] = '\\';
      out[o++] = 'f';
      break;
    case '\n':
      if (o + 2 >= cap) goto done;
      out[o++] = '\\';
      out[o++] = 'n';
      break;
    case '\r':
      if (o + 2 >= cap) goto done;
      out[o++] = '\\';
      out[o++] = 'r';
      break;
    case '\t':
      if (o + 2 >= cap) goto done;
      out[o++] = '\\';
      out[o++] = 't';
      break;
    default:
      if (c < 0x20u) {
        if (o + 6 >= cap) goto done;
        snprintf(out + o, cap - o, "\\u%04x", (unsigned)c);
        o += 6;
      } else {
        if (o + 1 >= cap) goto done;
        out[o++] = (char)c;
      }
      break;
    }
  }
done:
  out[o < cap ? o : cap - 1] = '\0';
}

/* 构造证据链 JSON 到 user_subject_json（≤4KiB）。 */
static void corr_build_subject_json(const CorrRule *rule, const CorrStateSlot *s,
                                    char *out, size_t cap) {
  char rule_id[96];
  char bundle[192];
  char title[384];
  uint32_t count;
  uint32_t distinct;
  int n;
  if (!out || cap == 0 || !rule || !s) {
    return;
  }
  corr_json_escape(rule->id, rule_id, sizeof(rule_id), 0);
  corr_json_escape(s_bundle_version, bundle, sizeof(bundle), 0);
  corr_json_escape(rule->title, title, sizeof(title), 0);
  distinct = s->n_distinct;
  count = distinct > 0 ? distinct : s->count;
  n = snprintf(out, cap,
               "{\"subject_type\":\"edr_correlation\",\"rule_id\":\"%s\","
               "\"rules_bundle_version\":\"%s\",\"display_title\":\"%s\","
               "\"window_ms\":%lld,\"count\":%u,\"distinct\":%u,\"evidence_chain\":[",
               rule_id, bundle, title, (long long)rule->window_ms, count, distinct);
  for (uint8_t i = 0; i < s->ev_count && n > 0 && (size_t)n < cap; i++) {
    char detail[256];
    corr_json_escape(s->ev[i].key_field, detail, sizeof(detail), 80);
    n += snprintf(out + n, cap - (size_t)n,
                  "%s{\"type\":%u,\"pid\":%u,\"detail\":\"%s\"}",
                  i ? "," : "", s->ev[i].type, s->ev[i].pid, detail);
  }
  if (n > 0 && (size_t)n < cap) {
    snprintf(out + n, cap - (size_t)n, "]}");
  }
}

static float corr_alert_score(const CorrRule *rule, const CorrStateSlot *s) {
  if (!rule) {
    return 0.7f;
  }
  if (strcmp(rule->id, "R-CORR-RANSOM-001") == 0) {
    uint32_t threshold = rule->th_threshold ? rule->th_threshold : 40u;
    if (s && s->n_distinct >= threshold * 3u) {
      return 0.90f;
    }
    if (s && s->n_distinct >= threshold * 2u) {
      return 0.84f;
    }
    return 0.76f;
  }
  return rule->severity >= 4 ? 0.9f : (rule->severity == 3 ? 0.8f : 0.7f);
}

static void corr_emit(const CorrRule *rule, CorrStateSlot *s, uint32_t pid,
                      const char *process_name) {
  AVEBehaviorAlert a;
  int64_t now_ms;
  if (!edr_correlation_enabled()) {
    return;
  }
  now_ms = (int64_t)(edr_monotonic_ns() / 1000000ULL);
  if (!corr_emit_allow(s, now_ms)) {
    return;
  }
  if (!corr_global_emit_allow(now_ms)) {
    return; /* 引擎级上限：本分钟发射过多，丢弃（计入 rate_dropped） */
  }
  memset(&a, 0, sizeof(a));
  a.pid = pid;
  if (process_name && process_name[0]) {
    snprintf(a.process_name, sizeof(a.process_name), "%s", process_name);
  }
  a.anomaly_score = corr_alert_score(rule, s);
  a.needs_l2_review = false;
  a.skip_ai_analysis = false;
  a.timestamp_ns = s->last_seen_ns;
  snprintf(a.triggered_tactics, sizeof(a.triggered_tactics), "%s", rule->mitre_csv);
  corr_build_subject_json(rule, s, a.user_subject_json, sizeof(a.user_subject_json));
  edr_behavior_alert_emit_to_batch(&a);
  corr_inc64(&s_stat_fired);
}

/* ------------------------------------------------------ 集成点 A：阈值 */

static uint64_t corr_interest_key(const CorrRule *rule, const EdrSensorInterestEvent *ev) {
  uint64_t h = corr_fnv64_u32(0, (uint32_t)rule->kind);
  h = corr_fnv64_str(h, rule->id);
  switch (rule->key_sel) {
  case CORR_KEY_PPID:
    return corr_fnv64_u32(h, ev->parent_pid);
  case CORR_KEY_HOST:
    return corr_fnv64_str(h, ev->process_name); /* 主机级键的占位；后续可换 endpoint_id */
  case CORR_KEY_PID:
  default:
    return corr_fnv64_u32(h, ev->pid);
  }
}

/* 从兴趣事件按规则维度取指纹 + 证据字符串。 */
static uint32_t corr_dimension_fp(const CorrRule *rule, const EdrSensorInterestEvent *ev,
                                  char *dim_out, size_t dim_cap) {
  if (dim_out && dim_cap) {
    dim_out[0] = '\0';
  }
  switch (rule->th_dim) {
  case CORR_DIM_PORT:
    if (dim_out && dim_cap) {
      snprintf(dim_out, dim_cap, "port=%u", ev->remote_port);
    }
    return corr_fnv64_u32(0, ev->remote_port) & 0xffffffffu;
  case CORR_DIM_PATH:
    if (dim_out && dim_cap) {
      snprintf(dim_out, dim_cap, "%.80s", ev->path);
    }
    return (uint32_t)(corr_fnv64_str(0, ev->path) & 0xffffffffu);
  case CORR_DIM_NONE:
  default:
    return 0u;
  }
}

static int corr_proc_is_bulk_file_safe(const char *process_name); /* 定义见下 */
static int corr_dns_is_tunnel_like(const char *qname);             /* 定义见下 */
static int corr_ransom_interest_ok(const EdrSensorInterestEvent *ev); /* 定义见下 */

void edr_correlation_observe_interest(const EdrSensorInterestEvent *ev) {
  int64_t now_ns;
  if (!edr_correlation_enabled() || !ev) {
    return;
  }
  edr_correlation_lazy_init();
  corr_inc64(&s_stat_observed);
  if (s_rule_count == 0u) {
    return; /* 骨架：无规则即 no-op */
  }
  now_ns = (int64_t)edr_monotonic_ns();
  for (uint32_t r = 0; r < s_rule_count; r++) {
    CorrRule *rule = &s_rules[r];
    CorrStateSlot *slot;
    uint32_t hit;
    int is_new = 1;
    char dim[CORR_EV_FIELD];
    if (!rule->in_use || rule->kind != CORR_KIND_THRESHOLD) {
      continue;
    }
    if (rule->th_event_type != 0 && ev->type != (EdrEventType)rule->th_event_type) {
      continue;
    }
    /* 白名单进程（备份/索引/编译等）不计入 RANSOM 类阈值，避免合法批量改写误报。 */
    if (rule->th_skip_safe_proc && corr_proc_is_bulk_file_safe(ev->process_name)) {
      continue;
    }
    if (strcmp(rule->id, "R-CORR-RANSOM-001") == 0 && !corr_ransom_interest_ok(ev)) {
      continue;
    }
    /* DNS 隧道：仅统计具备隧道特征（长标签/超长）的查询，正常域名不计入。 */
    if (rule->th_dns_long_label && !corr_dns_is_tunnel_like(ev->path)) {
      continue;
    }
    slot = corr_slot_acquire(s_threshold, CORR_THRESHOLD_SLOTS,
                             corr_interest_key(rule, ev), (uint16_t)r, now_ns,
                             rule->window_ms);
    if (!slot) {
      continue;
    }
    slot->last_seen_ns = now_ns;
    if (rule->th_distinct) {
      is_new = corr_distinct_add(slot, corr_dimension_fp(rule, ev, dim, sizeof(dim)));
      hit = slot->n_distinct;
    } else {
      (void)corr_dimension_fp(rule, ev, dim, sizeof(dim));
      slot->count++;
      hit = slot->count;
    }
    if (is_new) {
      corr_evidence_push(slot, (uint32_t)ev->type, ev->pid, now_ns, dim);
    }
    if (hit >= rule->th_threshold) {
      corr_emit(rule, slot, ev->pid, ev->process_name);
      corr_slot_reset_window(slot, now_ns);
    }
  }
}

/* ------------------------------------------------------ 集成点 B：序列 */

static uint64_t corr_record_key(const CorrRule *rule, const EdrBehaviorRecord *br) {
  uint64_t h = corr_fnv64_u32(0, (uint32_t)rule->kind);
  h = corr_fnv64_str(h, rule->id);
  switch (rule->key_sel) {
  case CORR_KEY_PPID:
    return corr_fnv64_u32(h, br->ppid);
  case CORR_KEY_HOST:
    return corr_fnv64_str(h, br->endpoint_id);
  case CORR_KEY_PID:
  default:
    return corr_fnv64_u32(h, br->pid);
  }
}

/* 仅查找不创建（供序列的中间步推进用，避免为孤立事件建空槽）。
 * 注：表满时 acquire 会 LRU 淘汰打散探测链，属尽力而为语义，极端压力下可能漏配。 */
static CorrStateSlot *corr_slot_find(CorrStateSlot *table, uint32_t cap,
                                     uint64_t key_hash, uint16_t rule_idx) {
  uint32_t start = (uint32_t)(key_hash % cap);
  for (uint32_t probe = 0; probe < cap; probe++) {
    CorrStateSlot *s = &table[(start + probe) % cap];
    if (s->used && s->key_hash == key_hash && s->rule_idx == rule_idx) {
      return s;
    }
    if (!s->used) {
      return NULL;
    }
  }
  return NULL;
}

/* 目的地是否为公网出站（用于 CORR_STEP_REQUIRE_EXTERNAL）。
 * 排除空、环回、私有(RFC1918)、链路本地、CGNAT、IPv6 环回/链路本地/ULA。
 * 无法确认为公网时保守返回 0（不计入网络步），以降低误报。 */
static int corr_ip_is_external(const char *ip) {
  unsigned a = 0, b = 0, c = 0, d = 0;
  if (!ip || !ip[0]) {
    return 0;
  }
  if (strchr(ip, ':')) {
    /* IPv6：排除环回/未指定/链路本地(fe80::)/ULA(fc00::/fd00::)，其余视为公网。 */
    if (strcmp(ip, "::1") == 0 || strcmp(ip, "::") == 0) {
      return 0;
    }
    if ((ip[0] == 'f' || ip[0] == 'F')) {
      char h = (char)((ip[1] >= 'A' && ip[1] <= 'Z') ? ip[1] + ('a' - 'A') : ip[1]);
      char l = ip[2];
      if (h == 'e' && (l == '8' || l == '9' || l == 'a' || l == 'b' ||
                       l == 'A' || l == 'B')) {
        return 0; /* fe80::/10 链路本地 */
      }
      if (h == 'c' || h == 'd') {
        return 0; /* fc00::/7 ULA */
      }
    }
    return 1;
  }
  if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255 || b > 255 || c > 255 || d > 255) {
    return 0;
  }
  if (a == 10u || a == 127u || a == 0u) {
    return 0;
  }
  if (a == 172u && b >= 16u && b <= 31u) {
    return 0;
  }
  if (a == 192u && b == 168u) {
    return 0;
  }
  if (a == 169u && b == 254u) {
    return 0; /* 链路本地 */
  }
  if (a == 100u && b >= 64u && b <= 127u) {
    return 0; /* CGNAT 100.64.0.0/10 */
  }
  if (a >= 224u) {
    return 0; /* 组播/保留 */
  }
  return 1;
}

/* 大小写无关子串匹配（路径归一化：仅折大小写，反斜杠/正斜杠均可命中）。 */
static int corr_path_contains_ci(const char *hay, const char *needle) {
  size_t nl, hl;
  if (!hay || !needle || !needle[0]) {
    return 0;
  }
  nl = strlen(needle);
  hl = strlen(hay);
  if (nl > hl) {
    return 0;
  }
  for (size_t i = 0; i + nl <= hl; i++) {
    size_t j = 0;
    for (; j < nl; j++) {
      char a = hay[i + j];
      char b = needle[j];
      if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
      if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
      if (a == '/') a = '\\';
      if (b == '/') b = '\\';
      if (a != b) {
        break;
      }
    }
    if (j == nl) {
      return 1;
    }
  }
  return 0;
}

static int corr_path_ends_ci(const char *s, const char *suffix) {
  size_t sl, nl;
  if (!s || !suffix || !suffix[0]) {
    return 0;
  }
  sl = strlen(s);
  nl = strlen(suffix);
  if (nl > sl) {
    return 0;
  }
  return corr_path_contains_ci(s + sl - nl, suffix);
}

static int corr_path_has_path_shape(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
  for (const char *p = path; *p; p++) {
    unsigned char c = (unsigned char)*p;
    if (c < 0x20u) {
      return 0;
    }
    if (*p == '\\' || *p == '/' || *p == ':') {
      return 1;
    }
  }
  return 0;
}

static int corr_path_is_low_value_file_write(const char *path) {
  static const char *const low_dirs[] = {
      "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\appdata\\local\\microsoft\\edge\\user data\\",
      "\\appdata\\local\\google\\chrome\\user data\\", "\\appdata\\local\\packages\\",
      "\\appdata\\local\\microsoft\\windows\\inetcache\\", "\\windows\\softwaredistribution\\",
      "\\windows\\system32\\winevt\\logs\\", "\\programdata\\microsoft\\windows defender\\",
      "\\programdata\\fdsecurity\\setup-ui\\", "\\programdata\\fdsecurity\\collector\\",
      "\\onedrive\\logs\\", "\\cache\\",
  };
  static const char *const low_exts[] = {
      ".tmp", ".temp", ".log", ".etl", ".evtx", ".cache", ".lock",
  };
  if (!path || !path[0]) {
    return 1;
  }
  for (size_t i = 0; i < sizeof(low_dirs) / sizeof(low_dirs[0]); i++) {
    if (corr_path_contains_ci(path, low_dirs[i])) {
      return 1;
    }
  }
  for (size_t i = 0; i < sizeof(low_exts) / sizeof(low_exts[0]); i++) {
    if (corr_path_ends_ci(path, low_exts[i])) {
      return 1;
    }
  }
  return 0;
}

static int corr_ransom_interest_ok(const EdrSensorInterestEvent *ev) {
  if (!ev || ev->type != EDR_EVENT_FILE_WRITE) {
    return 0;
  }
  if (ev->pid == 0u || ev->pid == 4u) {
    return 0;
  }
  if (!ev->process_name[0] || strncmp(ev->process_name, "pid:", 4) == 0) {
    return 0;
  }
  if (corr_proc_is_bulk_file_safe(ev->process_name)) {
    return 0;
  }
  if (!corr_path_has_path_shape(ev->path)) {
    return 0;
  }
  if (corr_path_is_low_value_file_write(ev->path)) {
    return 0;
  }
  return 1;
}

/* 路径是否为凭证类存储（用于 CORR_STEP_REQUIRE_CRED_PATH）。
 * 覆盖 SAM/SYSTEM/SECURITY Hive、lsass dump、ntds.dit、浏览器凭据库、云/SSH 凭据、
 * DPAPI/Vault 等；未命中则不计入，避免“任意文件读”误报。 */
static int corr_path_is_credential(const char *path) {
  static const char *const needles[] = {
      "\\config\\sam", "\\config\\system", "\\config\\security", "\\sam.save",
      "\\system.save", "ntds.dit", "lsass.dmp", "lsass.dump", "\\windows\\ntds\\",
      "\\login data", "\\cookies", "\\web data", "key4.db", "key3.db", "logins.json",
      "signons.sqlite", "\\microsoft\\credentials\\", "\\microsoft\\vault\\",
      "\\microsoft\\protect\\", "\\.aws\\credentials", "\\.azure\\", "\\.ssh\\id_",
      "\\.ssh\\known_hosts", "\\.gnupg\\", "\\credentials\\", "\\.docker\\config.json",
      "\\.kube\\config",
      /* AVE 凭证转储裁决回灌的合成标记（LSASS 内存转储无落地文件，用此标记接入）。 */
      "avecred:",
  };
  if (!path || !path[0]) {
    return 0;
  }
  for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
    if (corr_path_contains_ci(path, needles[i])) {
      return 1;
    }
  }
  return 0;
}

/* 取路径/进程名的 basename（去目录）。 */
static const char *corr_basename(const char *s) {
  const char *last = s ? s : "";
  if (!s) {
    return "";
  }
  for (const char *p = s; *p; p++) {
    if (*p == '\\' || *p == '/') {
      last = p + 1;
    }
  }
  return last;
}

static int corr_token_list_exact_ci(const char *list, const char *value) {
  if (!list || !list[0] || !value || !value[0]) {
    return 0;
  }
  const char *p = list;
  while (*p) {
    while (*p == ',' || *p == ';' || *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
      p++;
    }
    char tok[256];
    size_t n = 0u;
    while (*p && *p != ',' && *p != ';' && *p != '\n' && *p != '\r' && n + 1u < sizeof(tok)) {
      tok[n++] = *p++;
    }
    while (*p && *p != ',' && *p != ';' && *p != '\n' && *p != '\r') {
      p++;
    }
    while (n > 0u && (tok[n - 1u] == ' ' || tok[n - 1u] == '\t')) {
      n--;
    }
    tok[n] = '\0';
    if (tok[0] && strlen(tok) == strlen(value)) {
      int same = 1;
      for (size_t i = 0; tok[i]; i++) {
        char a = tok[i];
        char b = value[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) {
          same = 0;
          break;
        }
      }
      if (same) {
        return 1;
      }
    }
  }
  return 0;
}

/* 进程是否属于“会合法地批量改写大量文件”的白名单（备份/索引/压缩/编译/同步）。
 * 用于 RANSOM 阈值规则的降误报；EDR_CORR_RANSOM_ALLOW 逗号分隔可追加。 */
static int corr_proc_is_bulk_file_safe(const char *process_name) {
  static const char *const safe[] = {
      "wbadmin.exe", "vssadmin.exe", "diskshadow.exe", "robocopy.exe", "xcopy.exe",
      "backup.exe", "veeam.agent.exe", "acronis.exe", "msmpeng.exe", "searchindexer.exe",
      "searchprotocolhost.exe", "searchfilterhost.exe", "7z.exe", "7za.exe", "winrar.exe",
      "rar.exe", "zip.exe", "tar.exe", "compress.exe", "onedrive.exe", "dropbox.exe",
      "googledrivefs.exe", "msbuild.exe", "cl.exe", "link.exe", "gcc.exe", "clang.exe",
      "ld.exe", "devenv.exe", "node.exe", "python.exe", "java.exe", "javac.exe",
      "gradle.exe", "cargo.exe", "go.exe", "rustc.exe",
  };
  const char *base;
  const char *env;
  if (!process_name || !process_name[0]) {
    return 0;
  }
  base = corr_basename(process_name);
  for (size_t i = 0; i < sizeof(safe) / sizeof(safe[0]); i++) {
    if (corr_token_list_exact_ci(safe[i], base)) {
      return 1;
    }
  }
  env = getenv("EDR_CORR_RANSOM_ALLOW");
  if (env && env[0] && corr_token_list_exact_ci(env, base)) {
    return 1;
  }
  return 0;
}

/* DNS 查询名是否具备隧道特征（用于 th_dns_long_label）：
 * 任一点分标签长度 ≥ 阈值（EDR_CORR_DNS_LABEL_LEN，默认 30），或整名长度 ≥ 100。
 * 隧道把数据编码进子域标签，产生超长/高熵标签；正常域名标签通常 < 20，据此过滤误报。 */
static int corr_dns_is_tunnel_like(const char *qname) {
  size_t label_len = 0, total = 0;
  unsigned max_label = 0;
  unsigned long thr;
  const char *p;
  if (!qname || !qname[0]) {
    return 0;
  }
  thr = strtoul(getenv("EDR_CORR_DNS_LABEL_LEN") ? getenv("EDR_CORR_DNS_LABEL_LEN") : "", NULL, 10);
  if (thr == 0ul || thr > 63ul) {
    thr = 30ul;
  }
  for (p = qname; *p; p++) {
    total++;
    if (*p == '.') {
      if (label_len > max_label) {
        max_label = (unsigned)label_len;
      }
      label_len = 0;
    } else {
      label_len++;
    }
  }
  if (label_len > max_label) {
    max_label = (unsigned)label_len;
  }
  return (max_label >= (unsigned)thr) || (total >= 100u);
}

/* 步谓词是否满足（event_type 之外的附加约束）。 */
static int corr_step_predicate_ok(const CorrStep *step, const EdrBehaviorRecord *br) {
  if (step->flags & CORR_STEP_REQUIRE_EXTERNAL) {
    if (!corr_ip_is_external(br->net_dst)) {
      return 0;
    }
  }
  if (step->flags & CORR_STEP_REQUIRE_CRED_PATH) {
    if (!corr_path_is_credential(br->file_path)) {
      return 0;
    }
  }
  return 1;
}

/* br 是否命中该序列规则的第 step_idx 步（含步谓词）。 */
static int corr_seq_step_matches(const CorrRule *rule, int step_idx,
                                 const EdrBehaviorRecord *br) {
  if (step_idx < 0 || step_idx >= rule->n_steps) {
    return 0;
  }
  if (rule->steps[step_idx].event_type != br->type) {
    return 0;
  }
  return corr_step_predicate_ok(&rule->steps[step_idx], br);
}

/* br 是否与该规则任意一步相关（用于无序位图与快速剪枝）。返回命中的步下标，-1=无。 */
static int corr_seq_any_step(const CorrRule *rule, const EdrBehaviorRecord *br) {
  for (int i = 0; i < rule->n_steps; i++) {
    if (rule->steps[i].event_type == br->type && corr_step_predicate_ok(&rule->steps[i], br)) {
      return i;
    }
  }
  return -1;
}

static uint32_t corr_popcount(uint32_t v) {
  uint32_t c = 0;
  while (v) {
    v &= v - 1u;
    c++;
  }
  return c;
}

/* 对一条记录跑所有序列规则的推进/命中。仅由预处理线程调用（含排空注入 pending 时）。
 * evidence_detail 非空时作为本记录各步的证据 detail（用于注入回灌携带子技法）；否则用进程名。 */
static void corr_run_sequences(const EdrBehaviorRecord *br, int64_t now_ns,
                               const char *evidence_detail) {
  const char *detail = (evidence_detail && evidence_detail[0]) ? evidence_detail : br->process_name;
  for (uint32_t r = 0; r < s_rule_count; r++) {
    CorrRule *rule = &s_rules[r];
    CorrStateSlot *slot = NULL;
    uint64_t key;
    if (!rule->in_use || rule->kind != CORR_KIND_SEQUENCE || rule->n_steps <= 0) {
      continue;
    }
    if (corr_seq_any_step(rule, br) < 0) {
      continue; /* 与本规则任何步都不相关，快速剪枝 */
    }
    key = corr_record_key(rule, br);
    if (rule->ordered) {
      /* 由“槽当前等待的下一步”驱动推进，正确处理重复事件类型的步。 */
      slot = corr_slot_find(s_sequence, CORR_SEQUENCE_SLOTS, key, (uint16_t)r);
      if (!slot) {
        /* 仅当匹配起始步时才开新序列，避免为孤立中间事件建槽。 */
        if (!corr_seq_step_matches(rule, 0, br)) {
          continue;
        }
        slot = corr_slot_acquire(s_sequence, CORR_SEQUENCE_SLOTS, key, (uint16_t)r, now_ns,
                                 rule->window_ms);
        if (!slot) {
          continue;
        }
      }
      if (corr_seq_step_matches(rule, (int)slot->step, br)) {
        slot->last_seen_ns = now_ns;
        slot->step++;
        corr_evidence_push(slot, (uint32_t)br->type, br->pid, now_ns, detail);
        if (slot->step >= (uint16_t)rule->n_steps) {
          corr_emit(rule, slot, br->pid, br->process_name);
        }
      }
    } else {
      /* 乱序：用 count 低位做“已见步”位图，集齐即命中。 */
      int mi = corr_seq_any_step(rule, br);
      slot = corr_slot_acquire(s_sequence, CORR_SEQUENCE_SLOTS, key, (uint16_t)r, now_ns,
                               rule->window_ms);
      if (!slot) {
        continue;
      }
      slot->last_seen_ns = now_ns;
      if ((slot->count & (1u << mi)) == 0u) {
        slot->count |= (1u << mi);
        corr_evidence_push(slot, (uint32_t)br->type, br->pid, now_ns, detail);
      }
      if (corr_popcount(slot->count) >= (uint32_t)rule->n_steps) {
        corr_emit(rule, slot, br->pid, br->process_name);
      }
    }
  }
}

/* 排空 AVE 裁决 pending 环：按信号类别合成最小记录并入序列表。
 * 仅由预处理线程调用，保持“序列表单一写者”不变式。 */
static void corr_drain_injections(int64_t now_ns) {
  for (uint32_t i = 0; i < CORR_INJECT_PENDING_SLOTS; i++) {
    CorrInjectPending *p = &s_inject_pending[i];
    EdrBehaviorRecord br;
    char detail[CORR_EV_FIELD];
    const char *tech;
    if (p->ready == 0u) {
      continue;
    }
    tech = p->technique[0] ? p->technique : p->process_name;
    memset(&br, 0, sizeof(br));
    br.pid = p->pid;
    br.event_time_ns = p->event_time_ns > 0 ? p->event_time_ns : now_ns;
    snprintf(br.process_name, sizeof(br.process_name), "%s", p->process_name);
    if (p->kind == CORR_SIG_CRED_ACCESS) {
      /* 凭证转储裁决 → 合成带凭证标记的 FILE_READ，命中 CRED-EXFIL 的 require_cred_path。
       * LSASS 内存转储无落地文件，用合成标记路径接入现有凭证外泄检测。 */
      br.type = EDR_EVENT_FILE_READ;
      snprintf(br.file_path, sizeof(br.file_path), "avecred:%s", tech);
      snprintf(detail, sizeof(detail), "credaccess:%s", tech);
    } else {
      /* 注入裁决 → 合成 PROCESS_INJECT，证据 detail 携带子技法供图边归因。 */
      br.type = EDR_EVENT_PROCESS_INJECT;
      snprintf(detail, sizeof(detail), "inject:%s", tech);
    }
    p->ready = 0u; /* 先清可读位再处理，避免重复消费 */
    corr_run_sequences(&br, br.event_time_ns, detail);
    corr_inc64(&s_stat_inject_fed);
  }
}

void edr_correlation_evaluate(const EdrBehaviorRecord *br) {
  int64_t now_ns;
  if (!edr_correlation_enabled() || !br) {
    return;
  }
  edr_correlation_lazy_init();
  corr_inc64(&s_stat_evaluated);
  if (s_rule_count == 0u) {
    return; /* 骨架：无规则即 no-op */
  }
  now_ns = br->event_time_ns > 0 ? br->event_time_ns : (int64_t)edr_monotonic_ns();
  corr_drain_injections(now_ns); /* 先并入 AVE 注入回灌，再处理本事件 */
  corr_run_sequences(br, now_ns, NULL);
}

/* AVE 裁决回灌的共用写入器：原子领取 pending 槽并发布。由 AVE 裁决线程调用。 */
static void corr_note_ave_signal(CorrSignalKind kind, uint32_t pid, const char *process_name,
                                 int64_t event_time_ns, const char *technique) {
  long seq;
  CorrInjectPending *p;
  if (!edr_correlation_enabled() || pid == 0u) {
    return;
  }
  edr_correlation_lazy_init();
  seq = corr_fetch_inc_long(&s_inject_write_seq);
  p = &s_inject_pending[(uint32_t)seq % CORR_INJECT_PENDING_SLOTS];
  if (p->ready) {
    /* 槽尚未被预处理线程排空即被覆盖：计一次丢弃（低频下极少发生）。 */
    corr_inc64(&s_stat_inject_dropped);
  }
  p->ready = 0u; /* 写入期间标记不可读 */
  p->pid = pid;
  p->kind = (uint32_t)kind;
  p->event_time_ns = event_time_ns;
  if (process_name && process_name[0]) {
    snprintf(p->process_name, sizeof(p->process_name), "%s", process_name);
  } else {
    p->process_name[0] = '\0';
  }
  if (technique && technique[0]) {
    snprintf(p->technique, sizeof(p->technique), "%s", technique);
  } else {
    p->technique[0] = '\0';
  }
#if defined(_WIN32)
  MemoryBarrier();
#elif defined(__GNUC__) || defined(__clang__)
  __sync_synchronize();
#endif
  p->ready = 1u; /* 发布：字段就绪后再置可读 */
}

void edr_correlation_note_injection(uint32_t pid, const char *process_name, int64_t event_time_ns,
                                    const char *technique) {
  corr_note_ave_signal(CORR_SIG_INJECT, pid, process_name, event_time_ns, technique);
  if (pid != 0u) {
    long sequence = corr_fetch_inc_long(&s_inject_history_seq);
    CorrInjectHistory *slot = &s_inject_history[(uint32_t)sequence % CORR_INJECT_HISTORY_SLOTS];
    slot->ready = 0u;
    slot->sequence = (uint64_t)(unsigned long)sequence;
    slot->pid = pid;
    slot->event_time_ns = event_time_ns;
    snprintf(slot->process_name, sizeof(slot->process_name), "%s",
             process_name ? process_name : "");
    snprintf(slot->technique, sizeof(slot->technique), "%s",
             technique ? technique : "");
#if defined(_WIN32)
    MemoryBarrier();
#elif defined(__GNUC__) || defined(__clang__)
    __sync_synchronize();
#endif
    slot->ready = 1u;
  }
}

int edr_correlation_latest_injection(uint32_t pid,
                                     EdrCorrelationInjectionObservation *out) {
  if (!out || pid == 0u) return 0;
  memset(out, 0, sizeof(*out));
  uint64_t best_sequence = 0u;
  int found = 0;
  for (uint32_t i = 0; i < CORR_INJECT_HISTORY_SLOTS; i++) {
    CorrInjectHistory *slot = &s_inject_history[i];
    if (slot->ready == 0u || slot->pid != pid) continue;
    uint64_t sequence = slot->sequence;
    EdrCorrelationInjectionObservation candidate;
    memset(&candidate, 0, sizeof(candidate));
    candidate.pid = slot->pid;
    candidate.event_time_ns = slot->event_time_ns;
    snprintf(candidate.process_name, sizeof(candidate.process_name), "%s", slot->process_name);
    snprintf(candidate.technique, sizeof(candidate.technique), "%s", slot->technique);
    snprintf(candidate.source, sizeof(candidate.source), "%s", "ave_behavior");
#if defined(_WIN32)
    MemoryBarrier();
#elif defined(__GNUC__) || defined(__clang__)
    __sync_synchronize();
#endif
    if (slot->ready == 0u || slot->sequence != sequence || slot->pid != pid) continue;
    if (!found || sequence >= best_sequence) {
      *out = candidate;
      best_sequence = sequence;
      found = 1;
    }
  }
  return found;
}

void edr_correlation_note_cred_access(uint32_t pid, const char *process_name, int64_t event_time_ns,
                                      const char *technique) {
  corr_note_ave_signal(CORR_SIG_CRED_ACCESS, pid, process_name, event_time_ns, technique);
}

/* ------------------------------------------------------------ 维护/状态 */

static uint32_t corr_sweep(CorrStateSlot *table, uint32_t cap, int64_t now_ns) {
  uint32_t active = 0;
  for (uint32_t i = 0; i < cap; i++) {
    CorrStateSlot *s = &table[i];
    if (!s->used) {
      continue;
    }
    const CorrRule *rule = s->rule_idx < s_rule_count ? &s_rules[s->rule_idx] : NULL;
    int64_t win_ms = rule ? rule->window_ms : 60000;
    if (win_ms > 0 && now_ns - s->first_seen_ns > win_ms * 1000000LL) {
      memset(s, 0, sizeof(*s));
      corr_inc64(&s_stat_evicted);
      continue;
    }
    active++;
  }
  return active;
}

#define CORR_SWEEP_INTERVAL_MS 30000LL /* 全表清扫最小间隔（内部节流，允许每循环调用） */

void edr_correlation_poll_maintenance(int64_t now_ns) {
  int64_t now_ms;
  if (!edr_correlation_enabled()) {
    return;
  }
  edr_correlation_lazy_init();
  if (now_ns <= 0) {
    now_ns = (int64_t)edr_monotonic_ns();
  }
  /* 排空注入 pending：便宜（仅 32 槽），每次都做，兜底空闲期（无后续事件触发 evaluate）。
   * 注意：本函数写序列表（sweep + drain），须与 evaluate 同在预处理线程调用。 */
  corr_drain_injections(now_ns);
  /* 全表清扫较重（数千槽），内部节流到 ~30s 一次；可安全地被每次预处理循环调用。
   * 未到点也无妨：过期槽仍会在 corr_slot_acquire 命中时被惰性重置。 */
  now_ms = now_ns / 1000000LL;
  if (s_last_sweep_ms != 0 && now_ms - s_last_sweep_ms < CORR_SWEEP_INTERVAL_MS) {
    return;
  }
  s_last_sweep_ms = now_ms;
  (void)corr_sweep(s_threshold, CORR_THRESHOLD_SLOTS, now_ns);
  (void)corr_sweep(s_sequence, CORR_SEQUENCE_SLOTS, now_ns);
}

void edr_correlation_get_status(EdrCorrelationStatus *out) {
  uint32_t active;
  if (!out) {
    return;
  }
  memset(out, 0, sizeof(*out));
  out->enabled = edr_correlation_enabled();
  out->loaded = s_loaded;
  snprintf(out->bundle_version, sizeof(out->bundle_version), "%s", s_bundle_version);
  out->rule_count = s_rule_count;
  active = 0;
  for (uint32_t i = 0; i < CORR_THRESHOLD_SLOTS; i++) {
    if (s_threshold[i].used) {
      active++;
    }
  }
  for (uint32_t i = 0; i < CORR_SEQUENCE_SLOTS; i++) {
    if (s_sequence[i].used) {
      active++;
    }
  }
  out->active_states = active;
  out->observed = corr_load64(&s_stat_observed);
  out->evaluated = corr_load64(&s_stat_evaluated);
  out->fired = corr_load64(&s_stat_fired);
  out->suppressed = corr_load64(&s_stat_suppressed);
  out->evicted = corr_load64(&s_stat_evicted);
  out->inject_fed = corr_load64(&s_stat_inject_fed);
  out->inject_dropped = corr_load64(&s_stat_inject_dropped);
  out->rate_dropped = corr_load64(&s_stat_rate_dropped);
}

int edr_correlation_status_json(char *out, size_t cap) {
  EdrCorrelationStatus st;
  int n;
  if (!out || cap == 0u) {
    return 0;
  }
  edr_correlation_get_status(&st);
  n = snprintf(out, cap,
               "{\"enabled\":%d,\"loaded\":%d,\"bundle\":\"%s\",\"rules\":%u,"
               "\"active_states\":%u,\"observed\":%llu,\"evaluated\":%llu,"
               "\"fired\":%llu,\"suppressed\":%llu,\"evicted\":%llu,"
               "\"inject_fed\":%llu,\"inject_dropped\":%llu,\"rate_dropped\":%llu}",
               st.enabled, st.loaded, st.bundle_version, st.rule_count, st.active_states,
               (unsigned long long)st.observed, (unsigned long long)st.evaluated,
               (unsigned long long)st.fired, (unsigned long long)st.suppressed,
               (unsigned long long)st.evicted, (unsigned long long)st.inject_fed,
               (unsigned long long)st.inject_dropped, (unsigned long long)st.rate_dropped);
  if (n < 0 || (size_t)n >= cap) {
    out[0] = '\0';
    return 0;
  }
  return n;
}
