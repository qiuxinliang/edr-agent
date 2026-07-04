/* P0 #2/#3 单测：流级首段扫描去重 + TLS 记录短路判定。 */

#include "edr/flow_dedup.h"
#include "edr/proto_parse.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int fail(const char *m) {
  fprintf(stderr, "fail: %s\n", m);
  return 1;
}

int main(void) {
  /* --- flow key 方向无关 --- */
  EdrFlowKey a, b;
  edr_flow_key_make(&a, edr_flow_hash_str("10.0.0.1"), 12345, edr_flow_hash_str("10.0.0.2"), 445);
  edr_flow_key_make(&b, edr_flow_hash_str("10.0.0.2"), 445, edr_flow_hash_str("10.0.0.1"), 12345);
  if (a.ha != b.ha || a.hb != b.hb || a.pa != b.pa || a.pb != b.pb) {
    return fail("flow key must be direction-agnostic");
  }

  EdrFlowTable *t = edr_flow_table_create(256);
  if (!t) {
    return fail("table create");
  }
  uint64_t now = 1000000000ULL;

  /* --- 预算=0 → 始终深扫 --- */
  for (int i = 0; i < 5; i++) {
    if (edr_flow_table_admit(t, &a, 4096, 0u, now) != 1) {
      return fail("budget 0 must always scan");
    }
  }

  /* --- 预算 8000 字节、每段 4000：前两段扫，累计达上限后跳过 --- */
  EdrFlowKey f;
  edr_flow_key_make(&f, edr_flow_hash_str("1.1.1.1"), 5000, edr_flow_hash_str("2.2.2.2"), 3389);
  if (edr_flow_table_admit(t, &f, 4000, 8000u, now) != 1) {
    return fail("first segment should scan");
  }
  if (edr_flow_table_admit(t, &f, 4000, 8000u, now) != 1) {
    return fail("second segment (4000<8000) should scan");
  }
  if (edr_flow_table_admit(t, &f, 4000, 8000u, now) != 0) {
    return fail("third segment (8000>=8000) should skip");
  }
  if (edr_flow_table_admit(t, &f, 4000, 8000u, now) != 0) {
    return fail("subsequent segments stay skipped");
  }

  /* --- 不同连接互不影响 --- */
  EdrFlowKey g;
  edr_flow_key_make(&g, edr_flow_hash_str("1.1.1.1"), 5001, edr_flow_hash_str("2.2.2.2"), 3389);
  if (edr_flow_table_admit(t, &g, 4000, 8000u, now) != 1) {
    return fail("distinct flow must scan independently");
  }

  /* --- 陈旧槽位（>120s 未命中）可被复用并重置预算 --- */
  uint64_t later = now + 200ULL * 1000000000ULL;
  if (edr_flow_table_admit(t, &f, 4000, 8000u, later) != 1) {
    return fail("stale flow slot should reset and scan again");
  }

  edr_flow_table_destroy(t);

  /* NULL 表 → 不去重，始终扫 */
  if (edr_flow_table_admit(NULL, &a, 4096, 10000u, now) != 1) {
    return fail("null table must not dedup");
  }

  /* --- TLS 记录类型判定（P0 #3） --- */
  const uint8_t hs[] = {0x16, 0x03, 0x01, 0x00, 0x10};       /* handshake */
  const uint8_t appdata[] = {0x17, 0x03, 0x03, 0x01, 0x00};  /* application_data */
  const uint8_t alert[] = {0x15, 0x03, 0x03, 0x00, 0x02};    /* alert */
  const uint8_t notls[] = {0xFE, 'S', 'M', 'B', 0x00};       /* SMB2, not TLS */
  if (edr_proto_tls_record_type(hs, sizeof(hs)) != 22) {
    return fail("handshake record type");
  }
  if (edr_proto_tls_record_type(appdata, sizeof(appdata)) != 23) {
    return fail("appdata record type");
  }
  if (edr_proto_tls_record_type(alert, sizeof(alert)) != 21) {
    return fail("alert record type");
  }
  if (edr_proto_tls_record_type(notls, sizeof(notls)) != 0) {
    return fail("non-TLS must be 0");
  }
  if (edr_proto_tls_record_type(hs, 2) != 0) {
    return fail("too short must be 0");
  }

  /* --- P1 #4 令牌桶限速 --- */
  uint64_t t0 = 1000000000ULL;
  EdrTokenBucket tb;
  tb.tokens = 0.0;
  tb.last_ns = 0u;

  /* per_sec=0 → 不限 */
  for (int i = 0; i < 8; i++) {
    if (edr_token_bucket_admit(&tb, 0u, t0) != 1) {
      return fail("rate 0 must be unlimited");
    }
  }

  /* per_sec=5、同一时刻：满桶 5 个放行，第 6 个限速 */
  EdrTokenBucket tb2;
  tb2.tokens = 0.0;
  tb2.last_ns = 0u;
  int admitted = 0;
  for (int i = 0; i < 6; i++) {
    admitted += edr_token_bucket_admit(&tb2, 5u, t0);
  }
  if (admitted != 5) {
    return fail("burst should admit exactly cap=5");
  }
  if (edr_token_bucket_admit(&tb2, 5u, t0) != 0) {
    return fail("over-budget must be limited");
  }

  /* 过 1 秒补满 → 再次放行 */
  if (edr_token_bucket_admit(&tb2, 5u, t0 + 1000000000ULL) != 1) {
    return fail("refill after 1s should admit");
  }

  /* 部分补充：0.4s @5/s = +2 令牌 */
  EdrTokenBucket tb3;
  tb3.tokens = 0.0;
  tb3.last_ns = 0u;
  (void)edr_token_bucket_admit(&tb3, 5u, t0); /* 初始化满桶并消费1 → 4 */
  for (int i = 0; i < 4; i++) {
    (void)edr_token_bucket_admit(&tb3, 5u, t0); /* 耗尽 → 0 */
  }
  if (edr_token_bucket_admit(&tb3, 5u, t0) != 0) {
    return fail("tb3 should be drained");
  }
  int got = 0;
  for (int i = 0; i < 5; i++) {
    got += edr_token_bucket_admit(&tb3, 5u, t0 + 400000000ULL); /* +2 令牌 */
  }
  if (got != 2) {
    return fail("partial refill 0.4s@5/s should yield 2 tokens");
  }

  /* NULL 桶 → 始终放行 */
  if (edr_token_bucket_admit(NULL, 5u, t0) != 1) {
    return fail("null bucket must admit");
  }

  /* --- 自流量排除：URL 主机抽取（用于 WinDivert not 子句） --- */
  char h[256];
  if (edr_url_extract_host("https://platform.example.com:443/api/v1", h, sizeof(h)) != 0 ||
      strcmp(h, "platform.example.com") != 0) {
    return fail("https host:port/path");
  }
  if (edr_url_extract_host("http://10.0.0.5:8080/api", h, sizeof(h)) != 0 || strcmp(h, "10.0.0.5") != 0) {
    return fail("ipv4 with port/path");
  }
  if (edr_url_extract_host("https://[2001:db8::1]:8443/x", h, sizeof(h)) != 0 || strcmp(h, "2001:db8::1") != 0) {
    return fail("ipv6 literal");
  }
  if (edr_url_extract_host("https://user:pw@host.local/p", h, sizeof(h)) != 0 || strcmp(h, "host.local") != 0) {
    return fail("userinfo stripped");
  }
  if (edr_url_extract_host("relay.corp", h, sizeof(h)) != 0 || strcmp(h, "relay.corp") != 0) {
    return fail("bare host no scheme");
  }
  if (edr_url_extract_host("", h, sizeof(h)) == 0) {
    return fail("empty url must fail");
  }

  printf("ok: flow dedup + tls short-circuit + token bucket + url host extract\n");
  return 0;
}
