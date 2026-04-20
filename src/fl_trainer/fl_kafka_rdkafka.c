#include "fl_kafka_internal.h"

#include <librdkafka/rdkafka.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#ifndef FL_KAFKA_MSG_CAP
#define FL_KAFKA_MSG_CAP (256u * 1024u)
#endif

static rd_kafka_t *s_rk;
static int s_disabled;

static const char *fl_kafka_getenv(const char *k, const char *def) {
  const char *v = getenv(k);
  if (!v || !v[0]) {
    return def;
  }
  return v;
}

static int json_skip_ws(const char **pp) {
  const char *p = *pp;
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
    p++;
  }
  *pp = p;
  return 0;
}

static int json_get_u64(const char *json, const char *key, uint64_t *out) {
  char pat[48];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) {
    return -1;
  }
  p = strchr(p + strlen(pat), ':');
  if (!p) {
    return -1;
  }
  p++;
  json_skip_ws(&p);
  char *end = NULL;
  unsigned long long v = strtoull(p, &end, 10);
  if (!end || end == p) {
    return -1;
  }
  *out = (uint64_t)v;
  return 0;
}

static int json_get_string(const char *json, const char *key, char *out, size_t outsz) {
  char pat[48];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) {
    return -1;
  }
  p = strchr(p + strlen(pat), ':');
  if (!p) {
    return -1;
  }
  p++;
  json_skip_ws(&p);
  if (*p != '"') {
    return -1;
  }
  p++;
  size_t i = 0;
  while (*p && *p != '"' && i + 1u < outsz) {
    out[i++] = (char)*p++;
  }
  out[i] = '\0';
  return 0;
}

static int json_get_i64_optional(const char *json, const char *key, uint64_t *out, int *present) {
  char pat[48];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) {
    *present = 0;
    return 0;
  }
  p = strchr(p + strlen(pat), ':');
  if (!p) {
    *present = 0;
    return -1;
  }
  p++;
  json_skip_ws(&p);
  if (strncmp(p, "null", 4) == 0) {
    *present = 0;
    return 0;
  }
  char *end = NULL;
  long long v = strtoll(p, &end, 10);
  if (!end || end == p) {
    *present = 0;
    return -1;
  }
  *present = 1;
  *out = (uint64_t)(v < 0 ? 0 : v);
  return 0;
}

static int parse_round_announce_v1(const char *json, FLRoundInfoKafka *out) {
  memset(out, 0, sizeof(*out));
  uint64_t ver = 0;
  if (json_get_u64(json, "v", &ver) == 0 && ver != 0u && ver != 1u) {
    return -1;
  }
  if (json_get_u64(json, "round_id", &out->round_id) != 0 || out->round_id == 0u) {
    return -1;
  }
  (void)json_get_string(json, "model_target", out->model_target, sizeof(out->model_target));
  {
    uint64_t d = 0;
    int have_d = 0;
    if (json_get_i64_optional(json, "deadline_ts_unix", &d, &have_d) == 0 && have_d) {
      out->deadline_unix_s = d;
    }
  }
  return 0;
}

static int tenant_matches(const char *json) {
  const char *want = getenv("EDR_FL_KAFKA_TENANT");
  if (!want || !want[0]) {
    return 1;
  }
  char got[128];
  if (json_get_string(json, "tenant_id", got, sizeof(got)) != 0) {
    return 0;
  }
  return strcmp(got, want) == 0;
}

static void ensure_consumer(void) {
  if (s_rk || s_disabled) {
    return;
  }
  const char *brokers = getenv("EDR_FL_KAFKA_BROKERS");
  if (!brokers || !brokers[0]) {
    s_disabled = 1;
    return;
  }
  char err[512];
  rd_kafka_conf_t *conf = rd_kafka_conf_new();
  if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers, err, sizeof(err)) != RD_KAFKA_CONF_OK) {
    rd_kafka_conf_destroy(conf);
    s_disabled = 1;
    return;
  }
  const char *group = fl_kafka_getenv("EDR_FL_KAFKA_GROUP", "edr-agent-fl");
  if (rd_kafka_conf_set(conf, "group.id", group, err, sizeof(err)) != RD_KAFKA_CONF_OK) {
    rd_kafka_conf_destroy(conf);
    s_disabled = 1;
    return;
  }
  if (rd_kafka_conf_set(conf, "enable.auto.commit", "true", err, sizeof(err)) != RD_KAFKA_CONF_OK) {
    rd_kafka_conf_destroy(conf);
    s_disabled = 1;
    return;
  }
  if (rd_kafka_conf_set(conf, "auto.offset.reset", "latest", err, sizeof(err)) != RD_KAFKA_CONF_OK) {
    rd_kafka_conf_destroy(conf);
    s_disabled = 1;
    return;
  }
  rd_kafka_t *rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, err, sizeof(err));
  if (!rk) {
    rd_kafka_conf_destroy(conf);
    s_disabled = 1;
    return;
  }
  rd_kafka_poll_set_consumer(rk);
  const char *topic = fl_kafka_getenv("EDR_FL_KAFKA_ROUND_TOPIC", "edr.fl_round_announce");
  rd_kafka_topic_partition_list_t *tpl = rd_kafka_topic_partition_list_new(1);
  rd_kafka_topic_partition_list_add(tpl, topic, RD_KAFKA_PARTITION_UA);
  if (rd_kafka_subscribe(rk, tpl) != 0) {
    rd_kafka_topic_partition_list_destroy(tpl);
    rd_kafka_destroy(rk);
    s_disabled = 1;
    return;
  }
  rd_kafka_topic_partition_list_destroy(tpl);
  s_rk = rk;
}

int fl_kafka_poll_round_stub(void) {
  ensure_consumer();
  if (!s_rk) {
    return 0;
  }
  rd_kafka_message_t *msg = rd_kafka_consumer_poll(s_rk, 0);
  if (!msg) {
    return 0;
  }
  if (msg->err) {
    if (msg->err != RD_KAFKA_RESP_ERR__PARTITION_EOF) {
      /* ignore transient errors */
    }
    rd_kafka_message_destroy(msg);
    return 0;
  }
  if (!msg->payload || msg->len == 0) {
    rd_kafka_message_destroy(msg);
    return 0;
  }
  size_t n = msg->len;
  if (n > FL_KAFKA_MSG_CAP) {
    n = FL_KAFKA_MSG_CAP;
  }
  char *buf = (char *)malloc(n + 1u);
  if (!buf) {
    rd_kafka_message_destroy(msg);
    return 0;
  }
  memcpy(buf, msg->payload, n);
  buf[n] = '\0';
  rd_kafka_message_destroy(msg);

  FLRoundInfoKafka info;
  if (parse_round_announce_v1(buf, &info) != 0) {
    free(buf);
    return 0;
  }
  if (!tenant_matches(buf)) {
    free(buf);
    return 0;
  }
  free(buf);
  fl_kafka_dispatch_round(&info);
  return 1;
}

void fl_kafka_round_consumer_shutdown(void) {
  if (s_rk) {
    rd_kafka_consumer_close(s_rk);
    rd_kafka_destroy(s_rk);
    s_rk = NULL;
  }
  s_disabled = 0;
}
