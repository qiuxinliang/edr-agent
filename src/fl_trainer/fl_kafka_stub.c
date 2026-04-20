#include "edr/fl_kafka_stub.h"

static FLKafkaRoundCallback s_cb;
static void *s_user;

int fl_kafka_register_round_consumer(FLKafkaRoundCallback cb, void *user) {
  s_cb = cb;
  s_user = user;
  return 0;
}

void fl_kafka_dispatch_round(const FLRoundInfoKafka *info) {
  if (s_cb && info) {
    s_cb(info, s_user);
  }
}
