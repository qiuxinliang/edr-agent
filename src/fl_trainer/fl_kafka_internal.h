#ifndef FL_KAFKA_INTERNAL_H
#define FL_KAFKA_INTERNAL_H

#include "edr/fl_kafka_stub.h"

/** 由 `fl_kafka_rdkafka.c` 在解析消息后调用已注册的 `FLKafkaRoundCallback`。 */
void fl_kafka_dispatch_round(const FLRoundInfoKafka *info);

#endif
