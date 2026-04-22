/**
 * C2：Kafka Round 广播占位。生产环境接入 librdkafka 或等价实现后替换本文件中的空实现。
 */
#ifndef EDR_FL_KAFKA_STUB_H
#define EDR_FL_KAFKA_STUB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FLRoundInfoKafka {
  uint64_t round_id;
  uint64_t deadline_unix_s;
  char model_target[32];
} FLRoundInfoKafka;

typedef void (*FLKafkaRoundCallback)(const FLRoundInfoKafka *info, void *user);

/** 注册 Round 公告消费者回调（Kafka 关闭或未编译 librdkafka 时仍可注册，由轮询侧 no-op） */
int fl_kafka_register_round_consumer(FLKafkaRoundCallback cb, void *user);

/**
 * 轮询 Kafka 并投递一条 Round（若有）。未设置 `EDR_FL_KAFKA_BROKERS` 或未启用 librdkafka 时返回 0。
 * 返回值：1 表示处理了一条消息，0 表示无消息或跳过。
 */
int fl_kafka_poll_round_stub(void);

/** 释放 consumer（在 `fl_round_shutdown` 中调用） */
void fl_kafka_round_consumer_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif
