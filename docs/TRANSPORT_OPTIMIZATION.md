# 传输模块优化建议

**版本**：1.0
**日期**：2026-04-28
**状态**：已完成

---

## 1. 概述

本文档记录传输模块的优化建议，包括批量压缩和连接复用。

---

## 2. 当前实现分析

### 2.1 event_batch.c

**现有功能**：
- LZ4压缩支持（`EDR_HAVE_LZ4`）
- 批量超时刷新（`s_flush_timeout_s`）
- 持久化队列支持

**关键配置**：
```c
static int s_flush_timeout_s;       // 刷新超时（秒）
static size_t s_used;               // 已用缓冲区大小
static uint32_t s_frame_count;      // 帧计数
static uint64_t s_batch_seq;       // 批次序列号
```

### 2.2 ingest_http.c

**现有功能**：
- HTTP POST请求
- Protobuf编码
- 重试机制（stub中）

**缺失功能**：
- ❌ HTTP Keep-Alive连接复用
- ❌ 连接池
- ❌ 请求并发控制

---

## 3. 优化建议

### 3.1 批量压缩优化

#### 当前问题

```c
// event_batch.c
#ifndef EDR_LZ4_MIN_IN
#define EDR_LZ4_MIN_IN 1024u  // 只有>1KB的数据才压缩
#endif
```

**问题**：
- 小批量数据不压缩，传输效率低
- 没有根据网络状况动态调整压缩级别

#### 优化方案

```c
// 环境变量控制
EDR_LZ4_MIN_IN=512           // 压缩阈值（字节）
EDR_LZ4_COMPRESSION_LEVEL=6  // 压缩级别（1-12）
EDR_BATCH_COMPRESS_MIN_SIZE=256  // 最小压缩大小
```

```c
static int lz4_compress_batch(const uint8_t *in, size_t in_len,
                               uint8_t *out, size_t *out_len,
                               int level) {
    int compressed = LZ4_compress_fast((const char *)in, (char *)out,
                                       (int)in_len, (int)*out_len, level);
    if (compressed > 0 && (size_t)compressed < in_len) {
        *out_len = (size_t)compressed;
        return 1;
    }
    return 0;
}
```

### 3.2 连接复用优化

#### 当前问题

每次HTTP请求都创建新连接，TCP握手开销大。

#### 优化方案

```c
// 新增 HTTP 连接池
typedef struct {
    char host[256];
    int port;
    int sockfd;
    uint64_t last_used_ns;
    int in_use;
} HttpConnection;

#define MAX_POOL_SIZE 8

static HttpConnection s_conn_pool[MAX_POOL_SIZE];

static int get_connection_from_pool(const char *host, int port) {
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        if (s_conn_pool[i].in_use) continue;
        if (strcmp(s_conn_pool[i].host, host) == 0 && s_conn_pool[i].port == port) {
            uint64_t now = edr_monotonic_ns();
            if (now - s_conn_pool[i].last_used_ns < 60000000000ULL) { // 60秒
                s_conn_pool[i].in_use = 1;
                return s_conn_pool[i].sockfd;
            }
        }
    }
    return -1;
}
```

#### HTTP Keep-Alive 头

```c
static int http_post_with_keepalive(int sockfd, const char *host, int port,
                                     const uint8_t *data, size_t len) {
    char header[1024];
    int header_len = snprintf(header, sizeof(header),
        "POST /ingest HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        host, port, len);

    if (send(sockfd, header, header_len, 0) != header_len) {
        return -1;
    }
    if (send(sockfd, (const char *)data, len, 0) != (ssize_t)len) {
        return -1;
    }
    return 0;
}
```

### 3.3 并发请求控制

```c
// 信号量控制并发
#include <semaphore.h>
static sem_t s_http_sem;
static int s_max_concurrent = 4;

void ingest_http_init(void) {
    int max_concurrent = getenv_int_default("EDR_HTTP_MAX_CONCURRENT", 4);
    sem_init(&s_http_sem, 0, max_concurrent);
    s_max_concurrent = max_concurrent;
}

int ingest_http_post(const char *url, const uint8_t *data, size_t len) {
    sem_wait(&s_http_sem);
    int ret = http_post_internal(url, data, len);
    sem_post(&s_http_sem);
    return ret;
}
```

---

## 4. 配置参数

### 4.1 批量压缩配置

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `EDR_LZ4_MIN_IN` | 1024 | 压缩阈值（字节） |
| `EDR_LZ4_COMPRESSION_LEVEL` | 6 | 压缩级别（1-12） |
| `EDR_BATCH_COMPRESS_MIN_SIZE` | 256 | 最小压缩大小 |
| `EDR_BATCH_FLUSH_TIMEOUT_S` | 5 | 批量刷新超时（秒） |

### 4.2 连接复用配置

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `EDR_HTTP_KEEPALIVE` | 1 | 启用Keep-Alive（0=禁用） |
| `EDR_HTTP_CONN_POOL_SIZE` | 4 | 连接池大小 |
| `EDR_HTTP_CONN_TIMEOUT_S` | 60 | 连接超时（秒） |
| `EDR_HTTP_MAX_CONCURRENT` | 4 | 最大并发请求数 |

---

## 5. 预期效果

| 优化项 | 预期改善 |
|--------|----------|
| LZ4压缩级别优化 | 压缩率提升20-30% |
| 连接复用 | HTTP请求延迟降低50ms |
| 并发控制 | 避免连接耗尽 |

---

## 6. 实施建议

### 6.1 低优先级实施（立即可做）

1. 添加 `EDR_LZ4_COMPRESSION_LEVEL` 环境变量
2. 降低 `EDR_LZ4_MIN_IN` 阈值到512

### 6.2 中优先级实施

1. 实现HTTP Keep-Alive连接复用
2. 添加连接池

### 6.3 高优先级实施

1. 添加并发请求控制
2. 添加连接池大小自动调整

---

*文档生成时间：2026-04-28*