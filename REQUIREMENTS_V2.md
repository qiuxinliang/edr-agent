# EDR Agent 客户端需求 V2.0

> 版本：v2.0 | 更新日期：2026-05-19 | 状态：进行中

---

## 一、需求总览

### 1.1 核心目标
完成 Windows agent CI 生产构建通过，消除编译/链接问题，补全 stub 实现，优化传输层架构。

### 1.2 技术架构

| 技术栈 | 版本 | 说明 |
|---|---|---|
| C + C++20 | — | 编译语言 |
| CMake | 3.20+ | 构建系统 |
| vcpkg | manifest 模式 | 包管理 |
| curl | 8.x (vcpkg) | HTTP 传输 |
| SQLite3 | — | 事件队列 |
| cJSON | — | JSON 解析 |
| PCRE2 | — | 正则引擎 |
| OpenSSL | 3.x | SHA256 哈希 |
| zstd / lz4 | — | 压缩 |
| protobuf (可选) | — | gRPC codegen |
| Ninja | — | 构建后端 |

### 1.3 条件编译宏

| 宏 | 默认值 | 说明 |
|---|---|---|
| `EDR_HAVE_LIBCURL` | ON | curl HTTP |
| `EDR_HAVE_SQLITE` | ON | SQLite |
| `EDR_HAVE_PCRE2` | ON | 正则 |
| `EDR_HAVE_ZSTD` | ON | 压缩 |
| `EDR_HAVE_LZ4` | OFF | 备用压缩 |
| `EDR_HAVE_KAFKA` | OFF | Kafka |
| `EDR_WITH_P0_IR` | ON | P0 规则 |
| `EDR_WITH_GRPC` | OFF | gRPC |
| `EDR_WITH_DEEP_COLLECTOR` | ON | 深度取证 |
| `EDR_WITH_ETW_OBSERVABILITY` | ON (Win) | ETW |
| `EDR_WITH_PROCESS_TREE_CACHE` | ON | 进程树 |
| `EDR_WITH_SHELL_SESSION` | ON | Shell 会话 |

---

## 二、功能需求

### [P0] C-01：CI 生产构建通过

#### 2.1.1 背景
客户端 CI（`edr-agent-client-build.yml`）需要为 Windows 平台完成从 vcpkg 安装依赖到编译链接到生成最终 exe 的完整流程。

#### 2.1.2 CI 工作流文件

| 文件 | 说明 |
|---|---|
| [edr-agent-client-build.yml](file:///Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/.github/workflows/edr-agent-client-build.yml) | 客户端 CI |

#### 2.1.3 已修复问题

| 问题 | 状态 |
|---|---|
| vcpkg.json 缺失 → 添加 cjson/curl/protobuf 依赖 | ✅ |
| cJSON.h not found → third_party/cjson 无条件编译 | ✅ |
| agent.c L191-205 代码损坏 → 还原 | ✅ |
| agent.c edr_agent_destroy 截断 → 恢复清理代码 | ✅ |
| behavior_from_slot 参数不匹配 → 头文件补齐 | ✅ |
| p0_rule_ir_stub 缺少 2 个 stub | ✅ |
| queue_sqlite.c 误放代码 → 删除 trim_queue_if_full | ✅ |
| transport_stub.c 类型截断 → size_t 统一 | ✅ |
| response_utils.h 缺失 → 创建头文件 | ✅ |
| IngestHandler 未注入 RealtimeHub → 后端修复 | ✅ |

#### 2.1.4 待检查

| 检查项 | 状态 |
|---|---|
| OpenSSL 3.0 SHA256 弃用警告 (C4996) | ⚠️ 低优先级 |
| 最终链接是否完全通过 | 🔴 待 CI 运行确认 |

---

### [P0] C-02：传输层架构优化（已完成）

#### 2.2.1 重构内容
将 15 个静态全局变量收拢为 `EdrTransportCtx` 单例结构体。

#### 2.2.2 变更清单

| 文件 | 变更 |
|---|---|
| [transport_stub.c](file:///Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/src/transport/transport_stub.c) | 重建为 EdrTransportCtx 单例 + 工作线程队列 |
| [transport_sink.h](file:///Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/include/edr/transport_sink.h) | 添加 EdrTransportDispatchFn + inject_dispatch + ctx_get |
| [ingest_http.c](file:///Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/src/transport/ingest_http.c) | 添加 edr_ingest_http_shutdown 函数体 |
| [ingest_http.h](file:///Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/include/edr/ingest_http.h) | 添加 edr_ingest_http_shutdown 声明 |
| [main.c](file:///Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/src/main.c) | wire_bytes/batch_bytes 格式串 %lu→%zu |

#### 2.2.3 核心结构

```c
typedef struct EdrTransportCtx {
  char target[256];
  EdrTransportDispatchFn dispatch;
  void *dispatch_ud;
  unsigned long wire_events;
  size_t wire_bytes;
  unsigned long batch_count;
  size_t batch_bytes;
  unsigned long batch_lz4;
  EdrSendJob *q_head, *q_tail;
  size_t q_len, q_cap;
  int q_started;
  volatile int q_run;
} EdrTransportCtx;

static EdrTransportCtx g_ctx;
```

---

### [P1] C-03：OpenSSL 3.0 SHA256 弃用警告修复

#### 2.3.1 现状
[agent_update.c](file:///Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/src/core/agent_update.c) L201-205 使用 `SHA256_Init`/`SHA256_Update`/`SHA256_Final`，OpenSSL 3.0 已弃用。

#### 2.3.2 修复方案

```c
// 当前代码（C4996 警告）：
#include <openssl/sha.h>
SHA256_Init(&ctx);
SHA256_Update(&ctx, data, len);
SHA256_Final(hash, &ctx);

// 修复后（使用 EVP API）：
#include <openssl/evp.h>
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
EVP_DigestUpdate(ctx, data, len);
unsigned int hash_len;
EVP_DigestFinal_ex(ctx, hash, &hash_len);
EVP_MD_CTX_free(ctx);
```

#### 2.3.3 条件编译（兼容旧版 OpenSSL）

```c
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  // EVP API
#else
  // 旧 SHA256_Init API
#endif
```

#### 2.3.4 文件清单

| 文件 | 变更 |
|---|---|
| `src/core/agent_update.c` | 替换 SHA256 API → EVP API |

---

### [P1] C-04：stub 模块完善

#### 2.4.1 现状

| 模块 | 类型 | 当前状态 |
|---|---|---|
| webshell_detector | none | 空返回 |
| shellcode_detector | none | 空返回 |
| gRPC 客户端 | stub | 占位 |
| AVE 签名白名单 | stub | 非 Windows 占位 |
| PMFE 主机策略 | stub | 非 Windows 占位 |

#### 2.4.2 完善计划

| 模块 | 优先级 | 计划 |
|---|---|---|
| webshell_detector (Linux) | P2 | 实现基础 webshell 检测 |
| shellcode_detector (Linux) | P2 | 实现基础 shellcode 检测 |
| gRPC 客户端 | P2 | 如有需求再实现 |
| AVE 签名白名单 (Linux) | P2 | 补充 Linux 文件路径校验 |

---

### [P2] C-05：进程树缓存增强

#### 2.5.1 现状
`edr_pt_cache_infer_parent` 目前为 stub（返回 -1），[process_tree_cache.c](file:///Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/src/forensic/process_tree_cache.c) 需要实现。

#### 2.5.2 需求

```c
int edr_pt_cache_infer_parent(uint32_t pid, uint64_t event_time_ns,
                               uint32_t *out_ppid, char *out_parent_name,
                               size_t name_cap);
```

实现逻辑：
1. 在进程树缓存中查找 pid 的父进程
2. 如果缓存中没有，尝试从系统 /proc (Linux) 或 Toolhelp (Windows) 查询
3. 更新缓存
4. 返回 ppid 和 parent_name

---

## 三、模块完整文件清单

### 3.1 core/ 模块

| 文件 | 说明 | 状态 |
|---|---|---|
| `src/core/agent.c` | 主循环、配置、生命周期 | ✅ 完整（近期修复多次） |
| `src/core/agent_update.c` | 远程更新、SHA256 校验 | ✅ 完整（C4996 待修复） |
| `src/core/agent_remote_fetch.c` | 远程 TOML 拉取 | ✅ 完整 |
| `src/core/agent_oobe.c` | 首次启动配置 | ✅ 完整 |
| `src/core/agent_tasks.c` | 定时任务管理 | ✅ 完整 |

### 3.2 collector/ 模块

| 文件 | 说明 | 状态 |
|---|---|---|
| `src/collector/collector_win.c` | Windows ETW/Procmon 采集 | ✅ 完整 |
| `src/collector/collector_stub.c` | 非 Windows 占位 | ✅ 完整 |
| `src/collector/collector.h` | 接口定义 | ✅ 完整 |

### 3.3 preprocess/ 模块

| 文件 | 说明 | 状态 |
|---|---|---|
| `src/preprocess/preprocess_pipeline.c` | 分析流水线 | ✅ 完整 |
| `src/preprocess/p0_rule_match.c` | P0 规则匹配 | ✅ 完整 |
| `src/preprocess/p0_rule_ir.c` | P0 规则 IR 引擎 | ✅ 完整 |
| `src/preprocess/p0_rule_ir_stub.c` | P0 IR stub（无 PCRE2） | ✅ 完整（近期修复） |
| `src/preprocess/behavior_record.c` | 行为记录 | ✅ 完整 |
| `src/preprocess/behavior_from_slot.c` | 行为槽分析 | ✅ 完整（近期修复） |
| `src/preprocess/behavior_from_slot.h` | 行为槽头文件 | ✅ 完整（近期修复） |
| `src/preprocess/process_chain_depth.c` | 进程链深度 | ✅ 完整 |

### 3.4 transport/ 模块

| 文件 | 说明 | 状态 |
|---|---|---|
| `src/transport/ingest_http.c` | HTTP ingest  | ✅ 完整（近期修复） |
| `src/transport/transport_stub.c` | 传输层 stub（EdrTransportCtx） | ✅ 完整（近期重建） |
| `src/transport/grpc_client_stub.c` | gRPC 客户端 stub | ✅ 完整 |

### 3.5 storage/ 模块

| 文件 | 说明 | 状态 |
|---|---|---|
| `src/storage/queue_sqlite.c` | SQLite 事件队列 | ✅ 完整（近期修复） |
| `src/storage/queue_ringbuf.c` | 环形缓冲区队列 | ✅ 完整 |

### 3.6 command/ 模块

| 文件 | 说明 | 状态 |
|---|---|---|
| `src/command/registry.c` | 注册表操作 | ✅ 完整 |
| `src/command/eventlog.c` | 事件日志 | ✅ 完整 |
| `src/command/rtq_exec.c` | 实时查询执行 | ✅ 完整 |
| `src/command/command_util.c` | 命令工具 | ✅ 完整 |
| `src/command/shell_session.c` | Shell 会话 | ✅ 完整 |

### 3.7 forensic/ 模块

| 文件 | 说明 | 状态 |
|---|---|---|
| `src/forensic/deep_collector.c` | 深度取证采集 | ✅ 完整 |
| `src/forensic/process_tree_cache.c` | 进程树缓存 | ⚠️ infer_parent 为 stub |

### 3.8 config/ 模块

| 文件 | 说明 | 状态 |
|---|---|---|
| `src/config/config.c` | TOML 配置解析 | ✅ 完整 |
| `src/config/remote_fetch.c` | 远程配置拉取 | ✅ 完整 |

### 3.9 头文件清单

| 头文件 | 说明 |
|---|---|
| `include/edr/agent.h` | Agent 主接口 |
| `include/edr/transport_sink.h` | 传输层接口 |
| `include/edr/ingest_http.h` | HTTP ingest 接口 |
| `include/edr/p0_rule_ir.h` | P0 规则 IR 接口 |
| `include/edr/behavior_from_slot.h` | 行为槽接口 |
| `include/edr/process_tree_cache.h` | 进程树缓存接口 |
| `include/edr/collector.h` | 采集器接口 |
| `include/edr/response.h` | 响应命令接口 |
| `include/edr/response_utils.h` | 响应工具接口（近期新增） |
| `include/edr/shell_session.h` | Shell 会话接口 |
| `include/edr/self_protect.h` | 自保护接口 |
| `include/edr/command_util.h` | 命令工具接口 |
| `include/edr/shell_exec.h` | Shell 执行接口 |

---

## 四、构建配置

### 4.1 vcpkg.json

```json
{
  "name": "edr-agent",
  "version-string": "1.0.0",
  "dependencies": ["cjson", "curl"],
  "features": {
    "grpc-client": {
      "description": "gRPC client support",
      "dependencies": ["protobuf"]
    }
  }
}
```

### 4.2 CMakeLists.txt 关键配置

| 配置 | 值 | 说明 |
|---|---|---|
| CMAKE_C_STANDARD | 11 | C 语言标准 |
| CMAKE_CXX_STANDARD | 20 | C++ 语言标准 |
| MSVC /W4 | ⚠️ 含 C4267/C4057 警告 | 严格警告级别 |
| EDR_AGENT_SOURCES | ~60 个源文件 | 全部源文件 |
| EDR_AGENT_TEST_SOURCES | ~10 个测试文件 | 测试源文件 |

---

## 五、开发顺序

### 第 1 阶段（P0）
1. ✅ agent.c 代码损坏修复（已完成）
2. ✅ 头文件条件编译修复（已完成）
3. ✅ stub 补齐（已完成）
4. ✅ vcpkg.json 配置（已完成）
5. CI 生产构建验证（待 CI 运行）

### 第 2 阶段（P1）
6. OpenSSL 3.0 SHA256 EVP API 迁移
7. 全面警告清零（/W4 级别）

### 第 3 阶段（P2）
8. webshell_detector / shellcode_detector Linux 实现
9. `edr_pt_cache_infer_parent` 完整实现
10. gRPC 传输实现（按需）
