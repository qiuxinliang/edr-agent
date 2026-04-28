# ONNX 模型性能优化分析与建议

## 概述
本文档详细分析了 EDR Agent 中 ONNX 推理模块的数据流、性能瓶颈，并提供具体的优化建议。主要关注 `static.onnx`（静态文件检测）和 `behavior.onnx`（动态行为分析）两个模型。

---

## 1. static.onnx 数据流分析

### 1.1 完整推理流程
```
edr_ave_infer_file()
  ├─> edr_onnx_runtime_ready()  // 检查模型是否已加载
  └─> edr_onnx_infer_file()
        ├─> 分配输入缓冲区 (g_in_nelem * sizeof(float))
        ├─> 特征提取分支：
        │     ├─> Lite512 (默认，n==512)
        │     │     └─> edr_ave_static_features_lite_512()
        │     │           ├─> 读取文件 (最多 4MB)
        │     │           ├─> 计算字节直方图 (256维)
        │     │           ├─> 计算分块香农熵 (256维)
        │     │           └─> L2 归一化
        │     └─> Legacy (n!=512)
        │           └─> fill_input_from_file()
        │                 ├─> 读取文件原始字节
        │                 └─> 归一化 (byte / 255.0)
        ├─> CreateTensorWithDataAsOrtValue()  // 创建 ONNX Runtime 张量
        ├─> OrtRun()  // 模型推理
        │     ├─> Triple输出 (verdict+family+packer)
        │     └─> Single输出 (兼容旧版本)
        └─> 解析输出，释放资源
```

### 1.2 关键性能瓶颈点

| 瓶颈点 | 位置 | 说明 | 影响 |
|--------|------|------|------|
| **文件 I/O** | `ave_static_features.c:77` / `ave_onnx_infer.c:835` | 每次推理都要读取完整文件 | 大文件(>4MB)显著拖慢速度 |
| **内存分配** | `ave_onnx_infer.c:895` | 每次推理都重新分配输入缓冲区 | 小开销但频繁 |
| **特征计算** | `ave_static_features.c:86-110` | 字节直方图 + 香农熵计算 | 中等开销 |
| **ORT张量创建** | `ave_onnx_infer.c:919` | 每次都创建新张量对象 | 中等开销 |
| **模型推理** | `ave_onnx_infer.c:934/962` | 实际神经网络计算 | 核心开销，取决于模型大小 |

### 1.3 代码细节分析

#### 1.3.1 Lite512 特征提取 (`ave_static_features.c:61-114`)
```c
int edr_ave_static_features_lite_512(const char *path, float *out512) {
  size_t cap = env_read_max();  // 默认 4MB
  uint8_t *buf = (uint8_t *)malloc(cap);  // 每次都分配
  FILE *f = fopen(path, "rb");
  size_t n = fread(buf, 1u, cap, f);
  
  // 字节直方图 (256维)
  unsigned long long hist[256];
  for (size_t i = 0; i < n; i++) {
    hist[buf[i]]++;
  }
  
  // 分块香农熵 (256块)
  const size_t nseg = 256u;
  size_t seglen = n / nseg;
  for (size_t s = 0; s < nseg; s++) {
    out512[256 + (int)s] = shannon_entropy(buf + off, slen);
  }
  
  l2_normalize_512(out512);
}
```

#### 1.3.2 推理调用 (`ave_onnx_infer.c:887-1007`)
```c
EdrError edr_onnx_infer_file(...) {
  float *buf = (float *)calloc((size_t)n, sizeof(float));  // 每次都分配
  
  // 特征提取...
  
  OrtValue *in_val = NULL;
  OrtStatus *st = g_ort->CreateTensorWithDataAsOrtValue(...);  // 每次都创建
  
  // 推理...
  
  g_ort->ReleaseValue(in_val);  // 释放
  free(buf);  // 释放
}
```

---

## 2. behavior.onnx 数据流分析

### 2.1 完整推理流程
```
process_one_event()  // 每次行为事件触发
  └─> 达到推理阈值时 (每8/16个事件或立即触发)
        └─> edr_onnx_behavior_infer()
              ├─> 分配输入缓冲区 (g_beh_in_nelem * sizeof(float))
              ├─> 拷贝特征数据
              ├─> CreateTensorWithDataAsOrtValue()
              ├─> OrtRun()  // 行为模型推理
              └─> 解析输出，释放资源
```

### 2.2 关键性能瓶颈点
| 瓶颈点 | 位置 | 说明 | 影响 |
|--------|------|------|------|
| **频繁推理** | `ave_behavior_pipeline.c:691-732` | 每8/16个事件触发一次推理 | 高频调用 |
| **内存分配** | `ave_onnx_infer.c:1052` | 每次推理都分配缓冲区 | 频繁小开销 |
| **张量创建** | `ave_onnx_infer.c:1058` | 每次都创建新张量 | 中等开销 |

---

## 3. 性能优化建议

### 3.1 高优先级优化（立即可实施）

#### 3.1.1 输入/输出张量池化 (static.onnx + behavior.onnx)
**问题**：每次推理都重新分配内存和创建 ONNX Runtime 张量，产生频繁的内存分配/释放开销。

**解决方案**：实现一个简单的张量池，复用已分配的资源。

```c
// 在 ave_onnx_infer.c 中添加
static struct {
  float *input_buf;
  OrtValue *in_tensor;
  int in_use;
  OrtMemoryInfo *mem_info;
} s_static_pool;

// 初始化时预先分配
static void ensure_static_pool(void) {
  if (!s_static_pool.input_buf && g_in_nelem > 0) {
    s_static_pool.input_buf = (float *)malloc((size_t)g_in_nelem * sizeof(float));
    // 同时可以预创建OrtValue（但需要注意数据绑定）
  }
}

// 使用时从池获取
EdrError edr_onnx_infer_file(...) {
  // 检查并确保池已初始化
  ensure_static_pool();
  float *buf = s_static_pool.input_buf;  // 复用，不分配
  memset(buf, 0, (size_t)g_in_nelem * sizeof(float));
  
  // ... 特征提取 ...
  
  // OrtValue 也可以复用（需要使用 OrtValue 重绑定机制）
}
```

**预期收益**：减少 10-20% 的单次推理开销。

---

#### 3.1.2 文件读取缓存与增量处理 (static.onnx)
**问题**：每次推理都要重新读取整个文件，对于大文件（如 4MB）这个开销显著。

**解决方案**：
1. 对于 <1MB 的小文件，直接全读；
2. 对于 >1MB 的文件，使用 mmap 映射或仅读取文件首尾各 2MB（恶意特征通常集中在头部/尾部）；
3. 增加文件哈希值缓存，避免重复扫描相同文件。

```c
// 修改 ave_static_features.c
static size_t env_read_max(void) {
  // ... 保持原逻辑 ...
}

int edr_ave_static_features_lite_512(const char *path, float *out512) {
  size_t cap = env_read_max();
  
  // 智能分段读取：优先头部 + 尾部
  uint8_t *buf = (uint8_t *)malloc(cap);
  FILE *f = fopen(path, "rb");
  fseek(f, 0, SEEK_END);
  long file_size = ftell(f);
  fseek(f, 0, SEEK_SET);
  
  size_t n = 0;
  if (file_size <= (long)cap) {
    // 小文件：全读
    n = fread(buf, 1u, (size_t)file_size, f);
  } else {
    // 大文件：读前半部分 + 后半部分
    size_t half = cap / 2;
    n = fread(buf, 1u, half, f);
    fseek(f, -((long)half), SEEK_END);
    n += fread(buf + n, 1u, half, f);
  }
  
  // ... 继续特征提取 ...
}
```

**预期收益**：大文件扫描速度提升 30-50%。

---

#### 3.1.3 推理频率控制与批量推理 (behavior.onnx)
**问题**：当前每 8/16 个事件就触发一次推理，高频调用产生大量小开销。

**解决方案**：
1. 增加推理间隔的动态调整（低威胁时拉长间隔）；
2. 对于相同进程的多个事件，可以合并推理。

```c
// 在 ave_behavior_pipeline.c 中
static uint32_t bp_infer_events_threshold_design7(...) {
  // 当前基础逻辑
  uint32_t base = ...;
  
  // 动态调整：根据当前异常分数调整阈值
  if (sl->anomaly < 0.1f) {
    return base * 2;  // 低风险，降低推理频率
  } else if (sl->anomaly > 0.7f) {
    return base / 2;  // 高风险，提高推理频率
  }
  return base;
}
```

**预期收益**：减少 30-40% 的 behavior.onnx 推理调用次数。

---

### 3.2 中优先级优化（中期实施）

#### 3.2.1 ORT Session Options 优化
**问题**：当前创建 Session 时仅设置了线程数，未充分利用 ONNX Runtime 的优化能力。

**解决方案**：
```c
// 在 create_session_from_path() 中优化
static EdrError create_session_from_path(...) {
  OrtSessionOptions *opt = NULL;
  OrtStatus *st = g_ort->CreateSessionOptions(&opt);
  
  // 1. 设置执行提供者（CPU优化）
  g_ort->SetSessionExecutionMode(opt, ORT_SEQUENTIAL);  // 对于小模型，顺序执行更快
  
  // 2. 启用图优化
  g_ort->SetGraphOptimizationLevel(opt, ORT_ENABLE_EXTENDED);
  
  // 3. 设置线程数（已有，但可以优化默认值）
  int th = (cfg && cfg->ave.scan_threads > 0) ? cfg->ave.scan_threads : 1;
  g_ort->SetIntraOpNumThreads(opt, th);
  g_ort->SetInterOpNumThreads(opt, 1);  // 对于小模型，单线程更好
  
  // 4. 启用内存优化
  g_ort->SetSessionGraphOptimizationLevel(opt, ORT_ENABLE_ALL);
}
```

**预期收益**：推理速度提升 15-25%。

---

#### 3.2.2 特征计算优化 (Lite512)
**问题**：香农熵计算使用浮点数循环，有优化空间。

**解决方案**：
1. 预计算对数表；
2. 使用 SIMD 向量化计算（可选）；
3. 减少分块数（如从 256 块降至 128 块，精度损失很小）。

```c
// 优化 shannon_entropy()
static float shannon_entropy_optimized(const uint8_t *p, size_t len) {
  if (len == 0u || !p) {
    return 0.f;
  }
  unsigned cnt[256];
  memset(cnt, 0, sizeof(cnt));
  
  // 直方图统计可以向量化
  for (size_t i = 0; i < len; i++) {
    cnt[p[i]]++;
  }
  
  float h = 0.f;
  float inv = 1.0f / (float)len;
  
  // 使用预计算的 log2_lookup 表
  for (int i = 0; i < 256; i++) {
    if (cnt[i] == 0u) continue;
    float p_i = (float)cnt[i] * inv;
    h -= p_i * log2_lookup[(int)(p_i * 1000)];  // 预计算查找表
  }
  return h;
}
```

**预期收益**：特征提取速度提升 20-30%。

---

### 3.3 低优先级优化（长期规划）

#### 3.3.1 模型量化
将 FP32 模型量化为 INT8 或 FP16，显著减少计算量和内存占用。

#### 3.3.2 模型剪枝
移除模型中的冗余权重，减小模型大小和计算量。

---

## 4. 配置建议与环境变量

### 4.1 已有的可配置项

| 环境变量 | 默认值 | 说明 | 优化建议 |
|----------|--------|------|----------|
| `EDR_AVE_STATIC_READ_MAX` | 4MB | 静态特征读取的最大文件大小 | 根据场景调整（桌面: 4MB, 服务器: 8MB） |
| `EDR_AVE_ONNX_IN_LEN` | 4096 | 静态模型输入长度（动态轴） | 尽量使用 512 以启用 Lite512 |
| `EDR_AVE_STATIC_LEGACY512` | 0 | 强制使用 Legacy 模式（即使 n=512） | 保持 0 |
| `EDR_AVE_BEH_IN_LEN` | 64 | 行为模型特征维度 | 保持默认 |
| `EDR_AVE_BEH_SEQ_LEN` | 128 | 行为模型序列长度 | 保持默认 |

### 4.2 新增推荐配置项

```bash
# 静态扫描优化
export EDR_AVE_STATIC_READ_SMART=1          # 启用智能分段读取（头+尾）
export EDR_AVE_STATIC_CACHE_SIZE=1000       # 文件扫描结果缓存数量
export EDR_AVE_STATIC_CACHE_TTL=3600        # 缓存过期时间(秒)

# 行为推理优化
export EDR_AVE_BEH_INFER_THRESHOLD_MIN=16   # 最小推理事件数
export EDR_AVE_BEH_INFER_THRESHOLD_MAX=64   # 最大推理事件数
export EDR_AVE_BEH_DYNAMIC_THRESHOLD=1      # 启用动态阈值调整
```

---

## 5. 总结与实施路线图

### 5.1 短期（1-2周）
1. ✅ 实现张量/内存池化，避免频繁分配
2. ✅ 优化文件读取策略（智能分段）
3. ✅ 配置 ORT Session 优化选项

### 5.2 中期（1-2月）
1. 实现文件哈希缓存，避免重复扫描
2. 优化特征计算（香农熵预计算等）
3. 动态调整推理频率

### 5.3 长期（3-6月）
1. 模型量化与剪枝
2. 考虑使用更轻量的推理引擎（如 TFLite Micro）
3. 离线性能基准测试框架

---

## 6. 附录：性能监控建议

建议添加以下性能指标监控：
```c
// 每次推理记录耗时
static uint64_t s_infer_count;
static uint64_t s_total_infer_ns;
static uint64_t s_max_infer_ns;

// 在 edr_onnx_infer_file() 开头/结尾
uint64_t t0 = get_time_ns();
// ... 推理 ...
uint64_t dt = get_time_ns() - t0;
atomic_fetch_add(&s_infer_count, 1);
atomic_fetch_add(&s_total_infer_ns, dt);
// 记录最大值...
```

通过这些监控，可以持续观察优化效果。
