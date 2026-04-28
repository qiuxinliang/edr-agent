# EDR Agent ONNX/深度学习功能分析报告

**版本**：1.0
**日期**：2026-04-28
**状态**：已完成

---

## 1. 概述

EDR Agent 集成了基于 ONNX Runtime 的深度学习推理能力，用于：
1. **静态文件检测**：通过 `static.onnx` 模型检测恶意文件
2. **动态行为分析**：通过 `behavior.onnx` 模型分析进程行为异常
3. **联邦学习**：支持从 behavior.onnx 导出模型权重用于联邦训练

---

## 2. 架构组件

### 2.1 核心文件

| 文件 | 职责 |
|------|------|
| `ave_onnx_infer.c` | ONNX Runtime 封装、模型加载、推理执行 |
| `ave_behavior_pipeline.c` | 行为特征采集、推理调度、结果融合 |
| `edr_onnx_behavior_fl_tensor_export.c` | 联邦学习：张量导出 |
| `ave_engine.c` | AVE引擎主逻辑 |
| `ave_static_features.c` | 静态特征提取 |

### 2.2 ONNX Runtime 封装

```c
// ave_onnx_infer.c
typedef struct OrtVTable {
    OrtStatus* (*CreateSessionOptions)(OrtSessionOptions**);
    OrtStatus* (*SetIntraOpNumThreads)(OrtSessionOptions*, int);
    OrtStatus* (*CreateSession)(OrtEnv*, const wchar_t*, OrtSessionOptions*, OrtSession**);
    // ... 更多函数指针
} OrtVTable;

static OrtVTable *g_ort;  // ONNX Runtime 函数表
static OrtEnv *g_env;     // ONNX 环境
static OrtSession *g_session;  // 静态模型会话
static OrtSession *g_beh_session;  // 行为模型会话
```

---

## 3. 模型类型

### 3.1 静态检测模型 (static.onnx)

**用途**：检测恶意文件、壳、压缩器

**输出**：
```c
typedef struct {
    float verdict_probs[4];   // 判决概率 (malicious, suspicious, benign, unknown)
    float family_probs[32];  // 家族分类概率
    float packer_probs[8];   // 加壳检测概率
} EdrAveInferResult;
```

**特征输入**：
- 原始字节 `/255.0` 归一化
- 支持 LITE_512 和完整特征模式

### 3.2 行为分析模型 (behavior.onnx)

**用途**：基于进程行为序列的异常检测

**输入**：
```c
// 特征向量，维度由模型定义
float feature[行为特征维度];
```

**输出**：
```c
float score;              // 异常分数
float tactic_probs[14];   // Mitre ATT&CK 战术概率
```

**特征来源**：
- 进程历史事件（PID History）
- 14维战术向量（14 Mitre ATT&CK 战术）

### 3.3 联邦学习张量导出

**用途**：从 behavior.onnx 导出 FP32 权重用于联邦训练

**实现**：
- 直接解析 ONNX protobuf（不依赖 onnx 库）
- 导出 Graph.initializer 中的 FP32 张量
- 排除 tactic/head_b 相关权重（冻结层）

```c
int edr_onnx_behavior_export_fl_trainable_floats(
    float *out_floats,      // 输出缓冲区
    size_t *out_nelem_io,   // 输入：缓冲区大小，输出：实际元素数
    char *manifest_json,     // 张量清单 JSON
    size_t manifest_cap
);
```

---

## 4. 推理流程

### 4.1 静态文件检测

```
edr_onnx_infer_file(cfg, path, &out)
         │
         ▼
    加载 static.onnx 模型
         │
         ▼
    提取文件特征 (raw bytes /255.0)
         │
         ▼
    Run ONNX Session
         │
         ▼
    argmax + score 计算
         │
         ▼
    返回 verdict_probs, family_probs, packer_probs
```

### 4.2 行为异常检测

```
ave_behavior_pipeline_process(sl, bp_event)
         │
         ▼
    累积进程历史特征
         │
         ▼
    检查推理阈值 (min_events)
         │
         ├─── 未达到阈值 ──► 返回
         │
         ▼
    构建 ONNX 输入张量
         │
         ▼
    edr_onnx_behavior_infer()
         │
         ▼
    分数融合: anomaly = 0.35*old + 0.65*new
         │
         ▼
    更新 sl->anomaly, sl->last_anomaly_score
```

---

## 5. 关键参数

### 5.1 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `EDR_AVE_STATIC_ONNX` | - | 静态模型路径 |
| `EDR_AVE_BEHAVIOR_ONNX` | - | 行为模型路径 |
| `EDR_AVE_STATIC_LEGACY512` | 0 | 使用 LITE_512 特征 |
| `EDR_AVE_SCAN_THREADS` | 1 | ONNX 推理线程数 |
| `EDR_AVE_BEH_INFER_MIN_EVENTS` | - | 最少事件数触发推理 |

### 5.2 行为推理阈值

```c
// 《11》§7.1：立即触发或步长 16/8
uint32_t min_ev = bp_infer_events_threshold_design7(e, sl);

// 避免仅 PAD 步即推理
if (need > EDR_PID_HISTORY_FEAT_DIM && min_ev < 4u) {
    min_ev = 4u;
}
```

### 5.3 分数融合

```c
// 指数移动平均
sl->anomaly = fminf(1.f, 0.35f * sl->anomaly + 0.65f * u);
```

---

## 6. 联邦学习集成

### 6.1 张量导出流程

```c
int edr_onnx_behavior_export_fl_trainable_floats(
    float *out_floats,
    size_t *out_nelem_io,
    char *manifest_json,
    size_t manifest_cap) {

    // 1. 读取 ONNX 文件
    FILE *f = fopen(path, "rb");

    // 2. 解析 protobuf（无 onnx 库依赖）
    find_graph(buf, fsz, &g, &glen);
    walk_inits(g, glen, &recs, &rn, &total);

    // 3. 排除 tactic/head_b 权重
    fl_name_excluded(name);  // 返回 1 则跳过

    // 4. 排序并拼接
    qsort(recs, rn, sizeof(FlTensorRec), fl_rec_cmp);
    memcpy(out_floats + o, recs[i].data, recs[i].n * sizeof(float));

    // 5. 生成 manifest
    build_manifest(recs, rn, total, manifest_json, manifest_cap);
}
```

### 6.2 Manifest JSON 格式

```json
{
  "total_floats": 1234567,
  "tensors": [
    {"name": "model权重名1", "n": 12345, "o": 0},
    {"name": "model权重名2", "n": 67890, "o": 12345}
  ]
}
```

---

## 7. 当前状态评估

### 7.1 已实现功能

| 功能 | 状态 | 说明 |
|------|------|------|
| ONNX Runtime 封装 | ✅ 完整 | 支持 Windows/Linux |
| 静态文件检测 | ✅ 完整 | verdict/family/packer |
| 行为异常检测 | ✅ 完整 | 与特征管道集成 |
| 联邦学习导出 | ✅ 完整 | 无 protobuf 依赖 |
| 推理结果缓存 | ✅ 完整 | pid_history 滑动窗口 |

### 7.2 潜在改进点

| 问题 | 影响 | 建议 |
|------|------|------|
| **ONNX 模型管理** | 缺少模型热更新机制 | 添加模型版本检查和自动更新 |
| **推理性能** | 首次推理延迟高 | 添加模型预热机制 |
| **联邦学习** | 仅导出，无聚合 | 需要联邦聚合服务配合 |
| **特征工程** | 特征维度固定 | 考虑动态特征维度支持 |

### 7.3 依赖分析

| 组件 | 依赖 | 说明 |
|------|------|------|
| ONNX Runtime | `onnxruntime.dll` / `libonnxruntime.so` | 运行时依赖 |
| Protobuf | 无 | 联邦学习导出不依赖 protobuf |
| 张量库 | 无 | 纯 C 实现 |

---

## 8. 部署建议

### 8.1 模型文件位置

```bash
# Windows
C:\Program Files\EDR\models\
    ├── static.onnx
    └── behavior.onnx

# Linux
/opt/edr/models/
    ├── static.onnx
    └── behavior.onnx
```

### 8.2 环境变量配置

```bash
# 静态检测模型
export EDR_AVE_STATIC_ONNX=/opt/edr/models/static.onnx

# 行为分析模型
export EDR_AVE_BEHAVIOR_ONNX=/opt/edr/models/behavior.onnx

# 推理线程数（根据 CPU 核心数）
export EDR_AVE_SCAN_THREADS=4

# 最小事件触发阈值
export EDR_AVE_BEH_INFER_MIN_EVENTS=8
```

### 8.3 联邦学习配置

```bash
# 定期导出模型权重（供联邦训练使用）
# 建议：每天一次，在低峰期执行

./edr_agent --export-fl-weights --output /tmp/fl_weights.bin
```

---

## 9. 后续优化建议

### 9.1 短期优化

1. **模型热更新**：支持在不重启 Agent 的情况下更新模型
2. **推理缓存**：缓存相同特征的推理结果
3. **批量推理**：支持多个文件/行为批量推理

### 9.2 中期优化

1. **联邦聚合集成**：与联邦学习服务集成，实现模型聚合
2. **特征重要性**：输出哪些特征对最终判决影响最大
3. **模型版本管理**：支持多版本模型共存

### 9.3 长期优化

1. **增量学习**：支持在端上持续学习
2. **对抗鲁棒性**：增强对对抗样本的检测能力
3. **多模态融合**：结合静态和行为特征

---

## 10. 相关文档

| 文档 | 说明 |
|------|------|
| `docs/11_behavior_onnx_design.md` | behavior.onnx 详细设计 |
| `docs/CONFIGURATION_GUIDE.md` | 配置参数参考 |
| `ave_onnx_infer.c` | ONNX 推理实现 |
| `edr_onnx_behavior_fl_tensor_export.c` | 联邦学习导出实现 |

---

*文档生成时间：2026-04-28*