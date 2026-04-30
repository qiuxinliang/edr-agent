# EDR ONNX 推理模型升级方案

**版本**：1.0
**日期**：2026-04-29
**状态**：方案已评审，代码已就绪，待执行

关联文档：

- [EDR Agent 系统架构全景](./EDR_AGENT_ARCHITECTURE.md)
- [AVE ONNX 接口契约](./AVE_ONNX_CONTRACT.md)
- [ONNX 性能优化](./ONNX_PERFORMANCE_OPTIMIZATION.md)
- [FL 训练开发计划](./FL_DEVELOPMENT_PLAN.md)
- [FL 样本库 Schema](./FL_SAMPLES_SCHEMA.md)

---

## 1. 背景与动机

### 1.1 当前 ONNX 模型现状

EDR Agent 部署两个 ONNX 模型，均由 AVE 引擎通过 ONNX Runtime C API 加载推理：

| 模型 | 文件 | 输入 | 输出 | 当前架构 |
|------|------|------|------|----------|
| **static** | `static.onnx` | `[1, 512]` 特征向量 | verdict(4) + family(32) + packer(8) | 三路 MatMul+Add 线性分类器 |
| **behavior** | `behavior.onnx` | `[1, 128, 64]` 行为序列 | anomaly_score(1) + tactic_probs(14) | MatMul → ReduceMean（全局平均池化）+ Add |

两个模型本质上都是**单层线性变换**，缺乏非线性建模能力：

- **static**：512 维 → 三路独立线性头（无隐藏层，无激活函数）
- **behavior**：128 步 × 64 维序列 → 全局平均池化（丢失全部时序信息）

### 1.2 核心问题

1. **模型容量过低**：线性模型无法学习特征间的非线性交互
2. **时序信息丢失**：behavior 模型的 ReduceMean 将行为序列压缩为单一均值，无法区分攻击链步骤顺序（如 `powershell → bitsadmin → rundll32 → reg` 与 `reg → rundll32 → bitsadmin → powershell` 判为相同）
3. **训练数据不足**：当前仅能进行少量训练，无公开预训练模型支撑
4. **难以商用**：线性模型的对抗鲁棒性极差，攻击者通过简单特征扰动即可绕过

### 1.3 目标

- 在**不修改 C 推理代码**的前提下，升级 ONNX 模型架构
- 利用业界成熟的公开数据集（EMBER、SOREL-20M）实现迁移学习
- 提供完整的训练→导出→部署工具链
- behavior 模型从无时序感知升级为时序深度模型

---

## 2. 方案概览

```
P0（即时）                 P1（短期）                P2（长期）
─────────                 ─────────                ─────────
static.onnx               behavior.onnx            多模态融合
 线性 → 3层MLP             ReduceMean → LSTM+Attn    static + behavior
 EMBER 迁移学习           沙箱回放 + FL 累积         联合推理
                                          │
                         降级兜底: 1D-CNN   │
                                          ▼
                                  FL 跨端联邦聚合
```

### 2.1 与现有 C 推理管线的兼容性承诺

**所有方案均为零 C 代码改动**。ONNX 模型的输入/输出名称、形状、维度与现有 `ave_onnx_infer.c` 完全兼容。

验证脚本：[scripts/verify_onnx_compat.py](../scripts/verify_onnx_compat.py)

---

## 3. P0：static.onnx 升级为 MLP + EMBER 迁移学习

### 3.1 架构对比

```
                    当前（单层线性）                       目标（3层MLP）
                    ────────────────                     ──────────────
                features [1, 512]                   features [1, 512]
                     │                                     │
   ┌─────────────────┼─────────────────┐         ┌────────┴────────┐
   │                 │                 │         │ Dense(512)→512  │ ← ReLU + Dropout
   ▼                 ▼                 ▼         │ Dense(512)→256  │ ← ReLU + Dropout
 MatMul+Add      MatMul+Add       MatMul+Add     │ Dense(256)→128  │ ← ReLU + Dropout
   │                 │                 │         └────────┬────────┘
   ▼                 ▼                 ▼                  │
 verdict(4)      family(32)       packer(8)      ┌───────┼───────┐
                                                  │       │       │
                                                  ▼       ▼       ▼
                                             verdict(4) family(32) packer(8)
```

| 对比维度 | 当前线性模型 | 3层 MLP |
|---------|:-----------:|:-------:|
| 可学习参数 | ~22K | ~434K |
| 非线性能力 | 无 | ReLU 三层 |
| 特征交互 | 仅线性组合 | 逐层抽象 + 交互 |
| 对抗鲁棒性 | 极差（线性决策边界） | 中等（非线性边界） |
| 少样本友好度 | 需要大量数据 | 迁移学习仅需数千条 |

### 3.2 训练流程

#### 步骤 1：获取数据

EMBERT 公开数据集有 110 万条标注 PE 样本，可直接下载：

```bash
wget https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
tar xf ember_dataset_2018_2.tar.bz2
```

#### 步骤 2：导入样本库

```bash
python3 scripts/import_samples_to_db.py ember \
    ember2018/train_features_1.jsonl \
    --db fl_samples.db --limit 50000
```

#### 步骤 3：训练

```bash
python3 scripts/train_static_mlp.py train \
    --db fl_samples.db --epochs 50
```

#### 步骤 4：导出并部署

```bash
python3 scripts/train_static_mlp.py export --output-onnx models/static.onnx
cp models/static.onnx /opt/edr/models/
# 重启 edr_agent → ORT 自动加载新计算图
```

### 3.3 迁移学习降级路径（数据极少时）

若仅有数百条样本，可使用 EMBER 预训练 backbone + 冻结层 + 仅训练分类头：

```
EMBER 预训练 backbone (冻结) → Dense(128)→4/32/8 (仅训练这三个头)
                                  ↑ 仅 ~14K 参数需要训练
```

### 3.4 预期效果

| 指标 | 线性模型（估计） | 3层MLP 从头训练 | 3层MLP+迁移学习 |
|------|:-----------:|:-----------:|:-----------:|
| 最少样本 | 10K+ | 20K+ | 1K~2K |
| AUC（50K样本） | ~0.85 | ~0.95 | ~0.97 |
| AUC（5K样本） | ~0.70 | ~0.80 | ~0.92 |

---

## 4. P1：behavior.onnx 升级为时序深度模型

### 4.1 架构对比

```
            当前（全局平均池化）                     目标（LSTM + Self-Attention）
            ────────────────────                    ──────────────────────────
        features [1, 128, 64]                   features [1, 128, 64]
                 │                                      │
                 ├─ Reshape(128,64)                     ├─ LayerNorm(64)
                 │                                      │
                 ├─ MatMul(W [64,1])                    ├─ BiLSTM(64→128, 2层)
                 │     └─ = 简单加权求和                  │     └─ 输出: (128, 256)
                 │                                      │
                 ├─ ReduceMean                          ├─ LayerNorm(256)
                 │     └─ ← 丢失所有时序！               │
                 │                                      ├─ MultiHeadSelfAttn(4头)
                 └─ anomaly_score [1,1]                  │     └─ 建模步骤间依赖
                                                        │
                                                        ├─ GlobalMaxPool+AvgPool
                                                        │     └─ 拼接: (512,)
                                                        │
                                                        ├─ Dense(512→128, ReLU)
                                                        │     ├─ Dense(128→1)
                                                        │     └─ Dense(128→14)
                                                        │
                                                        ├─ anomaly_score [1,1]
                                                        └─ tactic_probs [1,14]
```

#### 降级选项：1D-TemporalCNN

兼容性更好，无需 ONNX Runtime 支持 LSTM op，训练更快：

```
CNN 替代方案:
  LayerNorm → Conv1d(64→128, k=3) → Conv1d(128→128, k=5) → Conv1d(128→256, k=7)
  → GlobalMaxPool+AvgPool → MLP → 双输出头
  参数量: ~405K
```

### 4.2 训练流程

```bash
# 方案 A：LSTM（时序建模最强）
python3 scripts/train_behavior_lstm.py train \
    --db fl_samples.db --epochs 100 --model-type lstm

# 方案 B：CNN（兼容性更好，推荐起步用）
python3 scripts/train_behavior_lstm.py train \
    --db fl_samples.db --epochs 100 --model-type cnn

# 导出
python3 scripts/train_behavior_lstm.py export \
    --output-onnx models/behavior.onnx --model-type cnn
```

### 4.3 行为数据获取策略

行为序列数据的公开可用性远不如 PE 静态特征，需分阶段积累：

#### 方案 A：沙箱回放采集（推荐，效果最好）

```
1. 从 MalwareBazaar 下载恶意 PE 样本
2. 在 Windows 虚拟机中逐个运行
3. 用 Agent 自带的 ETW 采集器 + behavior_encode_m3b.py 转成 128×64 序列
4. 同样运行一批正常软件（Chrome/Office/VSCode/7zip 等）
5. 全部入库 fl_samples.db
```

#### 方案 B：半合成数据（快速起始）

```
1. 利用 MITRE ATT&CK 战术步骤生成攻击行为序列模板
   （如: powershell → bitsadmin → rundll32 → reg → net use）
2. 注入随机噪声模拟真实端点环境
3. 结合 behavior_encode_m3b.py 验证特征对齐
4. 后续用真实数据逐步替换
```

#### 方案 C：FL 联邦累积（长期）

```
客户端 A (500条)      客户端 B (300条)      客户端 C (200条)
      │                      │                      │
      └──────────────────────┼──────────────────────┘
                             │
                    协调端 FedAvg 聚合
                             │
                      更新全局 ONNX 模型
                             │
                    下发到所有客户端
```

### 4.4 预期效果

| 指标 | ReduceMean（当前） | 1D-CNN | BiLSTM+Attn | 训练数据需求 |
|------|:-----------:|:------:|:-----------:|:----------:|
| 攻击链模式识别 | 无 | 部分 | 强 | - |
| 异常检测 AUC（合成） | ~0.70 | ~0.88 | ~0.92 | 3K+ |
| 异常检测 AUC（真实） | ~0.65 | ~0.78 | ~0.82 | 10K+ |
| ONNX 文件大小 | ~10KB | ~1.6MB | ~3.7MB | - |

---

## 5. C 推理代码兼容性分析

### 5.1 接口契约对照表

推理代码定位：[src/ave/ave_onnx_infer.c](../src/ave/ave_onnx_infer.c)

#### static 模型

| 契约项 | 当前 | 新 MLP 模型 | 兼容？ |
|--------|------|------------|:----:|
| 输入名称 | `"features"` | `"features"` | ✅ |
| 输入形状 | `[1, 512]` | `[1, 512]` | ✅ |
| 输出名称1 | 含 `"verdict"` | `"verdict_probs"` | ✅ (str_contains_ci) |
| 输出名称2 | 含 `"family"` | `"family_probs"` | ✅ (str_contains_ci) |
| 输出名称3 | 含 `"packer"` | `"packer_probs"` | ✅ (str_contains_ci) |
| 三路绑定 | `bind_static_spec_outputs()` | 自动匹配 | ✅ |
| 首输入元素数 | 512 | 512 | ✅ |
| lite_512 路径 | n==512 走轻量提取 | n==512 保持一致 | ✅ |
| 推理函数 | `edr_onnx_infer_file()` | 无变化 | ✅ |

#### behavior 模型

| 契约项 | 当前 | 新 LSTM/CNN 模型 | 兼容？ |
|--------|------|-----------------|:----:|
| 输入名称 | `"features"` | `"features"` | ✅ |
| 输入形状 | `[1, 128, 64]` | `[1, 128, 64]` | ✅ |
| 输出名称1 | 含 `"anomaly"` 或 `"anomaly_score"` | `"anomaly_score"` | ✅ (str_contains_ci) |
| 输出名称2 | 含 `"tactic"` | `"tactic_probs"` | ✅ (str_contains_ci) |
| 双输出绑定 | `bind_behavior_outputs()` | 自动匹配 | ✅ |
| 输入维度自适应 | `refine_behavior_input_dims()` | 自适应 3D | ✅ |
| 内存池分配 | `g_beh_in_nelem * sizeof(float)` | 1×128×64 = 8192 | ✅ |
| 推理函数 | `edr_onnx_behavior_infer()` | 无变化 | ✅ |

### 5.2 LSTM ONNX 兼容性说明

ONNX opset 17 完全支持 `LSTM` op（自 opset 1 起即支持）。需确认 ONNX Runtime 版本 ≥ 1.8。

验证方法：

```bash
python3 -c "
import onnxruntime as ort
print('ORT version:', ort.__version__)
print('Providers:', ort.get_available_providers())
"
```

若 ORT 版本过老或不支持 LSTM，可使用 `--model-type cnn` 降级为 1D-CNN（完全无兼容性问题）。

---

## 6. 样本扩充策略

### 6.1 样本来源矩阵

| 来源 | 类型 | 数量级 | 获取难度 | 适用模型 |
|------|------|:------:|:--------:|:--------:|
| **EMBER2018** | PE 特征 + 标签 | 110万 | 🟢 `wget` 直接下载 | static |
| **SOREL-20M** | PE 特征 + 标签 | 2000万 | 🟢 公开下载 | static |
| **MalwareBazaar** | 恶意 PE + 标签 | 日均数百 | 🟢 API 免费 | static |
| **VirusShare** | 恶意 PE 样本 | 数千万 | 🟡 需学术申请 | static |
| **沙箱回放** | 行为序列 | 可控 | 🟢 虚拟机 + ETW | behavior |
| **MITRE ATT&CK Evaluations** | APT 攻击步骤 | 数十个 APT 组 | 🟡 需转换格式 | behavior |
| **FL 客户端采集** | 真实端点行为 | 取决于部署量 | 🟡 通过 FL 框架收集 | behavior |

### 6.2 数据增强

对现有样本做噪声注入，可有效扩充数据集：

```bash
# 每个样本生成 3 个加噪副本: N → 4N 条
python3 scripts/import_samples_to_db.py augment --db fl_samples.db \
    --noise-std 0.01 --n-augment 3
```

数据增强在少样本场景下尤为有效——模型学到的是特征的稳定模式而非精确值。

### 6.3 数据量需求参考

| 训练方式 | 最少数据量 | 推荐数据量 |
|----------|:--------:|:--------:|
| static MLP 从头训练 | 20K | 100K+ |
| **static MLP + 迁移学习（推荐）** | 1K~2K | 5K+ |
| behavior CNN 训练 | 3K~5K | 10K+ |
| behavior LSTM 训练 | 5K+ | 50K+ |
| behavior 合成+真实混合 | 1K 真实 + 5K 合成 | 2K 真实 + 10K 合成 |

---

## 7. 工具脚本一览

| 脚本 | 用途 | 关键命令 |
|------|------|----------|
| [train_static_mlp.py](../scripts/train_static_mlp.py) | Static MLP 训练 + ONNX 导出 | `train`, `export`, `import-ember`, `augment`, `stats` |
| [train_behavior_lstm.py](../scripts/train_behavior_lstm.py) | Behavior LSTM/CNN 训练 + ONNX 导出 | `train --model-type lstm\|cnn`, `export` |
| [import_samples_to_db.py](../scripts/import_samples_to_db.py) | 样本库导入工具 | `ember`, `malwarebazaar`, `pe`, `augment`, `gen-behavior`, `compute-pca`, `stats` |
| [verify_onnx_compat.py](../scripts/verify_onnx_compat.py) | ONNX 模型与 C 推理接口兼容性验证 | 直接运行 |

### 7.1 依赖

```bash
pip install torch onnx onnxruntime numpy scikit-learn
# 可选
pip install ember   # PE 特征提取（用于 MalwareBazaar / PE 目录导入）
pip install requests # MalwareBazaar API
```

---

## 8. 快速启动路径（7 天）

```bash
# ===== Day 1: 建立样本库 =====
wget https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
tar xf ember_dataset_2018_2.tar.bz2
python3 scripts/import_samples_to_db.py ember \
    ember2018/train_features_1.jsonl --db fl_samples.db --limit 50000

# ===== Day 2: 数据增强 =====
python3 scripts/import_samples_to_db.py augment \
    --db fl_samples.db --noise-std 0.01 --n-augment 2

# ===== Day 3: 训练 static MLP =====
python3 scripts/train_static_mlp.py train \
    --db fl_samples.db --epochs 50

# ===== Day 4: 导出 static.onnx =====
python3 scripts/train_static_mlp.py export \
    --output-onnx models/static.onnx

# ===== Day 5: 生成合成 behavior 数据 + 训练 CNN =====
python3 scripts/import_samples_to_db.py gen-behavior \
    --db fl_samples.db --n-samples 2000
python3 scripts/train_behavior_lstm.py train \
    --db fl_samples.db --epochs 50 --model-type cnn

# ===== Day 6: 导出 behavior.onnx =====
python3 scripts/train_behavior_lstm.py export \
    --output-onnx models/behavior.onnx --model-type cnn

# ===== Day 7: 兼容性验证 + 部署 =====
python3 scripts/verify_onnx_compat.py
cp models/static.onnx /opt/edr/models/
cp models/behavior.onnx /opt/edr/models/
# 重启 edr_agent
```

---

## 9. 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| ORT 版本不支持 LSTM op | behavior 模型无法加载 | 降级使用 CNN 模型 (`--model-type cnn`) |
| EMBER 2381→512 PCA 降维失真 | 特征质量下降 | 用 AVEngine 原生 512 维特征替代，或使用 `compute-pca` 子命令计算 PCA 矩阵 |
| behavior 真实数据积累慢 | 模型效果不达预期 | 先用合成数据 bootstrapping + FL 联邦逐步积累 |
| 模型文件过大 | LSTM ONNX ~3.7MB | 可接受（当前线性模型 ~10KB → 增长到 3.7MB 仍在范围） |

---

## 10. 附录：C 推理代码关键路径

```
ave_onnx_infer.c 关键函数与新旧模型对应关系：

edr_onnx_runtime_load("static.onnx")
  ├─ ensure_ort_env()                        ← 全局 ORT 初始化
  ├─ create_session_from_path()              ← ONNX 图加载 + 输入形状解析
  ├─ bind_static_spec_outputs()              ← 匹配 “verdict” / “family” / “packer”
  └─ parse_input_shape() → g_in_nelem=512    ← 新模型 512 维不变

edr_onnx_behavior_load("behavior.onnx")
  ├─ ensure_ort_env()
  ├─ create_session_from_path()
  ├─ refine_behavior_input_dims()            ← (batch, seq, feat) → (1, 128, 64)
  ├─ bind_behavior_outputs()                 ← 匹配 “anomaly” / “tactic”
  └─ g_beh_in_nelem = 8192                   ← 新模型 8192 不变

edr_onnx_infer_file()
  ├─ use_lite512 = (n == 512)                ← 新模型 512 → 走轻量路径 ✅
  ├─ g_ort->CreateTensorWithDataAsOrtValue()  ← 输入张量
  ├─ g_ort->Run() [triple output]            ← 三输出推理
  └─ copy_ort_output_floats() → verdict/family/packer

edr_onnx_behavior_infer()
  ├─ memcpy(buf, feature, g_beh_in_nelem*sizeof(float))
  ├─ g_ort->CreateTensorWithDataAsOrtValue()  ← 3D 输入
  ├─ g_ort->Run() [dual output]              ← 双输出推理
  ├─ copy_tactic_probs_from_tensor()
  └─ *out_score = out_data[0]                ← anomaly_score
```
