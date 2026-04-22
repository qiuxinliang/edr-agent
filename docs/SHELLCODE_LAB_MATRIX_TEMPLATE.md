# 实验室矩阵模板 — `raw_private/` + `apply_lab_variants.py`（T-SC-032）

**目的**：在**不入库 raw 二进制**的前提下，对情报/红队片段做 **D2–D7** 结构变形后，在隔离机跑 Agent，记录 **TP / FP / FN**。本文件仅提供**空表模板**；统计结论写内网 wiki 或 **`docs/P2_PERF4_*`** 附录。

## 1. 目录约定

| 路径 | 说明 |
|------|------|
| **`edr-agent/test_data/shellcode_corpus/raw_private/`** | 本地 raw（**.gitignore**）；勿 **`git add`**。 |
| **`scripts/shellcode_corpus/apply_lab_variants.py`** | 对单文件生成多种载体（与团队脚本名对齐；若仓库内脚本名不同，以实际为准）。 |

## 2. 矩阵（复制到 wiki / 表格工具）

| 样本 ID | 来源类型 | 变形 ID | `proto_parse` 结果 | 期望规则 | Agent `got_rule` | TP/FP/FN | 备注 |
|---------|----------|---------|-------------------|----------|------------------|----------|------|
| | | | | | | | |
| | | | | | | | |

## 3. 最小闭环

1. 将脱敏片段放入 **`raw_private/`**。  
2. 运行变形脚本，输出到**临时目录**（不在 git）。  
3. **`eval_shellcode_corpus --mode pipeline`** 或实机 WinDivert。  
4. 将上表 **`TP/FP/FN`** 与 **`wd_stats`** 摘要粘贴到 **P2-PERF-4** 或内网结论页。
