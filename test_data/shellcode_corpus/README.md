# Shellcode 检测评估语料（`test_data/shellcode_corpus`）

## `baselines/`（已入库）

- **来源**：**合成** — 仅复现 **`shellcode_known.c`** 中已文档化的 **公开 IOC 字节模式**（与 **`tests/test_shellcode.c`** 同源思路），**不是**从互联网下载的完整恶意样本。**EternalBlue / BlueKeep** 带 **`proto_parse.c`** 认可的 **SMB1 / RDP 帧头**；**EternalBlue** 另含 **`eternalblue_nb_*.bin`**（NetBIOS 会话头 **`0x00` + 3 字节长度**，解析时 **`off=4`**），便于 **`eval_shellcode_corpus --mode pipeline`** 与线上一致。
- **覆盖**：**43** 个 **`.bin`** + **`manifest.tsv`**（在 **35** 条基线族上增加：**PetitPotam SMB2 帧** ×2、**EternalBlue SMB1 cmd 0x71/0xA2** ×2、**HTTP 边界** Follina ×3 + Log4Shell ×1；详见 **`emit_baseline_variants.py`**）。
- **生成**：`python3 scripts/shellcode_corpus/emit_baseline_variants.py`（重新生成后需提交变更）。**T-SC-000** 一键验证：**`cmake --build <builddir> --target shellcode_t_sc_000_verify`** 或 **`bash scripts/shellcode_corpus/t_sc_000_verify.sh <builddir>`**。
- **测试**：**`test_shellcode_corpus`**（CMake 在检测到 **`baselines/manifest.tsv`** 时注册）。  
- **评估报表**：构建目标 **`eval_shellcode_corpus`**，用法见 **`docs/SHELLCODE_EVALUATION_CORPUS.md`** §1.0.1。

## `raw_private/`（不入库）

用于你在**隔离实验环境**中自行放置从 **MalwareBazaar / 内部红队 / 经授权情报源** 获取的原始 shellcode（**勿提交 git**）。目录默认被 **`.gitignore`** 忽略。

将原始字节经 **`scripts/shellcode_corpus/apply_lab_variants.py`** 生成 ≥5 种结构变形后，仅在闭环实验机内与 Agent 联调。

## 合规

从公共网络抓取**可执行恶意载荷**可能违反当地法律与供应商 ToS。评估「真实攻击」能力时，请优先：**(1)** 本仓库 **baselines**；**(2)** 合同授权的红队样本；**(3)** 官方漏洞公告中的 **PoC 片段**在隔离机内自行编译生成，**不**向本仓库推送二进制。

详见 **`docs/SHELLCODE_EVALUATION_CORPUS.md`**。
