# Shellcode 检测能力评估 — 语料、变形与合规边界

**目标**：在**不将未授权第三方恶意二进制提交到本仓库**的前提下，为 **§17 Shellcode**（启发式、协议解析、**`edr_shellcode_match_known_exploit`**、可选 **YARA**）提供**可复现**的评估路径；并说明如何在**隔离实验环境**中引入「互联网/情报源」样本做扩展。

**关联**：**`test_data/shellcode_corpus/README.md`**、**`scripts/shellcode_corpus/`**、**`docs/SHELLCODE_ENHANCEMENT_PLAN.md`**（详细增强计划与任务 ID）、**`docs/WINDOWS_SHELLCODE_FORENSIC_TODO.md`**、**`docs/P2_PERF4_SYNTHETIC_TRAFFIC_REPORT.md`**（性能侧）。

---

## 1. 仓库内交付（默认评估路径）

| 内容 | 说明 |
|------|------|
| **`test_data/shellcode_corpus/baselines/*.bin`** | **43** 个文件：在 **35** 条基线（**EternalBlue** 10 + 其余五族各 5）上增加 **T-SC-011/012/031** 合成行：**PetitPotam** 带 **SMB2 头** ×2、**EternalBlue** **SMB1 cmd 0x71 / 0xA2** ×2、**HTTP** 大小写 / **chunked** / **ms-msdt 大小写** 与 **Log4Shell** 小写头等 **4** 条。 |
| **`manifest.tsv`** | 文件名 → **`EdrProtoKind`** 数值 → **期望规则名**。 |
| **`scripts/shellcode_corpus/emit_baseline_variants.py`** | 重新生成 baselines（修改规则后需重跑并提交）。 |
| **`tests/test_shellcode_corpus.c`** | CI：**`ctest -R shellcode_corpus`**，逐条断言 **`edr_shellcode_match_known_exploit`** 命中且规则名一致。 |
| **`eval_shellcode_corpus`**（CMake 目标，与语料同条件生成） | 在 baselines 上输出 **TSV 报告**：每条样本的 **`parse_ok` / `region_kind` / `match_kind` / `scan_len`、已知利用是否命中、规则名是否与 manifest 一致、以及 `entropy_bits` 与 `heuristic` 分数**。 |

> 基线：**EternalBlue** 共 **10** 条（含 NetBIOS 封装）；其余五族各 **5** 条 → **35** 条；另 **8** 条协议/HTTP 边界扩展 → 合计 **43** 条 **`manifest.tsv`** 数据行。

### 1.0.1 运行评估（`eval_shellcode_corpus`）

在 **`edr-agent`** 构建目录中编译并执行（示例）：

```bash
# T-SC-000（推荐）：重生成语料 + shellcode 单测 + 双模式 eval（一步）
cmake -S . -B build && cmake --build build --target shellcode_t_sc_000_verify

# 或仅评估（语料已生成）
cmake --build build --target eval_shellcode_corpus
./build/eval_shellcode_corpus --mode manifest | tee /tmp/shellcode_eval_manifest.tsv
./build/eval_shellcode_corpus --mode pipeline | tee /tmp/shellcode_eval_pipeline.tsv

# 无 CMake 时可用 Bash 包装（默认 BUILD=./build）
bash scripts/shellcode_corpus/t_sc_000_verify.sh build
```

- **`--mode manifest`**（默认）：整段 `.bin` + manifest 中的 **`proto_kind`**，与 **`shellcode_corpus`** 单测一致；**`# summary` 行中 `rule_ok_pct` 应为 100%**（用于「签名引擎在标注协议下的能力」）。  
- **`--mode pipeline`**：先 **`edr_proto_find_shellcode_region`**，再对 **payload 子区间** 做匹配，**`match_kind`** 与 WinDivert 路径一致（解析失败时为 **`UNKNOWN`**）。在 **EternalBlue / BlueKeep 已带帧头** 的当前 baselines 上，**`rule_ok_pct` 应为 100%**；若你本地混入**无帧头**的 raw 片段，仍可能出现 **`rule_ok=0`**，与 manifest 模式分开解读。  
- **YARA**：`--yara <dir>` 或环境变量 **`EDR_YARA_RULES_DIR`** 指向含 **`known_exploits.yar`** 的目录；启用后命中规则可能来自 YARA，**不一定**与 manifest 期望名一致，评估时请对比 **`got_rule`** 与 **`expected_rule`**。  
- **`--expect-builtin`**（**T-SC-022**）：不加载 YARA（与 **`--yara` / `EDR_YARA_RULES_DIR`** 互斥），仅验证 **C 内置**链；便于与带 YARA 的 CI job 对照。  
- **`--strict`**：若存在任一 **`rule_ok=0`**，进程以退出码 **3** 结束（便于把 manifest 模式挂进 CI）；默认成功跑完即 **0**，仅用于生成报表时可不加。
- **T-SC-001（CI）**：**`ctest -R shellcode`** 会额外运行 **`shellcode_corpus_pipeline_eval`**（内部等价于 **`eval_shellcode_corpus --mode pipeline --strict`**），与 **`edr-agent-ci.yml`** 中全量 **`ctest`** 一致，无需再单独调用 eval。

---

## 1.1 引擎检测矩阵（`edr_shellcode_match_known_exploit`）

| 阶段 | 行为 |
|------|------|
| **YARA**（若编译带 **`EDR_HAVE_YARA`** 且已成功从 **`yara_rules_dir`** 加载规则） | 对整段 **`data`** 调用 **`yr_rules_scan_mem`**；**首个**命中的规则名写入 **`rule_name_out`** 并返回（与 **`known_exploits.yar`** 中 **`rule` 标识符**一致）。 |
| **内置 C 规则**（YARA 未启用、加载失败或无命中时） | 按固定顺序尝试；**每条规则仍受 `EdrProtoKind kind` 约束**，避免把 SMB 特征套到 HTTP 等错误上下文。 |

**T-SC-021 — YARA 规则文件顺序与「首命中」**：**`known_exploits.yar`** 中 **`rule`** 自上而下为：**`EternalBlue_MS17_010`** → **`BlueKeep_CVE_2019_0708`** → **`PrintNightmare_CVE_2021_34527`** → **`PetitPotam_MS_EFSR`** → **`Follina_CVE_2022_30190`** → **`Log4Shell_CVE_2021_44228`**。扫描回调在 **多条同时匹配** 时保留 **先** 返回的那条（与 **YARA 编译器/版本** 行为一致）；**内置链**顺序见下表，与 YARA **不完全等价**（例如 **PrintNightmare** 与 **PetitPotam** 在 C 链中的先后与 YARA 文件序可能不同）。对比 **`got_rule` vs `expected_rule`** 时务必注明 **YARA on/off**。

**内置顺序与协议约束**（仅当 YARA 未命中时依次判断）：

| 顺序 | 规则名 | `EdrProtoKind` | 摘要 |
|------|--------|----------------|------|
| 1 | `EternalBlue_MS17_010` | **`SMB1`** | DoublePulsar 子串，或长 **0x00** run + **`05 00`** 尾 |
| 2 | `BlueKeep_CVE_2019_0708` | **`RDP`** | **`MS_T120`** + **`1F 00`** + **0x41** run ≥16 |
| 3 | `PrintNightmare_CVE_2021_34527` | **`UNKNOWN` 或 `SMB2`** | 伪造样 UUID + opnum 0x59 + UNC wide **`\\`** |
| 4 | `PetitPotam_MS_EFSR` | **`UNKNOWN` 或 `SMB2`** | MS-EFSR 接口 UUID **16 字节**（RFC 4122 线序）；排在 PrintNightmare **之后**，若同一缓冲同时满足 PrintNightmare，则 **PrintNightmare 优先** |
| 5 | `Follina_CVE_2022_30190` | **`HTTP`** | ASCII 子串 **`ms-msdt:`** |
| 6 | `Log4Shell_CVE_2021_44228` | **`HTTP`** | **`${jndi:`** 或常见混淆前缀 **`${${::-j`**；排在 Follina **之后** |

**说明**：YARA 与内置 C 的**规则名字符串对齐**，便于日志与语料 **`manifest.tsv`** 一致；YARA 命中时**不会**再跑内置链（当前实现）。

### 1.2 测试结论与后续加强（阶段一已完成）

**阶段一（语料与 pipeline 对齐）**：**`emit_baseline_variants.py`** 已为 **EternalBlue / BlueKeep** 增加 **`proto_parse.c` 认可的帧头**；**EternalBlue** 另含 **NetBIOS 会话封装**（**`eternalblue_nb_*.bin`**）。在全部 **43** 条 baselines 上，**`eval_shellcode_corpus`** 的 **`manifest`** 与 **`pipeline`** 均应 **`rule_ok_pct=100%`**。**`tests/test_shellcode.c`** 中含 **SMB1/SMB2 扩展、NetBIOS+SMB1、RDP TPKT、HTTP 小写方法、负样本** 等回归。

| 维度 | 现象 | 建议 |
|------|------|------|
| **协议解析覆盖面** | **T-SC-010/011/012** 已扩展 SMB2 / SMB1 Command 白名单；详见 **`docs/SHELLCODE_PROTO_SMB2_COMMAND_COVERAGE.md`**。 | **`pipeline`** 下 **`parse_ok=0`** 仍可能出现（无 **`\\r\\n\\r\\n`** 的畸形 HTTP 等）；**`manifest`** 模式仍可按标注 **`proto_kind`** 扫整段缓冲。 |
| **启发式与签名的互补** | 多数 baseline 上 **`heuristic` 接近 0**（载荷偏结构化/字符串 IOC，不像 NOP 滑板）。 | 不指望启发式覆盖此类 IOC；加强方向是：**YARA/已知规则命中后的分级**、**与行为/进程链关联**，以及对 **D2 XOR** 等变形的 **解码后再扫**（若产品路线需要）。 |
| **YARA 与内置双路径** | 无 libyara 的构建仅测 C 链；启用 YARA 时 **首条命中即返回**，规则编译顺序可能影响 **`got_rule`**。 | 在 **带 YARA 的 CI/专机** 上固定规则目录跑 **`eval_shellcode_corpus --yara ...`**，核对 **`expected_rule`** 与 **`got_rule`**；必要时约定 **规则优先级** 或拆分规则文件。 |
| **仅凭 UUID/子串的族** | PetitPotam 等仅依赖 **16 字节 UUID** 时，**误报风险**需结合会话方向、端口、调用栈等上下文压降。 | 增加 **负样本** 回归（合法 EFSR 流量片段）；在告警侧做 **置信度/关联字段**，而非无限加长子串。 |

---

## 2. 「互联网真实攻击」样本 — 合规采集与使用边界

1. **禁止**在公共仓库中提交从论坛 / 匿名网盘 / 未授权渠道下载的**完整恶意样本**（可能违反法律、雇主政策与 Git 平台 AUP）。  
2. **推荐**来源（需各自遵守 ToS 与内部流程）：  
   - **MalwareBazaar**（API Key、仅隔离机下载、**哈希登记**）；  
   - **VirusTotal** 等企业/研究接口（**不**再分发样本）；  
   - **MITRE ATT&CK** / **CVE** 公告中的 **PoC 链接** — 在**隔离机**上自行编译/截取**与你的检测面相关的片段**，**不**回传原始 zip 到 git；  
   - **合同授权**的红队 / 紫队样本库。  
3. **处理流程**：下载机与开发机网络隔离 → 病毒名+SHA256 台账 → 仅将**经变形后的评估副本**或**统计特征**（熵、长度、命中日志）写入内网 wiki；**不**将 raw 推送到本 monorepo。

---

## 3. 变形分类（每个「已知攻击」建议 ≥5 类）

下列适用于**实验室扩展**：在 **`raw_private/`** 放原始字节，用 **`apply_lab_variants.py`** 生成 5 类通用变形，再按家族追加**针对性**变形（需自行记录是否仍应命中 YARA / 内置规则）。

| ID | 变形 | 目的 |
|----|------|------|
| **D1** | **恒等** | 基线 |
| **D2** | **整段 XOR**（单字节或多字节轮密钥） | 绕过朴素字节签名 |
| **D3** | **高熵随机前缀 / 后缀** | 压 **熵阈值** 与 **启发式** |
| **D4** | **长 NOP / INT3 滑板** | 压 **NOP 滑板** 分支 |
| **D5** | **载荷重复拼接** | 压 **子串扫描** 与缓冲区大小 |
| **D6**（可选） | **子串散布**（仍保持 `has_subseq` 语义） | 压 **PrintNightmare** 类「多特征同现」 |
| **D7**（可选） | **协议封装偏移**（SMB/HTTP/RDP 合法头 + payload） | 压 **`edr_proto_find_shellcode_region`** |

仓库内 baseline 由 **`emit_baseline_variants.py`** 生成：**EternalBlue** 为 **10** 条（**D7** 直连 SMB + **NetBIOS 会话封装**各 5），其余五族各 **5** 条；更新后重跑脚本并提交 **`manifest.tsv`**（**`test_shellcode_corpus.c`** 按 manifest 行数自动校验）。新增 YARA 家族时仍建议 **≥5** 变体 / 族。

---

## 4. 实验室脚本

```bash
# 仅在你已合法取得 input.bin 的隔离机上执行；输出勿提交 git
python3 scripts/shellcode_corpus/apply_lab_variants.py /path/to/input.bin /path/to/out_dir
```

---

## 5. 与「性能压测」的关系

**P2-PERF-4** 关注 WinDivert 路径与 **`wd_stats`** / 总线丢弃；本页关注**检测逻辑**命中率与误报。二者可在同一专机实验中**串联**：先以本 baselines 验证规则回归，再注入网络层合成流量测性能。

---

## 6. 维护清单

- [ ] 新增 CVE 家族时：在 **`shellcode_known.c`** / **YARA** 落地规则后，追加 **≥5** 个合成变体到 **`emit_baseline_variants.py`**，更新 **`manifest.tsv`**（语料测试会校验 manifest 行数与文件一致）。  
- [ ] 每季度：在隔离环境用 **D1–D7** 对情报样本做一次**不提交二进制**的矩阵记录，将 **TP/FP/FN** 表写入内网 Confluence（外链勿指向直链恶意文件）。
