# forensic_collector_builtin（C baseline 兜底采集器）

独立的取证采集器二进制，由 agent 的 `src/forensic/deep_collector.c` 通过 fork/CreateProcess 调起。
**仅本地采集 + 打包，绝不联网**；上传由 agent 的 transport v2 通道负责。

> **命名裁决（重要）**：本 C target 的输出名为 **`forensic_collector_builtin`**（系统命令级，**兜底**用）。
> 生产**主**采集器是 `forensic-collector/`（Go 适配器，封装官方 Velociraptor v0.77.1），输出规范名 `forensic_collector(.exe)`。
> agent 采集层级：`velo(主) → builtin(本程序) → in-process`。详见 `docs/FORENSIC_INDEX.md`。

## 构建

```bash
# 随 agent 构建（默认开启）→ 产出 forensic_collector_builtin(.exe)
cmake -B build -DEDR_WITH_FORENSIC_COLLECTOR=ON
cmake --build build --target forensic_collector

# 或单文件直接编译（无第三方依赖）
cc -O2 -o forensic_collector_builtin tools/forensic_collector/main.c
```

## CLI 契约（与 deep_collector.c 对齐）

```
forensic_collector --scope=<triage|standard|full|targeted|all> \
                   --output-dir=<dir> --timeout=<sec> \
                   [--request=<reqfile>] [--out-file=<bundle.tar.gz>] [--reason=<str>]
```

- 同时接受 `--key=value` 与 `--key value`。
- 给了 `--out-file`：把 `--output-dir` 打包为该 tar.gz（**agent 上传的前提**）。
- `--request`：JSON 命令 payload，`full/targeted/all` scope 下按其中 `"path"` 拷贝目标文件。
- 退出码：`0` 成功；非 0 失败。

## 部署与信任链（agent 侧 env）

| env | 作用 |
|---|---|
| `EDR_FORENSIC_COLLECTOR=1` | 启用外移采集器（否则 agent 走 in-process 兜底） |
| `EDR_FORENSIC_COLLECTOR_BIN` | collector 路径（默认 POSIX `./forensic_collector` 或 PATH；Win `C:\Program Files\FDSecurity\collector\forensic_collector.exe`） |
| `EDR_FORENSIC_COLLECTOR_SHA256` | 执行前 SHA-256 pin 校验 |
| `EDR_FORENSIC_COLLECTOR_STRICT=1` | 外部失败不回退 in-process |
| `EDR_FORENSIC_COLLECTOR_URL` | 缺失时下载（配合 SHA256 验签） |

## 冒烟测试

```bash
BIN=./build/forensic_collector ./tools/forensic_collector/contract_smoke.sh
```

## 采集范围

| scope | 采集内容 |
|---|---|
| `triage` | system_info / process_list / network |
| `standard` | + startup/persistence、services、scheduled tasks、Run 键 |
| `full` / `targeted` / `all` | + 按 `--request` 拷贝目标文件 |

> 当前为 v1.0.0 baseline（系统命令驱动，契约正确、端到端可用）。
> KAPE/Velociraptor 级 raw/VSS、$MFT、内存采集等深度能力为后续增强，见 `docs/FORENSIC_COLLECTOR_SPEC.md`。
