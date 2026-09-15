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
- 给了 `--out-file`：只打包本次成功采集的文件。历史包、旧 scope 的文件、请求及日志不会进入归档；已有同名产物不会被覆盖。
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

## 容量与生命周期保护

- Agent 为每次外部采集使用独立的 `.work` 目录，归档位于该目录外；in-process 兜底也采用相同布局。
- baseline 采集总量上限为 64 MiB，最多 64 个文件（含元数据）。限制按实际写入累计，不能用多个文件绕过；超限失败，不上传不完整快照。
- baseline 开始前至少需要 256 MiB 可用空间，给原始文件、压缩包及 Agent 队列保留空间。显式内存转储仍使用其自身策略。
- Agent 父进程强制执行采集超时，Windows 使用 Job Object、POSIX 使用进程组终止子孙进程；超时不会再启动下一层取证兜底。失败、取消或超时的未完成归档会删除，已完成且进入上传重试队列的产物保留。
- Windows 打包失败直接失败，不再把 ZIP 内容写到 `.tar.gz` 路径，也不以残留文件存在作为成功依据。
- 平台自动补证按租户和终端串行检查预算，10 分钟内只允许一个快照；旧告警的延迟分析也检查之后已有的取证任务。阻止结果写入决策审计，告警、人工取证与防护动作保持可用。

回归测试只使用合成数据，并清理测试产物：

```bash
BIN=/path/to/forensic_collector_builtin python3 tools/forensic_collector/test_bundle.py
ctest --test-dir /path/to/build -R 'builtin_forensic_bundle|response_forensic_path_contract|deep_collector_manifest' --output-on-failure
```

发布时必须同时更新 Agent 与内置 collector，并重新生成包完整性清单；不能直接替换已安装目录中的 EXE 绕过完整性检查。
