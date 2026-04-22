# 自保护回归清单（§P2c **S2**）

**默认**：**`[self_protect] job_object_windows`**、**`anti_debug`** 在 **CI / 默认 `agent.toml`** 中为 **关闭**，避免破坏自动化与开发机调试。

---

## 1. 何时跑

- 发版前 **Windows** 专机；或合并涉及 **`self_protect.c` / `main.c` / Job Object** 的 PR 后。

---

## 2. 勾选项

| 项 | 配置 | 操作 | 预期 |
|----|------|------|------|
| **Job Object** | **`[self_protect] job_object_windows = true`** | 启动 **`edr_agent`**，stderr 含 **`[self_protect] 已绑定 Windows Job Object`** | 子进程受限策略符合设计（与 **§13** 一致） |
| **Anti-debug** | **`[self_protect] anti_debug = true`** | 附着调试器后观察 **`edr_self_protect_format_status`** / watchdog 日志 | 出现 **`检测到调试器附着`** 审计行（**不**默认退出） |
| **关闭** | 上述改回 **false** | **`ctest`** / **`edr-agent-ci`** | 与 **默认** CI 矩阵一致 |

---

## 3. ctest 相关

- 仓库 **`edr_agent`** 相关用例见 **`CMakeLists.txt`** 与 **`scripts/ci_build.sh`**；**无** Job Object 专用自动化用例时，本清单以 **手动** 为主。

---

**关联**：**`docs/WINDOWS_SHELLCODE_FORENSIC_TODO.md` §P2c**、**`README.md` P2 §9**。
