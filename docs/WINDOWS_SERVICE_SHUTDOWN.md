# Windows 服务停止 vs 控制台关机路径（§P2c **S1**）

**目标**：**`edr_agent_shutdown`** 被调用时，队列落盘、线程收敛等行为与 **Ctrl+C** 一致。

---

## 1. 现状（控制台 / 前台）

- **`agent_main.c`**：**`SetConsoleCtrlHandler(edr_on_console_ctrl, TRUE)`**  
  **`CTRL_C_EVENT` / `CTRL_CLOSE_EVENT` / `CTRL_BREAK_EVENT`** → **`edr_agent_shutdown`**。

---

## 2. 内置 **`--service` 模式（已实现）**

- **`main`** 若发现 **`--service`**，则调用 **`StartServiceCtrlDispatcher`**，由 **`ServiceMain`** 拉起与控制台相同的 **`edr_agent_application_main`**（同一初始化链 + **`edr_agent_run`**）。
- **`RegisterServiceCtrlHandler`**：**`SERVICE_CONTROL_STOP` / `SERVICE_CONTROL_SHUTDOWN`** → **`SERVICE_STOP_PENDING`** → **`edr_agent_shutdown(edr_agent_main_active_for_stop())`**。
- **服务名**须与 **`sc create <名称>`** 一致，并出现在 **`StartServiceCtrlDispatcher`** 的 **`SERVICE_TABLE_ENTRY`** 中：
  - **`binPath`** 推荐：  
    `"C:\Program Files\EDR\edr_agent.exe" --service EdrAgent --config "C:\ProgramData\EDR\agent.toml"`  
    其中 **`EdrAgent`** 与 **`sc create EdrAgent ...`** 同名。
  - 若 **`--service`** 后省略名称，默认 **`EdrAgent`**；或设环境变量 **`EDR_SERVICE_NAME`**（须仍与 **`sc create`** 名一致）。
- **勿从资源管理器双击**带 **`--service`** 的进程期望跑起来：未由 SCM 启动时 **`StartServiceCtrlDispatcher`** 会失败（约 **1063**），stderr 有说明；正常联调用 **`sc start <服务名>`**。

---

## 3. 与包装器（NSSM 等）的关系

- 仍可选用 **NSSM / 厂商包装器**；内置 **`--service`** 为「单进程直连 SCM」的默认路径，便于与 **`sc stop`** 对齐 **`edr_agent_shutdown`**。

---

## 4. 验收建议

| 步骤 | 预期 |
|------|------|
| 前台 **`edr_agent.exe --config …`**，**Ctrl+C** | stderr 预处理汇总、退出码 0。 |
| **`sc create` + `sc start`**，**`sc stop`** | 进程优雅退出；与 Ctrl+C 同类日志。 |

---

**关联**：**`docs/WINDOWS_DEPLOY.md`** §4、`README.md` **P2 §9**。
