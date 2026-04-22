# deploy（Windows 安装与服务 — **AGT-006 已关闭**）

本目录为 **AGT-006** 的 **文档型交付**（非 MSI）：生产安装包构建见 **edr-backend**。

| 文档 | 说明 |
|------|------|
| **[docs/WINDOWS_DEPLOY.md](../docs/WINDOWS_DEPLOY.md)** | 服务账户（含 LOCAL SERVICE 讨论）、ETW/WinDivert **预检清单**、`sc.exe` 示例草案、与 **AGENT_INSTALLER** / 平台 zip 的关系 |
| **[docs/AGENT_INSTALLER.md](../docs/AGENT_INSTALLER.md)** | 注册并生成 **`agent.toml`** |

后续若增加 **示例脚本**（如 `examples/service_install.ps1`），可置于本目录并在此表更新。
