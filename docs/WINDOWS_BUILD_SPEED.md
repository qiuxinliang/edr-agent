# Windows 本机构建加速（不改变功能的前提）

在**同一份源码、同一套 CMake 选项、同一 vcpkg triplet（如 `x64-windows`）**下，下述做法只影响**编链耗时**与**磁盘占用**，**不修改**可执行文件的业务逻辑；`sccache` / vcpkg 二进制缓存在**命中**时应产生与**冷编译**等价的**目标文件**（若怀疑可做一次无缓存的干净构建对哈希或跑测试）。

| 措施 | 说明 |
|------|------|
| **工程与 vcpkg 放在本机 NVMe** | 避免将 `build/`、`vcpkg_installed`、vcpkg 源目录放在网络盘/机械盘。 |
| **Defender/杀软对构建目录排除** | 将仓库根、常用 `out/build*`、`%LOCALAPPDATA%\sccache`、本机 vcpkg 与 `.vcpkg-bincache` 等加入「排除项」，减少海量小文件实时扫描。 |
| **vcpkg Binary Caching** | 见仓库根 `scripts/vcpkg_binary_cache_env.example.ps1` 与 [Binary Caching](https://learn.microsoft.com/en-us/vcpkg/users/binarycaching)。 |
| **sccache** | 安装 [sccache](https://github.com/mozilla/sccache) 后，在 **已执行 vcvars 的** shell 中执行 `scripts/sccache_env_windows.ps1`（或手设 `SCCACHE_DIR` 到 NVMe），Configure 时加 `-DCMAKE_C_COMPILER_LAUNCHER=sccache -DCMAKE_CXX_COMPILER_LAUNCHER=sccache`。与 CI 中用法一致。 |
| **Ninja + CMake Presets** | `cmake --preset w-vcpkg-ninja-dev` 等，见主目录 `README.md`「加速编译」与 `CMakePresets.json`。 |
| **勿频繁清空 build / 勿无故改 vcpkg.json** | 减少全量重配与重装依赖。 |

## 发版/验收

- **Release 安装包**应继续使用既有流水线（如 `w-vcpkg-ninja-grpc-ort` 全特性或与 `edr-agent-client-release` 一致选项），在 CI 中做**可复现**构建；上表措施与「开发机日常调试」不冲突。  
- **仅当**你刻意换 `CMAKE_BUILD_TYPE`（如 Debug / RelWithDebInfo / Release）时，**优化与调试符号**会不同，这是预期差异，**不是**因缓存/杀软排除本身引入的逻辑分支。

## 与「只 MinGW/交叉编」的区分

- 仓库内 `build_windows_mingw` 等产物与 **MSVC** ABI 不同，**不能**与上述 MSVC+vcpkg 快编混作同一发版；快编仅指 **同一目标ABI 下**缩短时间。
