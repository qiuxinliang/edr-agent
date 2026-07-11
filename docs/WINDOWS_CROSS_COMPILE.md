# Windows 目标交叉编译（MinGW）— ghcr 超时 / Docker Desktop 不可用

`brew install mingw-w64` 会从 **ghcr.io** 拉取 bottle，在国内或弱网环境下常出现 **`curl: (56) Recv failure: Operation timed out`**。若 **Docker Desktop 无法正常启动**，下面按「是否仍要用容器」分组。

## 0. Docker Desktop 不可用时的优先路径（macOS）

### A. 仍想用「Ubuntu + apt」思路（不经 ghcr）

不必依赖 **Docker Desktop**。任选一种能提供 **`docker`/`podman` CLI + 运行 Linux 容器** 的方式即可，脚本会自动探测：

| 方式 | 典型命令 |
|------|-----------|
| **Colima** + Docker CLI | `brew install colima docker`，然后 `colima start`，再 `./scripts/build_windows_mingw_docker.sh` |
| **Podman** | `brew install podman`，`podman machine init && podman machine start`，再同上 |
| **OrbStack** 等 | 安装后保证 `docker info` 成功即可 |

指定引擎（可选）：

```bash
EDR_CONTAINER=podman ./scripts/build_windows_mingw_docker.sh
```

`./scripts/build_windows_mingw.sh` 在本机没有 `x86_64-w64-mingw32-gcc` 时，若 **docker 或 podman** 任一可用，也会进入上述容器逻辑。

### B. 完全不用容器：MacPorts

```bash
sudo port install mingw-w64
cd edr-agent && ./scripts/build_windows_mingw.sh
```

MacPorts 从自有镜像构建/拉取，**不经过** Homebrew ghcr。若 `port` 也慢，可按 [MacPorts 文档](https://guide.macports.org/chunked/installing.macports.html) 配置镜像。

### C. 完全不用容器：`MINGW_PREFIX`

本仓库的 **`cmake/mingw-w64-x86_64.cmake`** 要求工具链 **`bin/`** 下存在 **`x86_64-w64-mingw32-gcc`**（GCC 风格前缀）。

- 将**已提供该可执行文件**的工具链解压到任意目录后：

```bash
export MINGW_PREFIX=/path/to/toolchain   # 目录下须有 bin/x86_64-w64-mingw32-gcc
./scripts/build_windows_mingw.sh
```

- **[llvm-mingw](https://github.com/mstorsjo/llvm-mingw/releases)** 以 **Clang** 为主，默认不提供上述 GCC 文件名；若要用 llvm-mingw，需另写 CMake toolchain，**不在**当前 `build_windows_mingw.sh` 路径内。
- 常见做法是：在 macOS 上用 **MacPorts** 或容器内 **apt 的 mingw-w64**，与「自带 GCC 前缀」的发行版一致即可。

## 1. Docker Desktop 正常时（可选）

宿主机安装并启动 **Docker Desktop**，在仓库 `edr-agent` 目录执行：

```bash
chmod +x scripts/build_windows_mingw_docker.sh
./scripts/build_windows_mingw_docker.sh
```

镜像内使用 **Ubuntu 官方 apt 源**安装 `mingw-w64`、`cmake`、`ninja-build`，与 ghcr 无关。`apt-get update` 失败会自动重试最多 5 次。

**网络仍不稳定时**可尝试：

```bash
EDR_MINGW_DOCKER_EXTRA='--network host' ./scripts/build_windows_mingw_docker.sh
```

若宿主机已配置代理，确保导出 `http_proxy`/`https_proxy`（或 `HTTP_PROXY`/`HTTPS_PROXY`），脚本会传入容器。

**换基础镜像**（例如更近的 LTS）：

```bash
EDR_MINGW_DOCKER_IMAGE=ubuntu:24.04 ./scripts/build_windows_mingw_docker.sh
```

## 2. 仍想用 Homebrew 时（可选）

- 多次重试：`brew fetch --retry=5 mingw-w64` 后再 `brew install mingw-w64`
- 按 [Homebrew 官方文档](https://docs.brew.sh/Installation) 配置 **Bottle 镜像**（镜像地址随时间可能变化，请以文档为准）

## 3. Docker Desktop 常见故障（简要）

若必须用 Docker Desktop 而非 Colima/Podman：

- **完全退出再打开**；macOS 上检查 **虚拟化** 是否被其它安全软件禁用。
- **Settings → Troubleshoot**：Restart / Reset to factory defaults（会清本地镜像与容器，先备份数据）。
- 资源不足时适当提高 **Memory / Disk** 配额。

仍无法恢复时，优先采用上文 **Colima / Podman / MacPorts**，不必卡在 Docker Desktop。

## 产物位置

成功后在仓库内 **`edr-agent/build-mingw/`** 下出现 **`FDSensor.exe`** / **`edr_agent.exe`**（以构建日志为准）。该二进制为 **MinGW ABI**，与 MSVC 产物不同。构建脚本会递归检查 PE import table，将 vcpkg 和 MinGW 工具链的非系统运行时 DLL 复制到可执行文件同目录；任何非系统 DLL 无法解析时构建直接失败，禁止只发布孤立 EXE。

运行时闭包由 **`scripts/stage_mingw_runtime_dlls.sh`** 负责，会继续检查已复制 DLL 的下一层依赖（例如 curl 引入的 nghttp2/zlib），而不是只处理 `FDSensor.exe` 的直接依赖。

## 终端编译注意要点

### 1. 保留构建中间文件（便于后查）

- **不要随意**对构建目录做 `rm -rf` 后再排错：失败分析依赖目录内保留的 **`CMakeCache.txt`**、**`build.ninja`**、目标文件 **`*.obj`**、依赖 **`*.d`**，以及若生成的 **`compile_commands.json`**。
- 约定：本地与终端流水线在**未有意全量清理**前，保留上一次完整配置与编译产物，便于对照日志、复现链接行与头文件路径。

### 2. 产品主线 no-gRPC 与脚本默认行为（重要）

端点产品构建已移除 gRPC 客户端，MinGW 交叉编译只验证 Windows 目标主线代码是否能通过编译：

- `scripts/build_windows_mingw.sh` / `scripts/build_windows_mingw_docker.sh` 固定传入 **`-DEDR_WITH_GRPC=OFF`**。
- `EDR_REQUIRE_GRPC` 已废弃，不再参与脚本检查。
- 需要 curl/nghttp2 等 Windows 目标依赖时，设置 **`EDR_MINGW_DEPS_PREFIX`** 指向 vcpkg `installed/<triplet>`。

```bash
EDR_MINGW_DEPS_PREFIX=/path/to/vcpkg/installed/x64-mingw-dynamic \
./scripts/build_windows_mingw.sh
```

Windows 客户端包要求真实 libyara 扫描能力；MinGW 路径也会强制：

- **`EDR_WITH_YARA=ON`**、**`EDR_REQUIRE_YARA=ON`**、**`VCPKG_MANIFEST_FEATURES=yara`**。
- **`EDR_MINGW_DEPS_PREFIX`** 必须指向 vcpkg 的 **MinGW 动态 triplet**（推荐 **`x64-mingw-dynamic`**），且包含：
  - **`include/yara.h`** 或 **`include/yara/yara.h`**；
  - **`share/unofficial-libyara/unofficial-libyara-config.cmake`**；
  - YARA 运行库 DLL，或 vcpkg 当前 YARA port 生成的静态 archive（如 `lib/liblibyara.a`）。
  - **`bin/*yara*.dll`** / **`bin/libyara*.dll`**。
- 不要把 **`EDR_MINGW_DEPS_PREFIX`** 指向 MSVC **`x64-windows`** 安装树；ABI 不匹配，且不会作为 MinGW 客户端包的有效运行时来源。

旧变量 **`EDR_MINGW_GRPC_PREFIX`** 仅作为兼容别名保留，建议新脚本和文档统一使用 **`EDR_MINGW_DEPS_PREFIX`**。

### 3. MinGW 侧目标依赖（vcpkg 等）

**让 CMake 找到 Windows 目标的包**（发布/客户端包推荐 **vcpkg** 的 `x64-mingw-dynamic` 安装树）：

- **CONFIG 路径（vcpkg 典型布局）**：`<prefix>/share/curl/CURLConfig.cmake`、`<prefix>/share/openssl/OpenSSLConfig.cmake`、`<prefix>/share/sqlite3/SQLite3Config.cmake`、`<prefix>/share/unofficial-libyara/unofficial-libyara-config.cmake` 等（部分发行版也可能在 `lib/cmake/...`，以实际树为准）。
- 构建时传入前缀，例如：

```bash
EDR_MINGW_DEPS_PREFIX=/path/to/vcpkg/installed/x64-mingw-dynamic \
./scripts/build_windows_mingw.sh
```

MSVC Windows 发布构建使用 **`x64-windows`**，MinGW 交叉构建使用 **`x64-mingw-dynamic`** 这类 MinGW 动态 triplet；两者不要混用。Windows 上 **`EDR_REQUIRE_YARA=ON`** 只接受 vcpkg config package 暴露的 **`unofficial::libyara::libyara`** target，缺少 vcpkg `yara` feature 或缺少 YARA runtime DLL 时，configure / staging / packaging 会直接失败。

**vcpkg 根目录路径：** 含**空格**的路径曾导致部分 port（如 OpenSSL）配置失败；可将 **`vcpkg`** 目录同步到无空格路径（例如 **`/tmp/vcpkg-mingw-deps`**）再执行 **`install --x-feature=yara`**。**edr-agent** 源码可仍在原路径。
