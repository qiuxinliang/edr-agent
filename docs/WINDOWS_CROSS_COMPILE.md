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

成功后在仓库内 **`edr-agent/build-mingw/`** 下出现 **`edr_agent.exe`**（或构建日志中的等价目标）。该二进制为 **MinGW ABI**，与 MSVC 产物不同，仅作交叉编译验证。

## 终端编译注意要点

### 1. 保留构建中间文件（便于后查）

- **不要随意**对构建目录做 `rm -rf` 后再排错：失败分析依赖目录内保留的 **`CMakeCache.txt`**、**`build.ninja`**、目标文件 **`*.obj`**、依赖 **`*.d`**，以及若生成的 **`compile_commands.json`**。
- 约定：本地与终端流水线在**未有意全量清理**前，保留上一次完整配置与编译产物，便于对照日志、复现链接行与头文件路径。

### 2. gRPC 真客户端与脚本默认行为（重要）

为避免「CMake 过了但实际仍编进 **`grpc_client_stub.c`**」：

- `scripts/build_windows_mingw.sh` / `scripts/build_windows_mingw_docker.sh` 默认 **`EDR_REQUIRE_GRPC=1`**：若 **`build-mingw/CMakeCache.txt`** 中 **`EDR_GRPC_CLIENT_AVAILABLE:INTERNAL`** 不为 **`1`**，脚本直接失败。
- 临时只想验证非 gRPC 模块时：

```bash
EDR_REQUIRE_GRPC=0 ./scripts/build_windows_mingw.sh
```

集成与发布环境建议始终保持 **`EDR_REQUIRE_GRPC=1`**，确保产物含真实 gRPC 客户端。

### 3. MinGW 侧 gRPC / Protobuf（vcpkg 等）

**让 CMake 找到 Windows 目标的包**（常见为 **vcpkg** 的 `x64-mingw-static` 安装树）：

- **CONFIG 路径（vcpkg 典型布局）**：`<prefix>/share/grpc/gRPCConfig.cmake`、`<prefix>/share/protobuf/protobuf-config.cmake`（部分发行版也可能在 `lib/cmake/...`，以实际树为准）。
- 构建时传入前缀，例如：

```bash
EDR_MINGW_GRPC_PREFIX=/path/to/vcpkg/installed/x64-mingw-static \
./scripts/build_windows_mingw.sh
```

**交叉编译时 `protoc`：** `gRPCConfig.cmake` 会拉取 **Protobuf**；宿主机跑 CMake 时必须能解析 **`Protobuf_PROTOC_EXECUTABLE`**。本仓库 **`cmake/mingw-w64-x86_64.cmake`** 在设置了 **`EDR_MINGW_GRPC_PREFIX`** 时，会将 **`Protobuf_PROTOC_EXECUTABLE`** 指到 **`<prefix>/tools/protobuf/protoc`**（vcpkg 提供的可在 macOS 上运行的生成器）。若仍失败，请确认该路径存在且与前缀一致。

**vcpkg 根目录路径：** 含**空格**的路径曾导致部分 port（如 OpenSSL）配置失败；可将 **`vcpkg`** 目录同步到无空格路径（例如 **`/tmp/vcpkg-mingw-grpc`**）再执行 **`install`**。**edr-agent** 源码可仍在原路径。

**生成代码与库版本一致：** `proto/edr/v1/ingest.proto` 生成的 **`src/grpc_gen/edr/v1/ingest.{pb.h,pb.cc,grpc.pb.h,grpc.pb.cc}`** 必须与**实际链接的** `libprotobuf` / 头文件版本一致（`ingest.pb.h` 内有 **`PROTOBUF_VERSION`** 检查）。升级 vcpkg 中的 **protobuf/grpc** 后，请用**同一安装前缀**下的 **`protoc`**，以及宿主机可用的 **`grpc_cpp_plugin`**（vcpkg 常见在 **`installed/<host-triplet>/tools/grpc/grpc_cpp_plugin`**）重新生成，避免不完整类型或 `#error` 版本不匹配。

**可选：grpc 大对象：** 若 MinGW 编 **grpc** 时出现 **`.obj` file too big**，可在对应 **triplet** 中为 **`VCPKG_C_FLAGS` / `VCPKG_CXX_FLAGS`** 增加 **`-Wa,-mbig-obj`**（见 vcpkg **community** triplet 实践）。
