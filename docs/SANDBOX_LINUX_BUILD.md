# 沙箱 / 容器内编译 Linux 版 Agent（CMake）

在 **本机未安装 CMake、gRPC 开发包** 或 **IDE 沙箱（如 Trae 等）仅提供干净 Linux 环境** 时，可用与 **`build_windows_mingw_docker.sh`** 相同思路：**用 Docker/Podman 拉 Ubuntu，在容器内 `apt` 安装 CMake + Ninja + 依赖再 `cmake` 编译**，产物落在仓库的 **`build-linux/`**（与 Windows 交叉编译的 `build-mingw/` 并列）。

## 一键脚本

```bash
cd edr-agent
chmod +x scripts/build_linux_native_docker.sh
./scripts/build_linux_native_docker.sh
```

- **前置**：宿主机已安装并启动 **Docker** 或 **Podman**（与 `docs/WINDOWS_CROSS_COMPILE.md` §0 一致）。
- **默认**：`EDR_WITH_GRPC=ON`，安装 `libgrpc++-dev` 等，链接真实 gRPC 客户端。
- **快速冒烟**（少依赖、仅验证 CMake 与主干可编）：  
  `EDR_WITH_GRPC=OFF ./scripts/build_linux_native_docker.sh`

## 环境变量（可选）

| 变量 | 说明 |
|------|------|
| `EDR_LINUX_DOCKER_IMAGE` | 默认 `ubuntu:22.04` |
| `EDR_LINUX_DOCKER_EXTRA` | 附加 `docker run` 参数，如 `--network host` |
| `EDR_CONTAINER` | 强制 `docker` 或 `podman` |
| `EDR_RUN_CTEST` | 设为 `1` 时构建后执行 `ctest`（部分测试可能依赖环境） |
| `http_proxy` / `https_proxy` | 传入容器，便于弱网 `apt` |

## 与 Windows 交叉编译脚本对比

| 脚本 | 目标 | 容器内安装 |
|------|------|------------|
| `scripts/build_windows_mingw_docker.sh` | Windows PE（MinGW） | `mingw-w64`、`cmake`、`ninja` |
| `scripts/build_linux_native_docker.sh` | Linux ELF（本仓库默认开发机架构） | `cmake`、`ninja`、`g++`、可选 gRPC/protobuf、SQLite |

## 无容器时

仍可在已安装 CMake 与依赖的机器上直接：

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

见仓库根 `README.md`「构建」一节。
