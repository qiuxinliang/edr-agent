# 联邦学习端侧构建与 CI（gRPC / OpenSSL / HTTPS）

## 选项一览

| CMake 选项 | 作用 |
|------------|------|
| `EDR_WITH_FL_TRAINER` | 编译 `src/fl_trainer/`（联邦线程、HTTP/gRPC 上传等） |
| `EDR_WITH_FL_KAFKA` | 编译 **librdkafka** Round 消费者（`fl_kafka_rdkafka.c`）；需 **`EDR_WITH_FL_TRAINER=ON`** 且系统已安装 **librdkafka**（`pkg-config rdkafka` 或 `CMAKE_PREFIX_PATH` 指向含 `librdkafka/rdkafka.h` 与 `rdkafka` 库的路径）。未开启时使用 `fl_kafka_poll_noop.c`，行为与原先 stub 轮询一致 |
| `[fl] gradient_chunk_size_kb` | 梯度密文**分块上传**单块上限（16–4096 KB）；密文大于该值时 HTTP/gRPC 按片顺序发送，共用 `gradient_upload_id`（见 `fl.proto` / `fl_gradient_upload.c`） |
| `EDR_WITH_GRPC` | 启用 **EventIngest** 与 **FL `UploadGradients`** 的 gRPC 客户端（需 `find_package(gRPC)` 成功） |
| `EDR_WITH_LIBTORCH` | FL 本地 `local_train` 使用 LibTorch（需 `Torch` / `TORCH_ROOT`） |

OpenSSL：`find_package(OpenSSL)` 成功且启用 FL 时定义 **`EDR_HAVE_OPENSSL_FL`**，链接 **`OpenSSL::SSL`**（HTTPS）与 **`OpenSSL::Crypto`**（`fl_crypto`）。**FL3**（ECDH/HKDF/GCM）使用 **`EVP_PKEY` / `EVP_PKEY_fromdata` / `EVP_PKEY_derive`**，需 **OpenSSL 3.0+**。

### 梯度封装（`fl_crypto`）

| 环境 / 配置 | 行为 |
|-------------|------|
| 默认 | `FLSTUB1` + 明文梯度（仅开发） |
| `EDR_FL_CRYPTO_OPENSSL=1` + `[fl] coordinator_secp256r1_pubkey_hex`（33 或 65 字节 SEC1 十六进制） | **FL3**：P-256 临时 ECDH + HKDF-SHA256 + AES-256-GCM；包内带客户端临时公钥，**无**密钥明文附尾 |
| `EDR_FL_CRYPTO_OPENSSL=1` 且无公钥 | 封装失败（`-4`），除非 `EDR_FL_CRYPTO_ALLOW_INSECURE_FL2=1` 启用已废弃的 **FL2**（演示用，勿用于生产） |
| 协调端解密 | `fl_crypto_coordinator_open_fl3`：P-256 **私钥** 32 字节 big-endian 标量 + FL3 blob → 明文（与端上 `fl_crypto_seal_gradient` / HKDF `info`=`edr-fl-gradient-v3` 一致） |
| 平台最小 HTTP / gRPC 接收端 | `edr-backend/platform/cmd/fl-coordinator` + `FL_COORDINATOR_MINIMAL.md` + **P1**：`FL_COORDINATOR_P1.md`（`DATABASE_DSN`、Kafka 公告、`FedAvg` / L2 门） |
| `ctest -R fl_crypto_fl3` | 需 OpenSSL + `EDR_WITH_FL_TRAINER=ON`，验证 FL3、端上 `open` 为 `-5`、协调端 `open_fl3` 还原明文 |

## 可复现：Ubuntu（与 CI 一致）

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build \
  libsqlite3-dev libssl-dev \
  protobuf-compiler libprotobuf-dev libgrpc++-dev protobuf-compiler-grpc
```

配置时让 CMake 找到 gRPC 的 `gRPCConfig.cmake`（常见路径如下，按机器调整）：

```bash
cd edr-agent
cmake -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DEDR_WITH_GRPC=ON \
  -DEDR_WITH_FL_TRAINER=ON \
  -DCMAKE_PREFIX_PATH="/usr/lib/x86_64-linux-gnu/cmake"
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

若仍找不到 gRPC，可显式设置（路径以 `dpkg -L libgrpc++-dev | grep gRPCConfig` 为准）：

```bash
cmake -B build -DgRPC_DIR=/usr/lib/x86_64-linux-gnu/cmake/grpc ...
```

## macOS（Homebrew）

```bash
brew install grpc openssl sqlite
cmake -B build -DEDR_WITH_GRPC=ON -DEDR_WITH_FL_TRAINER=ON \
  -DCMAKE_PREFIX_PATH="$(brew --prefix grpc);$(brew --prefix openssl)"
```

**AVE ↔ `fl_samples.db` 桥接自检**（不依赖 **`EDR_WITH_FL_TRAINER`**，仅需 SQLite）：`ctest --test-dir build -R fl_ave_samples_bridge --output-on-failure`。

## HTTPS 梯度上传（`coordinator_http_url` 为 `https://`）

需 **`EDR_HAVE_OPENSSL_FL`**（安装 OpenSSL 开发包并成功 `find_package`）。

- 默认校验服务端证书（`SSL_CTX_set_default_verify_paths`）。
- 额外 CA：`EDR_FL_HTTPS_CA_FILE=/path/to/ca.pem`
- 仅开发联调（**不安全**）：`EDR_FL_HTTPS_INSECURE=1` 关闭证书校验。

## Kafka Round 公告（`edr.fl_round_announce`，可选）

与平台 **`RoundAnnounceV1`** JSON 一致（见 `edr-backend/platform/internal/flcoord/round_kafka.go`）。开启 **`EDR_WITH_FL_KAFKA=ON`** 并安装 **librdkafka** 后，`fl_kafka_poll_round_stub` 会非阻塞拉取一条消息并调用已注册的回调（`fl_round.c` 内设置 `s_round_id` / `s_has_round`）。

| 环境变量 | 说明 |
|----------|------|
| `EDR_FL_KAFKA_BROKERS` | 必填（否则不创建 consumer，等价于无 Kafka）。逗号分隔 broker 列表，与协调端一致 |
| `EDR_FL_KAFKA_ROUND_TOPIC` | 默认 `edr.fl_round_announce` |
| `EDR_FL_KAFKA_GROUP` | 消费者组，默认 `edr-agent-fl` |
| `EDR_FL_KAFKA_TENANT` | 若设置，仅当 JSON `tenant_id` 与该值相等时接受公告；未设置则不过滤租户 |

未设置 `EDR_FL_KAFKA_BROKERS` 时，不链接 rdkafka 亦可运行；`mock_round_interval_s` 仍可用于本地假 Round。

## gRPC FL 上传（`coordinator_grpc_addr`）

需 **`EDR_HAVE_GRPC_FL`**（gRPC 可用且 `EDR_WITH_FL_TRAINER=ON`）。实现见 `fl_grpc_upload.cpp`（`GenericStub` + `fl_pb_wire`，不检入与 ingest 版本冲突的 `fl.pb.cc`）。

- 明文：`EDR_FL_GRPC_INSECURE=1`
- TLS 根证书：`EDR_FL_GRPC_CA_PEM=/path/to/ca.pem`

## 脚本

仓库内 **`scripts/cmake_fl_stack.sh`**：封装上述常见 `CMAKE_PREFIX_PATH` 与选项（便于本地与 CI 对齐）。
