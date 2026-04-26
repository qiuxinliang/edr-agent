# §19.5 gRPC `ReportSnapshot`（后续接入说明）

**产品策略（已确认）**：生产环境以 **REST** 为权威；本文所述 gRPC 为**可选演进**，不替代当前默认路径。

当前 Agent **默认**通过 **REST + `curl`** 上报攻击面 JSON（与平台 `POST …/attack-surface` 对齐）。详设 §19.5 的 **`AttackSurfaceService.ReportSnapshot`** 为 **gRPC**，若落地需与服务端**单独约定**；与 REST **二选一或并存**须明确幂等与监控。

## 本仓库已有 Proto

- `proto/edr/v1/attack_surface.proto`：`AttackSurfaceService` / `AttackSurfaceSnapshotProto` 等。

## 生成 C++ 代码

```bash
./scripts/gen_attack_surface_proto_cpp.sh
```

若已安装 `grpc_cpp_plugin`，会同时生成 `attack_surface.grpc.pb.{cc,h}`；否则仅生成 `attack_surface.pb.{cc,h}`。

**注意**：生成代码与 **本机 protobuf 运行时版本** 必须一致，否则链接或运行期会报 `PROTOBUF_VERSION` 不匹配。CI/发布机应在固定环境中生成并检入，或由 CMake 在配置阶段调用 `protoc`（需维护版本）。

## 接入 `grpc_client_impl.cpp` 的建议路径

1. 将生成的 `.pb.cc` / `.grpc.pb.cc` 加入 `CMakeLists.txt`（与 `ingest.pb.cc` 同级，并施加相同的弃用告警抑制）。
2. 在已有 `EventIngest::Stub` 通道上，**若**服务端将 `ReportSnapshot` 挂在同一端口，可增加 `AttackSurfaceService::Stub` 或 `grpc::GenericStub` 对 `/edr.v1.AttackSurfaceService/ReportSnapshot` 做 unary 调用。
3. 将 `write_snapshot_json` 产出的结构化数据映射为 `AttackSurfaceSnapshotProto`（或先保留 REST，仅对镜像流量做 gRPC）。

在未完成映射与联调前，**不要**在默认路径启用 gRPC 双写，以免与 REST 重复或序列化不一致。
