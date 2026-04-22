#!/usr/bin/env bash
# 可选：用与 gRPC 依赖一致的 protoc 生成 fl.pb（仅当需要 C++ Message 类型时）。
# 端侧上传实现为 fl_pb_wire.c + fl_grpc_upload.cpp（ByteBuffer + GenericStub），
# 不要求检入 fl.pb.cc，且勿用系统 protoc 覆盖 ingest 的 protobuf 主版本。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROTO="edr/v1/fl.proto"
if ! command -v protoc >/dev/null; then
  echo "protoc not found" >&2
  exit 1
fi
protoc -I proto --cpp_out=src/grpc_gen "$PROTO"
GEN="$(command -v grpc_cpp_plugin 2>/dev/null || true)"
if [[ -n "${GEN}" ]]; then
  protoc -I proto --grpc_out=src/grpc_gen --plugin=protoc-gen-grpc="${GEN}" "$PROTO"
  echo "OK: fl.pb + fl.grpc.pb generated (ensure protoc matches protobuf::libprotobuf)"
else
  echo "grpc_cpp_plugin not found; only fl.pb.cc generated."
fi
