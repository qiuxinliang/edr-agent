#!/usr/bin/env bash
# 由 proto/edr/v1/ingest.proto 生成 C++ gRPC 桩到 src/grpc_gen/edr/v1/
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="src/grpc_gen"
PROTO="proto/edr/v1/ingest.proto"
mkdir -p "$OUT"

if ! command -v protoc >/dev/null 2>&1; then
  echo "需要系统 protoc" >&2
  exit 1
fi
GRPC_PLUGIN="$(command -v grpc_cpp_plugin || true)"
if [[ -z "$GRPC_PLUGIN" ]]; then
  echo "需要 grpc_cpp_plugin（PATH）" >&2
  exit 1
fi

protoc -I proto "$PROTO" \
  --cpp_out="$OUT" \
  --grpc_out="$OUT" \
  --plugin=protoc-gen-grpc="$GRPC_PLUGIN"

echo "已生成: $OUT/edr/v1/ingest.pb.* ingest.grpc.pb.*"
