#!/usr/bin/env bash
# 由 proto/edr/v1/attack_surface.proto 生成 C++ protobuf 源码（供后续 gRPC ReportSnapshot 接入）。
# gRPC 存根需 grpc_cpp_plugin，请与本机 gRPC/protobuf 版本一致后再生成并接入 grpc_client_impl.cpp。
#
# 用法（在 edr-agent 根目录）：
#   chmod +x scripts/gen_attack_surface_proto_cpp.sh
#   ./scripts/gen_attack_surface_proto_cpp.sh
#
# 依赖：protoc、grpc_cpp_plugin（通常在 `$(brew --prefix grpc)/bin/grpc_cpp_plugin`）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="src/grpc_gen"
PLUGIN="${GRPC_CPP_PLUGIN:-}"
if [[ -z "$PLUGIN" ]]; then
  for c in "$(command -v grpc_cpp_plugin 2>/dev/null)" \
           "/opt/homebrew/opt/grpc/bin/grpc_cpp_plugin" \
           "/usr/local/opt/grpc/bin/grpc_cpp_plugin"; do
    if [[ -n "$c" && -x "$c" ]]; then
      PLUGIN="$c"
      break
    fi
  done
fi
mkdir -p "$OUT"
if [[ -n "$PLUGIN" ]]; then
  protoc -I proto --cpp_out="$OUT" --grpc_out="$OUT" --plugin=protoc-gen-grpc="$PLUGIN" \
    proto/edr/v1/attack_surface.proto
  echo "OK: $OUT/edr/v1/attack_surface.pb.{h,cc} + attack_surface.grpc.pb.{h,cc} (plugin=$PLUGIN)"
else
  protoc -I proto --cpp_out="$OUT" proto/edr/v1/attack_surface.proto
  echo "OK: $OUT/edr/v1/attack_surface.pb.{h,cc} only (no grpc_cpp_plugin; install grpc or set GRPC_CPP_PLUGIN)"
fi
