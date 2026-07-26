#!/usr/bin/env bash
# Archived EventIngest gRPC codegen. Product builds use HTTP ingest/control.
# Set EDR_ALLOW_LEGACY_INGEST_GRPC_CODEGEN=1 only for archived research.
set -euo pipefail
if [[ "${EDR_ALLOW_LEGACY_INGEST_GRPC_CODEGEN:-0}" != "1" ]]; then
  echo "EventIngest gRPC codegen is archived. Product path uses HTTP ingest/control." >&2
  echo "Set EDR_ALLOW_LEGACY_INGEST_GRPC_CODEGEN=1 only for archived research." >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="src/grpc_gen"
PROTO="proto/edr/v1/ingest.proto"
mkdir -p "$OUT"

resolve_protoc() {
  if command -v brew >/dev/null 2>&1; then
    local p
    p="$(brew --prefix protobuf 2>/dev/null)/bin/protoc"
    if [[ -x "$p" ]]; then
      echo "$p"
      return
    fi
  fi
  for p in /opt/homebrew/opt/protobuf/bin/protoc /usr/local/opt/protobuf/bin/protoc; do
    if [[ -x "$p" ]]; then
      echo "$p"
      return
    fi
  done
  command -v protoc 2>/dev/null || true
}

resolve_grpc_plugin() {
  if command -v brew >/dev/null 2>&1; then
    local p
    p="$(brew --prefix grpc 2>/dev/null)/bin/grpc_cpp_plugin"
    if [[ -x "$p" ]]; then
      echo "$p"
      return
    fi
  fi
  for p in /opt/homebrew/opt/grpc/bin/grpc_cpp_plugin /usr/local/opt/grpc/bin/grpc_cpp_plugin; do
    if [[ -x "$p" ]]; then
      echo "$p"
      return
    fi
  done
  command -v grpc_cpp_plugin 2>/dev/null || true
}

PROTOC="$(resolve_protoc)"
GRPC_PLUGIN="$(resolve_grpc_plugin)"
if [[ -z "$PROTOC" || ! -x "$PROTOC" ]]; then
  echo "需要 protoc（macOS: brew install protobuf，或设 PATH 指向与 libprotobuf 同版本的 protoc）" >&2
  exit 1
fi
if [[ -z "$GRPC_PLUGIN" || ! -x "$GRPC_PLUGIN" ]]; then
  echo "需要 grpc_cpp_plugin（macOS: brew install grpc）" >&2
  exit 1
fi

echo "protoc: $("$PROTOC" --version) ($PROTOC)"
echo "grpc_cpp_plugin: $GRPC_PLUGIN"

"$PROTOC" -I proto "$PROTO" \
  --cpp_out="$OUT" \
  --grpc_out="$OUT" \
  --plugin=protoc-gen-grpc="$GRPC_PLUGIN"

echo "已生成: $OUT/edr/v1/ingest.pb.* ingest.grpc.pb.*"
