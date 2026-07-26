#!/usr/bin/env bash
set -euo pipefail

PROGRAM="${EDR_EBPF_PROGRAM:-/usr/local/lib/edr-agent/edr-linux.bt}"
PIPE="${EDR_LINUX_EBPF_TRACE_PIPE_PATH:-/run/edr-agent/ebpf-events.pipe}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "edr eBPF loader must run as root" >&2
  exit 1
fi
if ! command -v bpftrace >/dev/null 2>&1; then
  echo "bpftrace is required for the managed Linux eBPF source" >&2
  exit 1
fi
if [[ ! -f "$PROGRAM" ]]; then
  echo "missing bpftrace program: $PROGRAM" >&2
  exit 1
fi

install -d -m 0750 "$(dirname "$PIPE")"
if [[ -e "$PIPE" && ! -p "$PIPE" ]]; then
  echo "refusing to replace non-FIFO path: $PIPE" >&2
  exit 1
fi
if [[ ! -p "$PIPE" ]]; then
  mkfifo -m 0600 "$PIPE"
fi

exec bpftrace "$PROGRAM" >"$PIPE"
