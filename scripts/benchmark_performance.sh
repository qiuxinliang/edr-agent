#!/bin/bash
set -e

BENCHMARK_DIR=$(dirname "$0")/../benchmark
mkdir -p "$BENCHMARK_DIR"

echo "=== EDR Agent Performance Benchmark ==="
echo "Date: $(date)"
echo "Host: $(hostname)"
echo "CPU: $(grep -c ^processor /proc/cpuinfo 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "unknown")"
echo "Memory: $(free -h 2>/dev/null | grep Mem | awk '{print $2}' || sysctl -n hw.memsize 2>/dev/null | awk '{print $1/1024/1024/1024" GB"}' || echo "unknown")"
echo ""

EDR_AGENT_BIN=${EDR_AGENT_BIN:-"./edr_agent"}

if [ ! -f "$EDR_AGENT_BIN" ]; then
    echo "Error: EDR Agent binary not found at $EDR_AGENT_BIN"
    echo "Set EDR_AGENT_BIN environment variable or build first"
    exit 1
fi

echo "=== Running Performance Tests ==="

run_benchmark() {
    local test_name=$1
    local duration=$2
    local description=$3
    
    echo ""
    echo "--- Test: $test_name ---"
    echo "Description: $description"
    echo "Duration: $duration seconds"
    
    EDR_BENCHMARK_DURATION=$duration \
    EDR_BENCHMARK_MODE=$test_name \
    "$EDR_AGENT_BIN" --benchmark 2>&1 | tail -20
}

run_benchmark "event_bus_mpmc" 10 "MPMC Event Bus Throughput Test"
run_benchmark "a44_decode" 10 "A44 Decode Performance Test"
run_benchmark "preprocess_pipeline" 10 "Preprocess Pipeline Test"
run_benchmark "transport_batch" 10 "Transport Batch Test"
run_benchmark "ave_infer" 10 "AVE Inference Test"

echo ""
echo "=== Benchmark Complete ==="
echo "Results saved to: $BENCHMARK_DIR"