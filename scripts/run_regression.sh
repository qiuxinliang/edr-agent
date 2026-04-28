#!/bin/bash
set -e

echo "=== EDR Agent Regression Test Suite ==="
echo "Date: $(date)"
echo ""

TEST_DIR=$(dirname "$0")/../test
REPORT_FILE="regression_report_$(date +%Y%m%d_%H%M%S).txt"

echo "Running regression tests..."

failed=0
total=0

run_test() {
    local test_name=$1
    local test_cmd=$2
    local description=$3
    
    total=$((total + 1))
    echo ""
    echo "Test $total: $test_name"
    echo "Description: $description"
    
    if eval "$test_cmd"; then
        echo "[PASS]"
        echo "$test_name: PASS" >> "$REPORT_FILE"
    else
        echo "[FAIL]"
        echo "$test_name: FAIL" >> "$REPORT_FILE"
        failed=$((failed + 1))
    fi
}

echo "" > "$REPORT_FILE"
echo "EDR Agent Regression Test Report" >> "$REPORT_FILE"
echo "Date: $(date)" >> "$REPORT_FILE"
echo "==================================" >> "$REPORT_FILE"

run_test "Event Bus MPMC Stress" \
    "./test_event_bus_mpmc_stress" \
    "MPMC event bus stress test"

run_test "P0 Rule Golden Test" \
    "./edr_p0_golden_test" \
    "P0 rule matching golden test"

run_test "Config Parsing" \
    "./edr_agent --config-test" \
    "Configuration parsing test"

run_test "A44 Split Path" \
    "./edr_agent --a44-test" \
    "A44 split path functionality test"

run_test "Preprocess Pipeline" \
    "./edr_agent --preprocess-test" \
    "Preprocess pipeline test"

echo ""
echo "=== Test Summary ==="
echo "Total: $total"
echo "Passed: $((total - failed))"
echo "Failed: $failed"

if [ $failed -eq 0 ]; then
    echo ""
    echo "All tests passed!"
    exit 0
else
    echo ""
    echo "Some tests failed! See $REPORT_FILE for details."
    exit 1
fi