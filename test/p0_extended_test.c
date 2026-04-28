/*
 * P0 扩展测试用例运行器
 * 从 JSON 文件加载测试用例并执行验证
 */
#include "edr/p0_rule_match.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

#define MAX_CASES 100

typedef struct {
    char rule_id[64];
    char process_name[256];
    char cmdline[1024];
    int expect_hit;
} TestCase;

static int g_pass_count = 0;
static int g_fail_count = 0;
static int g_total_count = 0;

extern int edr_p0_rule_matches3(
    const char *rule_id, const char *process_name, const char *cmdline,
    const char *parent_name, int chain_depth);

static int load_json_cases(const char *filename, TestCase *cases, int max_cases) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", filename);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = (char *)malloc(fsize + 1);
    fread(content, 1, fsize, f);
    fclose(f);
    content[fsize] = 0;

    int count = 0;
    char *p = content;
    int in_case = 0;
    int in_ev = 0;
    TestCase tc = {0};
    int field = 0;
    char field_value[1024] = {0};

    while (*p && count < max_cases) {
        if (strncmp(p, "\"rule_id\"", 9) == 0) {
            p = strchr(p, ':') + 1;
            while (*p && (*p == ' ' || *p == '"')) p++;
            char *end = strchr(p, '"');
            if (end) {
                int len = end - p < 63 ? end - p : 63;
                strncpy(tc.rule_id, p, len);
                tc.rule_id[len] = 0;
            }
        } else if (strncmp(p, "\"expect_hit\"", 11) == 0) {
            p = strchr(p, ':') + 1;
            while (*p && (*p == ' ')) p++;
            tc.expect_hit = (strncmp(p, "true", 4) == 0) ? 1 : 0;
        } else if (strncmp(p, "\"process_name\"", 13) == 0) {
            p = strchr(p, ':') + 1;
            while (*p && (*p == ' ' || *p == '"')) p++;
            char *end = strchr(p, '"');
            if (end) {
                int len = end - p < 255 ? end - p : 255;
                strncpy(tc.process_name, p, len);
                tc.process_name[len] = 0;
            }
        } else if (strncmp(p, "\"cmdline\"", 8) == 0) {
            p = strchr(p, ':') + 1;
            while (*p && (*p == ' ' || *p == '"')) p++;
            char *end = strchr(p, '"');
            if (end) {
                int len = end - p < 1023 ? end - p : 1023;
                strncpy(tc.cmdline, p, len);
                tc.cmdline[len] = 0;
            }
        } else if (strncmp(p, "\"event_type\"", 12) == 0) {
            p = strchr(p, ':') + 1;
            while (*p && (*p == ' ' || *p == '"')) p++;
            if (strncmp(p, "process_create", 13) != 0) {
                while (*p && *p != '}') p++;
                continue;
            }
        } else if (strncmp(p, "}", 1) == 0 && tc.rule_id[0]) {
            cases[count++] = tc;
            memset(&tc, 0, sizeof(tc));
        }
        p++;
    }

    free(content);
    return count;
}

static void run_tests(TestCase *cases, int count) {
    printf("=== Extended Test Cases (%d total) ===\n", count);
    g_total_count = count;

    for (int i = 0; i < count; i++) {
        TestCase *tc = &cases[i];
        int result = edr_p0_rule_matches3(
            tc->rule_id, tc->process_name, tc->cmdline, NULL, 0);

        if (result == tc->expect_hit) {
            printf("[PASS] Case %d: %s | %s | %s => %d\n",
                   i, tc->rule_id, tc->process_name,
                   tc->cmdline, result);
            g_pass_count++;
        } else {
            printf("[FAIL] Case %d: %s | %s | %s => %d (expected %d)\n",
                   i, tc->rule_id, tc->process_name,
                   tc->cmdline, result, tc->expect_hit);
            g_fail_count++;
        }
    }
}

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

static void run_performance_test(TestCase *cases, int count, int iterations) {
    printf("\n=== Performance Test (%d iterations, %d cases) ===\n", iterations, count);

    int64_t start_ns = get_time_ns();
    for (int iter = 0; iter < iterations; iter++) {
        for (int i = 0; i < count; i++) {
            edr_p0_rule_matches3(
                cases[i].rule_id, cases[i].process_name, cases[i].cmdline, NULL, 0);
        }
    }
    int64_t end_ns = get_time_ns();

    double total_s = (double)(end_ns - start_ns) / 1e9;
    int total_ops = iterations * count;
    double avg_latency_us = (double)(end_ns - start_ns) / (double)total_ops / 1000.0;

    printf("Total time: %.3f seconds\n", total_s);
    printf("Total operations: %d\n", total_ops);
    printf("Throughput: %.0f ops/sec\n", (double)total_ops / total_s);
    printf("Average latency: %.3f us/op\n", avg_latency_us);
}

int main(int argc, char *argv[]) {
    printf("P0 Rule Extended Test Suite\n");
    printf("============================\n\n");

#ifdef _WIN32
    SetEnvironmentVariableA("EDR_P0_DIRECT_EMIT", "1");
#else
    setenv("EDR_P0_DIRECT_EMIT", "1", 1);
#endif

    TestCase cases[MAX_CASES];
    int count = load_json_cases("src/preprocess/p0_extended_vectors.json", cases, MAX_CASES);
    if (count < 0) {
        fprintf(stderr, "Failed to load test cases\n");
        return 1;
    }

    printf("Loaded %d test cases\n\n", count);

    run_tests(cases, count);

    run_performance_test(cases, count, 1000);

    printf("\n=== Summary ===\n");
    printf("PASS: %d, FAIL: %d, TOTAL: %d\n", g_pass_count, g_fail_count, g_total_count);

    return g_fail_count > 0 ? 1 : 0;
}