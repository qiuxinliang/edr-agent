#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "edr/process_tree_cache.h"
#include "edr/mmap_storage.h"

static int g_pass = 0;
static int g_fail = 0;

#define TEST_ASSERT(expr, msg) do { \
    if (!(expr)) { \
        printf("FAIL: %s\n", msg); \
        g_fail++; \
    } else { \
        printf("PASS: %s\n", msg); \
        g_pass++; \
    } \
} while (0)

int main(void) {
    printf("=== Process Tree Cache Integration Test ===\n\n");
    
    const char *test_path = "/tmp/edr_test_cache";
    edr_pt_cache_init_with_path(test_path);
    
    printf("1. Testing process tree cache basic operations...\n");
    
    uint64_t now = 1778991868000000000ULL;
    
    int r = edr_pt_cache_put(1234, 5678, "cmd.exe", "cmd /c echo test", "C:\\Windows\\System32\\cmd.exe", "explorer.exe", now);
    TEST_ASSERT(r == 0, "edr_pt_cache_put should return 0");
    
    const ProcessTreeEntry *entry = edr_pt_cache_get(1234);
    TEST_ASSERT(entry != NULL, "edr_pt_cache_get should find entry");
    TEST_ASSERT(entry->pid == 1234, "pid should be 1234");
    TEST_ASSERT(entry->ppid == 5678, "ppid should be 5678");
    TEST_ASSERT(strcmp(entry->process_name, "cmd.exe") == 0, "process_name should be cmd.exe");
    TEST_ASSERT(strcmp(entry->parent_name, "explorer.exe") == 0, "parent_name should be explorer.exe");
    
    printf("\n2. Testing memory-mapped storage integration...\n");
    
    MMapProcessEntry mmap_entry = {0};
    r = edr_mmap_storage_get(1234, now, &mmap_entry);
    TEST_ASSERT(r == 0, "mmap storage should have the entry");
    TEST_ASSERT(mmap_entry.pid == 1234, "mmap pid should be 1234");
    TEST_ASSERT(mmap_entry.ppid == 5678, "mmap ppid should be 5678");
    TEST_ASSERT(strcmp(mmap_entry.name, "cmd.exe") == 0, "mmap name should be cmd.exe");
    
    printf("\n3. Testing process termination...\n");
    
    uint64_t terminate_time = now + 1000000000ULL;
    r = edr_pt_cache_mark_terminated(1234, terminate_time);
    TEST_ASSERT(r == 0, "edr_pt_cache_mark_terminated should return 0");
    
    r = edr_mmap_storage_get(1234, terminate_time, &mmap_entry);
    TEST_ASSERT(r == 0, "mmap storage should have updated entry");
    TEST_ASSERT(mmap_entry.exited == 1, "entry should be marked as exited");
    TEST_ASSERT(mmap_entry.exit_time == terminate_time, "exit_time should be set");
    
    printf("\n4. Testing historical query...\n");
    
    ProcessTreeEntry hist_entry = {0};
    r = edr_pt_cache_get_historical(1234, terminate_time, &hist_entry);
    TEST_ASSERT(r == 0, "edr_pt_cache_get_historical should return 0");
    TEST_ASSERT(hist_entry.pid == 1234, "historical pid should be 1234");
    TEST_ASSERT(hist_entry.terminated == 1, "historical entry should be terminated");
    
    printf("\n5. Testing statistics...\n");
    
    uint32_t count = edr_mmap_storage_get_count();
    TEST_ASSERT(count >= 1, "mmap storage should have at least 1 entry");
    
    printf("\n=== Test Summary ===\n");
    printf("Passed: %d\n", g_pass);
    printf("Failed: %d\n", g_fail);
    
    edr_pt_cache_shutdown();
    
    if (g_fail == 0) {
        printf("\nAll tests passed!\n");
        return 0;
    } else {
        printf("\nSome tests failed!\n");
        return 1;
    }
}