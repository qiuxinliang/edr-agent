/* Exercise the same missing standard-handle boundary as SCM/headless children. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
int main(int argc, char **argv) {
  assert(argc == 2);
  char temp[MAX_PATH], directory[MAX_PATH], command[2 * MAX_PATH + 80];
  assert(GetTempPathA(sizeof(temp), temp));
  assert(GetTempFileNameA(temp, "edl", 0, directory));
  assert(DeleteFileA(directory) && CreateDirectoryA(directory, NULL));
  snprintf(command, sizeof(command), "\"%s\" \"%s\" rotate-headless", argv[1], directory);
  STARTUPINFOA si; PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof(si)); memset(&pi, 0, sizeof(pi));
  si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = si.hStdOutput = si.hStdError = INVALID_HANDLE_VALUE;
  /* No standard handles are inherited. The child closes runtime-populated
   * streams and verifies the missing CRT/OS-handle boundary explicitly. */
  assert(CreateProcessA(argv[1], command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi));
  DWORD wait = WaitForSingleObject(pi.hProcess, 15000u);
  if (wait != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 2u);
  DWORD code = 2u;
  assert(GetExitCodeProcess(pi.hProcess, &code));
  CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
  if (wait != WAIT_OBJECT_0 || code != 0u) fprintf(stderr, "headless child failed: wait=%lu exit=%lu fixture=%s\n", (unsigned long)wait, (unsigned long)code, directory);
  assert(wait == WAIT_OBJECT_0 && code == 0u);
  char path[MAX_PATH + 20], data[128];
  snprintf(path, sizeof(path), "%s/agent.log", directory);
  FILE *f = fopen(path, "rb"); assert(f);
  size_t n = fread(data, 1u, sizeof(data)-1u, f); data[n] = 0; fclose(f);
  assert(strcmp(data, "after-rotation\nstdout-headless\n") == 0);
  for (unsigned i=0; i<3u; ++i) {
    if (i) snprintf(path, sizeof(path), "%s/agent.log.%u", directory, i);
    else snprintf(path, sizeof(path), "%s/agent.log", directory);
    assert(DeleteFileA(path));
  }
  snprintf(path, sizeof(path), "%s/headless.trace", directory);
  assert(DeleteFileA(path));
  assert(RemoveDirectoryA(directory));
  puts("headless logger: PASS (closed CRT streams, missing OS handles, native rotation)");
  return 0;
}
