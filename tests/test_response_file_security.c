#include "edr/response_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

static void require(int ok, const char *why) {
  if (!ok) { fprintf(stderr, "FAIL: %s\n", why); exit(1); }
}

int main(void) {
  char path[1024];
#ifdef _WIN32
  char tmp[MAX_PATH];
  require(GetTempPathA(sizeof(tmp), tmp) > 0, "temp directory");
  require(GetTempFileNameA(tmp, "ers", 0, path) != 0, "temp file");
#else
  snprintf(path, sizeof(path), "/tmp/edr-file-security-XXXXXX");
  int fd = mkstemp(path);
  require(fd >= 0, "temp file");
  close(fd);
  require(chmod(path, 0640) == 0, "initial mode");
#endif
  FILE *f = fopen(path, "wb");
  require(f != NULL, "open benign fixture");
  require(fwrite("benign evidence", 1, 15, f) == 15, "write fixture");
  require(fclose(f) == 0, "close fixture");
  EdrResponseFileSecurity original, locked, restored;
  require(response_file_security_snapshot(path, &original) == 0, "snapshot original security");
  require(response_file_security_lock(path, 1) != 0, "file cannot be treated as directory");
  require(response_file_security_lock(path, 0) == 0, "lock and read back security");
  require(response_file_security_snapshot(path, &locked) == 0, "read locked security");
#ifdef _WIN32
  require((locked.attributes & FILE_ATTRIBUTE_READONLY) != 0, "read-only attribute verified");
  require(strcmp(locked.dacl, "D:P(A;;FA;;;BA)(A;;FA;;;SY)") == 0, "restricted DACL verified");
#else
  require(locked.mode == 0400, "execute and write bits removed");
#endif
  require(response_file_security_restore(path, &original) == 0, "restore original security");
  require(response_file_security_snapshot(path, &restored) == 0, "verify restoration");
  require(memcmp(&original, &restored, sizeof(original)) == 0, "security restored exactly");
  char content[32] = {0};
  f = fopen(path, "rb");
  require(f && fread(content, 1, sizeof(content), f) == 15, "read evidence after restore");
  require(fclose(f) == 0 && strcmp(content, "benign evidence") == 0, "evidence unchanged");
#ifndef _WIN32
  char linkpath[1100];
  snprintf(linkpath, sizeof(linkpath), "%s.link", path);
  require(symlink(path, linkpath) == 0, "create own symlink fixture");
  require(response_file_security_snapshot(linkpath, &locked) != 0, "reject symlink evidence");
  require(response_file_security_lock(linkpath, 0) != 0, "do not follow symlink during locking");
  require(unlink(linkpath) == 0, "cleanup own link");
#endif
  require(remove(path) == 0, "cleanup own fixture");
  require(response_file_security_lock(path, 0) != 0, "missing file is not locked success");
  puts("PASS: file security lock, exact restore, unchanged evidence, failure paths");
  return 0;
}
