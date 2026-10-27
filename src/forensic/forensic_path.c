#include "edr/forensic_path.h"
#include "edr/sha256.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include <io.h>
#else
#include <unistd.h>
#endif

struct EdrForensicPath {
  char text[4096], leaf[1024];
  size_t count;
#ifdef _WIN32
  HANDLE parents[256];
  wchar_t wide[1024];
#else
  int parents[256];
#endif
};

void edr_forensic_path_release(EdrForensicPath *p) {
  if (!p) return;
  while (p->count) {
#ifdef _WIN32
    CloseHandle(p->parents[--p->count]);
#else
    close(p->parents[--p->count]);
#endif
  }
  free(p);
}

int edr_forensic_path_acquire(const char *path, int create_parents, EdrForensicPath **out) {
  if (!out) return -1;
  *out = NULL;
  if (!path || !*path || strlen(path) >= 4096) return -1;
  EdrForensicPath *p = calloc(1, sizeof(*p));
  if (!p) return -1;
#ifdef _WIN32
  wchar_t input[1024];
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, input, 1024)) goto failed;
  size_t n = wcslen(input);
  if (n < 4 || !((input[0] >= L'A' && input[0] <= L'Z') || (input[0] >= L'a' && input[0] <= L'z')) ||
      input[1] != L':' || (input[2] != L'\\' && input[2] != L'/')) goto failed;
  for (size_t i = 3, start = 3; i <= n; ++i) {
    if (input[i] == L':' || input[i] == L'"') goto failed;
    if (input[i] == L'/' || input[i] == L'\\' || !input[i]) {
      if (i == start || input[i-1] == L'.' || input[i-1] == L' ') goto failed;
      start = i + 1;
    }
  }
  DWORD full = GetFullPathNameW(input, 1024, p->wide, NULL);
  if (!full || full >= 1024 || !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, p->wide, -1,
                                                   p->text, sizeof(p->text), NULL, NULL)) goto failed;
  for (size_t i = 2; p->wide[i]; ++i) {
    if (p->wide[i] != L'\\') continue;
    if (p->count == 256) goto failed;
    size_t end = i == 2 ? i + 1 : i;
    wchar_t saved = p->wide[end]; p->wide[end] = 0;
    HANDLE h = CreateFileW(p->wide, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE && create_parents && i > 2 && GetLastError() == ERROR_FILE_NOT_FOUND) {
      if (CreateDirectoryW(p->wide, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
        h = CreateFileW(p->wide, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    }
    p->wide[end] = saved;
    if (h == INVALID_HANDLE_VALUE) goto failed;
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(h, &info) || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || GetFileType(h) != FILE_TYPE_DISK) {
      CloseHandle(h); goto failed;
    }
    p->parents[p->count++] = h;
  }
#else
  if (path[0] == '/') snprintf(p->text, sizeof(p->text), "%s", path);
  else {
    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd)) || snprintf(p->text, sizeof(p->text), "%s/%s", cwd, path) >= (int)sizeof(p->text)) goto failed;
  }
  /* An ordinary joined TMPDIR may contain repeated separators. Collapse
   * these lexically; do not resolve links or dot components. */
  if(p->text[1]=='/')goto failed;
  size_t used=1;
  for(size_t i=1;p->text[i];i++) {
    if(p->text[i]=='/' && p->text[used-1]=='/')continue;
    p->text[used++]=p->text[i];
  }
  p->text[used]=0;
#ifdef __APPLE__
  /* macOS's root-owned system aliases include TMPDIR under /var. Resolve
   * only these fixed OS spellings, never caller-controlled evidence links. */
  const char *aliases[]={"/tmp","/var","/etc"};
  for(size_t a=0;a<sizeof(aliases)/sizeof(aliases[0]);a++) {
    if(strncmp(p->text,aliases[a],4) || p->text[4]!='/')continue;
    char alias[64]; struct stat st;
    ssize_t len = readlink(aliases[a], alias, sizeof(alias)-1);
    if (len < 0 || lstat(aliases[a], &st) || st.st_uid != 0 || !S_ISLNK(st.st_mode)) goto failed;
    alias[len] = 0;
    char expected[32];snprintf(expected,sizeof(expected),"/private%s",aliases[a]);
    if (strcmp(alias, expected) && strcmp(alias,expected+1)) goto failed;
    if (strlen(p->text) + 8 >= sizeof(p->text)) goto failed;
    memmove(p->text + 8, p->text, strlen(p->text) + 1); memcpy(p->text, "/private", 8);
  }
#endif
  char parts[4096]; strcpy(parts, p->text);
  int current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (current < 0) goto failed;
  p->parents[p->count++] = current;
  char *part = parts + 1;
  for (;;) {
    char *slash = strchr(part, '/');
    if (slash) *slash = 0;
    if (!*part || !strcmp(part, ".") || !strcmp(part, "..") || strlen(part) >= sizeof(p->leaf)) goto failed;
    if (!slash) { strcpy(p->leaf, part); break; }
    if (p->count == 256) goto failed;
    int next = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0 && errno == ENOENT && create_parents) {
      if (!mkdirat(current, part, 0700) || errno == EEXIST)
        next = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    if (next < 0) goto failed;
    p->parents[p->count++] = current = next;
    part = slash + 1;
  }
#endif
  *out = p; return 0;
failed:
  edr_forensic_path_release(p); return -1;
}

FILE *edr_forensic_path_file(EdrForensicPath *p, const char *mode) {
  if (!p || !mode) return NULL;
  int read = !strcmp(mode, "rb"), fresh = !strcmp(mode, "wbx"), update = !strcmp(mode, "r+b");
  if (!read && !fresh && !update) return NULL;
#ifdef _WIN32
  HANDLE h = CreateFileW(p->wide, read ? GENERIC_READ : (fresh ? GENERIC_WRITE : GENERIC_READ | GENERIC_WRITE),
      read ? FILE_SHARE_READ : 0, NULL, fresh ? CREATE_NEW : OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (h == INVALID_HANDLE_VALUE) return NULL;
  BY_HANDLE_FILE_INFORMATION info;
  if (GetFileType(h) != FILE_TYPE_DISK || !GetFileInformationByHandle(h, &info) ||
      (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) { CloseHandle(h); return NULL; }
  int fd = _open_osfhandle((intptr_t)h, (read ? _O_RDONLY : (fresh ? _O_WRONLY : _O_RDWR)) | _O_BINARY | _O_NOINHERIT);
  if (fd < 0) { CloseHandle(h); return NULL; }
  FILE *f = _fdopen(fd, read ? "rb" : (fresh ? "wb" : "r+b"));
  if (!f) { _close(fd); if(fresh)DeleteFileW(p->wide); }
#else
  int fd = openat(p->parents[p->count-1], p->leaf,
      (read ? O_RDONLY | O_NONBLOCK : (fresh ? O_WRONLY | O_CREAT | O_EXCL : O_RDWR)) | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) return NULL;
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); return NULL; }
  FILE *f = fdopen(fd, read ? "rb" : (fresh ? "wb" : "r+b"));
  if (!f) { close(fd); if(fresh)unlinkat(p->parents[p->count-1],p->leaf,0); }
#endif
  return f;
}

int edr_forensic_path_size(EdrForensicPath *p, uint64_t *bytes) {
  if (!p || !bytes) return -1;
  *bytes = 0;
#ifdef _WIN32
  WIN32_FILE_ATTRIBUTE_DATA data;
  if (!GetFileAttributesExW(p->wide, GetFileExInfoStandard, &data)) return GetLastError() == ERROR_FILE_NOT_FOUND ? 1 : -1;
  if (data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) return -1;
  *bytes = ((uint64_t)data.nFileSizeHigh << 32) | data.nFileSizeLow;
#else
  struct stat st;
  if (fstatat(p->parents[p->count-1], p->leaf, &st, AT_SYMLINK_NOFOLLOW)) return errno == ENOENT ? 1 : -1;
  if (!S_ISREG(st.st_mode) || st.st_size < 0) return -1;
  *bytes = (uint64_t)st.st_size;
#endif
  return 0;
}

int edr_forensic_path_sync_parent(EdrForensicPath *p) {
#ifdef _WIN32
  (void)p; return 0; /* atomic publication uses MOVEFILE_WRITE_THROUGH */
#else
  return p ? fsync(p->parents[p->count-1]) : -1;
#endif
}
int edr_forensic_path_move(EdrForensicPath *from, EdrForensicPath *to, int replace) {
  if (!from || !to) return -1;
#ifdef _WIN32
  /* Every current publication is a same-directory rename. An absolute-name
   * MoveFileEx opens the parent for write and conflicts with our deliberately
   * strict directory share mode. The native simple-leaf form renames through
   * the verified source handle without reopening that parent. Never relax
   * sharing or silently fall back to a path-based/cross-directory move. */
  BY_HANDLE_FILE_INFORMATION a,b;
  if(!GetFileInformationByHandle(from->parents[from->count-1],&a) ||
     !GetFileInformationByHandle(to->parents[to->count-1],&b) ||
     a.dwVolumeSerialNumber!=b.dwVolumeSerialNumber || a.nFileIndexHigh!=b.nFileIndexHigh || a.nFileIndexLow!=b.nFileIndexLow){SetLastError(ERROR_NOT_SAME_DEVICE);return -1;}
  HANDLE file=CreateFileW(from->wide,DELETE|GENERIC_WRITE|FILE_READ_ATTRIBUTES,FILE_SHARE_READ,NULL,OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,NULL);
  if(file==INVALID_HANDLE_VALUE)return -1;
  int rc=-1;DWORD error=ERROR_INVALID_DATA;
  if(!GetFileInformationByHandle(file,&a) || GetFileType(file)!=FILE_TYPE_DISK ||
     (a.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)))goto rename_done;
  const wchar_t *leaf=wcsrchr(to->wide,L'\\');if(!leaf)goto rename_done;leaf++;
  size_t bytes=wcslen(leaf)*sizeof(wchar_t),size=offsetof(FILE_RENAME_INFO,FileName)+bytes;
  FILE_RENAME_INFO *info=calloc(1,size);if(!info)goto rename_done;
  info->ReplaceIfExists=replace!=0;info->FileNameLength=(DWORD)bytes;memcpy(info->FileName,leaf,bytes);
  typedef NTSTATUS (NTAPI *RenameFn)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS);
  typedef ULONG (WINAPI *ErrorFn)(NTSTATUS);
  HMODULE dll=GetModuleHandleW(L"ntdll.dll");
  RenameFn rename_fn=(RenameFn)(uintptr_t)GetProcAddress(dll,"NtSetInformationFile");
  ErrorFn error_fn=(ErrorFn)(uintptr_t)GetProcAddress(dll,"RtlNtStatusToDosError");
  IO_STATUS_BLOCK io={0};
  if(!rename_fn || !error_fn)error=ERROR_PROC_NOT_FOUND;
  else if(!FlushFileBuffers(file))error=GetLastError();
  else {
    NTSTATUS status=rename_fn(file,&io,info,(ULONG)size,FileRenameInformation);
    if(status>=0) {rc=FlushFileBuffers(file)?0:-1;error=GetLastError();}
    else error=error_fn(status);
  }
  free(info);
rename_done:
  CloseHandle(file);SetLastError(error);return rc;
#else
  int a = from->parents[from->count-1], b = to->parents[to->count-1];
  if (replace) { if (renameat(a, from->leaf, b, to->leaf)) return -1; }
  else {
    if (linkat(a, from->leaf, b, to->leaf, 0)) return -1;
    /* If unlink fails, retain BOTH copies. Never remove the published evidence. */
    if (unlinkat(a, from->leaf, 0)) return -1;
  }
  return edr_forensic_path_sync_parent(to);
#endif
}
int edr_forensic_path_remove_temp(EdrForensicPath *p) {
  if (!p) return -1;
#ifdef _WIN32
  return DeleteFileW(p->wide) ? 0 : -1;
#else
  return unlinkat(p->parents[p->count-1], p->leaf, 0);
#endif
}
int edr_forensic_path_parent_fd(const EdrForensicPath *p) {
#ifdef _WIN32
  (void)p; return -1;
#else
  return p ? p->parents[p->count-1] : -1;
#endif
}
const char *edr_forensic_path_text(const EdrForensicPath *p) { return p ? p->text : ""; }

int edr_forensic_path_sync_file(const char *path) {
  EdrForensicPath *guard=NULL;
  if(edr_forensic_path_acquire(path,0,&guard))return -1;
  FILE *f=edr_forensic_path_file(guard,"r+b");int rc=-1;
  if(f) {
#ifdef _WIN32
    rc=_commit(_fileno(f));
#else
    rc=fsync(fileno(f));
#endif
    if(fclose(f))rc=-1;
  }
  edr_forensic_path_release(guard);return rc;
}

int edr_forensic_path_hash(const char *path, char sha[65]) {
  EdrForensicPath *guard=NULL;
  if(edr_forensic_path_acquire(path,0,&guard))return -1;
  uint64_t bytes=0;
  int exists=edr_forensic_path_size(guard,&bytes);
  if(exists) { edr_forensic_path_release(guard);return exists==1 ? -2 : -1; }
  FILE *f=edr_forensic_path_file(guard,"rb");
  if(!f){edr_forensic_path_release(guard);return -1;}
  EdrSha256Ctx ctx;edr_sha256_init(&ctx);
  unsigned char data[16384],digest[EDR_SHA256_DIGEST_LEN];size_t n;uint64_t read=0;
  while((n=fread(data,1,sizeof(data),f))>0) {edr_sha256_update(&ctx,data,n);read+=n;}
  int ok=!ferror(f) && read==bytes;
  if(fclose(f))ok=0;
  edr_forensic_path_release(guard);
  if(!ok)return -1;
  edr_sha256_final(&ctx,digest);
  for(size_t i=0;i<sizeof(digest);++i)snprintf(sha+i*2,3,"%02x",digest[i]);
  return 0;
}
