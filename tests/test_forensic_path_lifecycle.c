/* Real directory/leaf boundaries used by manifest, sealing and publication. */
#include "edr/forensic_path.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif
int main(void) {
  char root[800],parent[900],moved[900],path[1000],final[1000],alias[900],through[1000];
#ifdef _WIN32
  char temp[700];assert(GetTempPathA(sizeof(temp),temp));
  assert(GetTempFileNameA(temp,"efp",0,root));assert(DeleteFileA(root));assert(!_mkdir(root));
#else
  strcpy(root,"/tmp/edr-path-lifecycle.XXXXXX");assert(mkdtemp(root));
#endif
  snprintf(parent,sizeof(parent),"%s/owned",root);snprintf(moved,sizeof(moved),"%s/moved",root);
  snprintf(path,sizeof(path),"%s/manifest",parent);snprintf(final,sizeof(final),"%s/sealed",parent);
  EdrForensicPath *a=NULL,*b=NULL;assert(!edr_forensic_path_acquire(path,1,&a));
  FILE *f=edr_forensic_path_file(a,"wbx");assert(f);assert(fputs("synthetic manifest",f)>=0);assert(!fclose(f));
  assert(!edr_forensic_path_file(a,"wbx")); /* Preserve prior content. */
  assert(!edr_forensic_path_acquire(final,0,&b));
#ifdef _WIN32
  assert(!MoveFileExA(parent,moved,0));assert(GetLastError()==ERROR_SHARING_VIOLATION);
#else
  assert(!rename(parent,moved));assert(!mkdir(parent,0700));
  char replacement[1000];snprintf(replacement,sizeof(replacement),"%s/manifest",parent);
  f=fopen(replacement,"wb");assert(f);assert(fputs("unrelated replacement",f)>=0);assert(!fclose(f));
#endif
  assert(!edr_forensic_path_move(a,b,0)); /* Anchored source and destination. */
  uint64_t bytes=0;assert(!edr_forensic_path_size(b,&bytes) && bytes==18);
  assert(!edr_forensic_path_file(b,"wbx"));
  edr_forensic_path_release(b);edr_forensic_path_release(a);
#ifndef _WIN32
  assert(!remove(replacement));assert(!rmdir(parent));assert(!rename(moved,parent));
#endif
  char sha[65];assert(!edr_forensic_path_hash(final,sha));
  assert(!strcmp(sha,"99d35512273e0bf7ceb7a67b0ec97805a5c6cfb2b30a8852e5c452c6cf6a108f"));
  snprintf(alias,sizeof(alias),"%s/alias",root);snprintf(through,sizeof(through),"%s/sealed",alias);
#ifdef _WIN32
  char command[2100];snprintf(command,sizeof(command),"cmd.exe /d /c mklink /J \"%s\" \"%s\" >NUL",alias,parent);
  assert(!system(command));
#else
  assert(!symlink(parent,alias));
#endif
  assert(edr_forensic_path_acquire(through,0,&a)!=0 && !a);
  assert(edr_forensic_path_hash(through,sha)!=0);
#ifdef _WIN32
  assert(RemoveDirectoryA(alias));
#else
  assert(!unlink(alias));
#endif
  puts("PASS: manifest exclusive create; held parent rename denied/anchored; seal and no-replace publication; hash; actual ancestor link rejected");
  return 0;
}
