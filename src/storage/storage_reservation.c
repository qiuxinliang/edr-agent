#include "edr/storage_reservation.h"
#include <stdatomic.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

static _Atomic(_Atomic(uint64_t) *) balance;
/* Startup can fail before the protected lock file is mapped. Retain that
 * unknown state locally so even previously reserved writers fail closed. */
static _Atomic(uint64_t) unmapped_balance;
static char attached_owner[1024]; /* Updated only under the command owner lock. */
static uint64_t attached_device, attached_file;

uint64_t edr_storage_artifact_reserved(void) {
  _Atomic(uint64_t) *value=atomic_load_explicit(&balance,memory_order_acquire);
  return value ? atomic_load_explicit(value,memory_order_acquire) :
      atomic_load_explicit(&unmapped_balance,memory_order_acquire);
}
void edr_storage_reservation_publish(uint64_t bytes) {
  _Atomic(uint64_t) *value=atomic_load_explicit(&balance,memory_order_acquire);
  if(value)atomic_store_explicit(value,bytes,memory_order_release);
  else atomic_store_explicit(&unmapped_balance,bytes,memory_order_release);
}
int edr_storage_reservation_readonly_snapshot(uint64_t bytes) {
  if(atomic_load_explicit(&balance,memory_order_acquire))return -1;
  atomic_store_explicit(&unmapped_balance,bytes,memory_order_release);return 0;
}
int edr_storage_reservation_attach(int fd,const char *owner_path) {
  if(!owner_path || !*owner_path || strlen(owner_path)>=sizeof(attached_owner))return -1;
  void *mapped=NULL;
#ifdef _WIN32
  HANDLE file=(HANDLE)_get_osfhandle(fd);
  BY_HANDLE_FILE_INFORMATION info;
  if(!GetFileInformationByHandle(file,&info))return -1;
  uint64_t device=info.dwVolumeSerialNumber;
  uint64_t identity=((uint64_t)info.nFileIndexHigh<<32u)|info.nFileIndexLow;
#else
  struct stat info;
  if(fstat(fd,&info))return -1;
  uint64_t device=(uint64_t)info.st_dev, identity=(uint64_t)info.st_ino;
#endif
  if(!strcmp(attached_owner,owner_path) && attached_device==device && attached_file==identity && atomic_load(&balance))return 0;
#ifdef _WIN32
  HANDLE mapping=CreateFileMappingA(file,NULL,PAGE_READWRITE,0,16,NULL);
  if(!mapping)return -1;
  mapped=MapViewOfFile(mapping,FILE_MAP_READ|FILE_MAP_WRITE,0,0,16);
  CloseHandle(mapping);
  if(!mapped)return -1;
#else
  if(info.st_size<16 && ftruncate(fd,16))return -1;
  mapped=mmap(NULL,16,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
  if(mapped==MAP_FAILED)return -1;
#endif
  _Atomic(uint64_t) *value=(_Atomic(uint64_t) *)((unsigned char *)mapped+8u);
  if(!atomic_is_lock_free(value)) {
#ifdef _WIN32
    UnmapViewOfFile(mapped);
#else
    munmap(mapped,16);
#endif
    return -1;
  }
  /* Keep old mappings alive for readers already using them. A service has one
   * immutable owner path; path changes occur only in isolated test processes. */
  atomic_store_explicit(&balance,value,memory_order_release);
  strcpy(attached_owner,owner_path);
  attached_device=device;attached_file=identity;
  return 0;
}
