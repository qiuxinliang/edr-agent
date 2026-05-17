#include "edr/peb_parser.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef LONG EDR_NTSTATUS;

typedef struct _EDR_PROCESS_BASIC_INFORMATION {
  void *ExitStatus;
  void *PebBaseAddress;
  void *AffinityMask;
  LONG BasePriority;
  void *UniqueProcessId;
  void *InheritedFromUniqueProcessId;
} EDR_PROCESS_BASIC_INFORMATION;

typedef EDR_NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
  HANDLE ProcessHandle,
  DWORD ProcessInformationClass,
  PVOID ProcessInformation,
  ULONG ProcessInformationLength,
  PULONG ReturnLength
);

static NtQueryInformationProcess_t g_NtQueryInformationProcess = NULL;

static void init_ntdll(void) {
  if (g_NtQueryInformationProcess) return;
  HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
  if (hNtdll) {
    g_NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
  }
}

int edr_peb_get_command_line(DWORD pid, char *buffer, size_t buffer_size) {
  if (!buffer || buffer_size == 0) return -1;
  init_ntdll();
  if (!g_NtQueryInformationProcess) return -1;
  
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!hProcess) return -1;
  
  EDR_PROCESS_BASIC_INFORMATION pbi;
  ULONG bytesReturned;
  EDR_NTSTATUS status = g_NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &bytesReturned);
  
  if (status != 0 || !pbi.PebBaseAddress) {
    CloseHandle(hProcess);
    return -1;
  }
  
  struct {
    ULONG Length;
    ULONG MaximumLength;
    PWSTR Buffer;
  } unicodeString;
  
  SIZE_T bytesRead;
  if (!ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + 0x20, &unicodeString, sizeof(unicodeString), &bytesRead)) {
    CloseHandle(hProcess);
    return -1;
  }
  
  if (!unicodeString.Buffer || unicodeString.Length == 0) {
    CloseHandle(hProcess);
    return -1;
  }
  
  WCHAR *wbuffer = (WCHAR *)malloc(unicodeString.Length + 2);
  if (!wbuffer) {
    CloseHandle(hProcess);
    return -1;
  }
  
  if (!ReadProcessMemory(hProcess, unicodeString.Buffer, wbuffer, unicodeString.Length, &bytesRead)) {
    free(wbuffer);
    CloseHandle(hProcess);
    return -1;
  }
  wbuffer[unicodeString.Length / sizeof(WCHAR)] = L'\0';
  
  WideCharToMultiByte(CP_UTF8, 0, wbuffer, -1, buffer, (int)buffer_size, NULL, NULL);
  
  free(wbuffer);
  CloseHandle(hProcess);
  return 0;
}

int edr_peb_get_environment(DWORD pid, char *buffer, size_t buffer_size) {
  if (!buffer || buffer_size == 0) return -1;
  init_ntdll();
  if (!g_NtQueryInformationProcess) return -1;
  
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!hProcess) return -1;
  
  EDR_PROCESS_BASIC_INFORMATION pbi;
  ULONG bytesReturned;
  EDR_NTSTATUS status = g_NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &bytesReturned);
  
  if (status != 0 || !pbi.PebBaseAddress) {
    CloseHandle(hProcess);
    return -1;
  }
  
  PVOID envBlock;
  if (!ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + 0x88, &envBlock, sizeof(envBlock), NULL)) {
    CloseHandle(hProcess);
    return -1;
  }
  
  if (!envBlock) {
    CloseHandle(hProcess);
    return -1;
  }
  
  char *env = (char *)malloc(buffer_size);
  if (!env) {
    CloseHandle(hProcess);
    return -1;
  }
  
  SIZE_T bytesRead;
  if (!ReadProcessMemory(hProcess, envBlock, env, buffer_size - 1, &bytesRead)) {
    free(env);
    CloseHandle(hProcess);
    return -1;
  }
  env[bytesRead] = '\0';
  
  strncpy(buffer, env, buffer_size - 1);
  buffer[buffer_size - 1] = '\0';
  
  free(env);
  CloseHandle(hProcess);
  return 0;
}

int edr_peb_get_user_info(DWORD pid, char *user, size_t user_size, char *domain, size_t domain_size) {
  if (!user || user_size == 0) return -1;
  
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!hProcess) return -1;
  
  HANDLE hToken = NULL;
  if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
    CloseHandle(hProcess);
    return -1;
  }
  
  DWORD needed = 0;
  GetTokenInformation(hToken, TokenUser, NULL, 0, &needed);
  if (needed == 0) {
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return -1;
  }
  
  PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(needed);
  if (!pTokenUser) {
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return -1;
  }
  
  if (!GetTokenInformation(hToken, TokenUser, pTokenUser, needed, &needed)) {
    free(pTokenUser);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return -1;
  }
  
  SID_NAME_USE snu;
  char localUser[256] = {0};
  char localDomain[256] = {0};
  DWORD userLen = 256;
  DWORD domainLen = 256;
  
  if (LookupAccountSidA(NULL, pTokenUser->User.Sid, localUser, &userLen, localDomain, &domainLen, &snu)) {
    strncpy(user, localUser, user_size - 1);
    user[user_size - 1] = '\0';
    if (domain && domain_size > 0) {
      strncpy(domain, localDomain, domain_size - 1);
      domain[domain_size - 1] = '\0';
    }
  }
  
  free(pTokenUser);
  CloseHandle(hToken);
  CloseHandle(hProcess);
  return 0;
}

int edr_peb_parse(DWORD pid, PEBProcessInfo *info) {
  if (!info) return -1;
  memset(info, 0, sizeof(PEBProcessInfo));
  info->pid = pid;
  
  edr_peb_get_command_line(pid, info->cmdline, sizeof(info->cmdline));
  
  edr_peb_get_environment(pid, info->environment, sizeof(info->environment));
  
  edr_peb_get_user_info(pid, info->user, sizeof(info->user), info->domain, sizeof(info->domain));
  
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (hProcess) {
    WCHAR path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
      WideCharToMultiByte(CP_UTF8, 0, path, -1, info->exe_path, sizeof(info->exe_path), NULL, NULL);
      const char *basename = strrchr(info->exe_path, '\\');
      if (basename) {
        strncpy(info->process_name, basename + 1, sizeof(info->process_name) - 1);
      }
    }
    CloseHandle(hProcess);
  }
  
  return 0;
}