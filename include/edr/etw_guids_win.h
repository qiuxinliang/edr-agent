/**
 * §3.1.1 核心 Provider GUID — Windows ETW，供 collector 与 TDH 模块共用。
 */
#ifndef EDR_ETW_GUIDS_WIN_H
#define EDR_ETW_GUIDS_WIN_H

#if !defined(_WIN32)
#error etw_guids_win is Windows-only
#endif

#include <windows.h>

#define EDR_DEFINE_ETW_GUID(var, Data1, Data2, Data3, B0, B1, B2, B3, B4, B5, B6, B7) \
  static const GUID var = {                                                         \
      (unsigned long)(Data1), (unsigned short)(Data2), (unsigned short)(Data3),     \
      { (unsigned char)(B0), (unsigned char)(B1), (unsigned char)(B2),                \
        (unsigned char)(B3), (unsigned char)(B4), (unsigned char)(B5),                \
        (unsigned char)(B6), (unsigned char)(B7) } }

EDR_DEFINE_ETW_GUID(EDR_ETW_GUID_KERNEL_PROCESS, 0x22fb2cd6, 0x0e7b, 0x422b, 0xa0,
                    0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16);
EDR_DEFINE_ETW_GUID(EDR_ETW_GUID_KERNEL_FILE, 0xedd08927, 0x9cc4, 0x4e65, 0xb9, 0x70,
                    0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89);
EDR_DEFINE_ETW_GUID(EDR_ETW_GUID_KERNEL_NETWORK, 0x7dd42a49, 0x5329, 0x4832, 0x8d, 0xfd,
                    0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88);
/** Microsoft-Windows-Kernel-Registry（Create/Open/Set/Delete 等；winevt 标识符一致） */
EDR_DEFINE_ETW_GUID(EDR_ETW_GUID_KERNEL_REGISTRY, 0x70eb4f03, 0xc1de, 0x4f73, 0xa0, 0x51,
                    0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd);
EDR_DEFINE_ETW_GUID(EDR_ETW_GUID_DNS_CLIENT, 0x1c95126e, 0x7eea, 0x49a9, 0xa3, 0xfe,
                    0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d);
EDR_DEFINE_ETW_GUID(EDR_ETW_GUID_POWERSHELL, 0xa0c1853b, 0x5c40, 0x4b15, 0x87, 0x66,
                    0x3c, 0xf1, 0xc5, 0x8f, 0x98, 0x5a);
EDR_DEFINE_ETW_GUID(EDR_ETW_GUID_SECURITY_AUDIT, 0x54849625, 0x5478, 0x4994, 0xa5, 0xba,
                    0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d);
EDR_DEFINE_ETW_GUID(EDR_ETW_GUID_WMI_ACTIVITY, 0x1418ef04, 0xb0b4, 0x4623, 0xbf, 0x7e,
                    0xd7, 0x4a, 0xb4, 0x7b, 0xbd, 0xaa);
/** §19.10 增补：监听/连接增量（与设计稿 Microsoft-Windows-TCPIP 一致） */
EDR_DEFINE_ETW_GUID(EDR_ETW_GUID_MICROSOFT_TCPIP, 0x2f07e2ee, 0x15db, 0x40f1, 0x90, 0xef, 0x9d,
                    0x7b, 0xa2, 0x82, 0x18, 0x8a);
/** §19.10 增补：防火墙规则变更 */
EDR_DEFINE_ETW_GUID(EDR_ETW_GUID_WINFIREWALL_WFAS, 0xd1bc9aeb, 0xc1e3, 0x4c58, 0xb9, 0xa5, 0x78,
                    0xd5, 0x2a, 0x19, 0xe1, 0xbd);

#endif
