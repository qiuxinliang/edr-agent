/*
 * WinDivert 2.x ABI fragments (LGPL — same as WinDivert). See upstream:
 * https://github.com/basil00/Divert/blob/master/include/windivert.h
 */
#ifndef EDR_WINDIVERT_ABI_H
#define EDR_WINDIVERT_ABI_H

#include <stdint.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201)
#endif

typedef enum { WINDIVERT_LAYER_NETWORK = 0 } WINDIVERT_LAYER;

typedef struct {
  uint32_t IfIdx;
  uint32_t SubIfIdx;
} WINDIVERT_DATA_NETWORK;

typedef struct {
  int64_t Timestamp;
  uint32_t Layer : 8;
  uint32_t Event : 8;
  uint32_t Sniffed : 1;
  uint32_t Outbound : 1;
  uint32_t Loopback : 1;
  uint32_t Impostor : 1;
  uint32_t IPv6 : 1;
  uint32_t IPChecksum : 1;
  uint32_t TCPChecksum : 1;
  uint32_t UDPChecksum : 1;
  uint32_t Reserved1 : 8;
  uint32_t Reserved2;
  union {
    WINDIVERT_DATA_NETWORK Network;
    uint8_t Reserved3[64];
  };
} WINDIVERT_ADDRESS;

#ifdef _MSC_VER
#pragma warning(pop)
#endif

typedef struct {
  uint8_t HdrLength : 4;
  uint8_t Version : 4;
  uint8_t TOS;
  uint16_t Length;
  uint16_t Id;
  uint16_t FragOff0;
  uint8_t TTL;
  uint8_t Protocol;
  uint16_t Checksum;
  uint32_t SrcAddr;
  uint32_t DstAddr;
} WINDIVERT_IPHDR;

typedef struct {
  uint16_t SrcPort;
  uint16_t DstPort;
  uint32_t SeqNum;
  uint32_t AckNum;
  uint16_t Reserved1 : 4;
  uint16_t HdrLength : 4;
  uint16_t Fin : 1;
  uint16_t Syn : 1;
  uint16_t Rst : 1;
  uint16_t Psh : 1;
  uint16_t Ack : 1;
  uint16_t Urg : 1;
  uint16_t Reserved2 : 2;
  uint16_t Window;
  uint16_t Checksum;
  uint16_t UrgPtr;
} WINDIVERT_TCPHDR;

typedef struct {
  uint8_t Type;
  uint8_t Code;
  uint16_t Checksum;
  uint32_t Body;
} WINDIVERT_ICMPHDR;

typedef struct {
  uint8_t Type;
  uint8_t Code;
  uint16_t Checksum;
  uint32_t Body;
} WINDIVERT_ICMPV6HDR;

typedef struct {
  uint16_t SrcPort;
  uint16_t DstPort;
  uint16_t Length;
  uint16_t Checksum;
} WINDIVERT_UDPHDR;

/** IPv6 header (WinDivert 2.x; for WinDivertHelperParsePacket when IPv4 ip==NULL). */
typedef struct {
  uint8_t TrafficClass0 : 4;
  uint8_t Version : 4;
  uint8_t FlowLabel0 : 4;
  uint8_t TrafficClass1 : 4;
  uint16_t FlowLabel1;
  uint16_t Length;
  uint8_t NextHdr;
  uint8_t HopLimit;
  uint32_t SrcAddr[4];
  uint32_t DstAddr[4];
} WINDIVERT_IPV6HDR;

typedef enum {
  WINDIVERT_PARAM_QUEUE_LENGTH = 0,
  WINDIVERT_PARAM_QUEUE_TIME = 1,
  WINDIVERT_PARAM_QUEUE_SIZE = 2,
} WINDIVERT_PARAM;

#define WINDIVERT_FLAG_SNIFF 0x0001
#define WINDIVERT_FLAG_RECV_ONLY 0x0004

#endif
