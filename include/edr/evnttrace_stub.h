#ifndef EDR_EVNTTRACE_STUB_H
#define EDR_EVNTTRACE_STUB_H

#if defined(_WIN32) && !defined(EVENT_TRACE_PROPERTIES)

#include <windows.h>

typedef LONGLONG LARGE_INTEGER;

typedef struct _WNODE_HEADER {
    ULONG BufferSize;
    ULONG ProviderId;
    GUID Guid;
    ULONG ClientContext;
    ULONG Flags;
} WNODE_HEADER, *PWNODE_HEADER;

typedef struct _ETW_BUFFER_CONTEXT {
    USHORT ProcessorNumber;
    USHORT Alignment;
} ETW_BUFFER_CONTEXT, *PETW_BUFFER_CONTEXT;

#define EVENT_TRACE_CONTROL_STOP 0
#define EVENT_TRACE_CONTROL_QUERY 1
#define EVENT_TRACE_CONTROL_UPDATE 2

#define TRACE_LEVEL_VERBOSE 5
#define EVENT_CONTROL_CODE_ENABLE_PROVIDER 1

#define PROCESS_TRACE_MODE_REAL_TIME 0x00000001
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x00000010

#define WNODE_FLAG_TRACED_GUID 0x00020000

typedef ULONG TRACEHANDLE;
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE)0xFFFFFFFF)

typedef struct _EVENT_TRACE_PROPERTIES {
    WNODE_HEADER Wnode;
    ULONG BufferSize;
    ULONG MinimumBuffers;
    ULONG MaximumBuffers;
    ULONG MaximumFileSize;
    ULONG LogFileMode;
    ULONG FlushTimer;
    ULONG EnableFlags;
    GUID LoggerId;
    ULONG LogFileNameOffset;
    ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;

__declspec(dllimport) ULONG WINAPI StartTraceW(TRACEHANDLE *SessionHandle, const WCHAR *SessionName, EVENT_TRACE_PROPERTIES *Properties);
__declspec(dllimport) ULONG WINAPI ControlTraceW(TRACEHANDLE SessionHandle, const WCHAR *SessionName, EVENT_TRACE_PROPERTIES *Properties, ULONG ControlCode);
__declspec(dllimport) ULONG WINAPI EnableTraceEx2(TRACEHANDLE SessionHandle, const GUID *ProviderId, ULONG ControlCode, UCHAR Level, ULONGLONG MatchAnyKeyword, ULONGLONG MatchAllKeyword, ULONG Timeout, PVOID EnableParameters);
__declspec(dllimport) TRACEHANDLE WINAPI OpenTraceW(const struct _EVENT_TRACE_LOGFILEW *LogFile);
__declspec(dllimport) ULONG WINAPI ProcessTrace(TRACEHANDLE *HandleArray, ULONG HandleCount, const LARGE_INTEGER *StartTime, const LARGE_INTEGER *EndTime);
__declspec(dllimport) ULONG WINAPI CloseTrace(TRACEHANDLE TraceHandle);

#endif

#endif