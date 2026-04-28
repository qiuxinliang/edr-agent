#ifndef EDR_EVNTTRACE_STUB_H
#define EDR_EVNTTRACE_STUB_H

#if defined(_WIN32)

#include <windows.h>

#ifndef EVENT_TRACE_PROPERTIES

typedef struct _EVENT_TRACE_PROPERTIES {
    struct _WNODE_HEADER {
        ULONG BufferSize;
        ULONG ProviderId;
        GUID Guid;
        ULONG ClientContext;
        ULONG Flags;
    } Wnode;
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

#endif

typedef struct _EVENT_TRACE_LOGFILEW {
    WCHAR *LoggerName;
    WCHAR *LogFileName;
    EVENT_TRACE_PROPERTIES *EventTraceProperties;
    ULONG ProcessTraceMode;
    PVOID EventRecordCallback;
    PVOID BufferCallback;
    PVOID Context;
    ULONG BufferSize;
    ULONG MinimumBuffers;
    ULONG MaximumBuffers;
    ULONG MaximumFileSize;
    ULONG LogFileMode;
    ULONG FlushTimer;
    ULONG EnableFlags;
    GUID LoggerId;
} EVENT_TRACE_LOGFILEW, *PEVENT_TRACE_LOGFILEW;

#ifndef TRACEHANDLE
typedef ULONG TRACEHANDLE;
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE)0xFFFFFFFF)
#endif

#define EVENT_TRACE_CONTROL_STOP 0
#define EVENT_TRACE_CONTROL_QUERY 1
#define EVENT_TRACE_CONTROL_UPDATE 2

#define TRACE_LEVEL_VERBOSE 5
#define EVENT_CONTROL_CODE_ENABLE_PROVIDER 1

#define PROCESS_TRACE_MODE_REAL_TIME 0x00000001
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x00000010

#define WNODE_FLAG_TRACED_GUID 0x00020000
#define EVENT_TRACE_REAL_TIME_MODE 0x00000001
#define EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING 0x00000080

#ifndef StartTraceW
__declspec(dllimport) ULONG WINAPI StartTraceW(TRACEHANDLE *SessionHandle, const WCHAR *SessionName, EVENT_TRACE_PROPERTIES *Properties);
#endif

#ifndef ControlTraceW
__declspec(dllimport) ULONG WINAPI ControlTraceW(TRACEHANDLE SessionHandle, const WCHAR *SessionName, EVENT_TRACE_PROPERTIES *Properties, ULONG ControlCode);
#endif

#ifndef EnableTraceEx2
__declspec(dllimport) ULONG WINAPI EnableTraceEx2(TRACEHANDLE SessionHandle, const GUID *ProviderId, ULONG ControlCode, UCHAR Level, ULONGLONG MatchAnyKeyword, ULONGLONG MatchAllKeyword, ULONG Timeout, PVOID EnableParameters);
#endif

#ifndef OpenTraceW
__declspec(dllimport) TRACEHANDLE WINAPI OpenTraceW(EVENT_TRACE_LOGFILEW *LogFile);
#endif

#ifndef ProcessTrace
__declspec(dllimport) ULONG WINAPI ProcessTrace(TRACEHANDLE *HandleArray, ULONG HandleCount, const LARGE_INTEGER *StartTime, const LARGE_INTEGER *EndTime);
#endif

#ifndef CloseTrace
__declspec(dllimport) ULONG WINAPI CloseTrace(TRACEHANDLE TraceHandle);
#endif

#endif

#endif