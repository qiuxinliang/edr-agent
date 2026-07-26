#ifndef EDR_EVNTTRACE_STUB_H
#define EDR_EVNTTRACE_STUB_H

/*
 * ETW control/trace APIs: use Windows SDK headers when building against WDK/Kit.
 * Do not duplicate macros/types from evntrace.h / evntcons.h — that clashes with
 * MSVC (C4005 redefinition, C4028 prototype mismatch) when those headers are
 * already included or pulled in by other translation units.
 */
#if defined(_WIN32)

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#endif

#endif /* EDR_EVNTTRACE_STUB_H */
