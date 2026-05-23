/* Stub implementation of ualds_log() for ldsca.dll.
   Inside an MSI custom action we have no syslog/file logger - route output
   to OutputDebugString so DebugView captures it.  Errors are silently
   dropped on the floor; the corresponding MsiLog calls in ldsca.cpp record
   the same events to the MSI install log, which is what end users actually
   look at when something goes wrong. */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "log.h"

void ualds_log(LogLevel level, const char *format, ...)
{
    char buf[1024];
    va_list ap;
    (void)level;
    va_start(ap, format);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, format, ap);
    va_end(ap);
    OutputDebugStringA(buf);
}
