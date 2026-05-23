/* Stub header for ldsca.dll build.
   UA-LDS\settings.c uses ualds_log() with UALDS_LOG_* levels.  In a custom
   action we don't have UA-LDS's logger; we route to MsiLog (which writes to
   the MSI install log) via the implementation in log_stub.c.  All other LDS
   log enums (LogTarget, ualds_openlog, ualds_closelog) are not needed here. */
#ifndef __LDSCA_STUB_LOG_H__
#define __LDSCA_STUB_LOG_H__

enum _LogLevel
{
    UALDS_LOG_EMERG = 0,
    UALDS_LOG_ALERT,
    UALDS_LOG_CRIT,
    UALDS_LOG_ERR,
    UALDS_LOG_WARNING,
    UALDS_LOG_NOTICE,
    UALDS_LOG_INFO,
    UALDS_LOG_DEBUG
};
typedef enum _LogLevel LogLevel;

#ifdef __cplusplus
extern "C" {
#endif
void ualds_log(LogLevel level, const char *format, ...);
#ifdef __cplusplus
}
#endif

#endif
