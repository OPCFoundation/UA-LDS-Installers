/* Stub UA-LDS platform helpers needed by settings.c when compiled into
   ldsca.dll.  The real win32/platform.c is part of opcualds.exe and pulls
   in too many other dependencies (Windows services, sockets, certstore,
   ...) - we only need these four trivial functions to satisfy settings.c. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UALDS_FILE FILE

UALDS_FILE *ualds_platform_fopen(const char *path, const char *mode)
{
    return fopen(path, mode);
}

int ualds_platform_fclose(UALDS_FILE *fp)
{
    return fclose(fp);
}

/* Default paths: identical to win32/platform.c so the custom action sees the
   same defaults the running LDS service would see. */
void getDefaultCertificateFolder(char *szFolderPath, size_t len)
{
    char *pszAppData = NULL;
    size_t sz = 0;
    if (_dupenv_s(&pszAppData, &sz, "ALLUSERSPROFILE") == 0 && pszAppData)
    {
        strncpy_s(szFolderPath, len, pszAppData, _TRUNCATE);
        strncat_s(szFolderPath, len, "\\OPC Foundation\\UA\\pki", _TRUNCATE);
        free(pszAppData);
    }
    else
    {
        szFolderPath[0] = '\0';
    }
}

void getDefaultLogFilePath(char *szFilePath, size_t len)
{
    char *pszAppData = NULL;
    size_t sz = 0;
    if (_dupenv_s(&pszAppData, &sz, "ALLUSERSPROFILE") == 0 && pszAppData)
    {
        strncpy_s(szFilePath, len, pszAppData, _TRUNCATE);
        strncat_s(szFilePath, len, "\\OPC Foundation\\UA\\Discovery\\opcualds.log", _TRUNCATE);
        free(pszAppData);
    }
    else
    {
        szFilePath[0] = '\0';
    }
}
