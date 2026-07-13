/* ========================================================================
 * Copyright (c) 2005-2026, OPC Federation AISBL, All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

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
