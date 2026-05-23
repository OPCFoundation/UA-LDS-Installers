// ldsca.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "ldsca.h"
#include "msilog.h"
#include <sys/stat.h>

extern "C"
{
#include "settings.h"   /* UA-LDS\settings.h via -I UA-LDS in CMakeLists */
}

#ifndef S_ISDIR
#define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#endif

/*============================================================================
 * OpcUa_StringToUnicode
 *===========================================================================*/
BOOL OpcUa_StringToUnicode(
    LPSTR a_sSource,
    LPWSTR* a_pUnicode)
{
    *a_pUnicode = NULL;

    if (a_sSource == NULL)
    {
        return TRUE;
    }

	int iLength = MultiByteToWideChar(
	   GetACP(), // CP_UTF8,
       0,
       a_sSource,
       -1,
       NULL,
       0);

    if (iLength == 0)
    {
		return FALSE;
    }

    *a_pUnicode = (WCHAR*)malloc(sizeof(WCHAR)*(iLength+1));

	iLength = MultiByteToWideChar(
	   GetACP(), // CP_UTF8,
       0,
       a_sSource,
       -1,
       (LPWSTR)*a_pUnicode,
       iLength+1);

    if (iLength == 0)
    {
        free(*a_pUnicode);
        *a_pUnicode = NULL;
		return FALSE;
    }

    (*a_pUnicode)[iLength] = L'\0';
	return TRUE;
}

BOOL OpcUa_MakeDir(LPSTR sFilePath)
{

	LPWSTR wszFilePath = NULL;

	if (!OpcUa_StringToUnicode(sFilePath, &wszFilePath))
    {
        MsiLog( _T("UpdateUaldsIni"), _T("Unicode Conversion Failed!") );
        return FALSE;
    }

    int result = 0;

    if (!CreateDirectoryW(wszFilePath, NULL))
    {
        result = GetLastError();
    }

    free(wszFilePath);
    wszFilePath = 0;

    if (result != 0 && result != ERROR_ALREADY_EXISTS)
    {
        MsiLog( _T("UpdateUaldsIni"), _T("Create Directory Failed!") );
        return FALSE;
    }

    return TRUE;
}

extern "C" LDSCA_API UINT BackupOldUaldsIni(MSIHANDLE hInstall)
{
    MsiLogSetHandle(hInstall);

    MsiLog(_T("BackupOldUaldsIni"), _T("Started"));

    char szCommonAppDataFolderUtf8[MAX_PATH + 1];
    
    char* buf = NULL;
    size_t sz = 0;
    if (_dupenv_s(&buf, &sz, "ALLUSERSPROFILE") == 0 && buf != NULL)
    {
        strcpy_s(szCommonAppDataFolderUtf8, sz, buf);
        free(buf);
        buf = NULL;
    }
    else
    {
        MsiLog(_T("BackupOldUaldsIni"), _T("Failed to get EnviromentVariable ALLUSERSPROFILE"));
        return 3;
    }

    char szUtf8Buffer[MAX_PATH * 2 + 1];
    sprintf_s(szUtf8Buffer, MAX_PATH * 2 + 1, "%s%s", szCommonAppDataFolderUtf8, "\\OPC Foundation\\UA\\Discovery\\ualds.ini");

    struct stat buffer;
    if (stat(szUtf8Buffer, &buffer) == 0)
    {
        // ini file exists
        char szUtf8Buffer_backup[MAX_PATH * 2 + 1 + 5];
        sprintf_s(szUtf8Buffer_backup, MAX_PATH * 2 + 1, "%s%s", szCommonAppDataFolderUtf8, "\\OPC Foundation\\UA\\Discovery\\ualds.ini.old");

        LPWSTR ws_szUtf8Buffer = NULL;
        if (!OpcUa_StringToUnicode(szUtf8Buffer, &ws_szUtf8Buffer))
        {
            MsiLog(_T("BackupOldUaldsIni"), _T("Unicode Conversion Failed!"));

            return 1;
        }

        LPWSTR ws_szUtf8Buffer_backup = NULL;
        if (!OpcUa_StringToUnicode(szUtf8Buffer_backup, &ws_szUtf8Buffer_backup))
        {
            MsiLog(_T("BackupOldUaldsIni"), _T("Unicode Conversion Failed!"));

            return 1;
        }

        BOOL copyREsult = CopyFile(ws_szUtf8Buffer, ws_szUtf8Buffer_backup, FALSE);
        if (copyREsult == 0)
        {
            MsiLog(_T("BackupOldUaldsIni"), _T("failed"));
        }
        else
        {
            MsiLog(_T("BackupOldUaldsIni"), _T("success"));
        }
    }
    else
    {
        MsiLog(_T("BackupOldUaldsIni"), _T("ualdsini not found"));
    }

    MsiLog(_T("BackupOldUaldsIni"), _T("Finished"));

    return 0;
}

extern "C" LDSCA_API UINT CopyPkiKeysFromOldIniFile(MSIHANDLE hInstall)
{
    MsiLogSetHandle(hInstall);

    MsiLog(_T("CopyPkiKeysFromOldIniFile"), _T("Started"));

    char szCommonAppDataFolderUtf8[MAX_PATH + 1];

    char* buf = NULL;
    size_t sz = 0;
    if (_dupenv_s(&buf, &sz, "ALLUSERSPROFILE") == 0 && buf != NULL)
    {
        strcpy_s(szCommonAppDataFolderUtf8, sz, buf);
        free(buf);
        buf = NULL;
    }
    else
    {
        MsiLog(_T("BackupOldUaldsIni"), _T("Failed to get EnviromentVariable ALLUSERSPROFILE"));
        return 3;
    }

    char szUtf8Buffer[MAX_PATH * 2 + 1];
    sprintf_s(szUtf8Buffer, MAX_PATH * 2 + 1, "%s%s", szCommonAppDataFolderUtf8, "\\OPC Foundation\\UA\\Discovery\\ualds.ini");
    char szUtf8Buffer_backup[MAX_PATH * 2 + 1 + 5];
    sprintf_s(szUtf8Buffer_backup, MAX_PATH * 2 + 1, "%s%s", szCommonAppDataFolderUtf8, "\\OPC Foundation\\UA\\Discovery\\ualds.ini.old");

    struct stat buffer;
    if (stat(szUtf8Buffer, &buffer) != 0)
    {
        MsiLog(_T("CopyPkiKeysFromOldIniFile"), _T("ualdsini not found!"));

        return 0;  /* fresh install - nothing to migrate from, not an error */
    }

    if (stat(szUtf8Buffer_backup, &buffer) != 0)
    {
        MsiLog(_T("CopyPkiKeysFromOldIniFile"), _T("ualdsini backup not found!"));
        return 0;  /* fresh install - nothing to migrate from, not an error */
    }

    // read PKI keys from old ini file
    int ret = ualds_settings_open(szUtf8Buffer_backup);

    if (ret) //Error opening ini file
    {
        MsiLog(_T("CopyPkiKeysFromOldIniFile ualds.ini.old"), _T("Error opening ini file"));
        return ret;
    }

    ret = ualds_settings_begingroup("PKI");

    char szUtf8Buffer_Old_TrustListPath[MAX_PATH * 2 + 1];
    ret = ualds_settings_readstring("TrustListPath", szUtf8Buffer_Old_TrustListPath, 256);
    {
        // check if valid path
        struct stat sb;
        if (stat(szUtf8Buffer_Old_TrustListPath, &sb) == 0 && S_ISDIR(sb.st_mode))
        {
			
			LPWSTR wszFilePath = NULL;

            OpcUa_StringToUnicode(szUtf8Buffer_Old_TrustListPath, &wszFilePath);
			
            MsiLog(_T("CopyPkiKeysFromOldIniFile Old TrustListPath read before modify: "), wszFilePath);
		    //MessageBoxW(NULL, wszFilePath,_T("CopyPkiKeysFromOldIniFile"),MB_OK);
            free(wszFilePath);
            wszFilePath = 0;
            // it is a valid directory
        }
        else
        {
            sprintf_s(szUtf8Buffer_Old_TrustListPath, MAX_PATH * 2 + 1, "\"%s%s\"", szCommonAppDataFolderUtf8, "\\OPC Foundation\\UA\\pki\\trusted\\certs");
						
			LPWSTR wszFilePath = NULL;

            OpcUa_StringToUnicode(szUtf8Buffer_Old_TrustListPath, &wszFilePath);
			
			MsiLog(_T("CopyPkiKeysFromOldIniFile: use default value for TrustListPath: "), wszFilePath);
		    //MessageBoxW(NULL, wszFilePath,_T("CopyPkiKeysFromOldIniFile_else"),MB_OK);
            free(wszFilePath);
            wszFilePath = 0;
        }
    }

    char szUtf8Buffer_Old_IssuerPath[MAX_PATH * 2 + 1];
    ret = ualds_settings_readstring("IssuerPath", szUtf8Buffer_Old_IssuerPath, 256);
    {
        // check if valid path
        struct stat sb;
        if (stat(szUtf8Buffer_Old_IssuerPath, &sb) == 0 && S_ISDIR(sb.st_mode))
        {
            // it is a valid directory
			{
					LPWSTR wszFilePath = NULL;

					OpcUa_StringToUnicode(szUtf8Buffer_Old_IssuerPath, &wszFilePath);
					
					MsiLog(_T("CopyPkiKeysFromOldIniFile Old IssuerPath read before modify: "), wszFilePath);
					//MessageBoxW(NULL, wszFilePath,_T("CopyPkiKeysFromOldIniFile"),MB_OK);
					free(wszFilePath);
					wszFilePath = 0;
			}
        }
        else
        {
            sprintf_s(szUtf8Buffer_Old_IssuerPath, MAX_PATH * 2 + 1, "\"%s%s\"", szCommonAppDataFolderUtf8, "\\OPC Foundation\\UA\\pki\\issuer\\certs");
			{
					LPWSTR wszFilePath = NULL;

					OpcUa_StringToUnicode(szUtf8Buffer_Old_IssuerPath, &wszFilePath);
					
					MsiLog(_T("CopyPkiKeysFromOldIniFile: use default value for IssuerPath: "), wszFilePath);
					//MessageBoxW(NULL, wszFilePath,_T("CopyPkiKeysFromOldIniFile_else"),MB_OK);
					free(wszFilePath);
					wszFilePath = 0;
			}
		}
    }

    char szUtf8Buffer_Old_RejectedPath[MAX_PATH * 2 + 1];
    ret = ualds_settings_readstring("RejectedPath", szUtf8Buffer_Old_RejectedPath, 256);
    {
        // check if valid path
        struct stat sb;
        if (stat(szUtf8Buffer_Old_RejectedPath, &sb) == 0 && S_ISDIR(sb.st_mode))
        {
            // it is a valid directory

			{
					LPWSTR wszFilePath = NULL;

					OpcUa_StringToUnicode(szUtf8Buffer_Old_RejectedPath, &wszFilePath);
					
					MsiLog(_T("CopyPkiKeysFromOldIniFile Old RejectedPath read before modify: "), wszFilePath);
					//MessageBoxW(NULL, wszFilePath,_T("CopyPkiKeysFromOldIniFile"),MB_OK);
					free(wszFilePath);
					wszFilePath = 0;
			}
		}
        else
        {
            sprintf_s(szUtf8Buffer_Old_RejectedPath, MAX_PATH * 2 + 1, "\"%s%s\"", szCommonAppDataFolderUtf8, "\\OPC Foundation\\UA\\pki\\rejected\\certs");
			{
					LPWSTR wszFilePath = NULL;

					OpcUa_StringToUnicode(szUtf8Buffer_Old_RejectedPath, &wszFilePath);
					
					MsiLog(_T("CopyPkiKeysFromOldIniFile: use default value for RejectedPath: "), wszFilePath);
					//MessageBoxW(NULL, wszFilePath,_T("CopyPkiKeysFromOldIniFile_else"),MB_OK);
					free(wszFilePath);
					wszFilePath = 0;
			} 
		}
    }

    char szUtf8Buffer_Old_CRLPath[MAX_PATH * 2 + 1];
    ret = ualds_settings_readstring("CRLPath", szUtf8Buffer_Old_CRLPath, 256);

    {
        // check if valid path
        struct stat sb;
        if (stat(szUtf8Buffer_Old_CRLPath, &sb) == 0 && S_ISDIR(sb.st_mode))
        {
            // it is a valid directory
			{
					LPWSTR wszFilePath = NULL;

					OpcUa_StringToUnicode(szUtf8Buffer_Old_CRLPath, &wszFilePath);
					
					MsiLog(_T("CopyPkiKeysFromOldIniFile Old CRLPath read before modify: "), wszFilePath);
					//MessageBoxW(NULL, wszFilePath,_T("CopyPkiKeysFromOldIniFile"),MB_OK);
					free(wszFilePath);
					wszFilePath = 0;
			}
		}
        else
        {
            sprintf_s(szUtf8Buffer_Old_CRLPath, MAX_PATH * 2 + 1, "\"%s%s\"", szCommonAppDataFolderUtf8, "\\OPC Foundation\\UA\\pki\\trusted\\crl");
			{
					LPWSTR wszFilePath = NULL;

					OpcUa_StringToUnicode(szUtf8Buffer_Old_CRLPath, &wszFilePath);
					
					MsiLog(_T("CopyPkiKeysFromOldIniFile: use default value for CRLPath: "), wszFilePath);
					//MessageBoxW(NULL, wszFilePath,_T("CopyPkiKeysFromOldIniFile_else"),MB_OK);
					free(wszFilePath);
					wszFilePath = 0;
			}
		}
    }

    char szUtf8Buffer_Old_CertificateChainFile[MAX_PATH * 2 + 1];
    ret = ualds_settings_readstring("CertificateChainFile", szUtf8Buffer_Old_CertificateChainFile, 256);
    {
        // check if valid path
        struct stat sb;
        if (stat(szUtf8Buffer_Old_CertificateChainFile, &sb) == 0)
        {
            // it is a valid file
        }
        else
        {
            sprintf_s(szUtf8Buffer_Old_CertificateChainFile, MAX_PATH * 2 + 1, "\"%s%s\"", szCommonAppDataFolderUtf8, "\\OPC Foundation\\UA\\pki\\trusted\\certs\\cacert.pem");
        }
    }

    ret = ualds_settings_endgroup();

    ret = ualds_settings_close(1);  /* flush to disk on close */

    // write the pki key values to new ini file

    // read PKI keys from old ini file
    ret = ualds_settings_open(szUtf8Buffer);

    if (ret) //Error opening ini file
    {
        MsiLog(_T("CopyPkiKeysFromOldIniFile"), _T("Error opening ini file"));
        return ret;
    }

    ret = ualds_settings_begingroup("PKI");

    ret = ualds_settings_writestring("TrustListPath", szUtf8Buffer_Old_TrustListPath);
    ret = ualds_settings_writestring("IssuerPath", szUtf8Buffer_Old_IssuerPath);
    ret = ualds_settings_writestring("RejectedPath", szUtf8Buffer_Old_RejectedPath);
    ret = ualds_settings_writestring("CRLPath", szUtf8Buffer_Old_CRLPath);
    ret = ualds_settings_writestring("CertificateChainFile", szUtf8Buffer_Old_CertificateChainFile);

    ret = ualds_settings_endgroup();

    ret = ualds_settings_close(1);  /* flush to disk on close */

	//MessageBoxW(NULL, _T("CopyPkiKeysFromOldIniFile completed."),_T("Info"),MB_OK);

    MsiLog(_T("CopyPkiKeysFromOldIniFile"), _T("Finished"));

    return 0;
}

extern "C" LDSCA_API UINT UpdateUaldsIni( MSIHANDLE hInstall )
{
	TCHAR szCustomActionData[MAX_PATH*2+1] = {0};	
    DWORD dwCustomActionDataLen = MAX_PATH*2+1;

    MsiLogSetHandle( hInstall );

    MsiLog(_T("UpdateUaldsIni"), _T("Started"));

	UINT gp = MsiGetProperty( hInstall, L"CustomActionData", szCustomActionData, &dwCustomActionDataLen );
	
	if( gp != 0 )
	{
        MsiLog( _T("UpdateUaldsIni"), _T("MsiGetProperty returned error") );
		return gp;
	}

	if( dwCustomActionDataLen == 0 )
	{
        MsiLog( _T("UpdateUaldsIni"), _T("CustomActionData Length is 0") );
		return 1;
	}

	char szCustomActionDataUtf8[MAX_PATH*2+1];
	WideCharToMultiByte( CP_UTF8, 0, szCustomActionData, -1, szCustomActionDataUtf8, MAX_PATH*2+1, NULL, NULL );

	char szCommonFilesFolderUtf8[MAX_PATH+1], szCommonAppDataFolderUtf8[MAX_PATH+1];
	char* mark = strchr( szCustomActionDataUtf8, '|' );

	if( mark == NULL )
	{
        MsiLog( _T("UpdateUaldsIni"), _T("CustomActionData mark not found") );
		return 2;
	}

	*mark = 0;
	strcpy_s( szCommonFilesFolderUtf8, MAX_PATH+1, szCustomActionDataUtf8 );
	strcpy_s( szCommonAppDataFolderUtf8, MAX_PATH+1, mark + 1 );

	char szUtf8Buffer[MAX_PATH*2+1];
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\Discovery\\ualds.ini" );
	
	int ret = ualds_settings_open( szUtf8Buffer );

	if( ret )	//Error opening ini file
	{
        MsiLog( _T("UpdateUaldsIni"), _T("Error opening ini file") );
		return ret;
	}

	ret = ualds_settings_begingroup( "PKI" );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\own" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\own\\certs" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\own\\private" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\trusted" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\trusted\\certs" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\trusted\\crl" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\issuer" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\issuer\\certs" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\issuer\\crl" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\rejected" );
	OpcUa_MakeDir(szUtf8Buffer);
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "%s%s", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\rejected\\certs" );
	OpcUa_MakeDir(szUtf8Buffer);

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\" );
	ret = ualds_settings_writestring( "CertificateStorePath", szUtf8Buffer );
    
	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\own\\certs\\ualdscert.der" );
	ret = ualds_settings_writestring( "CertificateFile", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\own\\private\\ualdskey.nopass.pem" );
	ret = ualds_settings_writestring( "CertificateKeyFile", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\trusted\\certs\\cacert.pem" );
	ret = ualds_settings_writestring( "CertificateChainFile", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\trusted\\crl" );
	ret = ualds_settings_writestring( "CRLPath", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\trusted\\certs" );
	ret = ualds_settings_writestring( "TrustListPath", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\issuer\\certs" );
	ret = ualds_settings_writestring( "IssuerPath", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\rejected\\certs" );
	ret = ualds_settings_writestring( "RejectedPath", szUtf8Buffer );

	ret = ualds_settings_endgroup();

	ret = ualds_settings_begingroup( "Log" );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\Discovery\\opcualds.log" );
	ret = ualds_settings_writestring( "LogFile", szUtf8Buffer );

	ret = ualds_settings_endgroup();

	ret = ualds_settings_begingroup( "urn:[gethostname]:UALocalDiscoveryServer" );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonFilesFolderUtf8, "OPC Foundation\\UA\\Discovery\\bin\\opcualds.exe" );
	ret = ualds_settings_writestring( "SemaphoreFilePath", szUtf8Buffer );

	ret = ualds_settings_endgroup();

	ret = ualds_settings_close(1);  /* flush to disk on close */

	//MessageBoxW(NULL, _T("UpdateUaldsIni completed."),_T("Info"),MB_OK);

	MsiLog(_T("UpdateUaldsIni"), _T("Finished"));

	return 0;
}
