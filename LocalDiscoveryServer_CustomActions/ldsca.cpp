// ldsca.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "ldsca.h"
#include "msilog.h"

extern "C"
{
#include "include\settings.h"
}

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

// This is an example of an exported function.
extern "C" LDSCA_API UINT UpdateUaldsIni( MSIHANDLE hInstall )
{
	TCHAR szCustomActionData[MAX_PATH*2+1] = {0};	
    DWORD dwCustomActionDataLen = MAX_PATH*2+1;

    MsiLogSetHandle( hInstall );

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

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\own\\certs\\ualdskey.nopass.pem" );
	ret = ualds_settings_writestring( "CertificateKeyFile", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\trusted\\certs\\cacert.pem" );
	ret = ualds_settings_writestring( "CertificateChainFile", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\pki\\trusted\\certs\\crl" );
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

	ret = ualds_settings_close();

	return 0;
}
