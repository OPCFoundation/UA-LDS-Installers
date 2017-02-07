// ldsca.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "ldsca.h"
#include "msilog.h"

extern "C"
{
#include "include\settings.h"
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

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\Discovery\\pki\\own\\ualdscert.der" );
	ret = ualds_settings_writestring( "CertificateFile", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\Discovery\\pki\\own\\ualdskey.nopass.pem" );
	ret = ualds_settings_writestring( "CertificateKeyFile", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\Discovery\\pki\\own\\cacert.pem" );
	ret = ualds_settings_writestring( "CertificateChainFile", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\Discovery\\pki\\crl" );
	ret = ualds_settings_writestring( "CRLPath", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\Discovery\\pki\\trusted\\certs" );
	ret = ualds_settings_writestring( "TrustListPath", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\Discovery\\pki\\issuer" );
	ret = ualds_settings_writestring( "IssuerPath", szUtf8Buffer );

	sprintf_s( szUtf8Buffer, MAX_PATH*2+1, "\"%s%s\"", szCommonAppDataFolderUtf8, "OPC Foundation\\UA\\Discovery\\pki\\rejected" );
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
