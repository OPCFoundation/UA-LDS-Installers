#include "stdafx.h"
#include "msilog.h"

MSIHANDLE _hInstall;

void MsiLogSetHandle( MSIHANDLE hInstall )
{
    _hInstall = hInstall;
}

void MsiLog( LPCTSTR context, LPCTSTR detail )
{
    PMSIHANDLE hRecord = MsiCreateRecord(2);
    // field 0 is the template
    MsiRecordSetString(hRecord, 0, _T("[1] - [2]") );
    MsiRecordSetString(hRecord, 1, context );
    MsiRecordSetString(hRecord, 2, detail );
    // send message to running installer
    MsiProcessMessage( _hInstall, INSTALLMESSAGE_INFO, hRecord);
}

void MsiLog( LPCTSTR context, LPCTSTR detail, HRESULT result )
{
    PMSIHANDLE hRecord = MsiCreateRecord(3);
    // field 0 is the template
    MsiRecordSetString(hRecord, 0, _T("[1] - [2] - Result: [3]") );
    MsiRecordSetString(hRecord, 1, context );
    MsiRecordSetString(hRecord, 2, detail );
    MsiRecordSetInteger(hRecord, 3, result );
    // send message to running installer
    MsiProcessMessage( _hInstall, INSTALLMESSAGE_INFO, hRecord);
}
