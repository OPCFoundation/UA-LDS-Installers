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
