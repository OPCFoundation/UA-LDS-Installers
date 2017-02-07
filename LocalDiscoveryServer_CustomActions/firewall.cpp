#include "stdafx.h"
#include "ldsca.h"
#include "msilog.h"


#define FWEL_PORT_PROTOCOL_TYPE_TCP       1
#define FWEL_PORT_PROTOCOL_TYPE_UDP       2
#define FWEL_PORT_PROTOCOL_TYPE_ANY       3

#define  APP_NAME_DSC _T("OPC UA Local Discovery Server")
#define  APP_NAME_BONJOUR_DSC _T("OPCF Bonjour Serice")

#define RET_ERROR		-1L
#define RET_OK			 0L

int checkWinVersionForFWEL()
{
  //the functions used for FWEL are supported only XP SP2 and later

    OSVERSIONINFO osVersion;
    ZeroMemory(&osVersion, sizeof(OSVERSIONINFO));
    osVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osVersion);

    TCHAR szSysInfor[501];
    _stprintf_s(szSysInfor, 500, _T("Maj:%d Min:%d PlatformId:%d Build: %d SP: %s"), 
       osVersion.dwMajorVersion,
       osVersion.dwMinorVersion,
       osVersion.dwPlatformId,
       osVersion.dwBuildNumber,
       osVersion.szCSDVersion);

    MsiLog( _T("checkWinVersionForFWEL"), szSysInfor);

    if( osVersion.dwMajorVersion < 5 )
      return 0;

    if( osVersion.dwMajorVersion == 5 && osVersion.dwMinorVersion < 1 )
      return 0;

    if(osVersion.dwMajorVersion == 5 && osVersion.dwMinorVersion == 1) //Windows XP
    {
      if(lstrlen(osVersion.szCSDVersion) == 0)
        return 0;

      if(_tcscmp( osVersion.szCSDVersion, L"Service Pack 2" ) < 0)
        return 0;
    }
   
  return 1; //supported 
}

HRESULT FWEL_Initialize(OUT INetFwProfile** fwProfile)
{
    HRESULT hr = S_OK;
    INetFwMgr* fwMgr = NULL;
    INetFwPolicy* fwPolicy = NULL;

    _ASSERT(fwProfile != NULL);

    *fwProfile = NULL;

    // Create an instance of the firewall settings manager.
    hr = CoCreateInstance( __uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER,
                           __uuidof(INetFwMgr),(void**)&fwMgr);

    if (FAILED(hr))
    {
        MsiLog(_T("FWEL_Initialize"),_T("CoCreateInstance"), hr);
    }else{
      // Retrieve the local firewall policy.
      hr = fwMgr->get_LocalPolicy(&fwPolicy);
      if (FAILED(hr))
      {
        MsiLog(_T("FWEL_Initialize"),_T("get_LocalPolicy"), hr);
      }else{
        // Retrieve the firewall profile currently in effect.
        hr = fwPolicy->get_CurrentProfile(fwProfile);
        if (FAILED(hr))
        {
          MsiLog(_T("FWEL_Initialize"),_T("get_CurrentProfile"), hr);
        }
      }
    }

    // Release the local firewall policy.
    if (fwPolicy != NULL)
      fwPolicy->Release();

    // Release the firewall settings manager.
    if (fwMgr != NULL)
      fwMgr->Release();

    return hr;
}

void FWEL_Cleanup(IN INetFwProfile* fwProfile)
{
  // Release the firewall profile.
  if (fwProfile != NULL)
    fwProfile->Release();
}


HRESULT FWEL_IsOn(IN INetFwProfile* fwProfile, OUT BOOL* fwOn)
{
    HRESULT hr = S_OK;
    VARIANT_BOOL fwEnabled;

    _ASSERT(fwProfile != NULL);
    _ASSERT(fwOn != NULL);

    *fwOn = FALSE;

    // Get the current state of the firewall.
    hr = fwProfile->get_FirewallEnabled(&fwEnabled);
    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_IsOn"),_T("get_FirewallEnabled"), hr);
      return hr;
    }

    // Check to see if the firewall is on.
    if (fwEnabled != VARIANT_FALSE)
      *fwOn = TRUE; //The firewall is on

    return hr;
}


HRESULT FWEL_TurnOn(IN INetFwProfile* fwProfile)
{
    HRESULT hr = S_OK;
    BOOL fwOn;
    _ASSERT(fwProfile != NULL);

    // Check to see if the firewall is off.
    hr = FWEL_IsOn(fwProfile, &fwOn);
    if (FAILED(hr))
       return hr;
    
    // If it is off, turn it on.
    if (!fwOn)
    {
      // Turn the firewall on.
      hr = fwProfile->put_FirewallEnabled(VARIANT_TRUE);
      if (FAILED(hr))
        MsiLog(_T("FWEL_TurnOn"),_T("put_FirewallEnabled"), hr);
    }
    return hr;
}


HRESULT FWEL_TurnOff(IN INetFwProfile* fwProfile)
{
    HRESULT hr = S_OK;
    BOOL fwOn;

    _ASSERT(fwProfile != NULL);

    // Check to see if the firewall is on.
    hr = FWEL_IsOn(fwProfile, &fwOn);
    if (FAILED(hr))
      return hr;

    // If it is on, turn it off.
    if (fwOn)
      hr = fwProfile->put_FirewallEnabled(VARIANT_FALSE);

    return hr;
}


HRESULT FWEL_IsAppEnabled(
            IN INetFwProfile* fwProfile,
            IN const TCHAR* fwProcessImageFileName,
            OUT BOOL* fwAppEnabled
            )
{
    HRESULT hr = S_OK;
    BSTR fwBstrProcessImageFileName = NULL;
    VARIANT_BOOL fwEnabled;
    INetFwAuthorizedApplication* fwApp = NULL;
    INetFwAuthorizedApplications* fwApps = NULL;

    _ASSERT(fwProfile != NULL);
    _ASSERT(fwProcessImageFileName != NULL);
    _ASSERT(fwAppEnabled != NULL);

    *fwAppEnabled = FALSE;

    // Retrieve the authorized application collection.
    hr = fwProfile->get_AuthorizedApplications(&fwApps);
    if (FAILED(hr))
    {
       MsiLog(_T("FWEL_IsAppEnabled"),_T("get_AuthorizedApplications"), hr);
    }else{
      // Allocate a BSTR for the process image file name.
      fwBstrProcessImageFileName = T2BSTR(fwProcessImageFileName);
      if (fwBstrProcessImageFileName == NULL)
      {
        hr = E_OUTOFMEMORY;
        MsiLog(_T("FWEL_IsAppEnabled"),_T("Convert String"), hr);
      }else{
        // Attempt to retrieve the authorized application.
        hr = fwApps->Item(fwBstrProcessImageFileName, &fwApp);
        if (SUCCEEDED(hr))
        {
          // Find out if the authorized application is enabled.
          hr = fwApp->get_Enabled(&fwEnabled);
          if (FAILED(hr))
          {
            MsiLog(_T("FWEL_IsAppEnabled"),_T("get_Enabled"), hr);
          }else{
            if (fwEnabled != VARIANT_FALSE)
            {
              // The authorized application is enabled.
              *fwAppEnabled = TRUE;
            }
          }
        }else{
          // The authorized application was not in the collection.
          hr = S_OK;
        }
      }
    }

    // Free the BSTR.
    SysFreeString(fwBstrProcessImageFileName);

    // Release the authorized application instance.
    if (fwApp != NULL)
        fwApp->Release();

    // Release the authorized application collection.
    if (fwApps != NULL)
        fwApps->Release();

    return hr;
}


HRESULT FWEL_AddApp(
            IN INetFwProfile* fwProfile,
            IN const TCHAR* fwProcessImageFileName,
            IN const TCHAR* fwName
            )
{
    HRESULT hr = S_OK;
    BOOL fwAppEnabled;
    BSTR fwBstrName = NULL;
    BSTR fwBstrProcessImageFileName = NULL;
    INetFwAuthorizedApplication* fwApp = NULL;
    INetFwAuthorizedApplications* fwApps = NULL;

    _ASSERT(fwProfile != NULL);
    _ASSERT(fwProcessImageFileName != NULL);
    _ASSERT(fwName != NULL);

    // First check to see if the application is already authorized.
    hr = FWEL_IsAppEnabled(fwProfile,fwProcessImageFileName,&fwAppEnabled);

    // Only add the application if it isn't already authorized.
    if (SUCCEEDED(hr) && !fwAppEnabled)
    {
      // Retrieve the authorized application collection.
      hr = fwProfile->get_AuthorizedApplications(&fwApps);
      if (FAILED(hr))
      {
        MsiLog(_T("FWEL_AddApp"),_T("get_AuthorizedApplications"), hr);
      }else{
        // Create an instance of an authorized application.
        hr = CoCreateInstance(__uuidof(NetFwAuthorizedApplication),NULL,CLSCTX_INPROC_SERVER,
                              __uuidof(INetFwAuthorizedApplication),(void**)&fwApp);
        if (FAILED(hr))
        {
          MsiLog(_T("FWEL_AddApp"),_T("CoCreateInstance"), hr);
        }else{
          // Allocate a BSTR for the process image file name.
          fwBstrProcessImageFileName = T2BSTR(fwProcessImageFileName);
          if (fwBstrProcessImageFileName == NULL)
          {
            hr = E_OUTOFMEMORY;
            MsiLog(_T("FWEL_AddApp"),_T("Convert String"), hr);
          }else{
            // Set the process image file name.
            hr = fwApp->put_ProcessImageFileName(fwBstrProcessImageFileName);
            if (FAILED(hr))
            {
              MsiLog(_T("FWEL_AddApp - file=put_ProcessImageFileName"), fwProcessImageFileName, hr);
            }else{
              // Allocate a BSTR for the application friendly name.
              fwBstrName = T2BSTR(fwName);
              if (SysStringLen(fwBstrName) == 0)
              {
                hr = E_OUTOFMEMORY;
                MsiLog(_T("FWEL_AddApp"),_T("Convert String"), hr);
              }else{
                // Set the application friendly name.
                hr = fwApp->put_Name(fwBstrName);
                if (FAILED(hr))
                {
                  MsiLog(_T("FWEL_AddApp"),_T("put_Name"), hr);
                }else{
                  // Add the application to the collection.
                  hr = fwApps->Add(fwApp);
                  if (FAILED(hr))
                  {
                    MsiLog(_T("FWEL_AddApp"),_T("Add App"), hr);
                  }
                }
              }
            }
          }
        }
      }
    }

    // Free the BSTRs.
    SysFreeString(fwBstrName);
    SysFreeString(fwBstrProcessImageFileName);

    // Release the authorized application instance.
    if (fwApp != NULL)
      fwApp->Release();

    // Release the authorized application collection.
    if (fwApps != NULL)
      fwApps->Release();

    return hr;
}

HRESULT FWEL_RemoveApp(
            IN INetFwProfile* fwProfile,
            IN const TCHAR* fwProcessImageFileName
            )
{
    HRESULT hr = S_OK;
    BOOL fwAppEnabled;
    BSTR fwBstrProcessImageFileName = NULL;
    INetFwAuthorizedApplication* fwApp = NULL;
    INetFwAuthorizedApplications* fwApps = NULL;

    _ASSERT(fwProfile != NULL);
    _ASSERT(fwProcessImageFileName != NULL);

    // First check to see if the application is already authorized.
    hr = FWEL_IsAppEnabled(fwProfile,fwProcessImageFileName,&fwAppEnabled);

    // Only remove the application if it is already authorized.
    if (SUCCEEDED(hr) && fwAppEnabled)
    {
      // Retrieve the authorized application collection.
      hr = fwProfile->get_AuthorizedApplications(&fwApps);
      if (FAILED(hr))
      {
        MsiLog(_T("FWEL_RemoveApp"), _T("get_AuthorizedApplications"), hr);
      }else{
        // Allocate a BSTR for the process image file name.
        fwBstrProcessImageFileName = T2BSTR(fwProcessImageFileName);
        if (fwBstrProcessImageFileName == NULL)
        {
          hr = E_OUTOFMEMORY;
          MsiLog(_T("FWEL_RemoveApp"),_T("Convert String"), hr);
        }else{
          hr = fwApps->Remove(fwBstrProcessImageFileName);
          if (FAILED(hr))
          {
            MsiLog(_T("FWEL_RemoveApp"),_T("Remove App"), hr);
          }
        }
      }
    }

    // Free the BSTRs.
    SysFreeString(fwBstrProcessImageFileName);

    // Release the authorized application instance.
    if (fwApp != NULL)
      fwApp->Release();

    // Release the authorized application collection.
    if (fwApps != NULL)
      fwApps->Release();

    return hr;
}

HRESULT FWEL_IsPortEnabled(
            IN INetFwProfile* fwProfile,
            IN LONG portNumber,
            IN NET_FW_IP_PROTOCOL ipProtocol,
            OUT BOOL* fwPortEnabled
            )
{
    HRESULT hr = S_OK;
    VARIANT_BOOL fwEnabled;
    INetFwOpenPort* fwOpenPort = NULL;
    INetFwOpenPorts* fwOpenPorts = NULL;

    _ASSERT(fwProfile != NULL);
    _ASSERT(fwPortEnabled != NULL);

    *fwPortEnabled = FALSE;

    // Retrieve the globally open ports collection.
    hr = fwProfile->get_GloballyOpenPorts(&fwOpenPorts);
    if (FAILED(hr))
    {
       MsiLog(_T("FWEL_IsPortEnabled"),_T("get_GloballyOpenPorts"), hr);
    }else{

      // Attempt to retrieve the globally open port.
      hr = fwOpenPorts->Item(portNumber, ipProtocol, &fwOpenPort);
      if (SUCCEEDED(hr))
      {
        // Find out if the globally open port is enabled.
        hr = fwOpenPort->get_Enabled(&fwEnabled);
        if (FAILED(hr))
        {
          MsiLog(_T("FWEL_IsPortEnabled"),_T("get_Enabled"), hr);
        }else{

          if (fwEnabled != VARIANT_FALSE)
          {
            // The globally open port is enabled.
            *fwPortEnabled = TRUE;
          }
        }
      }else{
        // The globally open port was not in the collection.
        hr = S_OK;
      }
    }

    // Release the globally open port.
    if (fwOpenPort != NULL)
      fwOpenPort->Release();

    // Release the globally open ports collection.
    if (fwOpenPorts != NULL)
      fwOpenPorts->Release();

    return hr;
}


HRESULT FWEL_AddPort(
            IN INetFwProfile* fwProfile,
            IN LONG portNumber,
            IN NET_FW_IP_PROTOCOL ipProtocol,
            IN const TCHAR* name
            )
{
    HRESULT hr = S_OK;
    BOOL fwPortEnabled;
    BSTR fwBstrName = NULL;
    INetFwOpenPort* fwOpenPort = NULL;
    INetFwOpenPorts* fwOpenPorts = NULL;

    _ASSERT(fwProfile != NULL);
    _ASSERT(name != NULL);

    // First check to see if the port is already added.
    hr = FWEL_IsPortEnabled(fwProfile,portNumber,ipProtocol,&fwPortEnabled);

    // Only add the port if it isn't already added.
    if (SUCCEEDED(hr) && !fwPortEnabled)
    {
      // Retrieve the collection of globally open ports.
      hr = fwProfile->get_GloballyOpenPorts(&fwOpenPorts);
      if (FAILED(hr))
      {
        MsiLog(_T("FWEL_PortAdd"),_T("get_GloballyOpenPorts"), hr);
      }else{
        // Create an instance of an open port.
        hr = CoCreateInstance(__uuidof(NetFwOpenPort),NULL,CLSCTX_INPROC_SERVER,
                              __uuidof(INetFwOpenPort),(void**)&fwOpenPort);

        if (FAILED(hr))
        {
          MsiLog(_T("FWEL_PortAdd"),_T("CoCreateInstance"), hr);
        }else{
          // Set the port number.
          hr = fwOpenPort->put_Port(portNumber);
          if (FAILED(hr))
          {
            MsiLog(_T("FWEL_PortAdd"),_T("put_Port"), hr);
          }else{
            // Set the IP protocol.
            hr = fwOpenPort->put_Protocol(ipProtocol);
            if (FAILED(hr))
            {
              MsiLog(_T("FWEL_PortAdd"),_T("put_Protocol"), hr);
            }else{
              // Allocate a BSTR for the friendly name of the port.
              fwBstrName = T2BSTR(name);
              if (SysStringLen(fwBstrName) == 0)
              {
                hr = E_OUTOFMEMORY;
                MsiLog(_T("FWEL_PortAdd"),_T("Convert String"), hr);
              }else{
                // Set the friendly name of the port.
                hr = fwOpenPort->put_Name(fwBstrName);
                if (FAILED(hr))
                {
                  MsiLog(_T("FWEL_PortAdd"),_T("put_Name"), hr);
                }else{
                  // Opens the port and adds it to the collection.
                  hr = fwOpenPorts->Add(fwOpenPort);
                  if (FAILED(hr))
                  {
                    MsiLog(_T("FWEL_PortAdd"),_T("Add Port"), hr);
                  }
                }
              }
            }
          }
        }
      }
    }

    // Free the BSTR.
    SysFreeString(fwBstrName);

    // Release the open port instance.
    if (fwOpenPort != NULL)
        fwOpenPort->Release();

    // Release the globally open ports collection.
    if (fwOpenPorts != NULL)
        fwOpenPorts->Release();

    return hr;
}

HRESULT FWEL_RemovePort(
            IN INetFwProfile* fwProfile,
            IN LONG portNumber,
            IN NET_FW_IP_PROTOCOL ipProtocol,
            IN const TCHAR* name
            )
{
    HRESULT hr = S_OK;
    BOOL fwPortEnabled;
    INetFwOpenPorts* fwOpenPorts = NULL;
    INetFwOpenPort* fwOpenPort = NULL;
    VARIANT_BOOL fwEnabled;

    _ASSERT(fwProfile != NULL);

    fwPortEnabled = FALSE;

    // Retrieve the globally open ports collection.
    hr = fwProfile->get_GloballyOpenPorts(&fwOpenPorts);
    if (FAILED(hr))
    {
       MsiLog(_T("FWEL_RemovePort"),_T("get_GloballyOpenPorts"), hr);
       return hr;
    }else{
      // Attempt to retrieve the globally open port.
      hr = fwOpenPorts->Item(portNumber, ipProtocol, &fwOpenPort);
      if (FAILED(hr))
      {
        // The globally open port was not in the collection, do nothing
        hr = S_OK;
        
        // Release the globally open ports collection.
        if (fwOpenPorts != NULL)
          fwOpenPorts->Release();
        
        return hr;
      }
    }

    // Find out if the globally open port is enabled.
    hr = fwOpenPort->get_Enabled(&fwEnabled);
    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_RemovePort"),_T("get_Enabled"), hr);
    }else{
      if (fwEnabled != VARIANT_FALSE)
        fwPortEnabled = TRUE;
    }

    if (SUCCEEDED(hr) && fwPortEnabled)
    {
      //disable it at first
      hr = fwOpenPort->put_Enabled(VARIANT_FALSE);
      if (FAILED(hr))
        MsiLog(_T("FWEL_RemovePort"),_T("put_Enabled"), hr);
    }


    // Only remove the port if it is already added.
    if (SUCCEEDED(hr))
    {
      hr = fwOpenPorts->Remove(portNumber, ipProtocol);
      if (FAILED(hr))
          MsiLog(_T("FWEL_RemovePort"),_T("Remove Port"), hr);
    }

    // Release the globally open port.
    if (fwOpenPort != NULL)
      fwOpenPort->Release();

    // Release the globally open ports collection.
    if (fwOpenPorts != NULL)
        fwOpenPorts->Release();

    return hr;
}

/*-----------------------------------------------------------------------------
 * FWEL_AddAppToList
 *
 * Add an application to the firewall exception list
 *  Input:
 *    szAppFileName : File name (including path) of the application
 *    szAppName     : Name of the application
 *    iPort         : Port no. used
 *    iProtocol     : Protocol type : 1 = TCP, 2 = UDP, 3 = Both 
 *    szPortName    : Name of the port
 *
 *  Output: none
 * returns:
 *	TRUE  - succeeded
 *	FALSE - failed
*/
BOOL FWEL_AddAppToList(TCHAR* szAppFileName,
                       TCHAR* szAppName,
                       INT iPort,
                       INT iProtocol,
                       TCHAR* szPortName
                      )
{
  BOOL bRet = TRUE;
  HRESULT hr = S_OK;
  HRESULT comInit = E_FAIL;
  INetFwProfile* fwProfile = NULL;

  // Initialize COM.
  comInit = CoInitializeEx(0,COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

  // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
  // initialized with a different mode. Since we don't care what the mode is,
  // we'll just use the existing mode.
  if (comInit != RPC_E_CHANGED_MODE)
  {
    hr = comInit;
    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_AddAppToList"),_T("CoInitializeEx"), hr);
      bRet = FALSE;
    }
  }

  if(bRet)
  {
    // Retrieve the firewall profile currently in effect.
    hr = FWEL_Initialize(&fwProfile);
    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_AddAppToList"),_T("FWEL_Initialize"), hr);
      bRet = FALSE;
    }
  }

  if(bRet)
  {
    // Turn off the firewall.
    hr = FWEL_TurnOff(fwProfile);
    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_AddAppToList"),_T("FWEL_TurnOff"), hr);

      if( E_NOTIMPL != hr)  //special handling for win7, which dose not support the function
        bRet = FALSE;
    }
  }

  if(bRet && SUCCEEDED(hr))
  {
    // Turn on the firewall.
    hr = FWEL_TurnOn(fwProfile);
    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_AddAppToList"),_T("FWEL_TurnOn"), hr);
      
      if( E_NOTIMPL != hr)  //special handling for win7, which dose not support the function
        bRet = FALSE;
    }
  }

  if(bRet)
  {
    hr = FWEL_AddApp(fwProfile,szAppFileName,szAppName);

    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_AddAppToList"),_T("FWEL_AddApp"), hr);
      bRet = FALSE;
    }
  }

  if( bRet && iProtocol > 0 )
  {
    if( iProtocol == FWEL_PORT_PROTOCOL_TYPE_TCP) //TCP
      hr = FWEL_AddPort(fwProfile, iPort, NET_FW_IP_PROTOCOL_TCP, szPortName);
    else if( iProtocol == FWEL_PORT_PROTOCOL_TYPE_UDP) //UDP 
      hr = FWEL_AddPort(fwProfile, iPort, NET_FW_IP_PROTOCOL_UDP, szPortName);
    else if( iProtocol == FWEL_PORT_PROTOCOL_TYPE_ANY) //ANY
      hr = FWEL_AddPort(fwProfile, iPort, NET_FW_IP_PROTOCOL_ANY, szPortName);

    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_AddAppToList"),_T("FWEL_PortAdd"), hr);
      bRet = FALSE;
    }
  }
  
  // Release the firewall profile.
  FWEL_Cleanup(fwProfile);

  // Uninitialize COM.
  if (SUCCEEDED(comInit))
    CoUninitialize();

  return bRet;
}                     

                       
/*-----------------------------------------------------------------------------
 * FWEL_RemoveAppFromList
 *
 * Remove an application from the firewall exception list
 *  Input:
 *    szAppFileName : File name (including path) of the application
 *    szAppName     : Name of the application
 *    iPort         : Port no. used
 *    iProtocol     : Protocol type : 1 = TCP, 2 = UDP, 3 = Both 
 *    szPortName    : Name of the port
 *
 *  Output: none
 * returns:
 *	TRUE  - succeeded
 *	FALSE - failed
*/
BOOL FWEL_RemoveAppFromList(TCHAR* szAppFileName,
                       TCHAR* szAppName,
                       INT iPort,
                       INT iProtocol,
                       TCHAR* szPortName
                      )
{
  BOOL bRet = TRUE;
  HRESULT hr = S_OK;
  HRESULT comInit = E_FAIL;
  INetFwProfile* fwProfile = NULL;

  // Initialize COM.
  comInit = CoInitializeEx(0,COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

  // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
  // initialized with a different mode. Since we don't care what the mode is,
  // we'll just use the existing mode.
  if (comInit != RPC_E_CHANGED_MODE)
  {
    hr = comInit;
    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_RemoveAppFromList"),_T("CoInitializeEx"), hr);
      bRet = FALSE;
    }
  }

  if(bRet)
  {
    // Retrieve the firewall profile currently in effect.
    hr = FWEL_Initialize(&fwProfile);
    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_RemoveAppFromList"),_T("FWEL_Initialize"), hr);
      bRet = FALSE;
    }
  }

  if(bRet)
  {
    hr = FWEL_RemoveApp(fwProfile,szAppFileName);

    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_RemoveAppFromList"),_T("FWEL_AddApp"), hr);
      bRet = FALSE;
    }
  }

  if( bRet && iProtocol > 0 )
  {
    if( iProtocol == FWEL_PORT_PROTOCOL_TYPE_TCP) //TCP
      hr = FWEL_RemovePort(fwProfile, iPort, NET_FW_IP_PROTOCOL_TCP, szPortName);
    else if( iProtocol == FWEL_PORT_PROTOCOL_TYPE_UDP) //UDP 
      hr = FWEL_AddPort(fwProfile, iPort, NET_FW_IP_PROTOCOL_UDP, szPortName);
    else if( iProtocol == FWEL_PORT_PROTOCOL_TYPE_ANY) //ANY
      hr = FWEL_AddPort(fwProfile, iPort, NET_FW_IP_PROTOCOL_ANY, szPortName);

    if (FAILED(hr))
    {
      MsiLog(_T("FWEL_RemoveAppFromList"),_T("FWEL_PortAdd"), hr);
      bRet = FALSE;
    }
  }
  
  // Release the firewall profile.
  FWEL_Cleanup(fwProfile);

  // Uninitialize COM.
  if (SUCCEEDED(comInit))
    CoUninitialize();

  return bRet;
}                     

/*-----------------------------------------------------------------------------
 * AddDiscoveryServiceToFWEL
 *
 *  the custom action for adding "Discovery Service" to the firewall exception list
 *  
 * returns:
 *	RET_OK  - succeeded
 *	RET_ERROR - failed
*/
extern "C" LDSCA_API LONG AddDiscoveryServiceToFWEL( MSIHANDLE hInstall )
{
	LONG lRet = RET_OK;
	MsiLogSetHandle( hInstall );
	
  MsiLog(_T("AddDiscoveryServiceToFWEL"),_T("Start ..."));

  if (0 == checkWinVersionForFWEL())
  {
    MsiLog(_T("AddDiscoveryServiceToFWEL"),_T("Windows version not supported!"));
    return lRet;
  }

  TCHAR szCustomActionData[MAX_PATH+1] = {0};
	DWORD dwCustomActionDataLen = MAX_PATH+1;
	UINT gp = MsiGetProperty( hInstall, L"CustomActionData", szCustomActionData, &dwCustomActionDataLen );
	
	if( gp != 0 )
	{
        MsiLog( _T("AddDiscoveryServiceToFWEL"), _T("MsiGetProperty returned error") );
		return gp;
	}

	if( dwCustomActionDataLen == 0 )
	{
        MsiLog( _T("AddDiscoveryServiceToFWEL"), _T("CustomActionData Length is 0") );
		return 1;
	}

    TCHAR szApplicationPath[MAX_PATH*2+1];
    _stprintf_s( szApplicationPath, MAX_PATH*2+1, _T("%s%s"), szCustomActionData, _T("OPC Foundation\\UA\\Discovery\\bin\\opcualds.exe") );

    TCHAR szApplicationPath_Bonjour[MAX_PATH*2+1];
    _stprintf_s( szApplicationPath_Bonjour, MAX_PATH*2+1, _T("%s%s"), szCustomActionData, _T("OPC Foundation\\UA\\Discovery\\bin\\mDNSResponder.exe") );
    
  BOOL bRet = TRUE;
  HRESULT hr = S_OK;
  HRESULT comInit = E_FAIL;
  INetFwProfile* fwProfile = NULL;

  // Initialize COM.
  comInit = CoInitializeEx(0,COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

  // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
  // initialized with a different mode. Since we don't care what the mode is,
  // we'll just use the existing mode.
  if (comInit != RPC_E_CHANGED_MODE)
  {
    hr = comInit;
    if (FAILED(hr))
    {
      MsiLog(_T("AddDiscoveryServiceToFWEL"),_T("CoInitializeEx"), hr);
      bRet = FALSE;
    }
  }

  if(bRet)
  {
    // Retrieve the firewall profile currently in effect.
    hr = FWEL_Initialize(&fwProfile);
    if (FAILED(hr))
    {
      MsiLog(_T("AddDiscoveryServiceToFWEL"),_T("FWEL_Initialize"), hr);
      bRet = FALSE;
    }
  }

  if(bRet)
  {
    hr = FWEL_AddApp(fwProfile, szApplicationPath, APP_NAME_DSC);
    if (FAILED(hr))
    {
      MsiLog(_T("AddDiscoveryServiceToFWEL"),_T("FWEL_AddApp"), hr);
      bRet = FALSE;
    }
  }

  // add OPCF Bonjour to the list
  if(bRet)
  {
    hr = FWEL_AddApp(fwProfile, szApplicationPath_Bonjour, APP_NAME_BONJOUR_DSC);
    if (FAILED(hr))
    {
      MsiLog(_T("AddOPCFBonjourServiceToFWEL"),_T("FWEL_AddApp"), hr);
      bRet = FALSE;
    }
  }
  
  if( bRet)
  {
      MsiLog(_T("AddDiscoveryServiceToFWEL"),_T("... Finished!"));
      MsiLog(_T("AddOPCFBonjourServiceToFWEL"),_T("... Finished!"));
  }

  // Release the firewall profile.
  FWEL_Cleanup(fwProfile);

  // Uninitialize COM.
  if (SUCCEEDED(comInit))
    CoUninitialize();

   if(!bRet)
    return RET_ERROR;

  return lRet;

}
/*-----------------------------------------------------------------------------
 * RemoveDiscoveryServiceFromFWEL
 *
 *  the custom action for removing "Discovery Service" from the firewall exception list
 *  
 * returns:
 *	RET_OK  - succeeded
 *	RET_ERROR - failed
*/
extern "C" LDSCA_API LONG RemoveDiscoveryServiceFromFWEL( MSIHANDLE hInstall )
{
  BOOL bRet = TRUE;
  HRESULT hr = S_OK;
  HRESULT comInit = E_FAIL;
  INetFwProfile* fwProfile = NULL;

  LONG lRet = RET_OK;
	MsiLogSetHandle( hInstall );

  MsiLog(_T("RemoveDiscoveryServiceFromFWEL"),_T("Start ..."));

  if (0 == checkWinVersionForFWEL())
  {
    MsiLog(_T("RemoveDiscoveryServiceFromFWEL"),_T("Windows version not supported!"));
    return lRet;
  }

  TCHAR szCustomActionData[MAX_PATH+1] = {0};
	DWORD dwCustomActionDataLen = MAX_PATH+1;
	UINT gp = MsiGetProperty( hInstall, L"CustomActionData", szCustomActionData, &dwCustomActionDataLen );
	
	if( gp != 0 )
	{
    MsiLog( _T("RemoveDiscoveryServiceFromFWEL"), _T("MsiGetProperty returned error") );
		return gp;
	}

	if( dwCustomActionDataLen == 0 )
	{
    MsiLog( _T("RemoveDiscoveryServiceFromFWEL"), _T("CustomActionData Length is 0") );
		return 1;
	}

    TCHAR szApplicationPath[MAX_PATH*2+1];
    _stprintf_s( szApplicationPath, MAX_PATH*2+1, _T("%s%s"), szCustomActionData, _T("OPC Foundation\\UA\\Discovery\\bin\\opcualds.exe") );

    TCHAR szApplicationPathBonjour[MAX_PATH*2+1];
    _stprintf_s( szApplicationPathBonjour, MAX_PATH*2+1, _T("%s%s"), szCustomActionData, _T("OPC Foundation\\UA\\Discovery\\bin\\mDNSResponder.exe") );

  // Initialize COM.
  comInit = CoInitializeEx(0,COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

  // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
  // initialized with a different mode. Since we don't care what the mode is,
  // we'll just use the existing mode.
  if (comInit != RPC_E_CHANGED_MODE)
  {
    hr = comInit;
    if (FAILED(hr))
    {
      MsiLog(_T("RemoveDiscoveryServiceFromFWEL"),_T("CoInitializeEx"), hr);
      bRet = FALSE;
    }
  }

  if(bRet)
  {
    // Retrieve the firewall profile currently in effect.
    hr = FWEL_Initialize(&fwProfile);
    if (FAILED(hr))
    {
      MsiLog(_T("RemoveDiscoveryServiceFromFWEL"),_T("FWEL_Initialize"), hr);
      bRet = FALSE;
    }
  }

  if(bRet)
  {
    hr = FWEL_RemoveApp( fwProfile, szApplicationPath );

    if (FAILED(hr))
    {
      MsiLog(_T("RemoveDiscoveryServiceFromFWEL"),_T("FWEL_RemoveApp"), hr);
      bRet = FALSE;
    }
    
    hr = FWEL_RemoveApp( fwProfile, szApplicationPathBonjour );

    if (FAILED(hr))
    {
      MsiLog(_T("RemoveOPCFBonjourServiceFromFWEL"),_T("FWEL_RemoveApp"), hr);
      bRet = FALSE;
    }
  }

  if( bRet)
  {  
      MsiLog(_T("RemoveDiscoveryServiceFromFWEL"),_T("... Finished"));
  }
  
  // Release the firewall profile.
  FWEL_Cleanup(fwProfile);

  // Uninitialize COM.
  if (SUCCEEDED(comInit))
    CoUninitialize();

  if(!bRet)
    return RET_ERROR;
  return lRet;
}
