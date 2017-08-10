// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the LDSCA_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// LDSCA_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef LDSCA_EXPORTS
#define LDSCA_API __declspec(dllexport)
#else
#define LDSCA_API __declspec(dllimport)
#endif

extern "C" LDSCA_API UINT UpdateUaldsIni( MSIHANDLE );

extern "C" LDSCA_API UINT BackupOldUaldsIni(MSIHANDLE);

extern "C" LDSCA_API UINT CopyPkiKeysFromOldIniFile(MSIHANDLE);

extern "C" LDSCA_API LONG AddDiscoveryServiceToFWEL(MSIHANDLE );

extern "C" LDSCA_API LONG RemoveDiscoveryServiceFromFWEL(MSIHANDLE );
