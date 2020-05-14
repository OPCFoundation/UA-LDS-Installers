ECHO off

SET ROOT=%~dp0
SET ZIP="C:\Program Files\7-zip\7z.exe"
SET LDSFN=OPC UA Local Discovery Server
SET VERSION=1.04.402.%BUILD_NUMBER%
SET SIGNTOOL=C:\Build\sign_output.bat
set VS_CONFIG=RelWithDebInfo

SET ISHIELD="C:\Program Files (x86)\InstallShield\2018\System\IsCmdBld.exe"
IF NOT EXIST %ISHIELD% SET ISHIELD="C:\Program Files (x86)\InstallShield\2016\System\IsCmdBld.exe"
ECHO Using %ISHIELD% 

ECHO 1) Cleaning Old Files
SET TARGET="%ROOT%\LocalDiscoveryServer_MergeModule\Product Configuration 1\LDS"
IF EXIST %TARGET% RMDIR /s /q %TARGET%
SET TARGET="%ROOT%\LocalDiscoveryServer_Installer\PROJECT_ASSISTANT\LDS"
IF EXIST %TARGET% RMDIR /s /q %TARGET%

ECHO 2) Copy Inputs
XCOPY /Q /S /Y %ROOT%\..\UA-LDS\build\bin\%VS_CONFIG%\*.* LDSBinaries\dist\bin\
XCOPY /Q /S /Y %ROOT%\..\mDNSResponder\bin\*.* LDSBinaries\dist\bin\
XCOPY /Q /S /Y %ROOT%\..\UA-LDS\etc\*.ini LDSBinaries\dist\etc\

CD %ROOT%\LocalDiscoveryServer_CustomActions
CALL build_custom-actions.bat 

ECHO 3) Build Merge Module
%ISHIELD% -p "%ROOT%\LocalDiscoveryServer_MergeModule\LocalDiscoveryServer_MergeModule.ism" -r "LDS" -c COMP -y "%VERSION%"
IF NOT ERRORLEVEL 0 EXIT /B 1
DIR "%ROOT%\LocalDiscoveryServer_MergeModule\Product Configuration 1\LDS\DiskImages\DISK1\"

CD "%ROOT%\LocalDiscoveryServer_MergeModule\Product Configuration 1\LDS\DiskImages\DISK1\"
REN "OPC_UA_Local_Discovery_Server_1.04*.exe" "OPC_UA_Local_Discovery_Server_%VERSION%.exe"

ECHO 4) Build Installer
%ISHIELD% -p "%ROOT%\LocalDiscoveryServer_Installer\LocalDiscoveryServer_Installer.ism" -r "LDS" -c COMP -y "%VERSION%"
IF NOT ERRORLEVEL 0 EXIT /B 2
DIR %ROOT%\LocalDiscoveryServer_Installer\PROJECT_ASSISTANT\LDS\DiskImages\DISK1\

REM Rename the installer so that it has the correct version number, not the hard-coded 1.03.341 version...
CD %ROOT%\LocalDiscoveryServer_Installer\PROJECT_ASSISTANT\LDS\DiskImages\DISK1\
REN "OPC UA Local Discovery Server 1.04*.exe" "OPC UA Local Discovery Server %VERSION%.exe"

ECHO STEP 5) Sign the Binaries
IF EXIST "%SIGNTOOL%" CALL "%SIGNTOOL%" "%ROOT%\LocalDiscoveryServer_MergeModule\Product Configuration 1\LDS\DiskImages\Disk1\*.msm"
IF EXIST "%SIGNTOOL%" CALL "%SIGNTOOL%" "opc ua local discovery server*.exe" /dual

ECHO STEP 6) ZIP the Binaries
CD %ROOT%\LocalDiscoveryServer_Installer\PROJECT_ASSISTANT\LDS\DiskImages\DISK1\
%ZIP% a "%LDSFN% %VERSION%.zip" "%LDSFN% *.exe"
%ZIP% a "%LDSFN% %VERSION%.zip" "%ROOT%\..\UA-LDS\Changelog.txt"
%ZIP% a "%LDSFN% %VERSION% MergeModule.zip" "%ROOT%\LocalDiscoveryServer_MergeModule\Product Configuration 1\LDS\DiskImages\Disk1\*.msm"

ECHO *** ALL DONE ***
GOTO theEnd

:theEnd
cd %ROOT%
ENDLOCAL
